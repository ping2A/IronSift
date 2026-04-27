//! API/Web platform state and orchestration for ingestion and runs.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahash::AHashMap;
use anomark::{
    load_char_training_data, load_csv_with_columns, load_jsonl_with_columns, train_parallel,
    validate_train_file_kinds, LoadedCharTrainingData, ModelHandler, TrainFileKind, resolve_column_name,
};
use sigma_zero::engine::SigmaEngine;
use sigma_zero::models::LogEntry;
use sigma_zero::parser::{filter_rules, load_rules_from_directory};

use chrono::Utc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::event_db::EventDb;

use crate::analysis::analyze_fleet;
use crate::config::DetectionConfig;
use crate::file_analysis::analyze_files_fleet;
use crate::json_parse::parse_json_logs;
use crate::loaders::{
    load_csv_data, load_files_csv_data, load_files_json_data, load_files_jsonl_data, load_json_data,
    load_jsonl_data,
};
use crate::report::{AnomalyLevel, AnalysisType};
use crate::sigma_log_export::export_process_sources_to_sigma_jsonl;
use crate::types::{MachineFileProfile, MachineProfile, RawLogEntry};
use crate::event_db::DatasetInspection;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DatasetKind {
    Process,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRecord {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub format: String,
    pub kind: DatasetKind,
    pub tags: Vec<String>,
    pub schema_profile: String,
    pub imported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub machine_id: String,
    pub severity: String,
    pub score: f64,
    pub reasons: Vec<String>,
    pub detectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRunRecord {
    pub id: String,
    pub created_at: String,
    pub dataset_ids: Vec<String>,
    pub baseline_tags: Vec<String>,
    pub candidate_tags: Vec<String>,
    pub findings: Vec<DetectionFinding>,
    #[serde(default)]
    pub baseline_finding_count: usize,
    #[serde(default)]
    pub candidate_finding_count: usize,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PlatformDb {
    pub datasets: Vec<DatasetRecord>,
    pub runs: Vec<DetectionRunRecord>,
    pub anomark: AnoMarkSettings,
    /// [sigmazero](https://github.com/ping2A/sigmazero) (`sigma_zero` crate) for Sigma rules on process JSONL.
    #[serde(default)]
    pub sigma_zero: SigmaZeroSettings,
    pub run_config: DetectionConfig,
    /// Each successful AnoMark `train` run: persisted model + input and request snapshot.
    #[serde(default)]
    pub anomark_trainings: Vec<AnoMarkTrainRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneycombCell {
    pub name: String,
    pub value: f64,
    pub severity: String,
    /// False when the host is in the run’s ingested data but has no finding (fleet “green”).
    #[serde(default = "honey_infected_default")]
    pub infected: bool,
    /// When `min_score` / `severity` query params are set, `false` means the finding is outside the filter (UI may dim; host still shown).
    #[serde(default = "honey_matches_default")]
    pub matches_filter: bool,
    /// Populated when [`Self::infected`]; for detail panel in the web UI.
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub detectors: Vec<String>,
}

fn honey_infected_default() -> bool {
    true
}

fn honey_matches_default() -> bool {
    true
}

fn finding_passes(
    f: &DetectionFinding,
    min_score: Option<f64>,
    severity: Option<&str>,
) -> bool {
    if let Some(m) = min_score {
        if f.score < m {
            return false;
        }
    }
    if let Some(s) = severity {
        if !f.severity.eq_ignore_ascii_case(s) {
            return false;
        }
    }
    true
}

#[derive(Clone)]
pub struct PlatformStore {
    db_path: String,
    sql_path: String,
    db: Arc<RwLock<PlatformDb>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDatasetRequest {
    pub name: String,
    pub source_path: String,
    pub kind: DatasetKind,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_schema_profile")]
    pub schema_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRunRequest {
    pub dataset_ids: Vec<String>,
    #[serde(default)]
    pub baseline_tags: Vec<String>,
    #[serde(default)]
    pub candidate_tags: Vec<String>,
    #[serde(default)]
    pub enable_anomark: bool,
    /// When set, score with this training job’s `model.bin` instead of `anomark.model_path`.
    #[serde(default)]
    pub anomark_train_id: Option<String>,
}

/// Which AnoMark model files exist on disk (for the Runs & Findings UI).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainingAvailability {
    pub id: String,
    pub created_at: String,
    /// Absolute path the server will use.
    pub model_path: String,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkAvailability {
    pub config_path: String,
    pub config_available: bool,
    pub trainings: Vec<AnoMarkTrainingAvailability>,
    pub any_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPipelineRequest {
    pub directory: String,
    #[serde(default)]
    pub baseline_tag: String,
    #[serde(default)]
    pub candidate_tag: String,
    #[serde(default)]
    pub enable_anomark: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPipelineResult {
    pub imported_dataset_ids: Vec<String>,
    pub run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkSettings {
    /// Ignored; AnoMark runs in-process via the `anomark` crate. Kept for older `db.json` files.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bin_path: String,
    pub model_path: String,
    pub column: String,
    pub machine_field: String,
}

impl Default for AnoMarkSettings {
    fn default() -> Self {
        Self {
            bin_path: String::new(),
            model_path: String::new(),
            column: "command".to_string(),
            machine_field: "machine_id".to_string(),
        }
    }
}

/// Settings for [sigmazero](https://github.com/ping2A/sigmazero) (`sigma_zero` crate) against exported process logs
/// (see `export_process_sources_to_sigma_jsonl` in `sigma_log_export.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaZeroSettings {
    /// Ignored; Sigma runs in-process via the `sigma_zero` crate. Kept for older `db.json` files.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bin_path: String,
    /// Directory of Sigma rule YAML files.
    pub rules_dir: String,
    /// Optional default `--field-map` (e.g. `ImagePath:process_name,CommandLine:command_line` for Windows rules).
    #[serde(default)]
    pub field_map: String,
    /// Optional default parallel worker count (`-w`).
    #[serde(default)]
    pub workers: Option<usize>,
}

impl Default for SigmaZeroSettings {
    fn default() -> Self {
        Self {
            bin_path: String::new(),
            rules_dir: String::new(),
            field_map: String::new(),
            workers: None,
        }
    }
}

/// Run Sigma evaluation on a log file path or on selected process datasets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigmaZeroCheckRequest {
    /// If set, use this file as the log (JSON/JSONL). Ignores dataset selection.
    #[serde(default)]
    pub log_path: String,
    #[serde(default)]
    pub dataset_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Override `SigmaZeroSettings.rules_dir`.
    #[serde(default)]
    pub rules_dir: Option<String>,
    /// Per-request `--field-map` (wins over settings default if non-empty).
    #[serde(default)]
    pub field_map: Option<String>,
    #[serde(default)]
    pub filter_tags: Vec<String>,
    #[serde(default)]
    pub filter_levels: Vec<String>,
    #[serde(default)]
    pub filter_rule_ids: Vec<String>,
    #[serde(default)]
    pub workers: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaZeroCheckResult {
    pub status: String,
    pub line_count: u64,
    pub source_dataset_ids: Vec<String>,
    pub rules_dir: String,
    pub rules_match_count: usize,
    /// Serialized [`sigma_zero::models::RuleMatch`] (one per detection).
    pub matches: Vec<serde_json::Value>,
    #[serde(default)]
    /// Reserved; in-process engine does not use stderr. Empty string.
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainRequest {
    #[serde(default)]
    pub training_path: String,
    #[serde(default)]
    pub dataset_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_anomark_column")]
    pub column: String,
    #[serde(default = "default_anomark_order")]
    pub order: u8,
    /// Optional extra output path. If empty, the model is written only to
    /// `{platform}/anomark-trains/{train_id}/model.bin` and can be downloaded from the API.
    #[serde(default)]
    pub output_model_path: String,
}

/// Stored in [`PlatformDb::anomark_trainings`] and on disk under `{platform_data_dir}/anomark-trains/{id}/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainRecord {
    pub id: String,
    pub created_at: String,
    /// Exact request. `output_model_path` may be empty (model only in platform storage).
    pub request: AnoMarkTrainRequest,
    /// If training came from built-in dataset selection, these process dataset ids were used.
    #[serde(default)]
    pub source_dataset_ids: Vec<String>,
    /// `true` when `training_path` in the request pointed at an on-disk file; input was a copy of that file.
    #[serde(default)]
    pub from_user_file: bool,
    /// Relative to the platform data directory, e.g. `anomark-trains/{uuid}/model.bin`.
    pub rel_model_path: String,
    pub rel_training_data_path: String,
    pub training_line_count: u64,
    pub bin_path_used: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnoMarkTrainResult {
    pub status: String,
    pub model_path: String,
    /// Id for [`AnoMarkTrainRecord`] and download API.
    pub train_id: String,
    /// Persisted copy paths and metadata.
    pub record: AnoMarkTrainRecord,
}

struct AnoMarkTrainingInputMeta {
    from_user_file: bool,
    source_dataset_ids: Vec<String>,
    /// `true` when the path was a generated file under the OS temp directory (delete after copy).
    remove_source: bool,
}

fn default_anomark_column() -> String {
    "command".to_string()
}

fn default_anomark_order() -> u8 {
    4
}

fn default_schema_profile() -> String {
    "osquery-5.22.1".to_string()
}

impl PlatformStore {
    pub fn load_or_create(db_path: &str) -> Result<Self, Box<dyn Error>> {
        let db = if Path::new(db_path).exists() {
            let content = fs::read_to_string(db_path)?;
            serde_json::from_str::<PlatformDb>(&content)?
        } else {
            PlatformDb::default()
        };
        Ok(Self {
            db_path: db_path.to_string(),
            sql_path: ".ironsift-platform/events.db".to_string(),
            db: Arc::new(RwLock::new(db)),
        })
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let parent = Path::new(&self.db_path)
            .parent()
            .ok_or("invalid db path")?;
        fs::create_dir_all(parent)?;
        let db = self.db.read();
        fs::write(&self.db_path, serde_json::to_vec_pretty(&*db)?)?;
        Ok(())
    }

    pub fn list_datasets(&self) -> Vec<DatasetRecord> {
        self.db.read().datasets.clone()
    }

    pub fn list_runs(&self) -> Vec<DetectionRunRecord> {
        self.db.read().runs.clone()
    }

    pub fn get_anomark_settings(&self) -> AnoMarkSettings {
        self.db.read().anomark.clone()
    }

    /// Discover config + saved training models on disk (for UI: enable AnoMark when any exist).
    pub fn anomark_availability(&self) -> AnoMarkAvailability {
        let cfg = self.get_anomark_settings();
        let config_path = cfg.model_path.trim().to_string();
        let config_available = !config_path.is_empty() && Path::new(&config_path).is_file();
        let mut list = self.list_anomark_trainings();
        list.reverse();
        let mut trainings: Vec<AnoMarkTrainingAvailability> = Vec::new();
        for t in list {
            let model_path = self
                .anomark_train_stored_model_path(&t.id)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let available = !model_path.is_empty() && Path::new(&model_path).is_file();
            trainings.push(AnoMarkTrainingAvailability {
                id: t.id,
                created_at: t.created_at,
                model_path,
                available,
            });
        }
        let any_available = config_available || trainings.iter().any(|x| x.available);
        AnoMarkAvailability {
            config_path,
            config_available,
            trainings,
            any_available,
        }
    }

    /// Settings to use for a detection run, or `None` if AnoMark should be skipped.
    fn resolve_anomark_settings_for_run(
        &self,
        req: &CreateRunRequest,
    ) -> Option<AnoMarkSettings> {
        let mut s = self.get_anomark_settings();
        if let Some(tid) = &req.anomark_train_id {
            let t = tid.trim();
            if !t.is_empty() {
                if let Some(p) = self.anomark_train_stored_model_path(t) {
                    if p.is_file() {
                        s.model_path = p.to_string_lossy().to_string();
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        }
        let p = s.model_path.trim();
        if p.is_empty() {
            return None;
        }
        if !Path::new(p).is_file() {
            return None;
        }
        s.model_path = p.to_string();
        Some(s)
    }

    pub fn get_run_config(&self) -> DetectionConfig {
        self.db.read().run_config.clone()
    }

    pub fn set_run_config(&self, cfg: DetectionConfig) -> Result<DetectionConfig, Box<dyn Error>> {
        self.db.write().run_config = cfg.clone();
        self.save()?;
        Ok(cfg)
    }

    pub fn set_anomark_settings(
        &self,
        settings: AnoMarkSettings,
    ) -> Result<AnoMarkSettings, Box<dyn Error>> {
        self.db.write().anomark = settings.clone();
        self.save()?;
        Ok(settings)
    }

    pub fn get_sigma_zero_settings(&self) -> SigmaZeroSettings {
        self.db.read().sigma_zero.clone()
    }

    pub fn set_sigma_zero_settings(
        &self,
        settings: SigmaZeroSettings,
    ) -> Result<SigmaZeroSettings, Box<dyn Error>> {
        self.db.write().sigma_zero = settings.clone();
        self.save()?;
        Ok(settings)
    }

    /// Run [sigmazero](https://github.com/ping2A/sigmazero) on a log file or exported process datasets.
    pub fn check_sigma_zero(
        &self,
        req: SigmaZeroCheckRequest,
    ) -> Result<SigmaZeroCheckResult, Box<dyn Error>> {
        let st = self.get_sigma_zero_settings();
        let rules_dir: String = if let Some(r) = &req.rules_dir {
            r.trim()
        } else {
            st.rules_dir.trim()
        }
        .to_string();
        if rules_dir.is_empty() {
            return Err(
                "rules_dir not set: set sigma_zero.rules_dir in the API/DB, or pass rules_dir in the request (directory of Sigma .yml rules)"
                    .into(),
            );
        }
        let rpath = Path::new(&rules_dir);
        if !rpath.is_dir() {
            return Err(format!("Sigma rules_dir is not a directory: {}", rules_dir).into());
        }
        let (log_path, source_ids, cleanup_log, line_count) =
            if !req.log_path.trim().is_empty() {
                let p = Path::new(req.log_path.trim());
                if !p.is_file() {
                    return Err(format!("log_path is not a file: {}", req.log_path).into());
                }
                let n = Self::count_file_lines(p)?;
                (p.to_path_buf(), vec![], false, n)
            } else {
                let db = self.db.read();
                let mut selected: Vec<DatasetRecord> = db.datasets.clone();
                if !req.dataset_ids.is_empty() {
                    selected.retain(|d| req.dataset_ids.iter().any(|id| id == &d.id));
                }
                if !req.tags.is_empty() {
                    selected.retain(|d| d.tags.iter().any(|t| req.tags.iter().any(|rt| rt == t)));
                }
                selected.retain(|d| d.kind == DatasetKind::Process);
                if selected.is_empty() {
                    return Err(
                        "no process datasets selected (set log_path, or dataset_ids / tags for process datasets)"
                            .into(),
                    );
                }
                for ds in &selected {
                    let p = Path::new(&ds.source_path);
                    if !p.is_file() {
                        return Err(format!(
                            "dataset {} source file is missing: {}",
                            ds.id, ds.source_path
                        )
                        .into());
                    }
                }
                let source_ids: Vec<String> = selected.iter().map(|d| d.id.clone()).collect();
                let sources: Vec<(String, String)> = selected
                    .iter()
                    .map(|d| (d.source_path.clone(), d.format.clone()))
                    .collect();
                drop(db);
                let tmp = std::env::temp_dir().join(format!("ironsift-sigma-in-{}.jsonl", Uuid::new_v4()));
                let n = export_process_sources_to_sigma_jsonl(&sources, &tmp)?;
                if n == 0 {
                    return Err("exported zero process lines; nothing for Sigma to evaluate".into());
                }
                (tmp, source_ids, true, n)
            };

        let field_map: String = req
            .field_map
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.to_string())
            .or_else(|| {
                let s = st.field_map.trim();
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .unwrap_or_default();
        let workers: Option<usize> = req.workers.or(st.workers);

        let all_rules = load_rules_from_directory(Path::new(&rules_dir))
            .map_err(|e: anyhow::Error| -> Box<dyn Error> { e.to_string().into() })?;
        let filtered = filter_rules(
            all_rules,
            &req.filter_tags,
            &req.filter_levels,
            &req.filter_rule_ids,
        );
        let count_loaded = filtered.len();
        if count_loaded == 0 {
            if cleanup_log {
                let _ = fs::remove_file(&log_path);
            }
            return Err(
                "no Sigma rules to evaluate after tag/level/id filters (check your rules_dir and filters)"
                    .into(),
            );
        }

        let mut engine = SigmaEngine::new(workers);
        if !field_map.is_empty() {
            engine.set_field_map(parse_sigma_field_map(&field_map));
        }
        let _n = engine
            .load_rules_from_rules(filtered)
            .map_err(|e: anyhow::Error| -> Box<dyn Error> { e.to_string().into() })?;

        let log_text = fs::read_to_string(&log_path)
            .map_err(|e| -> Box<dyn Error> { e.to_string().into() })?;
        let mut entries: Vec<LogEntry> = Vec::new();
        for line in log_text.lines() {
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(e) = serde_json::from_str::<LogEntry>(t) {
                entries.push(e);
            }
        }
        if entries.is_empty() {
            if cleanup_log {
                let _ = fs::remove_file(&log_path);
            }
            return Err("no valid JSON log lines to evaluate (expected JSON objects per line)".into());
        }

        let rule_matches = engine.evaluate_log_batch(&entries);
        let n_rules = rule_matches.len();
        let mut matches: Vec<serde_json::Value> = Vec::with_capacity(n_rules);
        for m in rule_matches {
            matches.push(serde_json::to_value(&m).map_err(|e| e.to_string())?);
        }

        if cleanup_log {
            let _ = fs::remove_file(&log_path);
        }
        Ok(SigmaZeroCheckResult {
            status: "ok".to_string(),
            line_count,
            source_dataset_ids: source_ids,
            rules_dir: rules_dir.to_string(),
            rules_match_count: n_rules,
            matches,
            stderr: String::new(),
        })
    }

    pub fn train_anomark(
        &self,
        req: AnoMarkTrainRequest,
    ) -> Result<AnoMarkTrainResult, Box<dyn Error>> {
        let (source_training_path, meta) = self.resolve_anomark_training_input(&req)?;
        let settings = self.get_anomark_settings();
        let train_id = Uuid::new_v4().to_string();
        let root = self.platform_root()?;
        let out_dir = root.join("anomark-trains").join(&train_id);
        fs::create_dir_all(&out_dir)?;
        let ext = source_training_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("jsonl");
        let stored_basename = format!("training_input.{}", ext);
        let stored_input = out_dir.join(&stored_basename);
        let stored_model = out_dir.join("model.bin");
        fs::copy(&source_training_path, &stored_input)?;
        if meta.remove_source {
            let _ = fs::remove_file(&source_training_path);
        }
        let line_count = Self::count_file_lines(&stored_input)?;

        let user_path = req.output_model_path.trim();
        let (anomark_out, also_copy_to_platform): (PathBuf, bool) = if user_path.is_empty() {
            (stored_model.clone(), false)
        } else {
            let p = Path::new(user_path).to_path_buf();
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            (p, true)
        };

        let order = req.order as usize;
        let kind = match ext.to_ascii_lowercase().as_str() {
            "csv" => TrainFileKind::Csv,
            "txt" => TrainFileKind::Txt,
            _ => TrainFileKind::Jsonl,
        };
        let files = vec![(stored_input.clone(), kind)];
        validate_train_file_kinds(&files).map_err(|e: anyhow::Error| e.to_string())?;
        let col = resolve_column_name(
            &files,
            if req.column.is_empty() {
                None
            } else {
                Some(req.column.as_str())
            },
        )
        .map_err(|e: anyhow::Error| e.to_string())?;
        let loaded = load_char_training_data(&files, col.as_deref(), None, None, None)
            .map_err(|e: anyhow::Error| e.to_string())?;

        let mut model = match loaded {
            LoadedCharTrainingData::Lines { ref lines, .. } if lines.is_empty() => {
                let _ = fs::remove_dir_all(&out_dir);
                return Err("no training lines in input".into());
            }
            LoadedCharTrainingData::Lines { lines, counts } => {
                if lines.len() > 2_000 {
                    train_parallel(&lines, order, counts.as_deref(), None)
                } else {
                    ModelHandler::train_from_csv(&lines, order, counts.as_deref(), None)
                }
            }
            .map_err(|e: anyhow::Error| e.to_string())?,
            LoadedCharTrainingData::Corpus { text } => {
                ModelHandler::train_from_txt(&text, order, None)
                    .map_err(|e: anyhow::Error| e.to_string())?
            }
        };
        model.normalize_model_and_compute_prior();
        let out_s = anomark_out
            .to_str()
            .ok_or("output model path is not valid UTF-8")?;
        ModelHandler::save_model(&model, Some(out_s)).map_err(|e: anyhow::Error| e.to_string())?;

        if !anomark_out.is_file() {
            let _ = fs::remove_dir_all(&out_dir);
            return Err("model file not found after anomark train (save failed)".into());
        }
        if also_copy_to_platform {
            if anomark_out != stored_model {
                fs::copy(&anomark_out, &stored_model)?;
            }
        }
        let rel = format!("anomark-trains/{}", train_id);
        let canonical_path = stored_model;
        let record = AnoMarkTrainRecord {
            id: train_id.clone(),
            created_at: Utc::now().to_rfc3339(),
            request: req.clone(),
            source_dataset_ids: meta.source_dataset_ids,
            from_user_file: meta.from_user_file,
            rel_model_path: format!("{}/model.bin", rel),
            rel_training_data_path: format!("{}/{}", rel, stored_basename),
            training_line_count: line_count,
            bin_path_used: "anomark (in-process library)".to_string(),
        };
        self.db.write().anomark_trainings.push(record.clone());
        self.save()?;
        let mut updated = settings;
        updated.model_path = canonical_path.to_string_lossy().to_string();
        updated.column = req.column.clone();
        self.set_anomark_settings(updated)?;
        Ok(AnoMarkTrainResult {
            status: "ok".to_string(),
            model_path: canonical_path.to_string_lossy().to_string(),
            train_id: train_id.clone(),
            record,
        })
    }

    fn platform_root(&self) -> Result<PathBuf, Box<dyn Error>> {
        Path::new(&self.db_path)
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "invalid platform database path (no parent directory)".into())
    }

    fn count_file_lines(path: &Path) -> Result<u64, Box<dyn Error>> {
        let f = fs::File::open(path)?;
        let n = BufReader::new(f).lines().count() as u64;
        Ok(n)
    }

    /// Returns path to a JSONL training file and metadata (dataset source vs external file).
    fn resolve_anomark_training_input(
        &self,
        req: &AnoMarkTrainRequest,
    ) -> Result<(PathBuf, AnoMarkTrainingInputMeta), Box<dyn Error>> {
        if !req.training_path.trim().is_empty() {
            let p = Path::new(&req.training_path);
            if !p.exists() {
                return Err(format!("training_path does not exist: {}", req.training_path).into());
            }
            return Ok((
                p.to_path_buf(),
                AnoMarkTrainingInputMeta {
                    from_user_file: true,
                    source_dataset_ids: vec![],
                    remove_source: false,
                },
            ));
        }

        let db = self.db.read();
        let mut selected: Vec<DatasetRecord> = db.datasets.clone();
        if !req.dataset_ids.is_empty() {
            selected.retain(|d| req.dataset_ids.iter().any(|id| id == &d.id));
        }
        if !req.tags.is_empty() {
            selected.retain(|d| d.tags.iter().any(|t| req.tags.iter().any(|rt| rt == t)));
        }
        selected.retain(|d| d.kind == DatasetKind::Process);
        if selected.is_empty() {
            return Err(
                "no process datasets selected for training (provide training_path or dataset_ids/tags)"
                    .into(),
            );
        }
        for ds in &selected {
            let p = Path::new(&ds.source_path);
            if !p.is_file() {
                return Err(format!(
                    "dataset {} source file is missing or not a file: {}",
                    ds.id, ds.source_path
                )
                .into());
            }
        }
        let source_ids: Vec<String> = selected.iter().map(|d| d.id.clone()).collect();
        drop(db);

        let tmp_name = format!("anomark-train-{}.jsonl", Uuid::new_v4());
        let tmp_path = std::env::temp_dir().join(&tmp_name);
        let mut out = String::new();
        for ds in selected {
            let profiles = load_process_profiles(&ds, &DetectionConfig::default())?;
            for p in profiles {
                for (sig, count) in p.counts {
                    for _ in 0..count {
                        out.push_str(
                            &serde_json::json!({
                                "machine_id": p.id,
                                "command": format!("{} {}", sig.path, sig.name),
                            })
                            .to_string(),
                        );
                        out.push('\n');
                    }
                }
            }
        }
        if out.trim().is_empty() {
            return Err("selected datasets produced no trainable commands".into());
        }
        fs::write(&tmp_path, &out)?;
        Ok((
            tmp_path,
            AnoMarkTrainingInputMeta {
                from_user_file: false,
                source_dataset_ids: source_ids,
                remove_source: true,
            },
        ))
    }

    /// List training jobs newest last (or reverse in UI from API).
    pub fn list_anomark_trainings(&self) -> Vec<AnoMarkTrainRecord> {
        self.db.read().anomark_trainings.clone()
    }

    /// Path to a persisted `model.bin` for download, or `None` if missing.
    pub fn anomark_train_stored_model_path(&self, train_id: &str) -> Option<PathBuf> {
        let rec = self
            .db
            .read()
            .anomark_trainings
            .iter()
            .find(|r| r.id == train_id)
            .cloned()?;
        let root = self.platform_root().ok()?;
        let p = root.join(&rec.rel_model_path);
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    /// Path to a persisted `training_input.jsonl`, or `None` if missing.
    pub fn anomark_train_stored_training_data_path(&self, train_id: &str) -> Option<PathBuf> {
        let rec = self
            .db
            .read()
            .anomark_trainings
            .iter()
            .find(|r| r.id == train_id)
            .cloned()?;
        let root = self.platform_root().ok()?;
        let p = root.join(&rec.rel_training_data_path);
        if p.is_file() {
            Some(p)
        } else {
            None
        }
    }

    pub fn get_run(&self, id: &str) -> Option<DetectionRunRecord> {
        self.db.read().runs.iter().find(|r| r.id == id).cloned()
    }

    /// Remove a single saved detection run from `db.json` (ingested datasets are unchanged).
    pub fn delete_run(&self, run_id: &str) -> Result<(), Box<dyn Error>> {
        {
            let mut w = self.db.write();
            let n = w.runs.len();
            w.runs.retain(|r| r.id != run_id);
            if w.runs.len() == n {
                return Err(format!("run not found: {}", run_id).into());
            }
        }
        self.save()?;
        Ok(())
    }

    /// Remove all detection runs (same storage as `delete_all_datasets` — only the run list in `db.json`).
    pub fn delete_all_runs(&self) -> Result<(), Box<dyn Error>> {
        self.db.write().runs.clear();
        self.save()?;
        Ok(())
    }

    pub fn inspect_dataset(&self, dataset_id: &str) -> Result<DatasetInspection, Box<dyn Error>> {
        EventDb::new(&self.sql_path)?.inspect_dataset(dataset_id)
    }

    pub fn delete_all_datasets(&self) -> Result<(), Box<dyn Error>> {
        EventDb::new(&self.sql_path)?.delete_all_datasets()?;
        self.db.write().datasets.clear();
        self.save()?;
        Ok(())
    }

    pub fn create_dataset(&self, req: CreateDatasetRequest) -> Result<DatasetRecord, Box<dyn Error>> {
        if !Path::new(&req.source_path).exists() {
            return Err(format!("source_path does not exist: {}", req.source_path).into());
        }
        let format = match Path::new(&req.source_path).extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.to_lowercase(),
            None => "unknown".to_string(),
        };
        let rec = DatasetRecord {
            id: Uuid::new_v4().to_string(),
            name: req.name,
            source_path: req.source_path,
            format,
            kind: req.kind,
            tags: req.tags,
            schema_profile: req.schema_profile,
            imported_at: Utc::now().to_rfc3339(),
        };
        EventDb::new(&self.sql_path)?.ingest_dataset(&rec)?;
        self.db.write().datasets.push(rec.clone());
        self.save()?;
        Ok(rec)
    }

    pub fn import_file_auto(
        &self,
        source_path: &str,
        name: Option<String>,
        tags: Vec<String>,
    ) -> Result<DatasetRecord, Box<dyn Error>> {
        let path = Path::new(source_path);
        if !path.exists() {
            return Err(format!("source_path does not exist: {}", source_path).into());
        }
        let kind = detect_kind(path)?;
        let dataset_name = name.unwrap_or_else(|| {
            path.file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("dataset")
                .to_string()
        });
        self.create_dataset(CreateDatasetRequest {
            name: dataset_name,
            source_path: source_path.to_string(),
            kind,
            tags,
            schema_profile: default_schema_profile(),
        })
    }

    pub fn add_dataset_tags(&self, dataset_id: &str, tags: &[String]) -> Result<DatasetRecord, Box<dyn Error>> {
        let mut db = self.db.write();
        let rec = db
            .datasets
            .iter_mut()
            .find(|d| d.id == dataset_id)
            .ok_or("dataset not found")?;
        for t in tags {
            if !rec.tags.iter().any(|x| x == t) {
                rec.tags.push(t.clone());
            }
        }
        let out = rec.clone();
        drop(db);
        EventDb::new(&self.sql_path)?.ingest_dataset(&out)?;
        self.save()?;
        Ok(out)
    }

    pub fn run_detection(&self, req: CreateRunRequest) -> Result<DetectionRunRecord, Box<dyn Error>> {
        let datasets = self.selected_datasets(&req)?;
        let config = self.get_run_config();

        let process_sets: Vec<_> = datasets
            .iter()
            .filter(|d| d.kind == DatasetKind::Process)
            .cloned()
            .collect();
        let file_sets: Vec<_> = datasets
            .iter()
            .filter(|d| d.kind == DatasetKind::File)
            .cloned()
            .collect();

        let mut finding_by_host: HashMap<String, DetectionFinding> = HashMap::new();

        if !process_sets.is_empty() {
            let mut all = Vec::<MachineProfile>::new();
            for d in &process_sets {
                all.extend(load_process_profiles(d, &config)?);
            }
            let merged = merge_process_profiles(&all);
            let report = analyze_fleet(&merged, &config)?;
            for an in report.anomalies {
                let sev_score = match an.severity {
                    AnomalyLevel::Critical => 1.0,
                    AnomalyLevel::High => 0.75,
                    AnomalyLevel::Medium => 0.5,
                    AnomalyLevel::Low => 0.25,
                };
                let e = finding_by_host
                    .entry(an.machine_id.clone())
                    .or_insert_with(|| DetectionFinding {
                        machine_id: an.machine_id.clone(),
                        severity: "LOW".to_string(),
                        score: 0.0,
                        reasons: Vec::new(),
                        detectors: Vec::new(),
                    });
                e.score = e.score.max(sev_score);
                e.reasons.extend(an.anomalous_features);
                e.detectors.push("ironsift-process".to_string());
            }
            if req.enable_anomark {
                if let Some(amo) = self.resolve_anomark_settings_for_run(&req) {
                    let an_scores = score_with_anomark(&process_sets, &amo)?;
                    for (host, s) in an_scores {
                        let s = finite_f64(s);
                        let e = finding_by_host.entry(host.clone()).or_insert_with(|| DetectionFinding {
                            machine_id: host,
                            severity: "LOW".to_string(),
                            score: 0.0,
                            reasons: Vec::new(),
                            detectors: Vec::new(),
                        });
                        e.score = e
                            .score
                            .max(finite_f64((e.score * 0.7) + (s * 0.3)));
                        e.reasons
                            .push(format!("AnoMark suspicious command ratio {:.2}", s));
                        e.detectors.push("anomark-rs".to_string());
                    }
                }
            }
        }

        if !file_sets.is_empty() {
            let mut all = Vec::<MachineFileProfile>::new();
            for d in &file_sets {
                all.extend(load_file_profiles(d, &config)?);
            }
            let merged = merge_file_profiles(&all);
            let report = analyze_files_fleet(&merged, &config)?;
            for an in report.anomalies {
                let sev_score = match an.severity {
                    AnomalyLevel::Critical => 1.0,
                    AnomalyLevel::High => 0.75,
                    AnomalyLevel::Medium => 0.5,
                    AnomalyLevel::Low => 0.25,
                };
                let e = finding_by_host
                    .entry(an.machine_id.clone())
                    .or_insert_with(|| DetectionFinding {
                        machine_id: an.machine_id.clone(),
                        severity: "LOW".to_string(),
                        score: 0.0,
                        reasons: Vec::new(),
                        detectors: Vec::new(),
                    });
                e.score = e.score.max(sev_score);
                e.reasons.extend(an.anomalous_features);
                e.detectors.push("ironsift-file".to_string());
            }
        }

        let mut findings: Vec<_> = finding_by_host
            .into_values()
            .map(|mut f| {
                f.score = finite_f64(f.score);
                f.severity = severity_from_score(f.score).to_string();
                f.reasons.sort();
                f.reasons.dedup();
                f.detectors.sort();
                f.detectors.dedup();
                f
            })
            .collect();
        findings.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        let selected_ids: Vec<String> = datasets.iter().map(|d| d.id.clone()).collect();
        let rec = DetectionRunRecord {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now().to_rfc3339(),
            dataset_ids: selected_ids,
            baseline_tags: req.baseline_tags,
            candidate_tags: req.candidate_tags,
            baseline_finding_count: 0,
            candidate_finding_count: findings.len(),
            summary: format!("{} findings", findings.len()),
            findings,
        };
        self.db.write().runs.push(rec.clone());
        self.save()?;
        Ok(rec)
    }

    pub fn honeycomb_for_run(&self, run_id: &str) -> Option<Vec<HoneycombCell>> {
        self.honeycomb_for_run_filtered(run_id, None, None)
    }

    /// One cell per host in the run: every machine seen in ingested datasets (SQLite) **plus** any
    /// host in findings. Clean machines are green; infected use score/severity from the run.
    /// Filter query params do not drop cells; they set [`HoneycombCell::matches_filter`].
    pub fn honeycomb_for_run_filtered(
        &self,
        run_id: &str,
        min_score: Option<f64>,
        severity: Option<&str>,
    ) -> Option<Vec<HoneycombCell>> {
        let r = self.get_run(run_id)?;
        let from_db: Vec<String> = EventDb::new(&self.sql_path)
            .and_then(|db| db.distinct_machine_ids_for_datasets(&r.dataset_ids))
            .unwrap_or_default();
        let mut ids: BTreeSet<String> = from_db.into_iter().collect();
        for f in &r.findings {
            ids.insert(f.machine_id.clone());
        }
        let mut all: Vec<String> = ids.into_iter().collect();
        all.sort();

        let by_machine: HashMap<String, &DetectionFinding> = r
            .findings
            .iter()
            .map(|f| (f.machine_id.clone(), f))
            .collect();

        let cells: Vec<HoneycombCell> = all
            .into_iter()
            .map(|name| {
                if let Some(f) = by_machine.get(&name) {
                    let matches_filter = finding_passes(f, min_score, severity);
                    HoneycombCell {
                        name,
                        value: f.score,
                        severity: f.severity.clone(),
                        infected: true,
                        matches_filter,
                        reasons: f.reasons.clone(),
                        detectors: f.detectors.clone(),
                    }
                } else {
                    HoneycombCell {
                        name,
                        value: 0.0,
                        severity: "CLEAN".to_string(),
                        infected: false,
                        matches_filter: true,
                        reasons: vec![],
                        detectors: vec![],
                    }
                }
            })
            .collect();
        Some(cells)
    }

    pub fn run_auto_pipeline(
        &self,
        req: AutoPipelineRequest,
    ) -> Result<AutoPipelineResult, Box<dyn Error>> {
        let dir = Path::new(&req.directory);
        if !dir.is_dir() {
            return Err(format!("directory not found: {}", req.directory).into());
        }
        let mut ids = Vec::new();
        for entry in fs::read_dir(dir)? {
            let p = entry?.path();
            if !p.is_file() {
                continue;
            }
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or_default();
            if ext != "csv" && ext != "json" && ext != "jsonl" {
                continue;
            }
            let mut tags = Vec::new();
            if !req.candidate_tag.is_empty() {
                tags.push(req.candidate_tag.clone());
            }
            let fname = p.file_name().and_then(|x| x.to_str()).unwrap_or_default();
            if fname.contains("baseline") && !req.baseline_tag.is_empty() {
                tags.push(req.baseline_tag.clone());
            }
            let rec = self.import_file_auto(p.to_str().unwrap_or_default(), None, tags)?;
            ids.push(rec.id);
        }
        if ids.is_empty() {
            return Err("no importable files found (csv/json/jsonl)".into());
        }
        let run = self.run_detection(CreateRunRequest {
            dataset_ids: ids.clone(),
            baseline_tags: if req.baseline_tag.is_empty() {
                Vec::new()
            } else {
                vec![req.baseline_tag]
            },
            candidate_tags: if req.candidate_tag.is_empty() {
                Vec::new()
            } else {
                vec![req.candidate_tag]
            },
            enable_anomark: req.enable_anomark,
            anomark_train_id: None,
        })?;
        Ok(AutoPipelineResult {
            imported_dataset_ids: ids,
            run_id: run.id,
        })
    }

    fn selected_datasets(&self, req: &CreateRunRequest) -> Result<Vec<DatasetRecord>, Box<dyn Error>> {
        let db = self.db.read();
        if db.datasets.is_empty() {
            return Err(
                "no datasets: import on Ingestion first, or check .ironsift-platform/db.json."
                    .into(),
            );
        }
        let mut selected: Vec<DatasetRecord> = db.datasets.clone();
        if !req.dataset_ids.is_empty() {
            selected.retain(|d| req.dataset_ids.iter().any(|id| id == &d.id));
        }
        let mut tag_filter: Vec<String> = req.baseline_tags.clone();
        tag_filter.extend(req.candidate_tags.clone());
        if !tag_filter.is_empty() {
            selected.retain(|d| d.tags.iter().any(|t| tag_filter.contains(t)));
        }
        if selected.is_empty() {
            return Err(
                "no datasets match the request: check dataset id(s) (comma field + checkboxes), and tags in baseline or candidate fields; tags must match dataset tags exactly."
                    .into(),
            );
        }
        Ok(selected)
    }
}

/// JSON and many JSON serializers reject NaN/±∞; keep scores in-range for the API and `db.json`.
fn finite_f64(x: f64) -> f64 {
    if x.is_finite() { x } else { 0.0 }
}

fn severity_from_score(score: f64) -> &'static str {
    let score = finite_f64(score);
    if score >= 0.9 {
        "CRITICAL"
    } else if score >= 0.7 {
        "HIGH"
    } else if score >= 0.4 {
        "MEDIUM"
    } else {
        "LOW"
    }
}

fn load_process_profiles(
    dataset: &DatasetRecord,
    cfg: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    match dataset.format.as_str() {
        "jsonl" => load_jsonl_data(&dataset.source_path, cfg),
        "json" => load_json_data(&dataset.source_path, cfg),
        "csv" => load_csv_data(&dataset.source_path, cfg),
        _ => Err(format!("unsupported process dataset format: {}", dataset.format).into()),
    }
}

fn detect_kind(path: &Path) -> Result<DatasetKind, Box<dyn Error>> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    if ext == "csv" {
        let mut rdr = csv::Reader::from_path(path)?;
        let headers = rdr.headers()?.clone();
        let h = headers
            .iter()
            .map(|x| x.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let has_pid = h.iter().any(|x| x == "pid");
        let has_name = h.iter().any(|x| x == "name");
        let has_args = h.iter().any(|x| x == "args");
        if has_pid || has_name || has_args {
            Ok(DatasetKind::Process)
        } else {
            Ok(DatasetKind::File)
        }
    } else if ext == "json" || ext == "jsonl" {
        // Heuristic based on filename when JSON shape is unknown.
        let n = path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if n.contains("file") {
            Ok(DatasetKind::File)
        } else {
            Ok(DatasetKind::Process)
        }
    } else {
        Err("unsupported format for auto detection".into())
    }
}

fn load_file_profiles(
    dataset: &DatasetRecord,
    cfg: &DetectionConfig,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    match dataset.format.as_str() {
        "jsonl" => load_files_jsonl_data(&dataset.source_path, cfg),
        "json" => load_files_json_data(&dataset.source_path, cfg),
        "csv" => load_files_csv_data(&dataset.source_path, cfg),
        _ => Err(format!("unsupported file dataset format: {}", dataset.format).into()),
    }
}

fn merge_process_profiles(input: &[MachineProfile]) -> Vec<MachineProfile> {
    let mut map: HashMap<String, MachineProfile> = HashMap::new();
    for p in input {
        let slot = map.entry(p.id.clone()).or_insert_with(|| MachineProfile::new(&p.id));
        slot.total_logs += p.total_logs;
        for (sig, count) in &p.counts {
            *slot.counts.entry(sig.clone()).or_insert(0) += *count;
        }
    }
    map.into_values().collect()
}

fn merge_file_profiles(input: &[MachineFileProfile]) -> Vec<MachineFileProfile> {
    let mut map: HashMap<String, MachineFileProfile> = HashMap::new();
    for p in input {
        let slot = map.entry(p.id.clone()).or_insert_with(|| MachineFileProfile::new(&p.id));
        slot.total_logs += p.total_logs;
        for (sig, count) in &p.counts {
            *slot.counts.entry(sig.clone()).or_insert(0) += *count;
        }
        for (path, mt) in &p.file_mtimes {
            slot.file_mtimes.insert(path.clone(), *mt);
        }
        for (k, v) in &p.file_path_owner {
            slot.file_path_owner.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.file_path_group {
            slot.file_path_group.insert(k.clone(), v.clone());
        }
        for (k, v) in &p.file_path_size {
            slot.file_path_size.insert(k.clone(), *v);
        }
    }
    map.into_values().collect()
}

fn score_with_anomark(
    process_datasets: &[DatasetRecord],
    settings: &AnoMarkSettings,
) -> Result<HashMap<String, f64>, Box<dyn Error>> {
    if settings.model_path.is_empty() {
        return Ok(HashMap::new());
    }
    let model_path = settings.model_path.as_str();
    let column = if settings.column.is_empty() {
        "command"
    } else {
        settings.column.as_str()
    };
    let machine_field = if settings.machine_field.is_empty() {
        "machine_id"
    } else {
        settings.machine_field.as_str()
    };

    let mut model = ModelHandler::load_model(model_path).map_err(|e: anyhow::Error| e.to_string())?;
    if !model.is_trained() {
        model.normalize_model_and_compute_prior();
    }
    let threshold_ln = ModelHandler::compute_threshold(&model, 95.0);

    let mut totals: HashMap<String, (u32, u32)> = HashMap::new();

    for ds in process_datasets {
        // `anomark::load_jsonl_with_columns` is for newline-delimited JSON, not a single JSON array file.
        // `json` process datasets are loaded elsewhere via `parse_json_logs` — match that here.
        let rows: Vec<AHashMap<String, String>> = match ds.format.as_str() {
            "json" => {
                let content = fs::read_to_string(&ds.source_path)
                    .map_err(|e: std::io::Error| e.to_string())?;
                let entries = parse_json_logs(&content).map_err(|e| e.to_string())?;
                if entries.is_empty() {
                    log::warn!(
                        "AnoMark: no parseable process rows in json dataset at {}",
                        ds.source_path
                    );
                }
                entries.iter().map(raw_log_entry_to_anomark_row).collect()
            }
            "jsonl" => load_jsonl_with_columns(&ds.source_path)
                .map_err(|e: anyhow::Error| e.to_string())?,
            "csv" => load_csv_with_columns(&ds.source_path)
                .map_err(|e: anyhow::Error| e.to_string())?,
            _ => return Err(
                format!(
                    "unsupported dataset format for anomark scoring: {} (use csv, json, or jsonl)",
                    ds.format
                )
                .into(),
            ),
        };
        for row in rows {
            let cmd = row_key_lookup(&row, column);
            let host = row_key_lookup(&row, machine_field);
            if cmd.is_empty() {
                continue;
            }
            let padded = format!("{}{}", "~".repeat(model.order), cmd);
            let score = model.log_likelihood(&padded);
            let suspect = ModelHandler::is_suspect_command(score, threshold_ln);
            let entry = totals.entry(host).or_insert((0, 0));
            entry.0 += 1;
            if suspect {
                entry.1 += 1;
            }
        }
    }

    let mut scores = HashMap::new();
    for (host, (all, suspect)) in totals {
        if all > 0 {
            scores.insert(host, suspect as f64 / all as f64);
        }
    }
    Ok(scores)
}

/// Comma-separated `RuleField:log_field` pairs for sigmazero.
fn parse_sigma_field_map(s: &str) -> HashMap<String, String> {
    s.split(',')
        .filter_map(|part| {
            let mut it = part.splitn(2, ':');
            let a = it.next()?.trim();
            let b = it.next()?.trim();
            if a.is_empty() {
                return None;
            }
            Some((a.to_string(), b.to_string()))
        })
        .collect()
}

/// Case-insensitive single-value lookup in a training row.
/// String rows for AnoMark, aligned with `parse_json_logs` / `load_json_data` (not line-oriented JSONL helpers).
fn raw_log_entry_to_anomark_row(e: &RawLogEntry) -> AHashMap<String, String> {
    let mut m = AHashMap::new();
    m.insert("machine_id".to_string(), e.machine_id.clone());
    m.insert("hostname".to_string(), e.machine_id.clone());
    m.insert("host".to_string(), e.machine_id.clone());
    let command = if !e.path.is_empty() {
        if e.args.is_empty() {
            e.path.clone()
        } else {
            format!("{} {}", e.path, e.args)
        }
    } else {
        e.name.clone()
    };
    m.insert("command".to_string(), command);
    m
}

fn row_key_lookup(row: &AHashMap<String, String>, col: &str) -> String {
    if let Some(v) = row.get(col) {
        return v.clone();
    }
    let want = col.to_ascii_lowercase();
    for (k, v) in row {
        if k.to_ascii_lowercase() == want {
            return v.clone();
        }
    }
    String::new()
}

#[allow(dead_code)]
fn _analysis_type_name(t: AnalysisType) -> &'static str {
    match t {
        AnalysisType::Process => "process",
        AnalysisType::File => "file",
    }
}
