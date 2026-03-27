//! File-based fleet analysis: build file profiles and run DBSCAN + mtime anomaly detection.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use ndarray::Array2;
use linfa::traits::Transformer;
use linfa_clustering::Dbscan;
use rayon::prelude::*;
use log;
use regex::Regex;

use crate::config::{DetectionConfig, FileRecentMtimeConfig};
use crate::interner::SharedInterner;
use crate::report::{AnalysisReport, AnalysisType, AnomalyDetails, AnomalyLevel};
use crate::types::{FileSignature, MachineFileProfile, RawFileEntry};
use crate::utils::{
    compile_regex_list, file_path_matches_exclusion, is_path_suspicious, is_path_whitelisted,
    parse_log_datetime, unix_permission_flags,
};

/// High-impact credential / boot paths: always eligible for the “recent mtime” signal (tighter
/// window than the old global 24h rule).
fn is_critical_credential_path(path: &str) -> bool {
    matches!(path, "/etc/shadow" | "/etc/gshadow")
        || path.starts_with("/etc/sudoers")
        || path.starts_with("/boot/")
        || path.ends_with("/authorized_keys")
}

/// System locations where a recent mtime matters only together with elevated or risky access.
fn is_system_path_for_recent_mtime(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/root/")
        || path == "/etc"
}

fn is_volatile_recent_mtime_path(path: &str, cfg: &FileRecentMtimeConfig) -> bool {
    cfg.volatile_path_prefixes
        .iter()
        .any(|p| path.starts_with(p.as_str()))
}

/// Whether mtime was updated shortly before the observed access, in a **low-FP** way:
/// - Skip volatile paths (logs, caches, `/run`, …).
/// - Require modification at or before access (small clock skew allowed).
/// - Use short windows; do **not** flag routine user reads of recently updated config (e.g. apt).
fn recently_modified_heuristic(
    frt: &FileRecentMtimeConfig,
    path: &str,
    access: DateTime<Utc>,
    mtime: DateTime<Utc>,
    uid: u32,
    path_suspicious: bool,
    is_world_writable: bool,
    is_group_writable: bool,
) -> bool {
    if is_volatile_recent_mtime_path(path, frt) {
        return false;
    }

    let skew = chrono::Duration::minutes(frt.clock_skew_minutes.max(0));
    // mtime far in the future vs access → bad data or skew; ignore.
    if mtime > access + skew {
        return false;
    }

    let delta = access.signed_duration_since(mtime);
    let delta = if delta < chrono::Duration::zero() {
        chrono::Duration::zero()
    } else {
        delta
    };

    let max_critical = chrono::Duration::hours(frt.max_hours_critical_paths as i64);
    let max_system = chrono::Duration::hours(frt.max_hours_system_elevated as i64);
    let max_suspicious = chrono::Duration::hours(frt.max_hours_suspicious_only as i64);

    let elevated_or_risky = uid == 0
        || path_suspicious
        || is_world_writable
        || (is_group_writable && (path.contains("/etc") || path.contains("/tmp")));

    if is_critical_credential_path(path) {
        return delta <= max_critical;
    }

    if is_system_path_for_recent_mtime(path) && elevated_or_risky {
        return delta <= max_system;
    }

    if path_suspicious {
        return delta <= max_suspicious;
    }

    false
}

/// Paths where owner/group/size are expected to be uniform across a homogeneous fleet.
fn path_supports_fleet_metadata_baseline(path: &str) -> bool {
    path.starts_with("/etc/")
        || path.contains("/bin/")
        || path.contains("/sbin/")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
        || path.starts_with("/var/log/")
}

/// Per-path fleet comparison: same path on ≥3 hosts, a string value (owner/group) must match a
/// majority that appears at least twice; hosts with a different value are flagged.
fn fleet_string_metadata_outliers(
    profiles: &[MachineFileProfile],
    field: impl Fn(&MachineFileProfile) -> &HashMap<Arc<str>, Arc<str>>,
    field_label: &str,
) -> HashMap<usize, Vec<String>> {
    let mut path_hosts: HashMap<Arc<str>, Vec<(usize, Arc<str>)>> = HashMap::new();
    for (i, p) in profiles.iter().enumerate() {
        for (path, val) in field(p) {
            if !path_supports_fleet_metadata_baseline(path.as_ref()) {
                continue;
            }
            path_hosts
                .entry(path.clone())
                .or_default()
                .push((i, val.clone()));
        }
    }
    let mut out: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, rows) in path_hosts {
        if rows.len() < 3 {
            continue;
        }
        let mut freq: HashMap<Arc<str>, usize> = HashMap::new();
        for (_, ref v) in &rows {
            *freq.entry(v.clone()).or_insert(0) += 1;
        }
        let (mode, mode_count) = freq.into_iter().max_by_key(|(_, c)| *c).unwrap();
        if mode_count < 2 {
            continue;
        }
        for (machine_idx, v) in rows {
            if v != mode {
                out.entry(machine_idx).or_default().push(format!(
                    "METADATA ANOMALY: {} on {} is '{}' (fleet majority: '{}')",
                    field_label,
                    path.as_ref(),
                    v.as_ref(),
                    mode.as_ref()
                ));
            }
        }
    }
    out
}

/// Same path on ≥3 hosts with recorded size; majority size must appear at least twice.
fn fleet_size_metadata_outliers(profiles: &[MachineFileProfile]) -> HashMap<usize, Vec<String>> {
    let mut path_hosts: HashMap<Arc<str>, Vec<(usize, u64)>> = HashMap::new();
    for (i, p) in profiles.iter().enumerate() {
        for (path, sz) in &p.file_path_size {
            if !path_supports_fleet_metadata_baseline(path.as_ref()) {
                continue;
            }
            path_hosts
                .entry(path.clone())
                .or_default()
                .push((i, *sz));
        }
    }
    let mut out: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, rows) in path_hosts {
        if rows.len() < 3 {
            continue;
        }
        let mut freq: HashMap<u64, usize> = HashMap::new();
        for (_, sz) in &rows {
            *freq.entry(*sz).or_insert(0) += 1;
        }
        let (mode_size, mode_count) = freq.into_iter().max_by_key(|(_, c)| *c).unwrap();
        if mode_count < 2 {
            continue;
        }
        for (machine_idx, sz) in rows {
            if sz != mode_size {
                out.entry(machine_idx).or_default().push(format!(
                    "METADATA ANOMALY: size on {} is {} bytes (fleet majority: {} bytes)",
                    path.as_ref(),
                    sz,
                    mode_size
                ));
            }
        }
    }
    out
}

/// Whether a raw file row should be ingested into file profiles. Applies glob whitelist
/// (`whitelisted_path_patterns`) and regex exclusions (`file_excluded_path_regexes`,
/// `file_excluded_filename_regexes` on compiled patterns).
pub fn should_ingest_file_entry(
    entry: &RawFileEntry,
    config: &DetectionConfig,
    path_exclude_res: &[Regex],
    filename_exclude_res: &[Regex],
) -> bool {
    if !config.whitelisted_path_patterns.is_empty()
        && is_path_whitelisted(&entry.path, &config.whitelisted_path_patterns)
    {
        return false;
    }
    if file_path_matches_exclusion(&entry.path, path_exclude_res, filename_exclude_res) {
        return false;
    }
    true
}

/// Append one file access log to a profile (batch and streaming loaders).
pub(crate) fn merge_file_log_into_profile(
    profile: &mut MachineFileProfile,
    entry: &RawFileEntry,
    config: &DetectionConfig,
    interner: &SharedInterner,
    file_counts: Option<&mut HashMap<String, u32>>,
) {
    let path_is_suspicious = is_path_suspicious(&entry.path, &config.suspicious_path_patterns);
    let timestamp = entry.timestamp.as_ref().and_then(|s| parse_log_datetime(s));
    let mtime = entry.mtime.as_ref().and_then(|s| parse_log_datetime(s));
    let uid = effective_file_uid(entry);
    let (is_world_writable, is_group_writable) = entry
        .permissions
        .as_deref()
        .map(unix_permission_flags)
        .unwrap_or((false, false));
    let recently_modified = match (timestamp, mtime) {
        (Some(ts), Some(mt)) => recently_modified_heuristic(
            &config.file_recent_mtime,
            &entry.path,
            ts,
            mt,
            uid,
            path_is_suspicious,
            is_world_writable,
            is_group_writable,
        ),
        _ => false,
    };
    let permissions = entry.permissions.as_deref().and_then(|p| {
        let t = p.trim();
        if t.is_empty() {
            None
        } else {
            Some(interner.intern(t))
        }
    });
    let owner = entry.owner.as_deref().and_then(|o| {
        let t = o.trim();
        if t.is_empty() {
            None
        } else {
            Some(interner.intern(t))
        }
    });
    let group = entry.group.as_deref().and_then(|g| {
        let t = g.trim();
        if t.is_empty() {
            None
        } else {
            Some(interner.intern(t))
        }
    });
    let sig = FileSignature {
        path: interner.intern(&entry.path),
        uid,
        is_suspicious_path: path_is_suspicious,
        has_mtime_anomaly: false,
        recently_modified,
        permissions,
        owner,
        group,
        size: entry.size,
        is_world_writable,
        is_group_writable,
    };
    if let Some(fc) = file_counts {
        let file_key = format!(
            "{}:{}:{:?}:{:?}:{:?}",
            sig.path, sig.uid, sig.permissions, sig.owner, sig.size
        );
        let is_new_file = !fc.contains_key(&file_key);
        fc.entry(file_key).and_modify(|c| *c += 1).or_insert(1);
        if config.debug_display && is_new_file {
            let risk_flags: Vec<&str> = [
                if path_is_suspicious {
                    Some("SUSPICIOUS_PATH")
                } else {
                    None
                },
                if entry.path.contains("/etc")
                    || entry.path.contains("/bin")
                    || entry.path.contains("/sbin")
                {
                    Some("SYSTEM_DIRECTORY")
                } else {
                    None
                },
                if uid == 0 {
                    Some("ROOT_ACCESS")
                } else {
                    None
                },
                if recently_modified {
                    Some("RECENTLY_MODIFIED")
                } else {
                    None
                },
            ]
            .into_iter()
            .flatten()
            .collect();
            let risk_str = if risk_flags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", risk_flags.join(", "))
            };
            log::debug!(
                "New file access in {}: {} (uid: {}){}",
                profile.id,
                entry.path,
                uid,
                risk_str
            );
        }
    }
    profile.add_file(sig, timestamp, mtime);
}

fn effective_file_uid(entry: &RawFileEntry) -> u32 {
    if entry.uid != 0 {
        return entry.uid;
    }
    if let Some(ref o) = entry.owner {
        let o = o.trim();
        if o.eq_ignore_ascii_case("root") {
            return 0;
        }
        if let Ok(u) = o.parse::<u32>() {
            return u;
        }
    }
    entry.uid
}

pub fn build_file_profiles(
    entries: Vec<RawFileEntry>,
    config: &DetectionConfig,
) -> Vec<MachineFileProfile> {
    log::info!("Building file profiles from {} raw file entries", entries.len());
    let path_exclude_res = compile_regex_list(&config.file_excluded_path_regexes);
    let filename_exclude_res = compile_regex_list(&config.file_excluded_filename_regexes);
    let before_count = entries.len();
    let entries: Vec<RawFileEntry> = entries
        .into_iter()
        .filter(|e| should_ingest_file_entry(e, config, &path_exclude_res, &filename_exclude_res))
        .collect();
    let after_count = entries.len();
    if config.debug_display && before_count != after_count {
        log::debug!(
            "File ingest filter (whitelist + regex exclusions): before={}, after={}, filtered={}",
            before_count,
            after_count,
            before_count - after_count
        );
    }

    let interner = SharedInterner::default();

    let mut machine_entries: HashMap<String, Vec<RawFileEntry>> = HashMap::new();
    for entry in entries {
        machine_entries
            .entry(entry.machine_id.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }

    if config.debug_display {
        log::debug!("Grouped into {} machines", machine_entries.len());
    }

    let profiles: Vec<MachineFileProfile> = machine_entries
        .par_iter()
        .map(|(machine_id, logs)| {
            let mut profile = MachineFileProfile::new(machine_id);
            let mut file_counts: HashMap<String, u32> = HashMap::new();
            let interner_par = interner.clone();
            for entry in logs {
                let fc = if config.debug_display {
                    Some(&mut file_counts)
                } else {
                    None
                };
                merge_file_log_into_profile(&mut profile, entry, config, &interner_par, fc);
            }
            profile
        })
        .collect();

    log::info!("Built {} machine file profiles", profiles.len());
    profiles
}

pub fn analyze_files_fleet(
    profiles: &[MachineFileProfile],
    config: &DetectionConfig,
) -> Result<AnalysisReport, Box<dyn Error>> {
    if profiles.is_empty() {
        return Ok(AnalysisReport {
            anomalies: vec![],
            cluster_stats: HashMap::new(),
            total_analyzed: 0,
            config_used: config.clone(),
            analysis_type: AnalysisType::File,
        });
    }

    let mut file_mtimes_fleet: HashMap<Arc<str>, Vec<(usize, DateTime<Utc>)>> = HashMap::new();
    for (i, profile) in profiles.iter().enumerate() {
        for (path, mtime) in &profile.file_mtimes {
            file_mtimes_fleet
                .entry(path.clone())
                .or_insert_with(Vec::new)
                .push((i, *mtime));
        }
    }

    let mut mtime_anomaly_machines: HashSet<usize> = HashSet::new();
    let mut mtime_anomaly_details: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, machine_mtimes) in &file_mtimes_fleet {
        if machine_mtimes.len() < 3 {
            continue;
        }
        let mut sorted_mtimes: Vec<DateTime<Utc>> =
            machine_mtimes.iter().map(|(_, mt)| *mt).collect();
        sorted_mtimes.sort();
        let median_mtime = sorted_mtimes[sorted_mtimes.len() / 2];
        for (machine_idx, mtime) in machine_mtimes {
            let diff = mtime.signed_duration_since(median_mtime);
            let diff_hours = diff.num_hours().abs();
            if diff_hours > 24 {
                mtime_anomaly_machines.insert(*machine_idx);
                let detail = if diff.num_hours() > 0 {
                    format!(
                        "MTIME ANOMALY: {} modified {}h NEWER than fleet baseline",
                        path.as_ref(),
                        diff_hours
                    )
                } else {
                    format!(
                        "MTIME ANOMALY: {} modified {}h OLDER than fleet baseline",
                        path.as_ref(),
                        diff_hours
                    )
                };
                mtime_anomaly_details
                    .entry(*machine_idx)
                    .or_insert_with(Vec::new)
                    .push(detail);
            }
        }
    }

    let mut metadata_anomaly_details: HashMap<usize, Vec<String>> = HashMap::new();
    for (k, v) in fleet_string_metadata_outliers(profiles, |p| &p.file_path_owner, "owner") {
        metadata_anomaly_details.entry(k).or_default().extend(v);
    }
    for (k, v) in fleet_string_metadata_outliers(profiles, |p| &p.file_path_group, "group") {
        metadata_anomaly_details.entry(k).or_default().extend(v);
    }
    for (k, v) in fleet_size_metadata_outliers(profiles) {
        metadata_anomaly_details.entry(k).or_default().extend(v);
    }
    let metadata_anomaly_machines: HashSet<usize> = metadata_anomaly_details.keys().copied().collect();

    let mut recently_modified_machines: HashSet<usize> = HashSet::new();
    let mut recently_modified_details: HashMap<usize, Vec<String>> = HashMap::new();
    for (i, profile) in profiles.iter().enumerate() {
        for sig in profile.counts.keys() {
            if sig.recently_modified {
                recently_modified_machines.insert(i);
                recently_modified_details
                    .entry(i)
                    .or_insert_with(Vec::new)
                    .push(format!(
                        "RECENTLY MODIFIED: {} — mtime close to access (credential / elevated / suspicious path rule)",
                        sig.path
                    ));
            }
        }
    }

    let mut unique_features: HashSet<&FileSignature> = HashSet::new();
    for p in profiles {
        for key in p.counts.keys() {
            unique_features.insert(key);
        }
    }
    let mut feature_list: Vec<&FileSignature> = unique_features.into_iter().collect();
    feature_list.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.uid.cmp(&b.uid))
            .then(a.is_suspicious_path.cmp(&b.is_suspicious_path))
            .then(a.has_mtime_anomaly.cmp(&b.has_mtime_anomaly))
            .then(a.recently_modified.cmp(&b.recently_modified))
            .then((&a.permissions, &a.owner, &a.group, &a.size).cmp(&(
                &b.permissions,
                &b.owner,
                &b.group,
                &b.size,
            )))
            .then(a.is_world_writable.cmp(&b.is_world_writable))
            .then(a.is_group_writable.cmp(&b.is_group_writable))
    });
    let n_samples = profiles.len();
    let n_features = feature_list.len();

    let feature_doc_freq: Vec<usize> = feature_list
        .par_iter()
        .map(|feature| profiles.iter().filter(|p| p.counts.contains_key(*feature)).count())
        .collect();

    let file_doc_count_map: HashMap<&FileSignature, usize> = feature_list
        .iter()
        .enumerate()
        .map(|(i, &f)| (f, feature_doc_freq[i]))
        .collect();

    let data = if n_features == 0 {
        Array2::<f64>::zeros((n_samples, 1))
    } else {
        let n_samples_f = n_samples as f64;
        let mut flat = vec![0.0f64; n_samples * n_features];
        flat.par_chunks_mut(n_features)
            .enumerate()
            .for_each(|(row_idx, row)| {
                let profile = &profiles[row_idx];
                if profile.total_logs == 0 {
                    return;
                }
                let tlog = profile.total_logs as f64;
                for (col_idx, feature) in feature_list.iter().enumerate() {
                    if let Some(&count) = profile.counts.get(feature) {
                        let tf = count as f64 / tlog;
                        let doc_count = feature_doc_freq[col_idx].max(1) as f64;
                        let idf = (n_samples_f / doc_count).ln() + 1.0;
                        row[col_idx] = tf * idf;
                    }
                }
            });

        if config.normalize_features {
            flat.par_chunks_mut(n_features).for_each(|row| {
                let norm = row.iter().map(|x| x * x).sum::<f64>().sqrt();
                if norm > 0.0 {
                    for x in row.iter_mut() {
                        *x /= norm;
                    }
                }
            });
        }

        Array2::from_shape_vec((n_samples, n_features), flat).map_err(|e| -> Box<dyn Error> {
            format!("internal: file TF-IDF matrix shape: {}", e).into()
        })?
    };

    let clusters = Dbscan::params(config.dbscan_min_samples)
        .tolerance(config.dbscan_tolerance)
        .transform(&data)?;

    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    let largest_cluster = cluster_counts
        .iter()
        .filter(|(k, _)| k.is_some())
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| k.unwrap());

    let mut anomalies = Vec::new();
    for (i, cluster_id) in clusters.iter().enumerate() {
        let profile = &profiles[i];
        let mut suspicious_count = 0u32;
        let mut anomalous_features = Vec::new();
        let mut has_genuine_risk = false;

        if let Some(mtime_details) = mtime_anomaly_details.get(&i) {
            for detail in mtime_details {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += mtime_details.len() as u32;
        }
        if let Some(recent_details) = recently_modified_details.get(&i) {
            for detail in recent_details {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += recent_details.len() as u32;
        }
        if let Some(meta_details) = metadata_anomaly_details.get(&i) {
            for detail in meta_details {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += meta_details.len() as u32;
        }

        for (sig, count) in &profile.counts {
            let is_behavioral_risk = sig.is_suspicious_path;
            let is_system_directory = sig.path.contains("/etc")
                || sig.path.contains("/bin")
                || sig.path.contains("/sbin");
            let is_root_access = sig.uid == 0
                && !sig.path.starts_with("/proc")
                && !sig.path.starts_with("/sys");
            let perm_risk = sig.is_world_writable
                || (sig.is_group_writable && (sig.path.contains("/etc") || sig.path.contains("/tmp")));
            let owner_mismatch = (sig.path.starts_with("/etc") || sig.path.starts_with("/root"))
                && sig.owner.as_ref().map_or(false, |o| {
                    let o = o.as_ref().trim();
                    !o.is_empty() && !o.eq_ignore_ascii_case("root")
                });
            if is_behavioral_risk || is_system_directory || is_root_access || perm_risk || owner_mismatch {
                suspicious_count += *count;
                has_genuine_risk = true;
                if sig.is_world_writable {
                    anomalous_features.push(format!(
                        "RISK DETECTED: world-writable {}",
                        sig.path
                    ));
                } else if owner_mismatch {
                    anomalous_features.push(format!(
                        "RISK DETECTED: non-root owner on sensitive path {} ({})",
                        sig.path.as_ref(),
                        sig.owner.as_deref().unwrap_or("")
                    ));
                } else if is_system_directory {
                    anomalous_features.push(format!(
                        "RISK DETECTED: system directory access {}",
                        sig.path
                    ));
                } else if sig.is_suspicious_path {
                    anomalous_features.push(format!(
                        "RISK DETECTED: suspicious file access {}",
                        sig.path
                    ));
                } else if is_root_access {
                    anomalous_features.push(format!("RISK DETECTED: root access to {}", sig.path));
                } else if perm_risk {
                    anomalous_features.push(format!(
                        "RISK DETECTED: group-writable sensitive file {}",
                        sig.path
                    ));
                }
            }
            let doc_count = file_doc_count_map.get(sig).copied().unwrap_or(0);
            if doc_count == 1 {
                anomalous_features.push(format!("Rare file access: {}", sig.path));
            }
        }

        let is_noise = cluster_id.is_none();
        let is_minority = cluster_id.is_some()
            && cluster_id.unwrap() != largest_cluster.unwrap_or(999);
        let has_mtime_anomaly = mtime_anomaly_machines.contains(&i);
        let has_recently_modified = recently_modified_machines.contains(&i);
        let has_metadata_fleet_anomaly = metadata_anomaly_machines.contains(&i);

        if is_noise
            || is_minority
            || has_genuine_risk
            || has_mtime_anomaly
            || has_recently_modified
            || has_metadata_fleet_anomaly
        {
            let severity = if has_mtime_anomaly || has_metadata_fleet_anomaly {
                AnomalyLevel::Critical
            } else if has_recently_modified && has_genuine_risk {
                AnomalyLevel::Critical
            } else if has_genuine_risk {
                if suspicious_count > 5 {
                    AnomalyLevel::Critical
                } else {
                    AnomalyLevel::High
                }
            } else if has_recently_modified {
                AnomalyLevel::High
            } else {
                AnomalyLevel::Medium
            };

            anomalies.push(AnomalyDetails {
                machine_id: profile.id.clone(),
                severity,
                distance_score: if has_mtime_anomaly || has_metadata_fleet_anomaly {
                    2.0
                } else if is_noise {
                    1.5
                } else {
                    0.8
                },
                cluster_assignment: *cluster_id,
                anomalous_features,
                process_count: profile.total_logs,
                suspicious_process_count: suspicious_count,
            });
        }
    }

    Ok(AnalysisReport {
        anomalies,
        cluster_stats: cluster_counts,
        total_analyzed: n_samples,
        config_used: config.clone(),
        analysis_type: AnalysisType::File,
    })
}
