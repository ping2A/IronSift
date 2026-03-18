//! File-based fleet analysis: build file profiles and run DBSCAN + mtime anomaly detection.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use chrono::{DateTime, Utc};
use ndarray::Array2;
use linfa::traits::Transformer;
use linfa_clustering::Dbscan;
use rayon::prelude::*;
use log;

use crate::config::DetectionConfig;
use crate::report::{AnalysisReport, AnalysisType, AnomalyDetails, AnomalyLevel};
use crate::types::{FileSignature, MachineFileProfile, RawFileEntry};
use crate::utils::{is_path_suspicious, is_path_whitelisted};

pub fn build_file_profiles(
    entries: Vec<RawFileEntry>,
    config: &DetectionConfig,
) -> Vec<MachineFileProfile> {
    log::info!("Building file profiles from {} raw file entries", entries.len());
    let entries: Vec<RawFileEntry> = if !config.whitelisted_path_patterns.is_empty() {
        let before_count = entries.len();
        let filtered: Vec<_> = entries
            .into_iter()
            .filter(|e| !is_path_whitelisted(&e.path, &config.whitelisted_path_patterns))
            .collect();
        let after_count = filtered.len();
        if config.debug_display {
            log::debug!(
                "Whitelisted file path filtering: before={}, after={}, filtered={}",
                before_count,
                after_count,
                before_count - after_count
            );
        }
        filtered
    } else {
        entries
    };

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
            for entry in logs {
                let path_is_suspicious =
                    is_path_suspicious(&entry.path, &config.suspicious_path_patterns);
                let timestamp = entry.timestamp.as_ref().and_then(|ts| {
                    DateTime::parse_from_rfc3339(ts).ok().map(|dt| dt.with_timezone(&Utc))
                });
                let mtime = entry.mtime.as_ref().and_then(|ts| {
                    DateTime::parse_from_rfc3339(ts).ok().map(|dt| dt.with_timezone(&Utc))
                });
                let recently_modified = if let (Some(ts), Some(mt)) = (timestamp, mtime) {
                    let diff = ts.signed_duration_since(mt);
                    diff.num_hours().abs() < 24
                } else {
                    false
                };
                let sig = FileSignature {
                    path: entry.path.clone(),
                    uid: entry.uid,
                    is_suspicious_path: path_is_suspicious,
                    has_mtime_anomaly: false,
                    recently_modified,
                };
                let file_key = format!("{}:{}", sig.path, sig.uid);
                let is_new_file = !file_counts.contains_key(&file_key);
                file_counts.entry(file_key).and_modify(|c| *c += 1).or_insert(1);
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
                        if entry.uid == 0 {
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
                        machine_id,
                        entry.path,
                        entry.uid,
                        risk_str
                    );
                }
                profile.add_file(sig, timestamp, mtime);
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

    let mut file_mtimes_fleet: HashMap<String, Vec<(usize, DateTime<Utc>)>> = HashMap::new();
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
                        path, diff_hours
                    )
                } else {
                    format!(
                        "MTIME ANOMALY: {} modified {}h OLDER than fleet baseline",
                        path, diff_hours
                    )
                };
                mtime_anomaly_details
                    .entry(*machine_idx)
                    .or_insert_with(Vec::new)
                    .push(detail);
            }
        }
    }

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
                        "RECENTLY MODIFIED: {} was modified within 24h of access",
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
    let feature_list: Vec<&FileSignature> = unique_features.into_iter().collect();
    let n_samples = profiles.len();
    let n_features = feature_list.len();

    let mut data = Array2::<f64>::zeros((n_samples, n_features));
    for (row_idx, profile) in profiles.iter().enumerate() {
        if profile.total_logs == 0 {
            continue;
        }
        for (col_idx, feature) in feature_list.iter().enumerate() {
            if let Some(&count) = profile.counts.get(feature) {
                let tf = count as f64 / profile.total_logs as f64;
                let doc_count = profiles.iter().filter(|p| p.counts.contains_key(feature)).count();
                let idf = ((n_samples as f64) / (doc_count as f64 + 1.0)).ln() + 1.0;
                data[[row_idx, col_idx]] = tf * idf;
            }
        }
    }

    if config.normalize_features {
        for mut row in data.rows_mut() {
            let norm = row.mapv(|x| x * x).sum().sqrt();
            if norm > 0.0 {
                row.mapv_inplace(|x| x / norm);
            }
        }
    }

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

        for (sig, count) in &profile.counts {
            let is_behavioral_risk = sig.is_suspicious_path;
            let is_system_directory = sig.path.contains("/etc")
                || sig.path.contains("/bin")
                || sig.path.contains("/sbin");
            let is_root_access = sig.uid == 0
                && !sig.path.starts_with("/proc")
                && !sig.path.starts_with("/sys");
            if is_behavioral_risk || is_system_directory || is_root_access {
                suspicious_count += *count;
                has_genuine_risk = true;
                if is_system_directory {
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
                }
            }
            let doc_count = profiles.iter().filter(|p| p.counts.contains_key(sig)).count();
            if doc_count == 1 {
                anomalous_features.push(format!("Rare file access: {}", sig.path));
            }
        }

        let is_noise = cluster_id.is_none();
        let is_minority = cluster_id.is_some()
            && cluster_id.unwrap() != largest_cluster.unwrap_or(999);
        let has_mtime_anomaly = mtime_anomaly_machines.contains(&i);
        let has_recently_modified = recently_modified_machines.contains(&i);

        if is_noise || is_minority || has_genuine_risk || has_mtime_anomaly || has_recently_modified
        {
            let severity = if has_mtime_anomaly {
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
                distance_score: if has_mtime_anomaly {
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
