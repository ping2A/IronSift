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

/// Paths that appear on each machine index (deduplicated per host).
fn path_to_machine_indices(profiles: &[MachineFileProfile]) -> HashMap<Arc<str>, Vec<usize>> {
    let mut m: HashMap<Arc<str>, HashSet<usize>> = HashMap::new();
    for (i, p) in profiles.iter().enumerate() {
        for sig in p.counts.keys() {
            m.entry(sig.path.clone()).or_default().insert(i);
        }
    }
    m.into_iter()
        .map(|(path, set)| {
            let mut v: Vec<usize> = set.into_iter().collect();
            v.sort_unstable();
            (path, v)
        })
        .collect()
}

/// Minimum hosts that must see a path before fleet comparison applies (same spirit as metadata baselines).
const FLEET_PATH_MIN_HOSTS: usize = 3;
/// Majority class must appear at least this many times.
const FLEET_PATH_MIN_MAJORITY: usize = 2;

/// For paths seen on enough hosts, compare a boolean attribute per host (e.g. root vs non-root).
/// Unanimous paths are ignored; ties are ignored. Only the **minority** hosts get detail strings.
fn fleet_path_binary_outliers<C>(
    profiles: &[MachineFileProfile],
    path_machines: &HashMap<Arc<str>, Vec<usize>>,
    path_gate: impl Fn(&str) -> bool,
    classify: C,
    minority_true_detail: impl Fn(&str, usize, usize, usize) -> String,
    minority_false_detail: impl Fn(&str, usize, usize, usize) -> String,
) -> HashMap<usize, Vec<String>>
where
    C: Fn(&MachineFileProfile, &Arc<str>) -> Option<bool>,
{
    let mut out: HashMap<usize, Vec<String>> = HashMap::new();
    for (path, machine_idxs) in path_machines {
        if machine_idxs.len() < FLEET_PATH_MIN_HOSTS || !path_gate(path.as_ref()) {
            continue;
        }
        let mut true_machines: Vec<usize> = Vec::new();
        let mut false_machines: Vec<usize> = Vec::new();
        for &mi in machine_idxs {
            match classify(&profiles[mi], path) {
                Some(true) => true_machines.push(mi),
                Some(false) => false_machines.push(mi),
                None => {}
            }
        }
        let n_true = true_machines.len();
        let n_false = false_machines.len();
        if n_true == 0 || n_false == 0 {
            continue;
        }
        let n_classified = n_true + n_false;
        if n_classified < FLEET_PATH_MIN_HOSTS {
            continue;
        }
        let path_s = path.as_ref();
        if n_true > n_false && n_true >= FLEET_PATH_MIN_MAJORITY {
            let msg = minority_false_detail(path_s, n_true, n_false, n_classified);
            for mi in false_machines {
                out.entry(mi).or_default().push(msg.clone());
            }
        } else if n_false > n_true && n_false >= FLEET_PATH_MIN_MAJORITY {
            let msg = minority_true_detail(path_s, n_false, n_true, n_classified);
            for mi in true_machines {
                out.entry(mi).or_default().push(msg.clone());
            }
        }
    }
    out
}

fn path_class_root_uid(profile: &MachineFileProfile, path: &Arc<str>) -> Option<bool> {
    let p = path.as_ref();
    if p.starts_with("/proc") || p.starts_with("/sys") {
        return None;
    }
    let mut seen = false;
    let mut has_root = false;
    for s in profile.counts.keys() {
        if s.path != *path {
            continue;
        }
        seen = true;
        if s.uid == 0 {
            has_root = true;
        }
    }
    if !seen {
        return None;
    }
    Some(has_root)
}

fn path_class_world_writable(profile: &MachineFileProfile, path: &Arc<str>) -> Option<bool> {
    let mut seen = false;
    let mut ww = false;
    for s in profile.counts.keys() {
        if s.path != *path {
            continue;
        }
        seen = true;
        if s.is_world_writable {
            ww = true;
        }
    }
    if !seen {
        return None;
    }
    Some(ww)
}

fn path_class_group_writable(profile: &MachineFileProfile, path: &Arc<str>) -> Option<bool> {
    let mut seen = false;
    let mut gw = false;
    for s in profile.counts.keys() {
        if s.path != *path {
            continue;
        }
        seen = true;
        if s.is_group_writable {
            gw = true;
        }
    }
    if !seen {
        return None;
    }
    Some(gw)
}

fn path_class_recently_modified(profile: &MachineFileProfile, path: &Arc<str>) -> Option<bool> {
    let mut seen = false;
    let mut recent = false;
    for s in profile.counts.keys() {
        if s.path != *path {
            continue;
        }
        seen = true;
        if s.recently_modified {
            recent = true;
        }
    }
    if !seen {
        return None;
    }
    Some(recent)
}

fn merge_fleet_details(
    into: &mut HashMap<usize, Vec<String>>,
    from: HashMap<usize, Vec<String>>,
) {
    for (k, mut v) in from {
        into.entry(k).or_default().append(&mut v);
    }
}

/// Whether a raw file row should be ingested into file profiles. Applies glob whitelist
/// (`whitelisted_path_patterns`) and regex exclusions (`file_excluded_path_regexes`,
/// `file_excluded_filename_regexes` on compiled patterns).
///
/// Rows for which this returns `false` must not appear in `MachineFileProfile` aggregates;
/// [`merge_file_log_into_profile`] enforces the same rules so callers cannot accidentally merge
/// excluded paths.
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
///
/// No-ops when the row is excluded by `file_excluded_*` regexes or the path whitelist (see
/// [`should_ingest_file_entry`]); the profile is not updated.
pub(crate) fn merge_file_log_into_profile(
    profile: &mut MachineFileProfile,
    entry: &RawFileEntry,
    config: &DetectionConfig,
    interner: &SharedInterner,
    file_counts: Option<&mut HashMap<String, u32>>,
    path_exclude_res: &[Regex],
    filename_exclude_res: &[Regex],
) {
    if !should_ingest_file_entry(entry, config, path_exclude_res, filename_exclude_res) {
        return;
    }

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
    let dropped = entries
        .iter()
        .filter(|e| {
            !should_ingest_file_entry(e, config, &path_exclude_res, &filename_exclude_res)
        })
        .count();
    if config.debug_display && dropped > 0 {
        log::debug!(
            "File ingest filter (whitelist + file_excluded_* regexes): raw_rows={}, excluded_rows={} (not merged into profiles)",
            before_count,
            dropped
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

    let mut profiles: Vec<MachineFileProfile> = machine_entries
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
                merge_file_log_into_profile(
                    &mut profile,
                    entry,
                    config,
                    &interner_par,
                    fc,
                    &path_exclude_res,
                    &filename_exclude_res,
                );
            }
            profile
        })
        .collect();

    profiles.retain(|p| p.total_logs > 0);
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

    // Fleet-relative access patterns: flag a host only when it differs from a clear majority on the
    // same path (≥3 hosts, majority ≥2). Avoids blanket "root access" / system-dir noise.
    let path_machines = path_to_machine_indices(profiles);

    let mut fleet_access_details: HashMap<usize, Vec<String>> = HashMap::new();

    merge_fleet_details(
        &mut fleet_access_details,
        fleet_path_binary_outliers(
            profiles,
            &path_machines,
            |_| true,
            path_class_root_uid,
            |path, n_maj_nonroot, _n_min_root, n_tot| {
                format!(
                    "FLEET OUTLIER: root UID access to {} — {} of {} hosts use non-root for this path (this host is in the minority)",
                    path, n_maj_nonroot, n_tot
                )
            },
            |path, n_maj_root, _n_min_nonroot, n_tot| {
                format!(
                    "FLEET OUTLIER: non-root access to {} — {} of {} hosts use root for this path (this host is in the minority)",
                    path, n_maj_root, n_tot
                )
            },
        ),
    );

    merge_fleet_details(
        &mut fleet_access_details,
        fleet_path_binary_outliers(
            profiles,
            &path_machines,
            |_| true,
            path_class_world_writable,
            |path, n_maj_not_ww, _n_min_ww, n_tot| {
                format!(
                    "FLEET OUTLIER: world-writable {} — {} of {} hosts are not world-writable (minority)",
                    path, n_maj_not_ww, n_tot
                )
            },
            |path, n_maj_ww, _n_min_not, n_tot| {
                format!(
                    "FLEET OUTLIER: non-world-writable {} — {} of {} hosts see world-writable mode (minority)",
                    path, n_maj_ww, n_tot
                )
            },
        ),
    );

    merge_fleet_details(
        &mut fleet_access_details,
        fleet_path_binary_outliers(
            profiles,
            &path_machines,
            |p| p.contains("/etc") || p.contains("/tmp"),
            path_class_group_writable,
            |path, n_maj_not_gw, _n_min_gw, n_tot| {
                format!(
                    "FLEET OUTLIER: group-writable {} under /etc or /tmp — {} of {} hosts are not group-writable (minority)",
                    path, n_maj_not_gw, n_tot
                )
            },
            |path, n_maj_gw, _n_min_not, n_tot| {
                format!(
                    "FLEET OUTLIER: not group-writable {} — {} of {} hosts see group-writable on this path (minority)",
                    path, n_maj_gw, n_tot
                )
            },
        ),
    );

    let fleet_recent_mtime_details = fleet_path_binary_outliers(
        profiles,
        &path_machines,
        |_| true,
        path_class_recently_modified,
        |path, n_maj_not_recent, _n_min_recent, n_tot| {
            format!(
                "FLEET OUTLIER: mtime close to access on {} — {} of {} hosts do not show this pattern (minority)",
                path, n_maj_not_recent, n_tot
            )
        },
        |path, n_maj_recent, _n_min_not, n_tot| {
            format!(
                "FLEET OUTLIER: no recent mtime-at-access signal on {} — {} of {} hosts do (minority)",
                path, n_maj_recent, n_tot
            )
        },
    );
    let recent_fleet_machine_idxs: HashSet<usize> =
        fleet_recent_mtime_details.keys().copied().collect();
    merge_fleet_details(&mut fleet_access_details, fleet_recent_mtime_details);

    let fleet_access_machines: HashSet<usize> = fleet_access_details.keys().copied().collect();

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
        if let Some(fleet_access) = fleet_access_details.get(&i) {
            for detail in fleet_access {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += fleet_access.len() as u32;
        }
        if let Some(meta_details) = metadata_anomaly_details.get(&i) {
            for detail in meta_details {
                anomalous_features.push(detail.clone());
            }
            has_genuine_risk = true;
            suspicious_count += meta_details.len() as u32;
        }

        // Per-signature "rare across fleet" (doc frequency 1). Other risk dimensions use fleet
        // outlier blocks above or metadata / mtime baselines — not per-row root/system-dir flags.
        for (sig, count) in &profile.counts {
            let doc_count = file_doc_count_map.get(sig).copied().unwrap_or(0);
            if doc_count == 1 {
                suspicious_count += *count;
                has_genuine_risk = true;
                anomalous_features.push(format!("Rare file access: {}", sig.path));
            }
        }

        let is_noise = cluster_id.is_none();
        let is_minority = cluster_id.is_some()
            && cluster_id.unwrap() != largest_cluster.unwrap_or(999);
        let has_mtime_anomaly = mtime_anomaly_machines.contains(&i);
        let has_recent_fleet = recent_fleet_machine_idxs.contains(&i);
        let has_metadata_fleet_anomaly = metadata_anomaly_machines.contains(&i);
        let has_fleet_access_outlier = fleet_access_machines.contains(&i);

        if is_noise
            || is_minority
            || has_genuine_risk
            || has_mtime_anomaly
            || has_fleet_access_outlier
            || has_metadata_fleet_anomaly
        {
            let severity = if has_mtime_anomaly || has_metadata_fleet_anomaly {
                AnomalyLevel::Critical
            } else if has_recent_fleet && has_genuine_risk {
                AnomalyLevel::Critical
            } else if has_genuine_risk {
                if suspicious_count > 5 {
                    AnomalyLevel::Critical
                } else {
                    AnomalyLevel::High
                }
            } else if has_recent_fleet {
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
