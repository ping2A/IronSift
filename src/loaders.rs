//! Data loaders: CSV/JSON and mock data.

use std::error::Error;
use std::fs;
use std::path::Path;
use log;

use crate::builder::{build_profiles, ProcessBuilder};
use crate::config::DetectionConfig;
use crate::file_analysis::build_file_profiles;
use crate::json_parse::{parse_files_json_logs, parse_json_logs, parse_jsonl_logs};
use crate::types::{MachineFileProfile, MachineProfile, RawFileEntry, RawLogEntry};

pub fn load_csv_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let mut rdr = csv::Reader::from_path(path)?;
    let entries: Vec<RawLogEntry> = rdr.deserialize().collect::<Result<Vec<_>, _>>()?;
    if entries.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }
    Ok(build_profiles(entries, config))
}

pub fn load_json_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let content = fs::read_to_string(path)?;
    let entries = parse_json_logs(&content)?;
    if entries.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }
    log::info!("Loaded {} process entries from JSON", entries.len());
    Ok(build_profiles(entries, config))
}

/// Load process data from a JSONL file (one JSON object per line).
/// Format: `{"timestamp": "...", "event_type": "process", "user": "0", "command": "...", "pid": 1, "ppid": 0}`
/// Optional per-line: `machine_id`, `hostname`, `host`. If absent, the file stem is used as machine_id.
pub fn load_jsonl_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let content = fs::read_to_string(path)?;
    let default_machine_id = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("default");
    let entries = parse_jsonl_logs(&content, default_machine_id)?;
    if entries.is_empty() {
        return Err(format!("No valid process lines found in '{}'.", path).into());
    }
    log::info!(
        "Loaded {} process entries from JSONL (machine_id: {})",
        entries.len(),
        default_machine_id
    );
    Ok(build_profiles(entries, config))
}

pub fn load_files_csv_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let mut rdr = csv::Reader::from_path(path)?;
    let entries: Vec<RawFileEntry> = rdr.deserialize().collect::<Result<Vec<_>, _>>()?;
    if entries.is_empty() {
        return Err(format!("No valid file access logs found in '{}'.", path).into());
    }
    Ok(build_file_profiles(entries, config))
}

pub fn load_files_json_data(
    path: &str,
    config: &DetectionConfig,
) -> Result<Vec<MachineFileProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }
    let content = fs::read_to_string(path)?;
    let entries = parse_files_json_logs(&content)?;
    if entries.is_empty() {
        return Err(format!("No valid file access logs found in '{}'.", path).into());
    }
    log::info!("Loaded {} file access entries from JSON", entries.len());
    Ok(build_file_profiles(entries, config))
}

pub fn generate_mock_data(config: &DetectionConfig) -> Vec<MachineProfile> {
    let entries: Vec<RawLogEntry> = (0..50)
        .flat_map(|i| {
            let machine_id = format!("machine_{:02}", i);
            let mut logs = Vec::new();
            for j in 0..100 {
                logs.push(RawLogEntry {
                    machine_id: machine_id.clone(),
                    pid: 1000 + j,
                    ppid: 1,
                    name: "nginx".to_string(),
                    uid: 33,
                    path: "/usr/sbin/nginx".to_string(),
                    args: "-c /etc/nginx.conf".to_string(),
                    timestamp: None,
                });
            }
            if i == 13 {
                for j in 0..50 {
                    logs.push(RawLogEntry {
                        machine_id: machine_id.clone(),
                        pid: 2000 + j,
                        ppid: 1,
                        name: "kworker".to_string(),
                        uid: 0,
                        path: "/tmp/.hidden/miner".to_string(),
                        args: "XkzL1^s09f87aH@9#".to_string(),
                        timestamp: None,
                    });
                }
            }
            logs.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "--system".to_string(),
                timestamp: None,
            });
            logs
        })
        .collect();
    build_profiles(entries, config)
}

pub fn build_profiles_simple(
    machine_processes: Vec<(String, String, String)>,
    config: &DetectionConfig,
) -> Vec<MachineProfile> {
    let mut builder = ProcessBuilder::new();
    for (machine_id, name, parent) in machine_processes {
        builder.add_process(&machine_id, &name, &parent);
    }
    let raw_entries = builder.build();
    build_profiles(raw_entries, config)
}
