//! JSON log parsing for process and file entries.

use std::error::Error;
use log;

use crate::types::{RawFileEntry, RawLogEntry};
use crate::utils::parse_command_line;

fn extract_string_field(data: &serde_json::Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = data.get(key) {
            if let Some(s) = value.as_str() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn extract_u32_field(data: &serde_json::Value, keys: &[&str]) -> Option<u32> {
    for key in keys {
        if let Some(value) = data.get(key) {
            if let Some(num) = value.as_u64() {
                return Some(num as u32);
            }
            if let Some(s) = value.as_str() {
                if let Ok(num) = s.parse::<u32>() {
                    return Some(num);
                }
            }
        }
    }
    None
}

/// Parse process information from JSON string.
pub fn parse_json_log(json: &str) -> Result<RawLogEntry, Box<dyn Error>> {
    let data: serde_json::Value = serde_json::from_str(json)?;

    let machine_id = extract_string_field(
        &data,
        &["machine_id", "hostname", "host", "server", "node", "container", "pod"],
    )
    .ok_or("Missing machine identifier (need: machine_id, hostname, host, server, node, container, or pod)")?;

    let pid = extract_u32_field(&data, &["pid", "process_id"]).unwrap_or(0);
    let ppid = extract_u32_field(&data, &["ppid", "parent_pid"]).unwrap_or(0);

    let name_opt = extract_string_field(&data, &["name", "process", "process_name", "comm"]);
    let path_opt = extract_string_field(&data, &["path", "exe", "executable"]);
    let args_opt = extract_string_field(&data, &["args", "arguments", "params"]);

    let (name, path, args) = if let (Some(n), Some(p), Some(a)) = (name_opt, path_opt, args_opt) {
        (n, p, a)
    } else if let Some(command) =
        extract_string_field(&data, &["command", "cmd", "cmdline", "commandline"])
    {
        parse_command_line(&command)
    } else if let Some(n) = extract_string_field(&data, &["name", "process", "process_name", "comm"]) {
        (n.clone(), n, String::new())
    } else {
        return Err("Missing process information (need: 'command', 'cmd', 'cmdline', 'commandline', OR 'name', 'process', 'process_name', 'comm')".into());
    };

    let uid = extract_u32_field(&data, &["uid", "user_id", "userid"]).unwrap_or(1000);
    let timestamp = extract_string_field(&data, &["timestamp", "time", "datetime"]);

    Ok(RawLogEntry {
        machine_id,
        pid,
        ppid,
        name,
        uid,
        path,
        args,
        timestamp,
    })
}

/// Parse a batch of JSON log entries (NDJSON or JSON array).
pub fn parse_json_logs(json: &str) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    let json = json.trim();
    if json.is_empty() {
        return Ok(Vec::new());
    }
    if json.starts_with('[') {
        let array: Vec<serde_json::Value> = serde_json::from_str(json)?;
        let mut entries = Vec::new();
        for value in array {
            let json_str = serde_json::to_string(&value)?;
            match parse_json_log(&json_str) {
                Ok(entry) => entries.push(entry),
                Err(e) => log::warn!("Failed to parse JSON entry: {}", e),
            }
        }
        return Ok(entries);
    }
    let mut entries = Vec::new();
    for line in json.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        match parse_json_log(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => log::warn!("Failed to parse JSON line: {}", e),
        }
    }
    Ok(entries)
}

/// Parse file access logs from JSON (array, single object, or NDJSON).
pub fn parse_files_json_logs(content: &str) -> Result<Vec<RawFileEntry>, Box<dyn Error>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(entries) = serde_json::from_str::<Vec<RawFileEntry>>(trimmed) {
        return Ok(entries);
    }
    if let Ok(entry) = serde_json::from_str::<RawFileEntry>(trimmed) {
        return Ok(vec![entry]);
    }
    let mut entries = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<RawFileEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => log::warn!("Failed to parse JSON line: {} - {}", line, e),
        }
    }
    Ok(entries)
}
