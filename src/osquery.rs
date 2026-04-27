//! Minimal osquery 5.22.1 oriented normalization helpers for process/file events.

use serde_json::Value;

use crate::types::{RawFileEntry, RawLogEntry};

fn get_u32(v: &Value, keys: &[&str]) -> u32 {
    keys.iter()
        .find_map(|k| v.get(*k))
        .and_then(|x| {
            x.as_u64()
                .map(|n| n as u32)
                .or_else(|| x.as_str().and_then(|s| s.parse::<u32>().ok()))
        })
        .unwrap_or(0)
}

fn get_string(v: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|k| v.get(*k))
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Normalize an osquery process-like row into `RawLogEntry`.
pub fn normalize_osquery_process_row(v: &Value, default_machine: &str) -> RawLogEntry {
    let machine_id = {
        let m = get_string(v, &["machine_id", "hostname", "host_identifier", "host", "node"]);
        if m.is_empty() {
            default_machine.to_string()
        } else {
            m
        }
    };

    let name = {
        let n = get_string(v, &["name"]);
        if n.is_empty() {
            get_string(v, &["cmdline", "command"])
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string()
        } else {
            n
        }
    };

    RawLogEntry {
        machine_id,
        pid: get_u32(v, &["pid"]),
        ppid: get_u32(v, &["parent", "ppid"]),
        name,
        uid: get_u32(v, &["uid", "euid"]),
        path: get_string(v, &["path", "exe"]),
        args: get_string(v, &["cmdline", "command"]),
        timestamp: {
            let ts = get_string(v, &["time", "timestamp", "calendar_time"]);
            if ts.is_empty() { None } else { Some(ts) }
        },
    }
}

/// Normalize an osquery file-like row into `RawFileEntry`.
pub fn normalize_osquery_file_row(v: &Value, default_machine: &str) -> RawFileEntry {
    let machine_id = {
        let m = get_string(v, &["machine_id", "hostname", "host_identifier", "host", "node"]);
        if m.is_empty() {
            default_machine.to_string()
        } else {
            m
        }
    };

    RawFileEntry {
        machine_id,
        path: get_string(v, &["path", "target_path", "file_path"]),
        uid: get_u32(v, &["uid", "owner_uid"]),
        timestamp: {
            let ts = get_string(v, &["time", "timestamp"]);
            if ts.is_empty() { None } else { Some(ts) }
        },
        mtime: {
            let mt = get_string(v, &["mtime", "btime", "date"]);
            if mt.is_empty() { None } else { Some(mt) }
        },
        permissions: {
            let p = get_string(v, &["mode", "permissions"]);
            if p.is_empty() { None } else { Some(p) }
        },
        owner: {
            let o = get_string(v, &["username", "owner"]);
            if o.is_empty() { None } else { Some(o) }
        },
        group: {
            let g = get_string(v, &["groupname", "group"]);
            if g.is_empty() { None } else { Some(g) }
        },
        size: v
            .get("size")
            .and_then(|x| x.as_u64())
            .or_else(|| v.get("size").and_then(|x| x.as_str()?.parse::<u64>().ok())),
    }
}
