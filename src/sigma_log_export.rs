//! Convert IronSift process dataset files to JSONL for the [sigmazero](https://github.com/ping2A/sigmazero) engine
//! (`LogEntry` / `evaluate_log_line`), with common field names like `process_name` and `command_line`.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};

use log;
use crate::json_parse::parse_json_log;
use crate::json_parse::parse_json_logs;
use crate::types::RawLogEntry;

fn command_line_str(e: &RawLogEntry) -> String {
    if !e.path.is_empty() {
        if e.args.is_empty() {
            e.path.clone()
        } else {
            format!("{} {}", e.path, e.args)
        }
    } else {
        e.name.clone()
    }
}

/// One JSON line per process event, aligned with typical Sigma-friendly field names.
pub fn raw_to_sigma_json(e: &RawLogEntry) -> serde_json::Value {
    serde_json::json!({
        "machine_id": e.machine_id,
        "event_type": "process_creation",
        "process_name": e.name,
        "command_line": command_line_str(e),
        "pid": e.pid,
        "ppid": e.ppid,
        "uid": e.uid,
        "timestamp": e.timestamp,
    })
}

/// Export process log files to a single JSONL file. Each `sources` entry is `(source_path, format)` where
/// `format` is a lowercase file extension, e.g. `jsonl`, `json`, `csv`.
pub fn export_process_sources_to_sigma_jsonl(
    sources: &[(String, String)],
    out_path: &std::path::Path,
) -> Result<u64, Box<dyn Error>> {
    let mut out = File::create(out_path)?;
    let mut total: u64 = 0;
    for (path, ext) in sources {
        let n = match ext.as_str() {
            "csv" => write_csv(path, &mut out)?,
            "json" => write_json_file(path, &mut out)?,
            "jsonl" => write_jsonl(path, &mut out)?,
            other => {
                return Err(format!(
                    "unsupported format for Sigma export: {} (path {})",
                    other, path
                )
                .into());
            }
        };
        total += n;
    }
    Ok(total)
}

fn write_line(w: &mut File, e: &RawLogEntry) -> std::io::Result<()> {
    let s = serde_json::to_string(&raw_to_sigma_json(e)).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    writeln!(w, "{}", s)
}

fn write_jsonl(path: &str, w: &mut File) -> Result<u64, Box<dyn Error>> {
    let f = File::open(path)?;
    let mut n: u64 = 0;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        match parse_json_log(t) {
            Ok(e) => {
                write_line(w, &e)?;
                n += 1;
            }
            Err(e) => {
                log::warn!("Sigma export skipped line in {}: {}", path, e);
            }
        }
    }
    Ok(n)
}

fn write_json_file(path: &str, w: &mut File) -> Result<u64, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let entries = parse_json_logs(&content)?;
    if entries.is_empty() {
        return Ok(0);
    }
    let mut n: u64 = 0;
    for e in &entries {
        write_line(w, e)?;
        n += 1;
    }
    Ok(n)
}

fn write_csv(path: &str, w: &mut File) -> Result<u64, Box<dyn Error>> {
    use csv::Reader;
    let mut n: u64 = 0;
    let mut rdr = Reader::from_path(path)?;
    for result in rdr.deserialize::<RawLogEntry>() {
        let e = result?;
        write_line(w, &e)?;
        n += 1;
    }
    Ok(n)
}
