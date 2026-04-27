//! SQLite event store for normalized ingested datasets/events.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::json_parse::{parse_files_json_logs, parse_json_logs, parse_jsonl_process_line};
use crate::platform::{DatasetKind, DatasetRecord};
use crate::types::{RawFileEntry, RawLogEntry};

pub struct EventDb {
    path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatasetInspection {
    pub dataset_id: String,
    pub schema_profile: String,
    pub kind: String,
    pub process_event_count: u64,
    pub file_event_count: u64,
    pub sample_process_events: Vec<serde_json::Value>,
    pub sample_file_events: Vec<serde_json::Value>,
}

impl EventDb {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let db = Self {
            path: path.to_string(),
        };
        db.init()?;
        Ok(db)
    }

    fn conn(&self) -> Result<Connection, Box<dyn Error>> {
        Ok(Connection::open(&self.path)?)
    }

    fn init(&self) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS datasets (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              source_path TEXT NOT NULL,
              format TEXT NOT NULL,
              kind TEXT NOT NULL,
              schema_profile TEXT NOT NULL,
              imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_tags (
              dataset_id TEXT NOT NULL,
              tag TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS process_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              dataset_id TEXT NOT NULL,
              machine_id TEXT NOT NULL,
              pid INTEGER NOT NULL,
              ppid INTEGER NOT NULL,
              name TEXT NOT NULL,
              uid INTEGER NOT NULL,
              path TEXT NOT NULL,
              args TEXT NOT NULL,
              timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS file_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              dataset_id TEXT NOT NULL,
              machine_id TEXT NOT NULL,
              path TEXT NOT NULL,
              uid INTEGER NOT NULL,
              timestamp TEXT,
              mtime TEXT,
              permissions TEXT,
              owner TEXT,
              group_name TEXT,
              size INTEGER
            );
            "#,
        )?;
        Ok(())
    }

    pub fn ingest_dataset(&self, ds: &DatasetRecord) -> Result<u64, Box<dyn Error>> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO datasets (id,name,source_path,format,kind,schema_profile,imported_at) VALUES (?,?,?,?,?,?,?)",
            params![
                ds.id,
                ds.name,
                ds.source_path,
                ds.format,
                match ds.kind { DatasetKind::Process => "process", DatasetKind::File => "file" },
                ds.schema_profile,
                ds.imported_at
            ],
        )?;
        tx.execute("DELETE FROM dataset_tags WHERE dataset_id = ?", params![ds.id])?;
        for t in &ds.tags {
            tx.execute(
                "INSERT INTO dataset_tags (dataset_id, tag) VALUES (?,?)",
                params![ds.id, t],
            )?;
        }

        tx.execute("DELETE FROM process_events WHERE dataset_id = ?", params![ds.id])?;
        tx.execute("DELETE FROM file_events WHERE dataset_id = ?", params![ds.id])?;

        let mut count = 0u64;
        match ds.kind {
            DatasetKind::Process => {
                let rows = read_process_rows(&ds.source_path)?;
                let mut stmt = tx.prepare(
                    "INSERT INTO process_events (dataset_id,machine_id,pid,ppid,name,uid,path,args,timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
                )?;
                for r in rows {
                    stmt.execute(params![
                        ds.id,
                        r.machine_id,
                        r.pid,
                        r.ppid,
                        r.name,
                        r.uid,
                        r.path,
                        r.args,
                        r.timestamp
                    ])?;
                    count += 1;
                }
            }
            DatasetKind::File => {
                let rows = read_file_rows(&ds.source_path)?;
                let mut stmt = tx.prepare(
                    "INSERT INTO file_events (dataset_id,machine_id,path,uid,timestamp,mtime,permissions,owner,group_name,size) VALUES (?,?,?,?,?,?,?,?,?,?)",
                )?;
                for r in rows {
                    stmt.execute(params![
                        ds.id,
                        r.machine_id,
                        r.path,
                        r.uid,
                        r.timestamp,
                        r.mtime,
                        r.permissions,
                        r.owner,
                        r.group,
                        r.size
                    ])?;
                    count += 1;
                }
            }
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn inspect_dataset(&self, dataset_id: &str) -> Result<DatasetInspection, Box<dyn Error>> {
        let conn = self.conn()?;
        let (schema_profile, kind): (String, String) = conn.query_row(
            "SELECT schema_profile, kind FROM datasets WHERE id = ? LIMIT 1",
            params![dataset_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let process_event_count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM process_events WHERE dataset_id = ?",
            params![dataset_id],
            |r| r.get(0),
        )?;
        let file_event_count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM file_events WHERE dataset_id = ?",
            params![dataset_id],
            |r| r.get(0),
        )?;

        let mut sample_process_events = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT machine_id,pid,ppid,name,uid,path,args,timestamp
                 FROM process_events WHERE dataset_id = ? LIMIT 10",
            )?;
            let rows = stmt.query_map(params![dataset_id], |r| {
                Ok(serde_json::json!({
                    "machine_id": r.get::<_, String>(0)?,
                    "pid": r.get::<_, u32>(1)?,
                    "ppid": r.get::<_, u32>(2)?,
                    "name": r.get::<_, String>(3)?,
                    "uid": r.get::<_, u32>(4)?,
                    "path": r.get::<_, String>(5)?,
                    "args": r.get::<_, String>(6)?,
                    "timestamp": r.get::<_, Option<String>>(7)?,
                }))
            })?;
            for row in rows {
                sample_process_events.push(row?);
            }
        }

        let mut sample_file_events = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT machine_id,path,uid,timestamp,mtime,permissions,owner,group_name,size
                 FROM file_events WHERE dataset_id = ? LIMIT 10",
            )?;
            let rows = stmt.query_map(params![dataset_id], |r| {
                Ok(serde_json::json!({
                    "machine_id": r.get::<_, String>(0)?,
                    "path": r.get::<_, String>(1)?,
                    "uid": r.get::<_, u32>(2)?,
                    "timestamp": r.get::<_, Option<String>>(3)?,
                    "mtime": r.get::<_, Option<String>>(4)?,
                    "permissions": r.get::<_, Option<String>>(5)?,
                    "owner": r.get::<_, Option<String>>(6)?,
                    "group": r.get::<_, Option<String>>(7)?,
                    "size": r.get::<_, Option<u64>>(8)?,
                }))
            })?;
            for row in rows {
                sample_file_events.push(row?);
            }
        }

        Ok(DatasetInspection {
            dataset_id: dataset_id.to_string(),
            schema_profile,
            kind,
            process_event_count,
            file_event_count,
            sample_process_events,
            sample_file_events,
        })
    }

    pub fn delete_all_datasets(&self) -> Result<(), Box<dyn Error>> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM dataset_tags", [])?;
        conn.execute("DELETE FROM process_events", [])?;
        conn.execute("DELETE FROM file_events", [])?;
        conn.execute("DELETE FROM datasets", [])?;
        Ok(())
    }

    /// Distinct `machine_id` values for the given ingested `dataset_id`s, across process and file events.
    pub fn distinct_machine_ids_for_datasets(
        &self,
        dataset_ids: &[String],
    ) -> Result<Vec<String>, Box<dyn Error>> {
        if dataset_ids.is_empty() {
            return Ok(vec![]);
        }
        let conn = self.conn()?;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for ds in dataset_ids {
            let mut stmt = conn
                .prepare("SELECT DISTINCT machine_id FROM process_events WHERE dataset_id = ?")?;
            for row in stmt.query_map(params![ds], |r| r.get::<_, String>(0))? {
                let mid = row?;
                if !mid.is_empty() {
                    seen.insert(mid);
                }
            }
        }
        for ds in dataset_ids {
            let mut stmt = conn
                .prepare("SELECT DISTINCT machine_id FROM file_events WHERE dataset_id = ?")?;
            for row in stmt.query_map(params![ds], |r| r.get::<_, String>(0))? {
                let mid = row?;
                if !mid.is_empty() {
                    seen.insert(mid);
                }
            }
        }
        Ok(seen.into_iter().collect())
    }
}

fn read_process_rows(path: &str) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    if path.ends_with(".csv") {
        let mut rdr = csv::Reader::from_path(path)?;
        let mut out = Vec::new();
        for row in rdr.deserialize::<RawLogEntry>() {
            out.push(row?);
        }
        return Ok(out);
    }
    if path.ends_with(".json") {
        let s = std::fs::read_to_string(path)?;
        return Ok(parse_json_logs(&s)?);
    }
    if path.ends_with(".jsonl") {
        let stem = Path::new(path)
            .file_stem()
            .and_then(|x| x.to_str())
            .unwrap_or("default");
        let mut out = Vec::new();
        let f = File::open(path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(r) = parse_jsonl_process_line(t, stem) {
                out.push(r);
            }
        }
        return Ok(out);
    }
    Err("unsupported process format".into())
}

fn read_file_rows(path: &str) -> Result<Vec<RawFileEntry>, Box<dyn Error>> {
    if path.ends_with(".csv") {
        let mut rdr = csv::Reader::from_path(path)?;
        let mut out = Vec::new();
        for row in rdr.deserialize::<RawFileEntry>() {
            out.push(row?);
        }
        return Ok(out);
    }
    if path.ends_with(".json") {
        let s = std::fs::read_to_string(path)?;
        let stem = Path::new(path)
            .file_stem()
            .and_then(|x| x.to_str())
            .unwrap_or("default");
        return Ok(parse_files_json_logs(&s, stem)?);
    }
    if path.ends_with(".jsonl") {
        let mut out = Vec::new();
        let f = File::open(path)?;
        for line in BufReader::new(f).lines() {
            let line = line?;
            let t = line.trim();
            if t.is_empty() {
                continue;
            }
            if let Ok(r) = serde_json::from_str::<RawFileEntry>(t) {
                out.push(r);
            }
        }
        return Ok(out);
    }
    Err("unsupported file format".into())
}
