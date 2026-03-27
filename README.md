<p align="center"><img width="240" src="./.github/logo.png"></p>
<h2 align="center">IronSift 🔍🛡️</h2>

> **"Where's Waldo?" for Cybersecurity** — Fleet-wide anomaly detection powered by unsupervised machine learning.

Created with [Claude.ai](https://claude.ai) but supervised by a human (me apparently).

---

## What is IronSift?

**IronSift** is a Rust-based security analyzer that finds **anomalous machines** in a fleet by comparing their **process** (and optionally **file access**) behavior. It does not rely on attack signatures or threat feeds: it learns what is “normal” from your own data and flags machines that stand out.

- **Fleet mode (default):** You feed process logs from many machines (CSV, JSON, or JSONL). IronSift builds a behavioral profile per machine, turns them into vectors (TF-IDF), and runs **DBSCAN clustering**. Machines that end up alone (noise) or in a small minority cluster are reported as anomalies, with severity and risk factors (entropy, suspicious paths, unexpected root, etc.).
- **Temporal mode:** For a **single machine**, you can compare two or more snapshots over time. IronSift reports **new processes**, **new or modified files**, and **new IP connections** between snapshots — no clustering involved.
- **File mode (`--files`):** File access logs per host are turned into **file profiles** (counts per `FileSignature`, plus per-path mtime and metadata). Fleet analysis combines **TF‑IDF + DBSCAN** (same pattern as process mode: noise / minority cluster) with **explicit cross-host rules**: mtime vs fleet median, owner/group/size baselines on comparable paths, **fleet-relative access outliers** (e.g. root UID on a path only where most peers use non-root—no blanket “root read” alerts), **rare signatures** seen on a single host, and configurable **mtime-vs-access** heuristics. Rows matching `file_excluded_*` regexes are never merged into profiles.

Input can come from CSV, JSON, or **JSONL** (one JSON object per line; each file can be one machine). Output is a console report and an optional JSON forensic report for integration with other tools.

---

## How it works (high-level)

```
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  INPUTS                                                                          │
  │  Process logs (CSV / JSON / JSONL)  or  File access logs  or  Temporal snapshots │
  └───────────────────────────────────────┬─────────────────────────────────────────┘
                                          │
          ┌───────────────────────────────┼───────────────────────────────┐
          │                               │                               │
          ▼                               ▼                               ▼
  ┌───────────────────┐         ┌───────────────────┐         ┌───────────────────┐
  │  FLEET ANALYSIS    │         │  FILE ANALYSIS    │         │  TEMPORAL         │
  │  (process logs)   │         │  (--files)        │         │  (same machine    │
  │                   │         │                   │         │   over time)       │
  └─────────┬─────────┘         └─────────┬─────────┘         └─────────┬─────────┘
            │                             │                             │
            │  Group by machine_id        │  Group by machine_id        │  Build snapshot
            │  Resolve parents,           │  Per-path mtime + metadata  │  per time point
            │  compute entropy & paths    │                             │
            ▼                             ▼                             ▼
  ┌───────────────────┐         ┌───────────────────┐         ┌───────────────────┐
  │  One profile per  │         │  One file profile  │         │  Diff snapshots:   │
  │  machine          │         │  per machine       │         │  new processes,    │
  │  (process counts) │         │  (file + mtime +  │         │  new/modified      │
  │                   │         │   owner/group/size)│         │  files, new IPs     │
  └─────────┬─────────┘         └─────────┬─────────┘         └───────────────────┘
            │                             │
            │  TF-IDF matrix              │  TF-IDF + mtime +
            │  (machines × features)      │  metadata fleet checks
            ▼                             ▼
  ┌───────────────────┐         ┌───────────────────┐
  │  DBSCAN           │         │  DBSCAN + fleet   │
  │  Noise = outlier  │         │  rules: mtime,    │
  │  Small cluster =  │         │  metadata, FLEET  │
  │  minority         │         │  OUTLIER, rare    │
  └─────────┬─────────┘         └─────────┬─────────┘
            │                             │
            └──────────────┬──────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  OUTPUTS                                                                         │
  │  Console report (anomalies, severity, process/file risk factors) + optional JSON export│
  └─────────────────────────────────────────────────────────────────────────────────┘
```

**In short:** Fleet and file modes turn many machines into profiles, then use **TF-IDF + DBSCAN** so hosts in **noise** or a **small cluster** diverge from the dense majority. File mode **also** flags hosts using **fleet baselines** (mtime, owner/group/size) and **path-level minority patterns** (root vs non-root, permissions, recent-mtime signal)—not per-row “every root access is suspicious.” Temporal mode skips clustering and **diffs** snapshots of one machine.

## 🎯 Quick Start (3 Ways)

### Option 1: Super Simple API (Recommended for Getting Started)

```rust
use ironsift::{build_profiles_simple, analyze_fleet, DetectionConfig};

fn main() {
    let config = DetectionConfig::default();
    
    // Just provide (machine_id, process_name, parent_name) - PIDs handled automatically!
    let processes = vec![
        ("server1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("server1".to_string(), "worker".to_string(), "nginx".to_string()),
        ("server2".to_string(), "miner".to_string(), "systemd".to_string()),  // ⚠️ Anomaly
    ];
    
    let profiles = build_profiles_simple(processes, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    report.print();
}
```

### Option 2: ProcessBuilder API (More Control)

```rust
use ironsift::{ProcessBuilder, ProcessEntry, build_profiles, analyze_fleet, DetectionConfig};

fn main() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Simple method
    builder.add_process("server1", "nginx", "systemd");
    
    // Or fluent API with full control
    builder.add(
        ProcessEntry::new("server1".to_string(), "worker".to_string())
            .parent("nginx")
            .uid(33)
            .path("/usr/sbin/nginx")
            .args("worker process")
    );
    
    // NEW: Automatic command line parsing!
    builder.add_command("server2", "/usr/bin/postgres -D /var/lib/postgresql/data", Some("systemd"));
    
    // NEW: Bare commands (no full path) work too!
    builder.add_command("server3", "ls /etc/", Some("bash"));
    
    // NEW: JSON log parsing!
    builder.add_json(r#"{"host": "server4", "cmd": "nginx", "uid": 33}"#);
    
    let profiles = build_profiles(builder.build(), &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    report.print();
}
```

### Option 3: With Real PIDs (From System Logs)

```rust
use ironsift::{RawLogEntry, build_profiles, analyze_fleet, DetectionConfig};

fn main() {
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "server1".to_string(),
            pid: 1, ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        // ... more entries
    ];
    
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    report.print();
}
```

See `EXAMPLES.md` for complete usage examples.

---

## ⏱️ Temporal comparison (same machine across time)

Compare **multiple snapshots** of the same machine over time to spot **new processes**, **new or modified files**, and **new IP connections** — without fleet-wide clustering.

| Concept | Description |
|--------|-------------|
| **MachineSnapshot** | One point-in-time view: processes + file accesses + connections for a single machine |
| **TemporalDiff** | Diff between two snapshots: `new_processes`, `new_files`, `modified_files` (mtime), `new_connections` |
| **RawConnectionEntry** | Connection log: `machine_id`, `remote_ip`, optional `local_ip`, `remote_port`, `process_name`, `timestamp` |

**Example:** build a baseline snapshot (e.g. Monday 10:00), then a current snapshot (Monday 14:00); `compare_temporal(&baseline, &current)` yields new processes, files, and IPs.

```rust
use ironsift::{build_machine_snapshot, compare_temporal, compare_temporal_series,
               DetectionConfig, RawLogEntry, RawFileEntry, RawConnectionEntry};

let config = DetectionConfig::default();
let baseline = build_machine_snapshot("server1", "2024-01-01T10:00Z",
    process_entries_t1, file_entries_t1, connection_entries_t1, &config);
let current  = build_machine_snapshot("server1", "2024-01-01T14:00Z",
    process_entries_t2, file_entries_t2, connection_entries_t2, &config);

let diff = compare_temporal(&baseline, &current);
// diff.new_processes, diff.new_files, diff.modified_files, diff.new_connections

// Or compare a series of snapshots (T1 vs T2, T2 vs T3, ...)
let diffs = compare_temporal_series(&[snap1, snap2, snap3]);
```

**Run the demo:** `cargo run --example temporal`

---

## 📜 Version History

### v0.4.0 (Current) - File fleet & performance
- **File fleet:** Fleet-relative **`FLEET OUTLIER`** signals (root/permissions/recent-mtime **per path** vs majority), ingest **`file_excluded_*`**, configurable **`file_recent_mtime`**, stricter recent-mtime heuristic to cut false positives.
- **Process/file profiles:** Hot strings deduplicated via **interning** (`Arc<str>` on signatures and file maps).
- 🧪 Expanded tests for file fleet and exclusions.

### v0.3.0 - Enhanced Analysis & Input Flexibility
- ✨ **Enhanced Detailed Console Output** - Rich reporting with attack categorization
- ✨ **Automatic Command Line Parsing** - Handles bare commands (`ls /etc/`) and full paths
- ✨ **Native JSON Log Parsing** - Docker, Kubernetes, CloudWatch, Elasticsearch support
- 📚 Comprehensive documentation (15+ guides)
- 🧪 Broad test coverage

### v0.2.0 - Flexible APIs & Automation
- 🎯 Three flexible APIs (Simple, Builder, Direct)
- 🔄 Automatic PID/PPID resolution
- 📁 Reorganized project structure (CLI separated)
- 📖 Extensive documentation

### v0.1.0 - Initial Release
- 🔍 Core DBSCAN clustering
- 📊 TF-IDF feature engineering
- 🚨 Anomaly detection
- 📈 Basic reporting

---

## 📥 Multiple Input Methods

IronSift accepts data in various formats - choose what works for your logs:

### Full Command Lines (with paths)
```rust
builder.add_command("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"));
// → Automatically extracts: name="nginx", path="/usr/bin/nginx", args="-c /etc/nginx.conf"
```

### Bare Commands (no paths)
```rust
// Common in ps output, shell commands
builder.add_command("server1", "ls /etc/", Some("bash"));
builder.add_command("server1", "grep error app.log", Some("bash"));
// → Works perfectly! name="ls", path="ls", args="/etc/"
```

### JSON Logs (Docker, Kubernetes, CloudWatch)
```rust
// Single JSON entry
builder.add_json(r#"{"host": "server1", "cmd": "/usr/bin/nginx", "uid": 33}"#);

// Batch (JSON array or NDJSON)
builder.add_json_batch(r#"[
    {"container": "web-1", "command": "nginx", "userid": 33},
    {"node": "worker-1", "cmd": "python3 app.py", "uid": 1000}
]"#);
```

**Supported JSON key names:**
- Machine: `machine_id`, `hostname`, `host`, `server`, `node`, `container`, `pod`
- Command: `command`, `cmd`, `cmdline`, `commandline`
- User: `uid`, `user_id`, `userid`

See `JSON_PARSING.md` and `COMMAND_PARSING.md` for complete documentation.

---

## 🎯 Features

### Core Detection Capabilities

| Feature | Description |
|---------|-------------|
| **Multivariate Analysis** | Analyzes 6 dimensions: Process Name, Parent (auto-resolved), UID, Path, Entropy, Path Risk |
| **PID Awareness** | Automatically resolves parent processes from PID/PPID relationships |
| **Unsupervised Learning** | Zero-config detection — no signature database required |
| **Scale Invariant** | Works on 10 logs or 10 million logs |
| **Minority Cluster Detection** | Identifies coordinated attacks (botnets, APTs) |
| **High Entropy Detection** | Flags obfuscated commands and encoded payloads |
| **Suspicious Path Analysis** | Detects execution from /tmp, /dev/shm, hidden directories |

### File fleet analysis (`--files`)

Logs can include **path**, **mtime**, **permissions**, **owner**, **group**, and **size** (CSV columns or JSON/JSONL fields). Profiles aggregate **per `FileSignature`** (path + uid + flags + optional metadata). IronSift compares hosts using several **independent** signals:

| Signal | What it does |
|--------|----------------|
| **DBSCAN (clustering-only)** | **TF‑IDF** over unique file signatures × normalized counts per host → **DBSCAN**. **Noise** (`cluster_id = none`) or membership in a **non-largest** cluster can mark a host as anomalous even if no text feature lines are attached—**purely geometric** distance from the main blob. |
| **MTIME anomaly** | Same path on **≥3** hosts: flags machines whose mtime is **>24 hours** from the fleet **median** for that path (`MTIME ANOMALY`). |
| **Metadata anomaly** | On **comparable** paths (`/etc/…`, `*/bin/*`, `*/sbin/*`, `/usr/bin/…`, `/usr/sbin/…`, `/var/log/…`), with **≥3** hosts and a **majority** value appearing **≥2** times, hosts that disagree on **owner**, **group**, or **size** are flagged (`METADATA ANOMALY`). |
| **FLEET OUTLIER** (path minorities) | For paths seen on **≥3** hosts with a **strict majority** (majority count **≥2**): flags hosts in the **minority** class for **root vs non-root** access to that path, **world-writable** vs not, **group-writable** (only under paths containing `/etc` or `/tmp`), and **recent mtime vs access** (see `file_recent_mtime` in config). Avoids fleet-wide false positives when everyone behaves the same. |
| **Rare file access** | A full **signature** appears on exactly **one** machine in the fleet (`Rare file access: …`). |
| **Ingest exclusions** | `file_excluded_path_regexes` / `file_excluded_filename_regexes`: matching rows are **not** merged into profiles (enforced in the merge path). |

**Per-signature** helpers (e.g. in `FileSignature::risk_factors`) still describe suspicious path, system dir, root, etc. for **local** explanations; the **fleet report** does **not** treat “root read” or “system directory” as automatic anomalies without a **fleet-relative** or **rare-signature** signal above.

**Config:** `file_recent_mtime` tunes clock skew, time windows, and volatile path prefixes for the recent-mtime heuristic. Metadata comparison stays **scoped** so `/home/…` variation does not dominate.

### Detection Scenarios

IronSift can identify:

- **Cryptominers**: Unusual processes with high CPU, suspicious paths
- **Web Shells**: PHP/Python processes with high-entropy eval() payloads
- **Privilege Escalation**: Normal processes suddenly running as root (UID 0)
- **Lateral Movement**: Unusual SSH/SCP activity with anomalous targets
- **Rootkits**: Processes masquerading as system services
- **APT Campaigns**: Small clusters of compromised machines with identical malware

---

## 📦 Installation

### Prerequisites

- Rust 1.70+ (`rustup` recommended)
- 4GB+ RAM for large datasets

### Build from Source

```bash
cd ironsift
cargo build --release
```

---

## 🔧 Quick Start

### 1. Generate Test Data

Create a realistic dataset with 100 machines and embedded attack scenarios:

```bash
cargo run --release --bin generator
```

**Output**: `large_dataset.csv` (100,000 logs with 10 compromised machines)

The generated data includes:
- Realistic PID/PPID relationships
- systemd as PID 1 on each machine
- Normal processes as children of systemd
- Attack processes with proper parent relationships

For file datasets, run `cargo run --release --bin generator -- --files`. The sample CSV includes **mtime** and **metadata** scenarios (fleet baseline owner/group/size on common paths, with a few hosts intentionally diverging) so `ironsift --files` exercises **MTIME ANOMALY** and **METADATA ANOMALY** lines in the report.

### 2. Run Analysis

Analyze the fleet and display results:

```bash
cargo run --release --bin ironsift
```

**Sample Output**:
```
================================================================================
                         IRONSIFT ANALYSIS REPORT                              
================================================================================
Fleet Size: 100 machines
Detection Sensitivity: High

--- Configuration ---
  DBSCAN Tolerance: 0.35
  Entropy Threshold: 4.5
  Minority Cluster Ratio: 10%

--- Cluster Distribution ---
  Cluster 0: 90 machines (90.0%)
  Noise (Outliers): 10 machines (10.0%)

================================================================================
Status: 🚨 ANOMALIES DETECTED
================================================================================
Suspicious Machines: 10

💀 CRITICAL (3):
   These machines are isolated outliers - likely compromised

  💀 machine_013 (Distance: 1.500)
     ├─ Cluster: Noise (isolated outlier)
     ├─ Total processes: 150
     ├─ Suspicious processes: 50 ⚠️
     ├─ Rare processes (< 5% of fleet):
     │  • kworker (path: /tmp/.X11-unix/kworker)
     │  • systemd (path: /var/tmp/.cache/systemd)
     ├─ Suspicious processes detected:
     │
     │  📛 kworker (count: 30)
     │     Parent: systemd
     │     Path: /tmp/.X11-unix/kworker
     │     UID: 0 (root) ⚠️
     │     Risk factors:
     │       🚨 High entropy arguments (possible obfuscation)
     │       🚨 Suspicious execution path: /tmp/.X11-unix/kworker
     │       🚨 Running as root (UID 0)
     │       🚨 Executing from temporary directory
     └─ Activity period: 2024-01-01 10:00:00 to 2024-01-07 15:30:00

🔴 HIGH (4):
   Strong deviation from baseline - investigate immediately

  🔴 machine_042 (Distance: 0.823)
     ├─ Suspicious processes: 15 ⚠️
     └─ Unusual: php-fpm (high entropy eval payloads)
  ...

--- Detected Attack Patterns ---
  ⛏️  Cryptomining (3 machines): machine_013, machine_027, machine_065
  🕸️  Web Shells (2 machines): machine_042, machine_088
  ⬆️  Privilege Escalation (4 machines): machine_019, machine_051, ...
  📂 Suspicious Execution Paths (5 machines): machine_013, machine_027, ...

================================================================================
Recommended Actions:
  1. Review flagged machines and investigate anomalous processes
  2. Check process execution paths and command arguments
  3. Verify parent-child process relationships
  4. Cross-reference with network logs and file access logs
  5. Export detailed report: cargo run --bin ironsift -- --export-json
================================================================================
```

See `OUTPUT_EXAMPLES.md` for complete output examples.

### 3. Export Forensic Report

Generate a detailed JSON report for incident response:

```bash
cargo run --release --bin ironsift -- --export-json
```

**Output**: `forensic_report.json`

### 4. Output control (scripts and pipelines)

For use by other tools or in scripts:

| Option | Effect |
|--------|--------|
| `-q`, `--quiet` | Minimal output: one-line summary only (e.g. `CLEAN` or `ANOMALIES: 5 (Critical: 2, High: 1, …)`). Progress and config are suppressed. |
| `--export-json -` | Write the JSON report to **stdout** (nothing else on stdout). Use `2>/dev/null` to hide progress on stderr. |
| Progress messages | Loading/config/progress lines are sent to **stderr** so stdout can be piped or parsed. |

**Examples:**

```bash
# One-line result for scripting
ironsift -q --input data.csv

# JSON only on stdout (e.g. pipe to jq or another tool)
ironsift --export-json - --input data.csv 2>/dev/null | jq '.anomalies_detected'

# Quiet + export to file
ironsift -q --export-json report.json --input data.csv
```

---

## ⚙️ Configuration

### Command Line Options

```bash
ironsift [OPTIONS]

Options:
  --config <file>       Load configuration from JSON file
  --export-json         Export detailed forensic report
  --tolerance <value>   Override DBSCAN tolerance (default: from config, 0.35)
  --help                Show help message
```

### Custom Configuration

On first run, IronSift creates `ironsift_config.json`. Important keys:

```json
{
  "entropy_threshold": 4.5,
  "minority_cluster_ratio": 0.10,
  "dbscan_tolerance": 0.35,
  "dbscan_min_samples": 2,
  "normalize_features": true,
  "suspicious_path_patterns": [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/home/[^/]+/\\.[^/]+",
    "^\\./",
    "/(?:bin|sbin|usr/bin|usr/sbin)/\\.[^/]+"
  ],
  "file_excluded_path_regexes": [],
  "file_excluded_filename_regexes": [],
  "file_recent_mtime": {
    "clock_skew_minutes": 5,
    "max_hours_critical_paths": 12,
    "max_hours_system_elevated": 6,
    "max_hours_suspicious_only": 3,
    "volatile_path_prefixes": [
      "/var/log/",
      "/var/cache/",
      "/var/lib/dpkg/",
      "/var/lib/apt/",
      "/var/tmp/",
      "/tmp/",
      "/run/",
      "/proc/",
      "/sys/",
      "/dev/"
    ]
  }
}
```

- **`file_excluded_path_regexes` / `file_excluded_filename_regexes`:** Rust regexes; matching file-log rows are dropped before profiling (e.g. `^/proc/`, `^/var/cache/`).
- **`file_recent_mtime`:** Controls the **mtime vs access-time** signal used in profiles and in **FLEET OUTLIER** comparisons (volatile prefixes, tiered hour limits).

#### Tuning Guide

| Parameter | Effect | Recommended Range |
|-----------|--------|-------------------|
| `dbscan_tolerance` | Detection sensitivity (process & file TF‑IDF clustering) | Default **0.35**; lower (e.g. 0.03–0.10) = stricter, higher = looser |
| `minority_cluster_ratio` | Botnet detection threshold | 0.05 - 0.15 |
| `entropy_threshold` | Obfuscation detection | 3.5 (sensitive) - 5.5 (strict) |
| `file_recent_mtime.*` | Strictness of “recent mtime near access” (file mode) | Adjust `max_hours_*` / `volatile_path_prefixes` if too noisy or too quiet |

**Example**: Increase sensitivity for high-security environments:

```bash
cargo run --bin ironsift -- --tolerance 0.03
```

---

## 📊 Understanding Results

### Anomaly Severity Levels

| Level | Score | Meaning | Action |
|-------|-------|---------|--------|
| 💀 **Critical** | > 1.0 | Isolated outlier, likely compromised | **Immediate isolation** |
| 🔴 **High** | 0.6-1.0 | Strong deviation, investigate ASAP | **Priority investigation** |
| 🟠 **Medium** | 0.3-0.6 | Moderate anomaly, worth reviewing | **Schedule review** |
| 🟡 **Low** | 0.0-0.3 | Minor deviation, may be benign | **Monitor** |

### Forensic Report Structure

The JSON export includes:

```json
{
  "report_timestamp": "2024-12-10T15:30:00Z",
  "fleet_size": 100,
  "anomalies_detected": 10,
  "config": { ... },
  "investigation_targets": [
    {
      "machine_id": "machine_013",
      "severity": "Critical",
      "distance_score": 1.5,
      "suspicious_processes": [
        {
          "name": "kworker",
          "path": "/tmp/.X11-unix/kworker",
          "parent": "systemd",
          "risk_factors": [
            "High entropy arguments (possible obfuscation)",
            "Suspicious execution path: /tmp/.X11-unix/kworker",
            "Running as root (UID 0)"
          ]
        }
      ]
    }
  ]
}
```

---

## 🧪 Testing

Run the comprehensive test suite:

```bash
cargo test
```

### Generator + CLI regression test

To check that the generator output is correctly analyzed by the CLI (catches regressions in ingestion or reporting):

```bash
./scripts/test_generator_ironsift.sh
```

This script builds release, generates process and file datasets, runs `ironsift` (and `ironsift --files`) on them, and verifies that anomalies are reported—including at least one **MTIME ANOMALY** and one **METADATA ANOMALY** line in the file report. Run from the repo root.

### Test Coverage

- Shannon entropy calculation
- Suspicious path detection
- Clean fleet (no false positives)
- Single outlier detection
- Minority cluster detection (botnet scenario)
- Process risk factor analysis
- PID/PPID parent resolution
- Unknown parent handling
- File fleet: DBSCAN + mtime/metadata baselines + `FLEET OUTLIER` path minorities + rare signatures + regex exclusions + `file_recent_mtime`; JSONL/CSV streaming loaders

---

## 🏗️ Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           IRONSIFT PIPELINE                                       │
└─────────────────────────────────────────────────────────────────────────────────┘

  Raw Input                    Profile Building              Analysis
  ─────────                    ────────────────              ───────

  ┌──────────────┐             ┌─────────────────┐           ┌─────────────────┐
  │ CSV / JSON   │             │ Group by        │           │ TF-IDF          │
  │ Process Logs │────────────►│ machine_id      │──────────►│ Vectorization   │
  │ or File      │   parse     │                 │  build    │ (rare = signal) │
  │ Access Logs  │             │ Resolve PPID →  │  profiles │                 │
  └──────────────┘             │ parent names    │           └────────┬────────┘
         │                     │                 │                    │
         │                     │ Whitelist /     │                    ▼
         │                     │ filter paths    │           ┌─────────────────┐
         └────────────────────►│                 │           │ L2 Normalize    │
                               └─────────────────┘           │ DBSCAN Cluster  │
                                                             └────────┬────────┘
                                                                      │
                                                                      ▼
  Output                     ┌─────────────────┐             ┌─────────────────┐
  ──────                     │ Anomaly Scoring │◄────────────│ Noise = outlier │
                             │ & Severity      │  cluster    │ Small cluster   │
  ┌──────────────┐           │ (Critical→Low)  │   ids       │ = minority      │
  │ Console      │◄──────────┤                 │             │ Large cluster   │
  │ Report       │  print    └────────┬────────┘             │ = baseline      │
  └──────────────┘                    │                      └─────────────────┘
         ▲                            │
         │                            ▼
  ┌──────────────┐             ┌─────────────────┐
  │ forensic_    │◄────────────│ Feature reasons │
  │ report.json  │  export     │ Process: entropy│
  └──────────────┘             │ path, root…     │
                               │ File: mtime,    │
                               │ metadata, FLEET │
                               │ OUTLIER, rare   │
                               └─────────────────┘
```

### Process vs File Analysis

```
  PROCESS MODE (default)              FILE MODE (--files)
  ─────────────────────              ───────────────────

  RawLogEntry                         RawFileEntry
  • machine_id, pid, ppid             • machine_id, path, uid
  • name, path, args, uid             • timestamp, mtime
  • timestamp                         • permissions, owner, group, size (optional)
         │                                    │
         ▼                                    ▼
  ProcessSignature                    FileSignature
  • name + parent + uid + path        • path + uid + metadata
  • is_suspicious_path, entropy       • is_suspicious_path, permissions
         │                            • owner, group, size; mtime flags
         ▼                                    │
  MachineProfile                      MachineFileProfile
  (counts per process)                (counts per file signature +
                                      latest mtime + owner/group/size per path)
         │                                    │
         └──────────────┬─────────────────────┘
                        ▼
              analyze_fleet / analyze_files_fleet
                        │
                        ▼
              AnalysisReport (anomalies, severity)
```

### Key Algorithms

1. **PID Resolution**: Automatically maps PPID to parent process names
2. **TF-IDF Weighting**: Boosts rare processes, reduces noise from common ones
3. **L2 Normalization**: Ensures distance metrics work correctly across varied fleet sizes
4. **DBSCAN**: Density-based clustering that naturally identifies outliers
5. **Shannon Entropy**: Measures randomness in command arguments (detects obfuscation)
6. **File fleet baselines**: Median mtime and majority owner/group/size per path (on comparable paths); **path-level binary minorities** (root, writable flags, recent-mtime pattern) when ≥3 hosts and a clear majority; **rare signatures** (single-host `FileSignature`)

---

## 🎓 How It Works

### The "Iron Consensus" Principle

IronSift treats each machine as a vector in N-dimensional feature space:

- **Normal machines** cluster tightly (distance ≈ 0)
- **Compromised machines** drift away due to:
  - Rare processes not seen elsewhere
  - Unusual execution paths
  - High-entropy obfuscated commands
  - Privilege escalation patterns
  - Abnormal parent-child relationships
  - **File mode:** DBSCAN distance, **rare** file signatures, mtime far from fleet median, metadata disagreements, or **minority** access pattern on a path vs most peers (not “every root read is bad”)

### Clustering (Conceptual)

```
    Feature space (simplified 2D view)
    ─────────────────────────────────

         • • •  • •
       •   • • •   •          ← Normal machines (tight cluster)
        • •   • • •
          • • • •
              ★                 ← Isolated outlier (NOISE)
                                → 💀 CRITICAL: likely compromised

                    ◄ ─ ─ ─ ─ ►
                 small cluster
                 (minority)        ← 🔴 HIGH: botnet / APT pattern
                    △ △
                     △

    DBSCAN: density-based clustering
    • Points in dense regions → same cluster (baseline).
    • Points in sparse regions → "noise" = anomaly.
    • Small clusters → minority = coordinated deviance.
```

### Example Detection

**Fleet**: 100 web servers running nginx, postgres, node

**Anomaly**: Machine #42 suddenly has:
```
php-fpm (PID 5432, PPID 108 [apache2]) → eval(base64_decode('aGVsbG8gd29ybGQ='))
```

**IronSift Analysis**:

```
  Raw log                    Resolution              TF-IDF              DBSCAN
  ───────                    ──────────              ──────              ──────

  machine_42                 PPID 108    rare        Machine #42         Main cluster
  pid 5432, ppid 108   ───►  → apache2   process  ──► vector differs  ──► • • • • •
  name php-fpm               parent      (1/100)     from baseline         •
  args eval(base64…)         resolved    ▼            ▼                    ★  ← #42
                                │        IDF boost   distance ≈ 1.2        (outlier)
                                │        100×        ▼
                                │                    🔴 HIGH severity
                                └─────────────────── anomaly
```
1. Resolves parent: PPID 108 → apache2  
2. Computes TF-IDF: This exact process appears on 1/100 machines  
3. IDF boost: 100× signal amplification for this rare event  
4. DBSCAN: Machine #42 is 1.2 units away from main cluster  
5. **Result**: 🔴 HIGH severity anomaly detected

---

## 📈 Performance

Benchmarks on a 4-core CPU:

| Fleet Size | Logs | Processing Time | Memory |
|------------|------|-----------------|--------|
| 100 machines | 100K | 0.8s | 45 MB |
| 1,000 machines | 1M | 6.2s | 320 MB |
| 10,000 machines | 10M | 58s | 2.8 GB |

*With parallel processing enabled (Rayon)*

---

## 🛠️ Use Cases

### Production Monitoring

```bash
# Daily cron job
0 2 * * * cd /opt/ironsift && \
  ./ingest_logs.sh && \
  cargo run --release --bin ironsift -- --export-json && \
  ./alert_soc.sh forensic_report.json
```

### Incident Response

```bash
# Quick triage after breach detection
cargo run --release --bin ironsift -- --tolerance 0.03 --export-json
```

### Research & Red Team

```bash
# Test detection against custom malware
./inject_attack.sh && cargo run --bin ironsift
```

---

**Stay secure. Sift the iron from the ore. 🔒**