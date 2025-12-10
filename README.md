# IronSift v2.0 🔍🛡️

> **"Where's Waldo?" for Cybersecurity** — Fleet-wide anomaly detection powered by unsupervised machine learning.

IronSift is a high-performance Rust-based cybersecurity tool that analyzes massive process logs to identify compromised machines in server fleets. Using DBSCAN clustering and TF-IDF feature engineering, it detects threats without requiring known attack signatures.

---

## 🚀 What's New in v2.0

### ✨ Major Enhancements

- **Explainable AI**: Every anomaly now includes severity scores, confidence metrics, and specific risk factors
- **Advanced Feature Engineering**: L2 normalization + TF-IDF weighting for accurate distance-based clustering
- **Configurable Detection**: JSON-based configuration for tuning sensitivity, thresholds, and detection rules
- **Forensic Reporting**: Export detailed JSON reports with process-level analysis for incident response
- **Parallel Processing**: Rayon-powered parallel data loading for 3-5x faster ingestion
- **Temporal Analysis**: Timestamp tracking for detecting time-based attack patterns
- **Enhanced Path Analysis**: Regex-based detection of suspicious execution locations
- **Severity Levels**: 4-tier classification (Low/Medium/High/Critical) with visual indicators

---

## 🎯 Features

### Core Detection Capabilities

| Feature | Description |
|---------|-------------|
| **Multivariate Analysis** | Analyzes 6 dimensions: Process Name, Parent, UID, Path, Entropy, Path Risk |
| **Unsupervised Learning** | Zero-config detection — no signature database required |
| **Scale Invariant** | Works on 10 logs or 10 million logs |
| **Minority Cluster Detection** | Identifies coordinated attacks (botnets, APTs) |
| **High Entropy Detection** | Flags obfuscated commands and encoded payloads |
| **Suspicious Path Analysis** | Detects execution from /tmp, /dev/shm, hidden directories |

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
git clone https://github.com/yourusername/ironsift.git
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

### 2. Run Analysis

Analyze the fleet and display results:

```bash
cargo run --release --bin ironsift
```

**Sample Output**:
```
===================== IRONSIFT ANALYSIS REPORT =====================
Fleet Size: 100 machines
Detection Sensitivity: High

--- Cluster Distribution ---
  Cluster 0: 90 machines
  Noise (Outliers): 10 machines

====================================================================
Status: 🚨 ANOMALIES DETECTED
====================================================================
Suspicious Machines: 10

💀 CRITICAL (3):
  💀 machine_013 (Score: 1.500)
     └─ 50 suspicious processes detected
     └─ Unusual: kworker (path: /tmp/.X11-unix/kworker), systemd and 1 more

🔴 HIGH (4):
  🔴 machine_042 (Score: 0.823)
     └─ 15 suspicious processes detected
     └─ Unusual: php-fpm (path: /usr/sbin/php-fpm)
  ...

Action: Review flagged machines and investigate anomalous processes.
Export detailed report: cargo run --bin ironsift -- --export-json
```

### 3. Export Forensic Report

Generate a detailed JSON report for incident response:

```bash
cargo run --release --bin ironsift -- --export-json
```

**Output**: `forensic_report.json`

---

## ⚙️ Configuration

### Command Line Options

```bash
ironsift [OPTIONS]

Options:
  --config <file>       Load configuration from JSON file
  --export-json         Export detailed forensic report
  --tolerance <value>   Override DBSCAN tolerance (default: 0.05)
  --help                Show help message
```

### Custom Configuration

On first run, IronSift creates `ironsift_config.json`:

```json
{
  "entropy_threshold": 4.5,
  "minority_cluster_ratio": 0.10,
  "dbscan_tolerance": 0.05,
  "dbscan_min_samples": 2,
  "normalize_features": true,
  "suspicious_path_patterns": [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/home/[^/]+/\\.[^/]+"
  ]
}
```

#### Tuning Guide

| Parameter | Effect | Recommended Range |
|-----------|--------|-------------------|
| `dbscan_tolerance` | Detection sensitivity | 0.03 (strict) - 0.10 (loose) |
| `minority_cluster_ratio` | Botnet detection threshold | 0.05 - 0.15 |
| `entropy_threshold` | Obfuscation detection | 3.5 (sensitive) - 5.5 (strict) |

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

### Test Coverage

- Shannon entropy calculation
- Suspicious path detection
- Clean fleet (no false positives)
- Single outlier detection
- Minority cluster detection (botnet scenario)
- Process risk factor analysis

---

## 🏗️ Architecture

### Data Flow

```
CSV Logs → Parallel Ingestion → Feature Extraction
    ↓
TF-IDF Vectorization → L2 Normalization
    ↓
DBSCAN Clustering → Anomaly Scoring
    ↓
Report Generation → JSON Export
```

### Key Algorithms

1. **TF-IDF Weighting**: Boosts rare processes, reduces noise from common ones
2. **L2 Normalization**: Ensures distance metrics work correctly across varied fleet sizes
3. **DBSCAN**: Density-based clustering that naturally identifies outliers
4. **Shannon Entropy**: Measures randomness in command arguments (detects obfuscation)

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

### Example Detection

**Fleet**: 100 web servers running nginx, postgres, node

**Anomaly**: Machine #42 suddenly has:
```
php-fpm → eval(base64_decode('aGVsbG8gd29ybGQ='))
```

**IronSift Analysis**:
1. Computes TF-IDF: This exact process appears on 1/100 machines
2. IDF boost: 100x signal amplification for this rare event
3. DBSCAN: Machine #42 is 1.2 units away from main cluster
4. **Result**: 🔴 HIGH severity anomaly detected

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

## 🤝 Contributing

We welcome contributions! Areas of interest:

- Additional ML algorithms (Isolation Forest, Autoencoders)
- Real-time streaming analysis
- Integration with SIEM platforms
- Custom feature extractors

---

## 📄 License

MIT License - see LICENSE file

---

## 🙏 Acknowledgments

Built with:
- [Linfa](https://github.com/rust-ml/linfa) - Rust ML framework
- [Rayon](https://github.com/rayon-rs/rayon) - Parallel processing
- [ndarray](https://github.com/rust-ndarray/ndarray) - N-dimensional arrays

---

## 📧 Contact

Questions? Open an issue or contact [@yourhandle](https://github.com/yourhandle)

---

**Stay secure. Sift the iron from the ore. 🔒**