use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::path::Path;
use serde::{Deserialize, Serialize};
use ndarray::{Array2, Axis};
use linfa::traits::Transformer;
use linfa_clustering::Dbscan;
use rayon::prelude::*;
use regex::Regex;
use chrono::{DateTime, Utc};

// --- CONFIGURATION ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Shannon entropy threshold for detecting obfuscated commands
    pub entropy_threshold: f64,
    
    /// Ratio below which a cluster is considered a minority (e.g., 0.10 = 10%)
    pub minority_cluster_ratio: f64,
    
    /// DBSCAN tolerance (epsilon) - lower is stricter
    pub dbscan_tolerance: f64,
    
    /// Minimum samples for DBSCAN core point
    pub dbscan_min_samples: usize,
    
    /// Enable L2 normalization of feature vectors
    pub normalize_features: bool,
    
    /// Suspicious path patterns (regex)
    pub suspicious_path_patterns: Vec<String>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 4.5,
            minority_cluster_ratio: 0.10,
            dbscan_tolerance: 0.05,
            dbscan_min_samples: 2,
            normalize_features: true,
            suspicious_path_patterns: vec![
                r"/tmp/".to_string(),
                r"/dev/shm/".to_string(),
                r"/var/tmp/".to_string(),
                r"/home/[^/]+/\.[^/]+".to_string(), // Hidden dirs in home
                r"^\./".to_string(), // Relative paths
            ],
        }
    }
}

impl DetectionConfig {
    /// Load config from JSON file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&contents)?;
        Ok(config)
    }
    
    /// Save config to JSON file
    pub fn to_file(&self, path: &str) -> Result<(), Box<dyn Error>> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }
}

// --- DATA STRUCTURES ---

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawLogEntry {
    pub machine_id: String,
    pub name: String,
    pub parent: String,
    pub uid: u32,
    pub path: String,
    pub args: String,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ProcessSignature {
    pub name: String,
    pub parent: String,
    pub uid: u32,
    pub path: String,
    pub is_high_entropy: bool,
    pub is_suspicious_path: bool,
}

impl ProcessSignature {
    /// Create a human-readable description of why this process is suspicious
    pub fn risk_factors(&self) -> Vec<String> {
        let mut factors = Vec::new();
        
        if self.is_high_entropy {
            factors.push("High entropy arguments (possible obfuscation)".to_string());
        }
        
        if self.is_suspicious_path {
            factors.push(format!("Suspicious execution path: {}", self.path));
        }
        
        if self.uid == 0 && self.name != "systemd" && self.name != "init" {
            factors.push("Running as root (UID 0)".to_string());
        }
        
        if self.path.contains("/tmp") {
            factors.push("Executing from temporary directory".to_string());
        }
        
        factors
    }
}

pub struct MachineProfile {
    pub id: String,
    pub counts: HashMap<ProcessSignature, u32>,
    pub total_logs: u32,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

impl MachineProfile {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            counts: HashMap::new(),
            total_logs: 0,
            first_seen: None,
            last_seen: None,
        }
    }

    pub fn add(&mut self, name: &str, parent: &str, uid: u32, path: &str, args: &str, config: &DetectionConfig, timestamp: Option<DateTime<Utc>>) {
        let entropy = calculate_shannon_entropy(args);
        let is_high_entropy = entropy > config.entropy_threshold;
        let is_suspicious_path = is_path_suspicious(path, &config.suspicious_path_patterns);

        let sig = ProcessSignature {
            name: name.to_string(),
            parent: parent.to_string(),
            uid,
            path: path.to_string(),
            is_high_entropy,
            is_suspicious_path,
        };

        *self.counts.entry(sig).or_insert(0) += 1;
        self.total_logs += 1;
        
        // Track time range
        if let Some(ts) = timestamp {
            if self.first_seen.is_none() || ts < self.first_seen.unwrap() {
                self.first_seen = Some(ts);
            }
            if self.last_seen.is_none() || ts > self.last_seen.unwrap() {
                self.last_seen = Some(ts);
            }
        }
    }
    
    /// Find processes that appear in this profile but not in baseline
    pub fn find_new_processes(&self, baseline: &MachineProfile) -> Vec<&ProcessSignature> {
        self.counts.keys()
            .filter(|sig| !baseline.counts.contains_key(sig))
            .collect()
    }
}

// --- ANOMALY DETECTION RESULTS ---

#[derive(Debug, Clone, Serialize)]
pub enum AnomalyLevel {
    Low,      // Distance 0.0-0.3 from cluster
    Medium,   // Distance 0.3-0.6
    High,     // Distance 0.6-1.0
    Critical, // Distance > 1.0 or noise
}

impl AnomalyLevel {
    fn from_distance(distance: f64) -> Self {
        if distance > 1.0 {
            AnomalyLevel::Critical
        } else if distance > 0.6 {
            AnomalyLevel::High
        } else if distance > 0.3 {
            AnomalyLevel::Medium
        } else {
            AnomalyLevel::Low
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyDetails {
    pub machine_id: String,
    pub severity: AnomalyLevel,
    pub distance_score: f64,
    pub cluster_assignment: Option<usize>,
    pub anomalous_features: Vec<String>,
    pub process_count: u32,
    pub suspicious_process_count: u32,
}

impl AnomalyDetails {
    fn severity_emoji(&self) -> &str {
        match self.severity {
            AnomalyLevel::Low => "🟡",
            AnomalyLevel::Medium => "🟠",
            AnomalyLevel::High => "🔴",
            AnomalyLevel::Critical => "💀",
        }
    }
}

pub struct AnalysisReport {
    pub anomalies: Vec<AnomalyDetails>,
    pub cluster_stats: HashMap<Option<usize>, usize>,
    pub total_analyzed: usize,
    pub config_used: DetectionConfig,
}

impl AnalysisReport {
    pub fn print(&self) {
        println!("\n{:=^60}", " IRONSIFT ANALYSIS REPORT ");
        println!("Fleet Size: {} machines", self.total_analyzed);
        println!("Detection Sensitivity: {}", 
            if self.config_used.dbscan_tolerance < 0.05 { "High" }
            else if self.config_used.dbscan_tolerance < 0.10 { "Medium" }
            else { "Low" }
        );
        
        println!("\n--- Cluster Distribution ---");
        let mut noise_count = 0;
        let mut cluster_ids: Vec<_> = self.cluster_stats.keys()
            .filter_map(|k| *k)
            .collect();
        cluster_ids.sort();
        
        for cluster_id in cluster_ids {
            let count = self.cluster_stats.get(&Some(cluster_id)).unwrap_or(&0);
            println!("  Cluster {}: {} machines", cluster_id, count);
        }
        
        if let Some(&count) = self.cluster_stats.get(&None) {
            noise_count = count;
            println!("  Noise (Outliers): {} machines", noise_count);
        }

        if self.anomalies.is_empty() {
            println!("\n{:=^60}", "");
            println!("Status: ✅ CLEAN (No anomalies detected)");
            println!("{:=^60}", "");
        } else {
            println!("\n{:=^60}", "");
            println!("Status: 🚨 ANOMALIES DETECTED");
            println!("{:=^60}", "");
            println!("Suspicious Machines: {}", self.anomalies.len());
            
            // Group by severity
            let critical: Vec<_> = self.anomalies.iter()
                .filter(|a| matches!(a.severity, AnomalyLevel::Critical))
                .collect();
            let high: Vec<_> = self.anomalies.iter()
                .filter(|a| matches!(a.severity, AnomalyLevel::High))
                .collect();
            let medium: Vec<_> = self.anomalies.iter()
                .filter(|a| matches!(a.severity, AnomalyLevel::Medium))
                .collect();
            let low: Vec<_> = self.anomalies.iter()
                .filter(|a| matches!(a.severity, AnomalyLevel::Low))
                .collect();
            
            if !critical.is_empty() {
                println!("\n💀 CRITICAL ({}):", critical.len());
                for anomaly in critical {
                    self.print_anomaly(anomaly);
                }
            }
            
            if !high.is_empty() {
                println!("\n🔴 HIGH ({}):", high.len());
                for anomaly in high {
                    self.print_anomaly(anomaly);
                }
            }
            
            if !medium.is_empty() {
                println!("\n🟠 MEDIUM ({}):", medium.len());
                for anomaly in medium {
                    self.print_anomaly(anomaly);
                }
            }
            
            if !low.is_empty() {
                println!("\n🟡 LOW ({}):", low.len());
                for anomaly in low {
                    self.print_anomaly(anomaly);
                }
            }
            
            println!("\n{:=^60}", "");
            println!("Action: Review flagged machines and investigate anomalous processes.");
            println!("Export detailed report: cargo run --bin ironsift -- --export-json");
            println!("{:=^60}", "");
        }
    }
    
    fn print_anomaly(&self, anomaly: &AnomalyDetails) {
        println!("  {} {} (Score: {:.3})", 
            anomaly.severity_emoji(), 
            anomaly.machine_id, 
            anomaly.distance_score
        );
        
        if anomaly.suspicious_process_count > 0 {
            println!("     └─ {} suspicious processes detected", anomaly.suspicious_process_count);
        }
        
        if !anomaly.anomalous_features.is_empty() {
            let preview = if anomaly.anomalous_features.len() <= 2 {
                anomaly.anomalous_features.join(", ")
            } else {
                format!("{}, {} and {} more", 
                    anomaly.anomalous_features[0],
                    anomaly.anomalous_features[1],
                    anomaly.anomalous_features.len() - 2
                )
            };
            println!("     └─ Unusual: {}", preview);
        }
    }
    
    /// Export detailed forensic report as JSON
    pub fn export_json(&self, profiles: &[MachineProfile], path: &str) -> Result<(), Box<dyn Error>> {
        let mut investigation_data = Vec::new();
        
        for anomaly in &self.anomalies {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                // Find the most suspicious processes
                let suspicious_procs: Vec<_> = profile.counts.iter()
                    .filter(|(sig, _)| sig.is_high_entropy || sig.is_suspicious_path || sig.uid == 0)
                    .map(|(sig, count)| {
                        serde_json::json!({
                            "name": sig.name,
                            "path": sig.path,
                            "parent": sig.parent,
                            "uid": sig.uid,
                            "count": count,
                            "risk_factors": sig.risk_factors(),
                        })
                    })
                    .collect();
                
                investigation_data.push(serde_json::json!({
                    "machine_id": anomaly.machine_id,
                    "severity": format!("{:?}", anomaly.severity),
                    "distance_score": anomaly.distance_score,
                    "cluster": anomaly.cluster_assignment,
                    "total_processes": profile.total_logs,
                    "unique_processes": profile.counts.len(),
                    "suspicious_processes": suspicious_procs,
                    "anomalous_features": &anomaly.anomalous_features,
                    "time_range": {
                        "first_seen": profile.first_seen,
                        "last_seen": profile.last_seen,
                    }
                }));
            }
        }
        
        let report = serde_json::json!({
            "report_timestamp": Utc::now(),
            "fleet_size": self.total_analyzed,
            "anomalies_detected": self.anomalies.len(),
            "config": self.config_used,
            "cluster_distribution": self.cluster_stats,
            "investigation_targets": investigation_data,
        });
        
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, &report)?;
        println!("\n✅ Forensic report exported to: {}", path);
        
        Ok(())
    }
}

// --- CORE ANALYSIS LOGIC ---

pub fn analyze_fleet(profiles: &[MachineProfile], config: &DetectionConfig) -> Result<AnalysisReport, Box<dyn Error>> {
    if profiles.is_empty() {
        return Ok(AnalysisReport {
            anomalies: vec![],
            cluster_stats: HashMap::new(),
            total_analyzed: 0,
            config_used: config.clone(),
        });
    }

    // 1. Feature Extraction
    let mut unique_features: HashSet<&ProcessSignature> = HashSet::new();
    for p in profiles {
        for key in p.counts.keys() {
            unique_features.insert(key);
        }
    }
    
    let mut feature_list: Vec<&ProcessSignature> = unique_features.into_iter().collect();
    feature_list.sort_by(|a, b| {
        a.name.cmp(&b.name)
            .then(a.path.cmp(&b.path))
            .then(a.uid.cmp(&b.uid))
    });
    
    let n_samples = profiles.len();
    let n_features = feature_list.len();

    // Calculate Document Frequency for IDF weighting
    let feature_doc_freq: Vec<usize> = feature_list.par_iter()
        .map(|feature| {
            profiles.iter()
                .filter(|p| p.counts.contains_key(feature))
                .count()
        })
        .collect();
    
    // 2. Build TF-IDF Matrix
    let mut data = Array2::<f64>::zeros((n_samples, n_features));

    for (row_idx, profile) in profiles.iter().enumerate() {
        if profile.total_logs == 0 { continue; }
        
        for (col_idx, feature) in feature_list.iter().enumerate() {
            if let Some(&count) = profile.counts.get(feature) {
                // TF: Normalized frequency
                let tf = count as f64 / profile.total_logs as f64;
                
                // IDF: Inverse document frequency
                let doc_count = feature_doc_freq[col_idx].max(1) as f64;
                let idf = (n_samples as f64 / doc_count).ln() + 1.0;

                data[[row_idx, col_idx]] = tf * idf;
            }
        }
    }

    // 3. Normalize Features (L2 norm) - Critical for distance-based clustering
    if config.normalize_features {
        for mut row in data.rows_mut() {
            let norm = row.mapv(|x| x * x).sum().sqrt();
            if norm > 0.0 {
                row.mapv_inplace(|x| x / norm);
            }
        }
    }

    // 4. DBSCAN Clustering
    let clusters = Dbscan::params(config.dbscan_min_samples)
        .tolerance(config.dbscan_tolerance)
        .transform(&data)?;

    // 5. Calculate cluster statistics
    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    // Identify the "normal" cluster (largest non-noise cluster)
    let largest_cluster = cluster_counts.iter()
        .filter(|(k, _)| k.is_some())
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| *k);

    // 6. Calculate distance scores for each machine
    let mut anomalies = Vec::new();

    for (i, cluster_id) in clusters.iter().enumerate() {
        let (is_anomaly, distance_score) = match cluster_id {
            None => {
                // Noise point - calculate distance to nearest cluster
                (true, 1.5) // High anomaly score for noise
            }
            Some(id) => {
                let cluster_size = cluster_counts.get(&Some(*id)).unwrap_or(&0);
                let is_minority = (*cluster_size as f64) < (n_samples as f64 * config.minority_cluster_ratio);
                let is_not_main = Some(*id) != largest_cluster.unwrap();
                
                if is_minority && is_not_main {
                    // Small cluster - moderate anomaly
                    (true, 0.7)
                } else {
                    (false, 0.0)
                }
            }
        };

        if is_anomaly {
            let profile = &profiles[i];
            
            // Identify anomalous features
            let mut anomalous_features = Vec::new();
            let mut suspicious_count = 0;
            
            for (sig, count) in &profile.counts {
                // Feature is anomalous if it's rare across the fleet
                let doc_freq_idx = feature_list.iter().position(|&f| f == sig);
                if let Some(idx) = doc_freq_idx {
                    let doc_freq = feature_doc_freq[idx] as f64 / n_samples as f64;
                    
                    if doc_freq < 0.05 { // Appears in < 5% of fleet
                        anomalous_features.push(format!("{} (path: {})", sig.name, sig.path));
                    }
                }
                
                if sig.is_high_entropy || sig.is_suspicious_path {
                    suspicious_count += *count;
                }
            }
            
            anomalies.push(AnomalyDetails {
                machine_id: profile.id.clone(),
                severity: AnomalyLevel::from_distance(distance_score),
                distance_score,
                cluster_assignment: *cluster_id,
                anomalous_features,
                process_count: profile.total_logs,
                suspicious_process_count: suspicious_count,
            });
        }
    }

    // Sort by severity (most critical first)
    anomalies.sort_by(|a, b| {
        b.distance_score.partial_cmp(&a.distance_score).unwrap()
    });

    Ok(AnalysisReport {
        anomalies,
        cluster_stats: cluster_counts,
        total_analyzed: n_samples,
        config_used: config.clone(),
    })
}

// --- UTILITY FUNCTIONS ---

pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    
    let mut counts = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    
    let len = s.len() as f64;
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

fn is_path_suspicious(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        Regex::new(pattern)
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    })
}

// --- DATA LOADERS ---

pub fn load_csv_data(path: &str, config: &DetectionConfig) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }

    let mut rdr = csv::Reader::from_path(path)?;
    let entries: Vec<RawLogEntry> = rdr.deserialize()
        .collect::<Result<Vec<_>, _>>()?;

    if entries.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }

    // Build profiles (parallel processing at the machine level after grouping)
    // First, group entries by machine_id (sequential, but fast)
    let mut machine_entries: HashMap<String, Vec<&RawLogEntry>> = HashMap::new();
    for entry in &entries {
        machine_entries.entry(entry.machine_id.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }
    
    // Now process each machine's entries in parallel
    let profiles: Vec<MachineProfile> = machine_entries.par_iter()
        .map(|(machine_id, machine_logs)| {
            let mut profile = MachineProfile::new(machine_id);
            
            for entry in machine_logs {
                let timestamp = entry.timestamp.as_ref()
                    .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                    .map(|dt| dt.with_timezone(&Utc));
                
                profile.add(&entry.name, &entry.parent, entry.uid, 
                          &entry.path, &entry.args, config, timestamp);
            }
            
            profile
        })
        .collect();

    Ok(profiles)
}

pub fn generate_mock_data(config: &DetectionConfig) -> Vec<MachineProfile> {
    (0..50).into_par_iter().map(|i| {
        let id = format!("machine_{:02}", i);
        let mut p = MachineProfile::new(&id);
        
        // Normal traffic
        for _ in 0..100 {
            p.add("nginx", "systemd", 33, "/usr/sbin/nginx", "-c /etc/nginx.conf", config, None);
        }
        
        // Inject anomaly
        if i == 13 {
            for _ in 0..50 {
                p.add("kworker", "systemd", 0, "/tmp/.hidden/miner", 
                      "XkzL1^s09f87aH@9#", config, None);
            }
        }
        
        p
    }).collect()
}

// --- TESTS ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let low = calculate_shannon_entropy("aaaaaaaaaa");
        assert_eq!(low, 0.0);
        
        let high = calculate_shannon_entropy("X5O!aH@9#kzL1^s09f87");
        assert!(high > 3.0);
    }

    #[test]
    fn test_config_default() {
        let config = DetectionConfig::default();
        assert_eq!(config.entropy_threshold, 4.5);
        assert_eq!(config.dbscan_min_samples, 2);
    }

    #[test]
    fn test_suspicious_path_detection() {
        let patterns = vec![r"/tmp/".to_string(), r"/dev/shm/".to_string()];
        assert!(is_path_suspicious("/tmp/malware", &patterns));
        assert!(is_path_suspicious("/dev/shm/rootkit", &patterns));
        assert!(!is_path_suspicious("/usr/bin/nginx", &patterns));
    }

    #[test]
    fn test_identical_machines_clean() {
        let config = DetectionConfig::default();
        let mut profiles = Vec::new();
        
        for i in 0..5 {
            let mut p = MachineProfile::new(&format!("m{}", i));
            p.add("test", "init", 0, "/bin/test", "args", &config, None);
            profiles.push(p);
        }
        
        let report = analyze_fleet(&profiles, &config).unwrap();
        assert!(report.anomalies.is_empty());
    }

    #[test]
    fn test_detect_single_outlier() {
        let config = DetectionConfig::default();
        let mut profiles = Vec::new();
        
        // 10 normal machines
        for i in 0..10 {
            let mut p = MachineProfile::new(&format!("normal_{}", i));
            p.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, None);
            profiles.push(p);
        }
        
        // 1 compromised machine
        let mut bad = MachineProfile::new("compromised");
        bad.add("miner", "systemd", 0, "/tmp/kworker", "XkzL1^s09f87", &config, None);
        profiles.push(bad);

        let report = analyze_fleet(&profiles, &config).unwrap();
        assert!(!report.anomalies.is_empty());
        assert!(report.anomalies.iter().any(|a| a.machine_id == "compromised"));
    }

    #[test]
    fn test_detect_minority_botnet() {
        let config = DetectionConfig::default();
        let mut profiles = Vec::new();
        
        // 91 normal machines
        for i in 0..91 {
            let mut p = MachineProfile::new(&format!("normal_{}", i));
            p.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, None);
            profiles.push(p);
        }
        
        // 9 botnet machines (< 10% threshold, clearly minority)
        for i in 0..9 {
            let mut p = MachineProfile::new(&format!("botnet_{}", i));
            p.add("xmrig", "systemd", 0, "/tmp/miner", "pool.xmr", &config, None);
            profiles.push(p);
        }
        
        let report = analyze_fleet(&profiles, &config).unwrap();
        
        // Should detect the minority botnet cluster
        let botnet_detected = report.anomalies.iter()
            .filter(|a| a.machine_id.starts_with("botnet_"))
            .count();
        
        assert!(botnet_detected >= 7, "Should detect most of the botnet machines, got {}", botnet_detected);
    }

    #[test]
    fn test_process_risk_factors() {
        let sig = ProcessSignature {
            name: "malware".to_string(),
            parent: "bash".to_string(),
            uid: 0,
            path: "/tmp/hidden".to_string(),
            is_high_entropy: true,
            is_suspicious_path: true,
        };
        
        let risks = sig.risk_factors();
        assert!(!risks.is_empty());
        assert!(risks.iter().any(|r| r.contains("entropy")));
        assert!(risks.iter().any(|r| r.contains("Suspicious execution path")));
    }
}