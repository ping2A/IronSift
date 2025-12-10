use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use ndarray::Array2;
use linfa::traits::Transformer;
use linfa_clustering::Dbscan;
use linfa_nn::KdTree;

// --- DATA STRUCTURES ---

#[derive(Debug, Deserialize, Serialize)]
pub struct RawLogEntry {
    pub machine_id: String,
    pub name: String,
    pub parent: String,
    pub uid: u32,
    pub path: String,
    pub args: String,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize)]
pub struct ProcessSignature {
    pub name: String,
    pub parent: String,
    pub uid: u32,
    pub path: String,
    pub is_high_entropy: bool,
}

pub struct MachineProfile {
    pub id: String,
    pub counts: HashMap<ProcessSignature, u32>,
    pub total_logs: u32,
}

impl MachineProfile {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            counts: HashMap::new(),
            total_logs: 0,
        }
    }

    pub fn add(&mut self, name: &str, parent: &str, uid: u32, path: &str, args: &str) {
        let entropy = calculate_shannon_entropy(args);
        let is_high_entropy = entropy > 4.5; 

        let sig = ProcessSignature {
            name: name.to_string(),
            parent: parent.to_string(),
            uid,
            path: path.to_string(),
            is_high_entropy,
        };

        *self.counts.entry(sig).or_insert(0) += 1;
        self.total_logs += 1;
    }
}

// --- ANALYSIS REPORTING ---

pub struct AnalysisReport {
    pub suspicious_machines: Vec<String>,
    pub cluster_stats: HashMap<Option<usize>, usize>, // Debug info: Cluster ID -> Count
    pub total_analyzed: usize,
}

impl AnalysisReport {
    pub fn print(&self) {
        println!("\n=== IRONSIFT ANALYSIS REPORT ===");
        println!("Fleet Size: {} machines", self.total_analyzed);
        
        println!("\n--- Cluster Distribution ---");
        // Print clean summary of how machines grouped
        let mut noise_count = 0;
        for (cluster_id, count) in &self.cluster_stats {
            match cluster_id {
                Some(id) => println!("Cluster {}: {} machines", id, count),
                None => noise_count = *count,
            }
        }
        if noise_count > 0 {
            println!("Noise (Outliers): {} machines", noise_count);
        }

        if self.suspicious_machines.is_empty() {
            println!("\nStatus: ✅ CLEAN (No anomalies detected)");
        } else {
            println!("\nStatus: 🚨 COMPROMISED");
            println!("Suspicious Machines Detected: {}", self.suspicious_machines.len());
            println!("{:-<40}", "");
            for machine_id in &self.suspicious_machines {
                println!(" • {}", machine_id);
            }
            println!("{:-<40}", "");
            println!("Action: Isolate these machines and inspect process trees.");
        }
    }
}

// --- CORE LOGIC ---

pub fn analyze_fleet(profiles: &[MachineProfile], tolerance: f64) -> Result<AnalysisReport, Box<dyn Error>> {
    // 1. Feature Extraction
    let mut unique_features: HashSet<&ProcessSignature> = HashSet::new();
    for p in profiles {
        for key in p.counts.keys() {
            unique_features.insert(key);
        }
    }
    
    let mut feature_list: Vec<&ProcessSignature> = unique_features.into_iter().collect();
    // Sort for deterministic matrix columns
    feature_list.sort_by(|a, b| a.name.cmp(&b.name).then(a.path.cmp(&b.path)));
    
    let n_samples = profiles.len();
    let n_features = feature_list.len();

    // NEW: Calculate Document Frequency (DF) for weighting
    // Count how many machines have each feature.
    let mut feature_doc_freq = vec![0; n_features];
    for p in profiles {
        for (idx, feature) in feature_list.iter().enumerate() {
            if p.counts.contains_key(feature) {
                feature_doc_freq[idx] += 1;
            }
        }
    }
    
    // 2. Vectorization (Matrix Building)
    let mut data = Array2::<f64>::zeros((n_samples, n_features));

    for (row_idx, profile) in profiles.iter().enumerate() {
        if profile.total_logs == 0 { continue; }
        for (col_idx, feature) in feature_list.iter().enumerate() {
            if let Some(&count) = profile.counts.get(feature) {
                // TF (Term Frequency): Normalized frequency of process on this machine
                let tf = count as f64 / profile.total_logs as f64;
                
                // IDF (Inverse Document Frequency): Weight boosting for rare events
                // If a process is on 1/100 machines, it gets a 100x signal boost.
                // If it's on 100/100 machines, it gets 1x (no boost).
                // This prevents "noisy" frequent processes from drowning out "rare" malware.
                let doc_count = feature_doc_freq[col_idx].max(1) as f64;
                let idf = n_samples as f64 / doc_count;

                data[[row_idx, col_idx]] = tf * idf;
            }
        }
    }

    // 3. DBSCAN Clustering
    if n_samples == 0 {
        return Ok(AnalysisReport {
            suspicious_machines: vec![],
            cluster_stats: HashMap::new(),
            total_analyzed: 0,
        });
    }

    let clusters = Dbscan::params(2)
        .tolerance(tolerance) 
        .transform(&data)?;

    // 4. Outlier Extraction & Minority Cluster Detection
    let mut suspicious_machines = Vec::new();
    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();

    // Pass 1: Count cluster sizes
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    // Identify "Normal" Cluster (The largest one)
    let largest_cluster = cluster_counts.iter()
        .filter(|(k, _)| k.is_some()) // Ignore noise for a moment
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| *k);

    // Pass 2: Flag anomalies
    for (i, cluster_id) in clusters.iter().enumerate() {
        let is_anomaly = match cluster_id {
            // Case A: DBSCAN explicitly marked it as Noise
            None => true,
            // Case B: It is in a cluster, BUT it's a tiny minority cluster (< 10% of fleet)
            // This catches botnets or groups of hacked machines.
            Some(id) => {
                let size = cluster_counts.get(&Some(*id)).unwrap_or(&0);
                let is_minority = (*size as f64) < (n_samples as f64 * 0.10);
                let is_not_main = Some(*id) != largest_cluster.unwrap();
                is_minority && is_not_main
            }
        };

        if is_anomaly {
            suspicious_machines.push(profiles[i].id.clone());
        }
    }

    Ok(AnalysisReport {
        suspicious_machines,
        cluster_stats: cluster_counts,
        total_analyzed: n_samples,
    })
}

// --- DATA LOADERS ---

pub fn load_csv_data(path: &str) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }

    let mut rdr = csv::Reader::from_path(path)?;
    let mut map: HashMap<String, MachineProfile> = HashMap::new();

    for result in rdr.deserialize() {
        let entry: RawLogEntry = result?;
        let profile = map.entry(entry.machine_id.clone())
            .or_insert_with(|| MachineProfile::new(&entry.machine_id));
        profile.add(&entry.name, &entry.parent, entry.uid, &entry.path, &entry.args);
    }

    if map.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }

    Ok(map.into_values().collect())
}

pub fn generate_mock_data() -> Vec<MachineProfile> {
    let mut profiles = Vec::new();
    for i in 0..50 {
        let id = format!("machine_{:02}", i);
        let mut p = MachineProfile::new(&id);
        for _ in 0..100 {
            p.add("nginx", "systemd", 33, "/usr/sbin/nginx", "-c /etc/nginx.conf");
        }
        if i == 13 {
            for _ in 0..50 { p.add("nginx", "systemd", 33, "/tmp/nginx", "-c conf"); }
        }
        profiles.push(p);
    }
    profiles
}

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

// --- TESTS ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let low = calculate_shannon_entropy("aaaaaaaaaa");
        assert_eq!(low, 0.0);
        let high = calculate_shannon_entropy("X5O!aH@9#kzL1^s09f87");
        assert!(high > 2.0);
    }

    #[test]
    fn test_identical_machines_are_consistent() {
        let mut profiles = Vec::new();
        for i in 0..5 {
            let mut p = MachineProfile::new(&format!("m{}", i));
            p.add("test", "init", 0, "/bin", "args");
            profiles.push(p);
        }
        let report = analyze_fleet(&profiles, 0.1).unwrap();
        assert!(report.suspicious_machines.is_empty());
    }

    #[test]
    fn test_detect_outlier() {
        let mut profiles = Vec::new();
        for i in 0..10 {
            let mut p = MachineProfile::new(&format!("normal_{}", i));
            p.add("nginx", "systemd", 33, "/usr/bin", "conf");
            profiles.push(p);
        }
        let mut bad = MachineProfile::new("bad_guy");
        bad.add("nginx", "systemd", 33, "/tmp/hidden", "conf"); 
        profiles.push(bad);

        let report = analyze_fleet(&profiles, 0.05).unwrap();
        assert_eq!(report.suspicious_machines.len(), 1);
        assert_eq!(report.suspicious_machines[0], "bad_guy");
    }
}