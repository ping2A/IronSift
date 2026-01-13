use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::path::Path;
use serde::{Deserialize, Serialize};
use ndarray::Array2;
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
    
    /// Exclude Linux kernel threads (names starting with '[' and ending with ']')
    /// Examples: [kworker/1:0], [migration/0], [ksoftirqd/1]
    pub exclude_kernel_threads: bool,
    
    /// Common system processes that legitimately run as root (UID 0)
    /// These will not be flagged as suspicious just for being root
    pub common_root_processes: Vec<String>,
    
    /// Penalize root processes that are NOT in common_root_processes list
    /// If false, root processes are not considered suspicious
    pub flag_unexpected_root: bool,
    
    /// Enable debug output for detailed process information
    pub debug_display: bool,
    
    /// Exclude processes that are direct children of init/systemd (PPID = 1)
    /// Many system services run as children of init and are typically normal
    pub exclude_init_children: bool,
    
    /// Path whitelist patterns (glob-style wildcards: * and ?)
    /// Processes with paths matching these patterns will not be flagged as suspicious
    /// Examples: "/opt/conda/*", "/usr/local/bin/*", "/home/*/venv/*"
    pub whitelisted_path_patterns: Vec<String>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            entropy_threshold: 4.5,
            minority_cluster_ratio: 0.10,
            dbscan_tolerance: 0.35,
            dbscan_min_samples: 2,
            normalize_features: true,
            suspicious_path_patterns: vec![
                r"/tmp/".to_string(),
                r"/dev/shm/".to_string(),
                r"/var/tmp/".to_string(),
                r"/home/[^/]+/\.[^/]+".to_string(), // Hidden dirs in home
                r"^\./".to_string(), // Relative paths
            ],
            exclude_kernel_threads: true,
            common_root_processes: vec![
                "systemd".to_string(),
                "init".to_string(),
                "sshd".to_string(),
                "cron".to_string(),
                "crond".to_string(),
                "rsyslogd".to_string(),
                "dockerd".to_string(),
                "containerd".to_string(),
                "kubelet".to_string(),
                "networkd".to_string(),
                "systemd-networkd".to_string(),
                "systemd-resolved".to_string(),
                "systemd-journald".to_string(),
                "systemd-logind".to_string(),
                "systemd-udevd".to_string(),
                "dbus-daemon".to_string(),
                "polkitd".to_string(),
                "snapd".to_string(),
                "unattended-upgr".to_string(),  // Ubuntu auto-updates
                "accounts-daemon".to_string(),
                "rtkit-daemon".to_string(),
                "cups-browsed".to_string(),
                "cupsd".to_string(),
                "avahi-daemon".to_string(),
            ],
            flag_unexpected_root: true,
            debug_display: false,
            exclude_init_children: false,  // Off by default to avoid over-filtering
            whitelisted_path_patterns: vec![],  // Empty by default
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
    
    /// Print comprehensive configuration display
    pub fn print(&self) {
        println!("Configuration:");
        println!("  Core Detection Parameters:");
        println!("    Entropy Threshold: {:.2}", self.entropy_threshold);
        println!("    DBSCAN Tolerance: {:.3}", self.dbscan_tolerance);
        println!("    DBSCAN Min Samples: {}", self.dbscan_min_samples);
        println!("    Minority Cluster Ratio: {:.1}%", self.minority_cluster_ratio * 100.0);
        println!("    Normalize Features: {}", self.normalize_features);
        
        println!("  Filtering Options:");
        println!("    Exclude Kernel Threads: {}", self.exclude_kernel_threads);
        println!("    Exclude Init Children (PPID=1): {}", self.exclude_init_children);
        println!("    Flag Unexpected Root: {}", self.flag_unexpected_root);
        println!("    Debug Display: {}", self.debug_display);
        
        if !self.suspicious_path_patterns.is_empty() {
            println!("  Suspicious Path Patterns ({}):", self.suspicious_path_patterns.len());
            for pattern in &self.suspicious_path_patterns {
                println!("    • {}", pattern);
            }
        }
        
        if !self.whitelisted_path_patterns.is_empty() {
            println!("  Whitelisted Path Patterns ({}):", self.whitelisted_path_patterns.len());
            for pattern in &self.whitelisted_path_patterns {
                println!("    • {}", pattern);
            }
        }
        
        if !self.common_root_processes.is_empty() {
            println!("  Common Root Processes ({}):", self.common_root_processes.len());
            let display_count = self.common_root_processes.len().min(10);
            for process in self.common_root_processes.iter().take(display_count) {
                println!("    • {}", process);
            }
            if self.common_root_processes.len() > display_count {
                println!("    ... and {} more", self.common_root_processes.len() - display_count);
            }
        }
    }
}

// --- DATA STRUCTURES ---

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RawLogEntry {
    pub machine_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub uid: u32,
    pub path: String,
    pub args: String,
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Flexible process entry that doesn't require PIDs upfront
#[derive(Debug, Clone)]
pub struct ProcessEntry {
    pub machine_id: String,
    pub name: String,
    pub parent_name: Option<String>,  // Optional - if None, will try to infer
    pub ppid: Option<u32>,  // ⭐ PPID - preserved when provided
    pub uid: u32,
    pub path: String,
    pub args: String,
    pub timestamp: Option<String>,
}

impl ProcessEntry {
    pub fn new(machine_id: String, name: String) -> Self {
        println!("🔧 Creating ProcessEntry: machine={}, name={}", machine_id, name);
        Self {
            machine_id,
            name,
            parent_name: None,
            ppid: None,  // ⭐ Initialize PPID as None
            uid: 1000,
            path: String::new(),
            args: String::new(),
            timestamp: None,
        }
    }
    
    /// Create ProcessEntry from a full command line
    /// 
    /// Automatically extracts name, path, and args from the command string.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessEntry;
    /// 
    /// let entry = ProcessEntry::from_command_line(
    ///     "machine1".to_string(),
    ///     "/usr/bin/nginx -c /etc/nginx.conf",
    ///     Some("systemd")
    /// );
    /// 
    /// assert_eq!(entry.name, "nginx");
    /// assert_eq!(entry.path, "/usr/bin/nginx");
    /// assert_eq!(entry.args, "-c /etc/nginx.conf");
    /// ```
    pub fn from_command_line(machine_id: String, command: &str, parent: Option<&str>) -> Self {
        let (name, path, args) = crate::parse_command_line(command);
        
        println!("🔧 Creating ProcessEntry from command: machine={}, command={}", machine_id, command);
        
        Self {
            machine_id,
            name,
            parent_name: parent.map(|p| p.to_string()),
            ppid: None,  // ⭐ Initialize PPID as None
            uid: 1000,
            path,
            args,
            timestamp: None,
        }
    }
    
    pub fn parent(mut self, parent: &str) -> Self {
        println!("  ├─ Setting parent: {}", parent);
        self.parent_name = Some(parent.to_string());
        self
    }
    
    /// Set PPID - this value will be preserved
    pub fn ppid(mut self, ppid: u32) -> Self {
        println!("  ├─ Setting PPID: {} ⭐", ppid);
        self.ppid = Some(ppid);
        self
    }
    
    pub fn uid(mut self, uid: u32) -> Self {
        println!("  ├─ Setting UID: {}", uid);
        self.uid = uid;
        self
    }
    
    pub fn path(mut self, path: &str) -> Self {
        if !path.is_empty() {
            println!("  ├─ Setting path: {}", path);
        }
        self.path = path.to_string();
        self
    }
    
    pub fn args(mut self, args: &str) -> Self {
        if !args.is_empty() {
            let display = if args.len() > 50 { 
                format!("{}...", &args[..50]) 
            } else { 
                args.to_string() 
            };
            println!("  ├─ Setting args: {}", display);
        }
        self.args = args.to_string();
        self
    }
    
    pub fn timestamp(mut self, timestamp: String) -> Self {
        println!("  └─ Setting timestamp: {}", timestamp);
        self.timestamp = Some(timestamp);
        self
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ProcessSignature {
    pub name: String,
    pub parent_name: String,
    //pub ppid: u32,  // ⭐ PPID preserved for forensics
    pub uid: u32,
    pub path: String,
    pub is_high_entropy: bool,
    pub is_suspicious_path: bool,
}

impl ProcessSignature {
    /// Check if this is an unexpected root process (not in common list)
    pub fn is_unexpected_root(&self, common_root_processes: &[String]) -> bool {
        if self.uid != 0 {
            return false;
        }
        
        // Check if it's in the common root processes list
        !common_root_processes.iter().any(|common| {
            self.name == *common || self.name.starts_with(common)
        })
    }
    
    /// Create a human-readable description of why this process is suspicious
    pub fn risk_factors(&self, config: &DetectionConfig) -> Vec<String> {
        let mut factors = Vec::new();
        
        if self.is_high_entropy {
            factors.push("High entropy arguments (possible obfuscation)".to_string());
        }
        
        if self.is_suspicious_path {
            factors.push(format!("Suspicious execution path: {}", self.path));
        }
        
        if config.flag_unexpected_root && self.is_unexpected_root(&config.common_root_processes) {
            factors.push(format!("Unexpected process running as root (UID 0): {}", self.name));
        }
        
        if self.path.contains("/tmp") {
            factors.push("Executing from temporary directory".to_string());
        }
        
        factors
    }
    
    /// Legacy method for backwards compatibility (uses default config)
    #[deprecated(since = "2.0.0", note = "Use risk_factors(&config) instead")]
    pub fn risk_factors_legacy(&self) -> Vec<String> {
        let config = DetectionConfig::default();
        self.risk_factors(&config)
    }
}

#[derive(Debug)]
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

    pub fn add_process(&mut self, sig: ProcessSignature, timestamp: Option<DateTime<Utc>>) {
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
    Low,      // Distance 0.0 - <0.3 from cluster
    Medium,   // Distance 0.3 - <0.6
    High,     // Distance 0.6 - <1.0
    Critical, // Distance >= 1.0 or noise
}

impl AnomalyLevel {
    pub fn from_distance(distance: f64) -> Self {
        if distance >= 1.0 {
            AnomalyLevel::Critical
        } else if distance >= 0.6 {
            AnomalyLevel::High
        } else if distance >= 0.3 {
            AnomalyLevel::Medium
        } else {
            AnomalyLevel::Low
        }
    }
    
    /// Get severity as string
    pub fn as_str(&self) -> &str {
        match self {
            AnomalyLevel::Low => "LOW",
            AnomalyLevel::Medium => "MEDIUM",
            AnomalyLevel::High => "HIGH",
            AnomalyLevel::Critical => "CRITICAL",
        }
    }
    
    /// Get emoji representation
    pub fn emoji(&self) -> &str {
        match self {
            AnomalyLevel::Low => "🟡",
            AnomalyLevel::Medium => "🟠",
            AnomalyLevel::High => "🔴",
            AnomalyLevel::Critical => "💀",
        }
    }
    
    /// Get numeric severity score (0-3)
    pub fn score(&self) -> u8 {
        match self {
            AnomalyLevel::Low => 0,
            AnomalyLevel::Medium => 1,
            AnomalyLevel::High => 2,
            AnomalyLevel::Critical => 3,
        }
    }
}

impl std::fmt::Display for AnomalyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
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
        self.severity.emoji()
    }
    
    fn severity_str(&self) -> &str {
        self.severity.as_str()
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
        self.print_detailed(None);
    }
    
    /// Print detailed analysis report with optional profile access
    pub fn print_detailed(&self, profiles: Option<&[MachineProfile]>) {
        println!("\n{:=^80}", " IRONSIFT ANALYSIS REPORT ");
        println!("Fleet Size: {} machines", self.total_analyzed);
        println!("Detection Sensitivity: {}", 
            if self.config_used.dbscan_tolerance < 0.05 { "High" }
            else if self.config_used.dbscan_tolerance < 0.10 { "Medium" }
            else { "Low" }
        );
        
        // Configuration summary
        println!("\n--- Configuration ---");
        println!("  DBSCAN Tolerance: {}", self.config_used.dbscan_tolerance);
        println!("  Entropy Threshold: {}", self.config_used.entropy_threshold);
        println!("  Minority Cluster Ratio: {}%", self.config_used.minority_cluster_ratio * 100.0);
        
        println!("\n--- Cluster Distribution ---");
        let mut cluster_ids: Vec<_> = self.cluster_stats.keys()
            .filter_map(|k| *k)
            .collect();
        cluster_ids.sort();
        
        for cluster_id in cluster_ids {
            let count = self.cluster_stats.get(&Some(cluster_id)).unwrap_or(&0);
            let pct = (*count as f64 / self.total_analyzed as f64) * 100.0;
            println!("  Cluster {}: {} machines ({:.1}%)", cluster_id, count, pct);
        }
        
        if let Some(&noise_count) = self.cluster_stats.get(&None) {
            let pct = (noise_count as f64 / self.total_analyzed as f64) * 100.0;
            println!("  Noise (Outliers): {} machines ({:.1}%)", noise_count, pct);
        }

        if self.anomalies.is_empty() {
            println!("\n{:=^80}", "");
            println!("Status: ✅ CLEAN (No anomalies detected)");
            println!("{:=^80}", "");
            println!("\nAll machines appear to be operating normally.");
            println!("No suspicious processes or unusual behavior patterns detected.");
        } else {
            println!("\n{:=^80}", "");
            println!("Status: 🚨 ANOMALIES DETECTED");
            println!("{:=^80}", "");
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
            
            // Severity breakdown
            println!("\nSeverity Breakdown:");
            if !critical.is_empty() {
                println!("  💀 CRITICAL: {} machine(s)", critical.len());
            }
            if !high.is_empty() {
                println!("  🔴 HIGH: {} machine(s)", high.len());
            }
            if !medium.is_empty() {
                println!("  🟠 MEDIUM: {} machine(s)", medium.len());
            }
            if !low.is_empty() {
                println!("  🟡 LOW: {} machine(s)", low.len());
            }
            
            if !critical.is_empty() {
                println!("\n💀 CRITICAL ({}):", critical.len());
                println!("   These machines are isolated outliers - likely compromised");
                for anomaly in critical {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            
            if !high.is_empty() {
                println!("\n🔴 HIGH ({}):", high.len());
                println!("   Strong deviation from baseline - investigate immediately");
                for anomaly in high {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            
            if !medium.is_empty() {
                println!("\n🟠 MEDIUM ({}):", medium.len());
                println!("   Moderate anomaly - worth reviewing");
                for anomaly in medium {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            
            if !low.is_empty() {
                println!("\n🟡 LOW ({}):", low.len());
                println!("   Minor deviation - may be benign");
                for anomaly in low {
                    self.print_anomaly_detailed(anomaly, profiles);
                }
            }
            
            // Attack type summary
            self.print_attack_summary(profiles);
            
            println!("\n{:=^80}", "");
            println!("Recommended Actions:");
            println!("  1. Review flagged machines and investigate anomalous processes");
            println!("  2. Check process execution paths and command arguments");
            println!("  3. Verify parent-child process relationships");
            println!("  4. Cross-reference with network logs and file access logs");
            println!("  5. Export detailed report: cargo run --bin ironsift -- --export-json");
            println!("{:=^80}", "");
        }
    }
    
    fn print_anomaly_detailed(&self, anomaly: &AnomalyDetails, profiles: Option<&[MachineProfile]>) {
        println!("\n  {} {} [{}] (Distance: {:.3})", 
            anomaly.severity_emoji(), 
            anomaly.machine_id,
            anomaly.severity_str(),
            anomaly.distance_score
        );
        
        // Cluster information
        if let Some(cluster) = anomaly.cluster_assignment {
            println!("     ├─ Cluster: {}", cluster);
        } else {
            println!("     ├─ Cluster: Noise (isolated outlier)");
        }
        
        // Process counts
        println!("     ├─ Total processes: {}", anomaly.process_count);
        if anomaly.suspicious_process_count > 0 {
            println!("     ├─ Suspicious processes: {} ⚠️", anomaly.suspicious_process_count);
        }
        
        // Anomalous features
        if !anomaly.anomalous_features.is_empty() {
            println!("     ├─ Rare processes (< 5% of fleet):");
            let display_count = anomaly.anomalous_features.len().min(5);
            for feature in &anomaly.anomalous_features[..display_count] {
                println!("     │  • {}", feature);
            }
            if anomaly.anomalous_features.len() > 5 {
                println!("     │  • ... and {} more", anomaly.anomalous_features.len() - 5);
            }
        }
        
        // Detailed process information if profiles available
        if let Some(profiles) = profiles {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                self.print_suspicious_processes(profile);
                
                // Time range
                if profile.first_seen.is_some() && profile.last_seen.is_some() {
                    println!("     └─ Activity period: {} to {}", 
                        profile.first_seen.unwrap().format("%Y-%m-%d %H:%M:%S"),
                        profile.last_seen.unwrap().format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }
        } else {
            println!("     └─ Run with profiles for detailed process information");
        }
    }
    
    fn print_suspicious_processes(&self, profile: &MachineProfile) {
        // Find the most suspicious processes
        let mut suspicious: Vec<_> = profile.counts.iter()
            .filter(|(sig, _)| sig.is_high_entropy || sig.is_suspicious_path || sig.uid == 0)
            .collect();
        
        if suspicious.is_empty() {
            return;
        }
        
        // Sort by "suspiciousness" - prioritize high entropy + suspicious path + root
        suspicious.sort_by(|(a, _), (b, _)| {
            let a_score = (a.is_high_entropy as i32) + (a.is_suspicious_path as i32) + 
                          ((a.uid == 0 && a.name != "systemd" && a.name != "init") as i32);
            let b_score = (b.is_high_entropy as i32) + (b.is_suspicious_path as i32) + 
                          ((b.uid == 0 && b.name != "systemd" && b.name != "init") as i32);
            b_score.cmp(&a_score)
        });
        
        println!("     ├─ Suspicious processes detected:");
        let display_count = suspicious.len().min(3);
        
        for (sig, count) in &suspicious[..display_count] {
            println!("     │");
            println!("     │  📛 {} (count: {})", sig.name, count);
            
            // ⭐ Show PPID alongside parent name
      /*       if sig.ppid > 0 {
                println!("     │     Parent: {} (PPID: {})", sig.parent_name, sig.ppid);
            } else {
                println!("     │     Parent: {}", sig.parent_name);
            }
         */   
            println!("     │     Path: {}", sig.path);
            if sig.uid == 0 {
                println!("     │     UID: {} (root) ⚠️", sig.uid);
            } else {
                println!("     │     UID: {}", sig.uid);
            }
            
            let risks = sig.risk_factors(&self.config_used);
            if !risks.is_empty() {
                println!("     │     Risk factors:");
                for risk in risks {
                    println!("     │       🚨 {}", risk);
                }
            }
        }
        
        if suspicious.len() > 3 {
            println!("     │  ... and {} more suspicious processes", suspicious.len() - 3);
        }
    }
    
    fn print_attack_summary(&self, profiles: Option<&[MachineProfile]>) {
        if profiles.is_none() {
            return;
        }
        
        let profiles = profiles.unwrap();
        
        // Categorize attacks by characteristics
        let mut cryptominers = Vec::new();
        let mut web_shells = Vec::new();
        let mut privilege_escalation = Vec::new();
        let mut suspicious_paths = Vec::new();
        
        for anomaly in &self.anomalies {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                for (sig, _) in &profile.counts {
                    // Cryptominer indicators
                    if (sig.name.contains("miner") || sig.name.contains("xmr") || 
                        sig.name.contains("kworker") || sig.name.contains("worker")) &&
                       (sig.is_suspicious_path || sig.uid == 0) {
                        cryptominers.push(anomaly.machine_id.clone());
                        break;
                    }
                    
                    // Web shell indicators
                    if (sig.name.contains("php") || sig.name.contains("eval")) && sig.is_high_entropy {
                        web_shells.push(anomaly.machine_id.clone());
                        break;
                    }
                    
                    // Privilege escalation
                    if sig.uid == 0 && sig.name != "systemd" && sig.name != "init" && 
                       (sig.is_high_entropy || sig.is_suspicious_path) {
                        privilege_escalation.push(anomaly.machine_id.clone());
                        break;
                    }
                    
                    // Suspicious execution paths
                    if sig.is_suspicious_path && sig.path.contains("/tmp") {
                        suspicious_paths.push(anomaly.machine_id.clone());
                        break;
                    }
                }
            }
        }
        
        if cryptominers.is_empty() && web_shells.is_empty() && 
           privilege_escalation.is_empty() && suspicious_paths.is_empty() {
            return;
        }
        
        println!("\n--- Detected Attack Patterns ---");
        
        if !cryptominers.is_empty() {
            println!("  ⛏️  Cryptomining ({} machines):", cryptominers.len());
            for machine in cryptominers.iter().take(5) {
                println!("     • {}", machine);
            }
            if cryptominers.len() > 5 {
                println!("     • ... and {} more", cryptominers.len() - 5);
            }
        }
        
        if !web_shells.is_empty() {
            println!("  🕸️  Web Shells ({} machines):", web_shells.len());
            for machine in web_shells.iter().take(5) {
                println!("     • {}", machine);
            }
            if web_shells.len() > 5 {
                println!("     • ... and {} more", web_shells.len() - 5);
            }
        }
        
        if !privilege_escalation.is_empty() {
            println!("  ⬆️  Privilege Escalation ({} machines):", privilege_escalation.len());
            for machine in privilege_escalation.iter().take(5) {
                println!("     • {}", machine);
            }
            if privilege_escalation.len() > 5 {
                println!("     • ... and {} more", privilege_escalation.len() - 5);
            }
        }
        
        if !suspicious_paths.is_empty() {
            println!("  📂 Suspicious Execution Paths ({} machines):", suspicious_paths.len());
            for machine in suspicious_paths.iter().take(5) {
                println!("     • {}", machine);
            }
            if suspicious_paths.len() > 5 {
                println!("     • ... and {} more", suspicious_paths.len() - 5);
            }
        }
    }
    
    /// Export detailed forensic report as JSON with complete PPID information
    /// 
    /// This method exports a comprehensive forensic report including:
    /// - Machine anomalies with severity scores
    /// - Suspicious processes with PPID, entropy, and risk factors
    /// - Complete process details for incident response
    /// - Timeline information (first/last seen)
    /// - Cluster distribution
    pub fn export_json(&self, profiles: &[MachineProfile], path: &str) -> Result<(), Box<dyn Error>> {
        let mut investigation_data = Vec::new();
        
        for anomaly in &self.anomalies {
            if let Some(profile) = profiles.iter().find(|p| p.id == anomaly.machine_id) {
                // Find the most suspicious processes
                let suspicious_procs: Vec<_> = profile.counts.iter()
                    .filter(|(sig, _)| {
                        let is_common = self.config_used.common_root_processes.iter().any(|p| sig.name.contains(p));
                        sig.is_high_entropy || sig.is_suspicious_path || (sig.uid == 0 && !is_common)
                    })
                    .map(|(sig, count)| {
                        // Calculate entropy for args display
                        let entropy_status = if sig.is_high_entropy { "HIGH" } else { "NORMAL" };
                        
                        serde_json::json!({
                            "name": sig.name,
                            "path": sig.path,
                            "parent": sig.parent_name,
                   //         "ppid": sig.ppid,  // ⭐ PPID included for forensics!
                            "uid": sig.uid,
                            "count": count,
                            "is_high_entropy": sig.is_high_entropy,
                            "entropy_status": entropy_status,
                            "is_suspicious_path": sig.is_suspicious_path,
                            "risk_factors": sig.risk_factors(&self.config_used),
                        })
                    })
                    .collect();
                
                // ⭐ Export ALL processes for complete forensics (not just suspicious)
                let all_procs: Vec<_> = profile.counts.iter()
                    .map(|(sig, count)| {
                        serde_json::json!({
                            "name": sig.name,
                            "parent": sig.parent_name,
                //            "ppid": sig.ppid,  // ⭐ PPID for complete process tree
                            "uid": sig.uid,
                            "path": sig.path,
                            "count": count,
                            "is_high_entropy": sig.is_high_entropy,
                            "is_suspicious_path": sig.is_suspicious_path,
                        })
                    })
                    .collect();
                
                investigation_data.push(serde_json::json!({
                    "machine_id": anomaly.machine_id,
                    "severity": {
                        "level": anomaly.severity.as_str(),
                        "score": anomaly.severity.score(),
                        "emoji": anomaly.severity.emoji(),
                    },
                    "distance_score": anomaly.distance_score,
                    "cluster": anomaly.cluster_assignment,
                    "total_processes": profile.total_logs,
                    "unique_processes": profile.counts.len(),
                    "suspicious_processes": suspicious_procs,
                    "all_processes": all_procs,  // ⭐ Complete process list with PPID
                    "anomalous_features": &anomaly.anomalous_features,
                    "time_range": {
                        "first_seen": profile.first_seen,
                        "last_seen": profile.last_seen,
                    }
                }));
            }
        }
        
        // Convert cluster_stats to string-keyed map for JSON serialization
        let cluster_distribution: serde_json::Map<String, serde_json::Value> = self.cluster_stats
            .iter()
            .map(|(k, v)| {
                let key = match k {
                    Some(id) => format!("cluster_{}", id),
                    None => "outliers".to_string(),
                };
                (key, serde_json::json!(v))
            })
            .collect();
        
        let report = serde_json::json!({
            "report_timestamp": Utc::now(),
            "fleet_size": self.total_analyzed,
            "anomalies_detected": self.anomalies.len(),
            "config": self.config_used,
            "cluster_distribution": cluster_distribution,
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
            anomalies: vec![], cluster_stats: HashMap::new(), total_analyzed: 0, config_used: config.clone(),
        });
    }

    // 1. Feature Extraction
    let mut unique_features: HashSet<&ProcessSignature> = HashSet::new();
    for p in profiles {
        for key in p.counts.keys() { unique_features.insert(key); }
    }
    
    let mut feature_list: Vec<&ProcessSignature> = unique_features.into_iter().collect();
    let n_samples = profiles.len();
    let n_features = feature_list.len();

    // 2. Build Matrix
    let mut data = Array2::<f64>::zeros((n_samples, n_features));
    for (row_idx, profile) in profiles.iter().enumerate() {
        if profile.total_logs == 0 { continue; }
        for (col_idx, feature) in feature_list.iter().enumerate() {
            if let Some(&count) = profile.counts.get(feature) {
                let tf = count as f64 / profile.total_logs as f64;
                let doc_count = profiles.iter().filter(|p| p.counts.contains_key(feature)).count();
                // Standard IDF
                let idf = ((n_samples as f64) / (doc_count as f64 + 1.0)).ln() + 1.0;
                data[[row_idx, col_idx]] = tf * idf;
            }
        }
    }

    // 3. Normalize
    if config.normalize_features {
        for mut row in data.rows_mut() {
            let norm = row.mapv(|x| x * x).sum().sqrt();
            if norm > 0.0 { row.mapv_inplace(|x| x / norm); }
        }
    }

    // 4. DBSCAN
    let clusters = Dbscan::params(config.dbscan_min_samples)
        .tolerance(config.dbscan_tolerance)
        .transform(&data)?;

    let mut cluster_counts: HashMap<Option<usize>, usize> = HashMap::new();
    for cluster_id in clusters.iter() {
        *cluster_counts.entry(*cluster_id).or_insert(0) += 1;
    }

    let largest_cluster = cluster_counts.iter()
        .filter(|(k, _)| k.is_some())
        .max_by_key(|(_, v)| *v)
        .map(|(k, _)| k.unwrap());

    let mut anomalies = Vec::new();
    
    for (i, cluster_id) in clusters.iter().enumerate() {
        let profile = &profiles[i];
        let mut suspicious_count = 0;
        let mut anomalous_features = Vec::new();
        let mut has_genuine_risk = false;

        for (sig, count) in &profile.counts {
            // RISK CHECK: Is this process dangerous?
            let is_common_root = config.common_root_processes.iter().any(|p| sig.name.contains(p));
            let is_behavioral_risk = sig.is_high_entropy || sig.is_suspicious_path;
            let is_unexpected_root = sig.uid == 0 && !is_common_root; // "exploit" (UID 0) != "sshd" -> True
            
            if is_behavioral_risk || is_unexpected_root {
                suspicious_count += *count;
                has_genuine_risk = true; 
                anomalous_features.push(format!("RISK DETECTED: {} (root/path/entropy)", sig.name));
            }
            
            // Still check for statistical rarity
            let doc_count = profiles.iter().filter(|p| p.counts.contains_key(sig)).count();
            if doc_count == 1 && !is_common_root { 
                anomalous_features.push(format!("Rare process: {}", sig.name));
            }
        }

        // --- NEW DETECTION LOGIC ---
        let is_noise = cluster_id.is_none();
        let is_minority = cluster_id.is_some() && cluster_id.unwrap() != largest_cluster.unwrap_or(999);
        
        // FIX: Flag if (Statistical Outlier) OR (Behavioral Risk)
        if is_noise || is_minority || has_genuine_risk {
            // Determine severity based on WHY it was flagged
            let severity = if has_genuine_risk {
                // If it has rootkits/exploits, it's Critical/High regardless of clustering
                if suspicious_count > 5 { AnomalyLevel::Critical } else { AnomalyLevel::High }
            } else {
                // If just a statistical outlier (Noise), it's Medium
                AnomalyLevel::Medium 
            };

            anomalies.push(AnomalyDetails {
                machine_id: profile.id.clone(),
                severity,
                distance_score: if is_noise { 1.5 } else { 0.8 }, // Manual score override
                cluster_assignment: *cluster_id,
                anomalous_features, // Now includes "RISK DETECTED" tags
                process_count: profile.total_logs,
                suspicious_process_count: suspicious_count,
            });
        }
    }

    Ok(AnalysisReport {
        anomalies, cluster_stats: cluster_counts, total_analyzed: n_samples, config_used: config.clone(),
    })
}

pub fn analyze_fleet2(profiles: &[MachineProfile], config: &DetectionConfig) -> Result<AnalysisReport, Box<dyn Error>> {
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
    
    // For very long strings (> 100 chars), entropy naturally increases
    // due to more unique characters, which causes false positives.
    // We normalize by considering entropy density rather than absolute entropy.
    
    // Remove common path separators and normalize to focus on actual content
    // Long paths like "/home/ecbuilds/proj/subproj/file" should not be penalized
    let normalized = s.replace('/', " ")
                      .replace('.', " ")
                      .replace('-', " ")
                      .replace('_', " ");
    
    let mut counts = HashMap::new();
    for c in normalized.chars() {
        if !c.is_whitespace() {  // Ignore whitespace in entropy calculation
            *counts.entry(c).or_insert(0) += 1;
        }
    }
    
    if counts.is_empty() { return 0.0; }
    
    let len = normalized.chars().filter(|c| !c.is_whitespace()).count() as f64;
    if len == 0.0 { return 0.0; }
    
    let entropy = counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    });
    
    // Normalize entropy for length to reduce false positives from long paths
    // Base entropy on character diversity, not string length
    // Typical paths have lower diversity than obfuscated strings
    //
    // For reference:
    // - Normal paths: entropy ~2.5-3.5 (limited character set: a-z, 0-9, /)
    // - Obfuscated: entropy ~4.5-5.5 (high character diversity, random-looking)
    // - Base64: entropy ~5.5-6.0 (high entropy by design)
    //
    // We want to catch obfuscated/encoded strings, not legitimate long paths
    entropy
}

/// Check if a path matches a glob-style pattern with wildcards (* and ?)
/// Examples:
///   - "/opt/conda/*" matches "/opt/conda/bin/python"
///   - "/usr/*/bin" matches "/usr/local/bin"
///   - "/home/user/*.py" matches "/home/user/script.py"
pub fn matches_wildcard(path: &str, pattern: &str) -> bool {
    // Convert glob pattern to regex
    // Escape regex special chars except * and ?
    let mut regex_pattern = String::new();
    regex_pattern.push('^');
    
    for ch in pattern.chars() {
        match ch {
            '*' => regex_pattern.push_str(".*"),      // * matches anything
            '?' => regex_pattern.push('.'),            // ? matches one char
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex_pattern.push('\\');
                regex_pattern.push(ch);
            }
            _ => regex_pattern.push(ch),
        }
    }
    
    regex_pattern.push('$');
    
    Regex::new(&regex_pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

/// Check if path matches any whitelisted pattern
pub fn is_path_whitelisted(path: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|pattern| matches_wildcard(path, pattern))
}

pub fn is_path_suspicious(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        Regex::new(pattern)
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    })
}

/// Parse a command line into (name, path, args)
/// 
/// Handles commands with or without full paths:
/// - "/usr/bin/nginx -c /etc/nginx.conf" → name="nginx", path="/usr/bin/nginx"
/// - "ls /etc/" → name="ls", path="ls" (bare command, no path)
/// - "nginx" → name="nginx", path="nginx"
/// 
/// # Examples
/// 
/// ```
/// use ironsift::parse_command_line;
/// 
/// // Full path
/// let (name, path, args) = parse_command_line("/usr/bin/nginx -c /etc/nginx.conf");
/// assert_eq!(name, "nginx");
/// assert_eq!(path, "/usr/bin/nginx");
/// assert_eq!(args, "-c /etc/nginx.conf");
/// 
/// // Bare command (common in ps output, shell commands)
/// let (name, path, args) = parse_command_line("ls /etc/");
/// assert_eq!(name, "ls");
/// assert_eq!(path, "ls");
/// assert_eq!(args, "/etc/");
/// 
/// // Just command name
/// let (name, path, args) = parse_command_line("nginx");
/// assert_eq!(name, "nginx");
/// assert_eq!(path, "nginx");
/// assert_eq!(args, "");
/// ```
pub fn parse_command_line(command: &str) -> (String, String, String) {
    let command = command.trim();
    
    if command.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    
    // SPECIAL CASE: Linux kernel threads with bracket notation
    // Examples: "[kworker/1:0]", "[migration/0]", "[ksoftirqd/1]"
    // These have no arguments and should be treated specially
    if command.starts_with('[') && command.ends_with(']') {
        // It's a kernel thread - use the full bracketed name
        return (command.to_string(), command.to_string(), String::new());
    }
    
    // Split on whitespace, respecting quotes
    let parts = parse_command_parts(command);
    
    if parts.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    
    let path = parts[0].clone();
    let args = if parts.len() > 1 {
        parts[1..].join(" ")
    } else {
        String::new()
    };
    
    // Extract name from path
    // For paths like "/usr/bin/nginx", extract "nginx"
    // For paths like "/home/ecbuilds/some/long/path/executable", extract "executable"
    // For bare commands like "ls", use "ls" as both name and path
    let name = if let Some(pos) = path.rfind('/') {
        path[pos + 1..].to_string()
    } else {
        // No path separator - it's a bare command like "ls" or "nginx"
        // Check if it's a kernel thread notation
        if path.starts_with('[') && path.ends_with(']') {
            path.clone()
        } else {
            path.clone()
        }
    };
    
    (name, path, args)
}

/// Parse command line respecting quotes
fn parse_command_parts(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = command.chars().peekable();
    
    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => {
                in_quotes = !in_quotes;
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    
    if !current.is_empty() {
        parts.push(current);
    }
    
    parts
}

// --- JSON PARSING ---

/// Parse process information from JSON string
/// 
/// # JSON Key Matching (Priority Order - First Match Wins)
/// 
/// ## ✅ REQUIRED KEYS (at least ONE from each group)
/// 
/// ### Group 1: Machine Identifier (REQUIRED)
/// Priority order:
/// 1. `machine_id` ⭐ (recommended)
/// 2. `hostname`
/// 3. `host`
/// 4. `server`
/// 5. `node`
/// 6. `container` (Docker)
/// 7. `pod` (Kubernetes)
/// 
/// ### Group 2: Process Information (REQUIRED - use EITHER Option A or B)
/// 
/// **Option A: Full Command Line** (priority order):
/// 1. `command` ⭐ (recommended)
/// 2. `cmd`
/// 3. `cmdline`
/// 4. `commandline`
/// 
/// **Option B: Process Name** (priority order):
/// 1. `name` ⭐ (recommended)
/// 2. `process`
/// 3. `process_name`
/// 4. `comm`
/// 
/// ## 🔧 OPTIONAL KEYS (with defaults)
/// 
/// - **Process IDs** (default: 0, auto-generated)
///   - `pid`, `process_id`
///   - `ppid`, `parent_pid`
/// 
/// - **User ID** (default: 1000)
///   - `uid`, `user_id`, `userid`
/// 
/// - **Executable Path** (default: parsed from command or name)
///   - `path`, `exe`, `executable`
/// 
/// - **Arguments** (default: parsed from command or empty string)
///   - `args`, `arguments`, `params`
/// 
/// - **Timestamp** (default: None)
///   - `timestamp`, `time`, `datetime`
/// 
/// # Examples
/// 
/// ```
/// use ironsift::parse_json_log;
/// 
/// // Minimal (2 required keys)
/// let json = r#"{"host": "server1", "cmd": "nginx"}"#;
/// let entry = parse_json_log(json).unwrap();
/// 
/// // Docker-style JSON
/// let json = r#"{"container": "web-prod-1", "command": "/usr/bin/nginx", "uid": 33}"#;
/// let entry = parse_json_log(json).unwrap();
/// 
/// // Kubernetes-style JSON
/// let json = r#"{"node": "worker-1", "pod": "nginx-7d8b", "cmd": "nginx", "userid": 0}"#;
/// let entry = parse_json_log(json).unwrap();
/// 
/// // CloudWatch-style JSON
/// let json = r#"{"hostname": "ec2-10-0-1-50", "commandline": "/usr/sbin/sshd -D", "user_id": "0"}"#;
/// let entry = parse_json_log(json).unwrap();
/// 
/// // Full detail JSON
/// let json = r#"{
///     "machine_id": "server1",
///     "pid": 100,
///     "ppid": 1,
///     "name": "nginx",
///     "path": "/usr/sbin/nginx",
///     "args": "-c /etc/nginx.conf",
///     "uid": 33,
///     "timestamp": "2024-01-06T10:00:00Z"
/// }"#;
/// let entry = parse_json_log(json).unwrap();
/// ```
pub fn parse_json_log(json: &str) -> Result<RawLogEntry, Box<dyn Error>> {
    let data: serde_json::Value = serde_json::from_str(json)?;
    
    // ═══════════════════════════════════════════════════════════════════════════
    // REQUIRED GROUP 1: Machine Identifier
    // ═══════════════════════════════════════════════════════════════════════════
    // Tries multiple key names in priority order (first match wins):
    // - machine_id (⭐ standard/recommended)
    // - hostname (system logs)
    // - host (Docker, generic logging)
    // - server (monitoring systems)
    // - node (Kubernetes cluster nodes)
    // - container (Docker containers)
    // - pod (Kubernetes pods)
    let machine_id = extract_string_field(&data, &[
        "machine_id", "hostname", "host", "server", "node", "container", "pod"
    ])
    .ok_or("Missing machine identifier (need: machine_id, hostname, host, server, node, container, or pod)")?;
    
    // ═══════════════════════════════════════════════════════════════════════════
    // OPTIONAL: Process IDs (auto-generated if not provided)
    // ═══════════════════════════════════════════════════════════════════════════
    // pid: Process ID - defaults to 0 (will be auto-generated sequentially per machine)
    // ppid: Parent Process ID - defaults to 0 (typically init/systemd)
    let pid = extract_u32_field(&data, &["pid", "process_id"]).unwrap_or(0);
    let ppid = extract_u32_field(&data, &["ppid", "parent_pid"]).unwrap_or(0);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // OPTIONAL: Direct process attributes (if available)
    // ═══════════════════════════════════════════════════════════════════════════
    let name_opt = extract_string_field(&data, &["name", "process", "process_name", "comm"]);
    let path_opt = extract_string_field(&data, &["path", "exe", "executable"]);
    let args_opt = extract_string_field(&data, &["args", "arguments", "params"]);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // REQUIRED GROUP 2: Process Information
    // ═══════════════════════════════════════════════════════════════════════════
    // Strategy (in order):
    // 1. If name + path + args all provided → use them directly
    // 2. Else if command field exists → parse it into (name, path, args)
    // 3. Else if name field exists → use name (no args)
    // 4. Else → ERROR (missing required process info)
    let (name, path, args) = if let (Some(n), Some(p), Some(a)) = (name_opt, path_opt, args_opt) {
        // All three fields provided directly - use as-is
        (n, p, a)
    } else {
        // Try to parse from command field (most common in modern logs)
        // Keys tried: command (⭐), cmd, cmdline, commandline
        if let Some(command) = extract_string_field(&data, &["command", "cmd", "cmdline", "commandline"]) {
            // Parse full command line into (name, path, args)
            // Example: "/usr/bin/nginx -c /etc/nginx.conf" → ("nginx", "/usr/bin/nginx", "-c /etc/nginx.conf")
            parse_command_line(&command)
        } else if let Some(n) = extract_string_field(&data, &["name", "process", "process_name", "comm"]) {
            // Only name available, no command - use name as both name and path, empty args
            (n.clone(), n, String::new())
        } else {
            // No process information found - this is an error
            return Err("Missing process information (need: 'command', 'cmd', 'cmdline', 'commandline', OR 'name', 'process', 'process_name', 'comm')".into());
        }
    };
    
    // ═══════════════════════════════════════════════════════════════════════════
    // OPTIONAL: User ID (defaults to 1000 = typical non-root user)
    // ═══════════════════════════════════════════════════════════════════════════
    // uid: User ID running the process
    // Keys tried: uid (⭐ Unix standard), user_id, userid
    // Default: 1000 (typical first non-root user on Linux)
    let uid = extract_u32_field(&data, &["uid", "user_id", "userid"]).unwrap_or(1000);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // OPTIONAL: Timestamp (for temporal/time-series analysis)
    // ═══════════════════════════════════════════════════════════════════════════
    // Keys tried: timestamp (⭐ ISO 8601), time, datetime
    // Format: ISO 8601 recommended (e.g., "2024-01-06T10:00:00Z")
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

/// Parse a batch of JSON log entries
/// 
/// Supports newline-delimited JSON (NDJSON) or JSON array.
/// 
/// # Examples
/// 
/// ```
/// use ironsift::parse_json_logs;
/// 
/// // Newline-delimited JSON
/// let ndjson = r#"
/// {"host": "server1", "command": "/usr/bin/nginx -c /etc/nginx.conf"}
/// {"host": "server2", "command": "python3 app.py"}
/// "#;
/// let entries = parse_json_logs(ndjson).unwrap();
/// 
/// // JSON array
/// let json_array = r#"[
///     {"host": "server1", "command": "/usr/bin/nginx"},
///     {"host": "server2", "command": "python3 app.py"}
/// ]"#;
/// let entries = parse_json_logs(json_array).unwrap();
/// ```
pub fn parse_json_logs(json: &str) -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    let json = json.trim();
    
    if json.is_empty() {
        return Ok(Vec::new());
    }
    
    // Try to parse as JSON array first
    if json.starts_with('[') {
        let array: Vec<serde_json::Value> = serde_json::from_str(json)?;
        let mut entries = Vec::new();
        for value in array {
            let json_str = serde_json::to_string(&value)?;
            match parse_json_log(&json_str) {
                Ok(entry) => entries.push(entry),
                Err(e) => eprintln!("Warning: Failed to parse JSON entry: {}", e),
            }
        }
        return Ok(entries);
    }
    
    // Otherwise, treat as newline-delimited JSON
    let mut entries = Vec::new();
    for line in json.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        match parse_json_log(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => eprintln!("Warning: Failed to parse JSON line: {}", e),
        }
    }
    
    Ok(entries)
}

// Helper functions for JSON extraction
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

// --- PARENT PROCESS RESOLUTION ---

/// Builder for collecting processes without PIDs, then auto-resolving relationships
pub struct ProcessBuilder {
    entries: Vec<ProcessEntry>,
}

impl ProcessBuilder {
    pub fn new() -> Self {
        println!("\n📦 Initializing ProcessBuilder");
        Self {
            entries: Vec::new(),
        }
    }
    
    /// Add a process entry without needing PIDs
    pub fn add(&mut self, entry: ProcessEntry) -> &mut Self {
        println!("\n➕ Adding ProcessEntry: machine={}, name={}, ppid={:?}", 
            entry.machine_id, entry.name, entry.ppid);
        self.entries.push(entry);
        self
    }
    
    /// Add a simple process with just name and parent
    pub fn add_process(&mut self, machine_id: &str, name: &str, parent: &str) -> &mut Self {
        println!("\n➕ Adding simple process: machine={}, name={}, parent={}", machine_id, name, parent);
        self.entries.push(ProcessEntry {
            machine_id: machine_id.to_string(),
            name: name.to_string(),
            parent_name: Some(parent.to_string()),
            ppid: None,  // ⭐ Initialize ppid as None
            uid: 1000,
            path: format!("/usr/bin/{}", name),
            args: String::new(),
            timestamp: None,
        });
        self
    }
    
    /// Add a process from a full command line string
    /// 
    /// Automatically extracts name, path, and args from the command.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessBuilder;
    /// 
    /// let mut builder = ProcessBuilder::new();
    /// 
    /// // Parse full command lines
    /// builder.add_command("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"));
    /// builder.add_command("server1", "/tmp/suspicious --obfuscated XkzL1", Some("bash"));
    /// 
    /// // Works with just executable name
    /// builder.add_command("server2", "postgres", Some("systemd"));
    /// ```
    pub fn add_command(&mut self, machine_id: &str, command: &str, parent: Option<&str>) -> &mut Self {
        let entry = ProcessEntry::from_command_line(machine_id.to_string(), command, parent);
        self.entries.push(entry);
        self
    }
    
    /// Add a process with UID from command line
    pub fn add_command_with_uid(&mut self, machine_id: &str, command: &str, parent: Option<&str>, uid: u32) -> &mut Self {
        let mut entry = ProcessEntry::from_command_line(machine_id.to_string(), command, parent);
        entry.uid = uid;
        self.entries.push(entry);
        self
    }
    
    /// Add a process from a JSON string
    /// 
    /// Automatically extracts all available fields from JSON.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessBuilder;
    /// 
    /// let mut builder = ProcessBuilder::new();
    /// 
    /// // Docker-style JSON
    /// builder.add_json(r#"{"host": "server1", "command": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33}"#);
    /// 
    /// // Kubernetes-style JSON  
    /// builder.add_json(r#"{"node": "worker-1", "cmd": "python3 app.py", "userid": 1000}"#);
    /// ```
    pub fn add_json(&mut self, json: &str) -> &mut Self {
        match crate::parse_json_log(json) {
            Ok(raw_entry) => {
                println!("\n➕ Processing JSON entry for machine: {}", raw_entry.machine_id);
                if raw_entry.ppid > 0 {
                    println!("  ├─ ⭐ PPID found in JSON: {}", raw_entry.ppid);
                }
                
                let (name, path, args) = if raw_entry.name.is_empty() {
                    // Parse from command if name is empty
                    let cmd = format!("{} {}", raw_entry.path, raw_entry.args).trim().to_string();
                    crate::parse_command_line(&cmd)
                } else {
                    (raw_entry.name, raw_entry.path, raw_entry.args)
                };
                
                let entry = ProcessEntry {
                    machine_id: raw_entry.machine_id,
                    name,
                    parent_name: None, // Will be resolved from PPID later
                    ppid: if raw_entry.ppid > 0 { Some(raw_entry.ppid) } else { None },  // ⭐ PRESERVE PPID!
                    uid: raw_entry.uid,
                    path,
                    args,
                    timestamp: raw_entry.timestamp,
                };
                
                println!("  └─ Created ProcessEntry: name={}, ppid={:?}", entry.name, entry.ppid);
                
                self.entries.push(entry);
            }
            Err(e) => {
                eprintln!("⚠️  Warning: Failed to parse JSON: {}", e);
            }
        }
        self
    }
    
    /// Add multiple processes from a JSON string (array or newline-delimited)
    /// 
    /// # Examples
    /// 
    /// ```
    /// use ironsift::ProcessBuilder;
    /// 
    /// let mut builder = ProcessBuilder::new();
    /// 
    /// // JSON array
    /// builder.add_json_batch(r#"[
    ///     {"host": "server1", "command": "/usr/bin/nginx"},
    ///     {"host": "server2", "command": "python3 app.py"}
    /// ]"#);
    /// 
    /// // Newline-delimited JSON
    /// builder.add_json_batch(r#"
    /// {"host": "server1", "command": "/usr/bin/nginx"}
    /// {"host": "server2", "command": "python3 app.py"}
    /// "#);
    /// ```
    pub fn add_json_batch(&mut self, json: &str) -> &mut Self {
        match crate::parse_json_logs(json) {
            Ok(entries) => {
                for raw_entry in entries {
                    let (name, path, args) = if raw_entry.name.is_empty() {
                        let cmd = format!("{} {}", raw_entry.path, raw_entry.args).trim().to_string();
                        crate::parse_command_line(&cmd)
                    } else {
                        (raw_entry.name, raw_entry.path, raw_entry.args)
                    };
                    
                    let entry = ProcessEntry {
                        machine_id: raw_entry.machine_id,
                        name,
                        parent_name: None,
                        ppid: if raw_entry.ppid > 0 { Some(raw_entry.ppid) } else { None },  // ⭐ PRESERVE PPID!
                        uid: raw_entry.uid,
                        path,
                        args,
                        timestamp: raw_entry.timestamp,
                    };
                    
                    self.entries.push(entry);
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse JSON batch: {}", e);
            }
        }
        self
    }
    
    /// Get the number of collected process entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    
    /// Convert collected entries into RawLogEntry with auto-generated PIDs
    pub fn build(self) -> Vec<RawLogEntry> {
        let mut raw_entries = Vec::new();
        
        // Group by machine to assign PIDs per machine
        let mut machine_groups: HashMap<String, Vec<ProcessEntry>> = HashMap::new();
        for entry in self.entries {
            machine_groups.entry(entry.machine_id.clone())
                .or_insert_with(Vec::new)
                .push(entry);
        }
        
        for (machine_id, entries) in machine_groups {
            // Build name -> PID mapping for this machine
            let mut name_to_pid: HashMap<String, u32> = HashMap::new();
            let mut next_pid = 1u32;
            
            // First pass: assign PIDs to all unique process names
            for entry in &entries {
                if !name_to_pid.contains_key(&entry.name) {
                    name_to_pid.insert(entry.name.clone(), next_pid);
                    next_pid += 1;
                }
            }
            
            // Second pass: create RawLogEntry with resolved PIDs and PPIDs
            for entry in entries {
                let pid = *name_to_pid.get(&entry.name).unwrap();
                
                // ⭐ Use PPID from ProcessEntry if provided, otherwise resolve from parent name
                let ppid = if let Some(provided_ppid) = entry.ppid {
                    // PPID was explicitly provided - preserve it!
                    provided_ppid
                } else if let Some(parent_name) = &entry.parent_name {
                    // Resolve PPID from parent name
                    *name_to_pid.get(parent_name).unwrap_or(&0)
                } else {
                    // If no parent specified, assume systemd (PID 1) or init
                    if entry.name == "systemd" || entry.name == "init" {
                        0
                    } else {
                        1 // Default to systemd as parent
                    }
                };
                
                raw_entries.push(RawLogEntry {
                    machine_id: machine_id.clone(),
                    pid,
                    ppid,
                    name: entry.name,
                    uid: entry.uid,
                    path: entry.path,
                    args: entry.args,
                    timestamp: entry.timestamp,
                });
            }
        }
        
        println!("\n✅ ProcessBuilder built: {} total entries", raw_entries.len());
        
        raw_entries
    }
}

impl Default for ProcessBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve parent process names from PIDs
pub fn resolve_parent_names(entries: &[RawLogEntry]) -> HashMap<(String, u32), String> {
    let mut pid_to_name: HashMap<(String, u32), String> = HashMap::new();
    
    // First pass: build PID -> name mapping
    for entry in entries {
        pid_to_name.insert(
            (entry.machine_id.clone(), entry.pid),
            entry.name.clone()
        );
    }
    
    pid_to_name
}

/// Build machine profiles from raw log entries with automatic parent resolution
pub fn build_profiles(entries: Vec<RawLogEntry>, config: &DetectionConfig) -> Vec<MachineProfile> {
    println!("\n🔨 Building profiles from {} raw entries", entries.len());
    
    // Debug: Show PPID resolution statistics if enabled
    if config.debug_display {
        println!("🔍 PPID Resolution Debug Info:");
        println!("   Total entries to process: {}", entries.len());
        
        // Show some sample entries with PPIDs
        println!("   Sample entries with PPIDs:");
        for entry in entries.iter().take(5) {
            println!("     {}:{} (PPID: {})", entry.machine_id, entry.name, entry.ppid);
        }
    }
    
    // Resolve parent names
    let pid_to_name = resolve_parent_names(&entries);
    
    if config.debug_display {
        println!("   Resolved {} PID-to-name mappings", pid_to_name.len());
        println!("   Sample mappings:");
        for ((machine, pid), name) in pid_to_name.iter().take(5) {
            println!("     {}:{} -> {}", machine, pid, name);
        }
        println!();
    }
    
    // Filter out kernel threads if configured
    let entries: Vec<RawLogEntry> = if config.exclude_kernel_threads {
        let before_count = entries.len();
        let filtered: Vec<_> = entries.into_iter()
            .filter(|e| !is_kernel_thread(&e.name))
            .collect();
        let after_count = filtered.len();
        
        if config.debug_display {
            println!("   Kernel thread filtering:");
            println!("     Before: {} entries", before_count);
            println!("     After: {} entries", after_count);
            println!("     Filtered out: {} kernel threads", before_count - after_count);
            println!();
        }
        
        filtered
    } else {
        entries
    };
    
    // Filter out init children if configured
    let entries: Vec<RawLogEntry> = if config.exclude_init_children {
        let before_count = entries.len();
        let filtered: Vec<_> = entries.into_iter()
            .filter(|e| e.ppid != 1)
            .collect();
        let after_count = filtered.len();
        
        if config.debug_display {
            println!("   Init children filtering:");
            println!("     Before: {} entries", before_count);
            println!("     After: {} entries", after_count);
            println!("     Filtered out: {} init children (PPID=1)", before_count - after_count);
            println!();
        }
        
        filtered
    } else {
        entries
    };
    
    // Filter out whitelisted paths if configured
    let entries: Vec<RawLogEntry> = if !config.whitelisted_path_patterns.is_empty() {
        let before_count = entries.len();
        let filtered: Vec<_> = entries.into_iter()
            .filter(|e| !is_path_whitelisted(&e.path, &config.whitelisted_path_patterns))
            .collect();
        let after_count = filtered.len();
        
        if config.debug_display {
            println!("   Whitelisted path filtering:");
            println!("     Before: {} entries", before_count);
            println!("     After: {} entries", after_count);
            println!("     Filtered out: {} whitelisted paths", before_count - after_count);
            println!();
        }
        
        filtered
    } else {
        entries
    };
    
    // Group by machine
    let mut machine_entries: HashMap<String, Vec<RawLogEntry>> = HashMap::new();
    for entry in entries {
        machine_entries.entry(entry.machine_id.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }
    
    if config.debug_display {
        println!("   Grouped into {} machines", machine_entries.len());
        println!();
    }
    
    // Build profiles in parallel
    let profiles: Vec<MachineProfile> = machine_entries.par_iter()
        .map(|(machine_id, logs)| {
            let mut profile = MachineProfile::new(machine_id);
            let mut process_counts: HashMap<String, u32> = HashMap::new(); // Track unique processes for logging
            
            for entry in logs {
                // Resolve parent name
                let parent_name = pid_to_name
                    .get(&(entry.machine_id.clone(), entry.ppid))
                    .cloned()
                    .unwrap_or_else(|| {
                        if config.debug_display && entry.ppid != 0 {
                            eprintln!("⚠️  Unresolved PPID for {}:{} (PPID: {})", 
                                entry.machine_id, entry.name, entry.ppid);
                        }
                        format!("[unknown:{}]", entry.ppid)
                    });
                
                // Calculate entropy and path risk
                let entropy = calculate_shannon_entropy(&entry.args);
                let is_high_entropy = entropy > config.entropy_threshold;
                
                // Check if path is suspicious (whitelisted paths are already filtered out above)
                let is_suspicious_path = is_path_suspicious(&entry.path, &config.suspicious_path_patterns);
                
                let timestamp = entry.timestamp.as_ref()
                    .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                    .map(|dt| dt.with_timezone(&Utc));
                
                let sig = ProcessSignature {
                    name: entry.name.clone(),
                    parent_name: parent_name.clone(),
           //         ppid: entry.ppid,  // ⭐ PRESERVE PPID!
                    uid: entry.uid,
                    path: entry.path.clone(),
                    is_high_entropy,
                    is_suspicious_path,
                };
                
                // Track if this is a new unique process signature
                let process_key = format!("{}:{}:{}:{}", sig.name, sig.path, sig.parent_name, sig.uid);
                let is_new_process = !process_counts.contains_key(&process_key);
                process_counts.entry(process_key).and_modify(|c| *c += 1).or_insert(1);
                
                // Log new process additions when debug is enabled
                if config.debug_display && is_new_process {
                    let risk_flags = vec![
                        if is_high_entropy { "HIGH_ENTROPY" } else { "" },
                        if is_suspicious_path { "SUSPICIOUS_PATH" } else { "" },
                        if entry.uid == 0 && !config.common_root_processes.iter().any(|p| entry.name.contains(p)) { "UNEXPECTED_ROOT" } else { "" },
                    ].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>();
                    
                    let risk_str = if risk_flags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", risk_flags.join(", "))
                    };
                    
                    println!("  ➕ New process in {}: {} (path: {}, parent: {}, uid: {}){}",
                        machine_id, entry.name, entry.path, parent_name, entry.uid, risk_str);
                }
                
                profile.add_process(sig, timestamp);
            }
            
            profile
        })
        .collect();
    
    println!("\n✅ Built {} machine profiles", profiles.len());
    if config.debug_display {
        println!("   Profiles ready for analysis");
    }
    
    profiles
}

/// Check if a process name indicates a Linux kernel thread
fn is_kernel_thread(name: &str) -> bool {
    name.starts_with('[') && name.ends_with(']')
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

    Ok(build_profiles(entries, config))
}

/// Load and parse JSON log data from a file
/// Supports JSON arrays, NDJSON (newline-delimited JSON), and single JSON objects
/// 
/// # Arguments
/// * `path` - Path to the JSON file
/// * `config` - Detection configuration
/// 
/// # Returns
/// Vector of machine profiles ready for analysis
/// 
/// # Examples
/// ```no_run
/// use ironsift::{load_json_data, DetectionConfig};
/// 
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = DetectionConfig::default();
/// let profiles = load_json_data("logs.json", &config)?;
/// println!("Loaded {} machine profiles", profiles.len());
/// # Ok(())
/// # }
/// ```
pub fn load_json_data(path: &str, config: &DetectionConfig) -> Result<Vec<MachineProfile>, Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("Input file not found: '{}'", path).into());
    }
    
    let metadata = fs::metadata(path)?;
    if metadata.len() == 0 {
        return Err(format!("Input file is empty: '{}'", path).into());
    }

    // Read the entire file content
    let content = fs::read_to_string(path)?;
    
    // Parse JSON logs (supports arrays, NDJSON, and single objects)
    let entries = parse_json_logs(&content)?;

    if entries.is_empty() {
        return Err(format!("No valid machine logs found in '{}'.", path).into());
    }

    println!("• Loaded {} process entries from JSON", entries.len());
    Ok(build_profiles(entries, config))
}

pub fn generate_mock_data(config: &DetectionConfig) -> Vec<MachineProfile> {
    let entries: Vec<RawLogEntry> = (0..50).flat_map(|i| {
        let machine_id = format!("machine_{:02}", i);
        let mut logs = Vec::new();
        
        // Normal traffic
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
        
        // Inject anomaly
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
        
        // Add systemd as parent
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
    }).collect();
    
    build_profiles(entries, config)
}

/// Convenient function to build profiles from simple name/parent pairs
/// This is useful when you don't have PID information upfront
pub fn build_profiles_simple(
    machine_processes: Vec<(String, String, String)>, // (machine_id, process_name, parent_name)
    config: &DetectionConfig
) -> Vec<MachineProfile> {
    let mut builder = ProcessBuilder::new();
    
    for (machine_id, name, parent) in machine_processes {
        builder.add_process(&machine_id, &name, &parent);
    }
    
    let raw_entries = builder.build();
    build_profiles(raw_entries, config)
}

#[cfg(test)]
mod tests;