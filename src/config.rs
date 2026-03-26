//! Detection configuration and defaults.

use std::error::Error;
use std::fs;
use std::fs::File;
use log;
use serde::{Deserialize, Serialize};

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
    pub exclude_kernel_threads: bool,

    /// Common system processes that legitimately run as root (UID 0)
    pub common_root_processes: Vec<String>,

    /// Penalize root processes that are NOT in common_root_processes list
    pub flag_unexpected_root: bool,

    /// Enable debug output for detailed process information
    pub debug_display: bool,

    /// Exclude processes that are direct children of init/systemd (PPID = 1)
    pub exclude_init_children: bool,

    /// Path whitelist patterns (glob-style wildcards: * and ?)
    pub whitelisted_path_patterns: Vec<String>,

    /// **File analysis only:** Rust regex patterns matched against the full file path; matching
    /// events are dropped before profiling (no effect on process analysis).
    #[serde(default)]
    pub file_excluded_path_regexes: Vec<String>,

    /// **File analysis only:** Rust regex patterns matched against the basename (last `/` segment);
    /// matching events are dropped before profiling.
    #[serde(default)]
    pub file_excluded_filename_regexes: Vec<String>,

    /// When true, suppress progress and verbose output (for use by scripts/pipelines)
    #[serde(default)]
    pub quiet: bool,
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
                r"/home/[^/]+/\.[^/]+".to_string(),
                r"^\./".to_string(),
                // Hidden files in system paths (e.g. /bin/.rootme, /usr/sbin/.hidden)
                r"/(?:bin|sbin|usr/bin|usr/sbin)/\.[^/]+".to_string(),
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
                "unattended-upgr".to_string(),
                "accounts-daemon".to_string(),
                "rtkit-daemon".to_string(),
                "cups-browsed".to_string(),
                "cupsd".to_string(),
                "avahi-daemon".to_string(),
            ],
            flag_unexpected_root: true,
            debug_display: false,
            exclude_init_children: false,
            whitelisted_path_patterns: vec![],
            file_excluded_path_regexes: vec![],
            file_excluded_filename_regexes: vec![],
            quiet: false,
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

    /// Print comprehensive configuration display (no-op when quiet)
    pub fn print(&self) {
        if self.quiet {
            return;
        }
        log::info!(
            "Configuration: entropy_threshold={:.2}, dbscan_tolerance={:.3}, min_samples={}, minority_ratio={:.1}%, normalize={}",
            self.entropy_threshold,
            self.dbscan_tolerance,
            self.dbscan_min_samples,
            self.minority_cluster_ratio * 100.0,
            self.normalize_features
        );
        log::info!(
            "Filtering: exclude_kernel_threads={}, exclude_init_children={}, flag_unexpected_root={}, debug_display={}",
            self.exclude_kernel_threads,
            self.exclude_init_children,
            self.flag_unexpected_root,
            self.debug_display
        );
        if !self.suspicious_path_patterns.is_empty() {
            log::info!("Suspicious path patterns: {} configured", self.suspicious_path_patterns.len());
        }
        if !self.whitelisted_path_patterns.is_empty() {
            log::info!("Whitelisted path patterns: {} configured", self.whitelisted_path_patterns.len());
        }
        if !self.file_excluded_path_regexes.is_empty() {
            log::info!(
                "File analysis: {} excluded-path regex(es)",
                self.file_excluded_path_regexes.len()
            );
        }
        if !self.file_excluded_filename_regexes.is_empty() {
            log::info!(
                "File analysis: {} excluded-filename regex(es)",
                self.file_excluded_filename_regexes.len()
            );
        }
        if !self.common_root_processes.is_empty() {
            log::info!("Common root processes: {} listed", self.common_root_processes.len());
        }
    }
}
