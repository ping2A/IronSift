//! Detection configuration and defaults.

use std::error::Error;
use std::fs;
use std::fs::File;
use log;
use serde::{Deserialize, Serialize};

/// **File analysis:** tunables for “mtime close to access” (`FileSignature.recently_modified`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileRecentMtimeConfig {
    /// Treat `mtime` up to this many minutes **after** access as clock skew (still eligible).
    pub clock_skew_minutes: i64,
    /// Max hours between `mtime` and access for credential/boot–heavy paths (shadow, sudoers, …).
    pub max_hours_critical_paths: u32,
    /// Max hours for system dirs (`/etc`, `/usr/bin`, …) when access is elevated or risky.
    pub max_hours_system_elevated: u32,
    /// Max hours for paths that match suspicious patterns only (non-system).
    pub max_hours_suspicious_only: u32,
    /// Path prefixes where recent-mtime is never flagged (logs, caches, ephemeral dirs).
    pub volatile_path_prefixes: Vec<String>,
}

impl Default for FileRecentMtimeConfig {
    fn default() -> Self {
        Self {
            clock_skew_minutes: 5,
            max_hours_critical_paths: 12,
            max_hours_system_elevated: 6,
            max_hours_suspicious_only: 3,
            volatile_path_prefixes: vec![
                "/var/log/".to_string(),
                "/var/cache/".to_string(),
                "/var/lib/dpkg/".to_string(),
                "/var/lib/apt/".to_string(),
                "/var/tmp/".to_string(),
                "/tmp/".to_string(),
                "/run/".to_string(),
                "/proc/".to_string(),
                "/sys/".to_string(),
                "/dev/".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    // NOTE: persisted in `.ironsift-platform/db.json` as part of the platform `run_config`.
    // This must be backwards-compatible: older/partial objects must still deserialize.
    // `#[serde(default)]` for scalars/Vecs uses type default (0.0, empty) — wrong for us — so fields
    // that must match `DetectionConfig::default()` use `default = "def_..."` helpers.

    /// Shannon entropy threshold for detecting obfuscated commands
    #[serde(default = "def_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Ratio below which a cluster is considered a minority (e.g., 0.10 = 10%)
    #[serde(default = "def_minority_cluster_ratio")]
    pub minority_cluster_ratio: f64,

    /// DBSCAN tolerance (epsilon) - lower is stricter
    #[serde(default = "def_dbscan_tolerance")]
    pub dbscan_tolerance: f64,

    /// Minimum samples for DBSCAN core point
    #[serde(default = "def_dbscan_min_samples")]
    pub dbscan_min_samples: usize,

    /// Enable L2 normalization of feature vectors
    #[serde(default = "def_normalize_features")]
    pub normalize_features: bool,

    /// Suspicious path patterns (regex)
    #[serde(default = "def_suspicious_path_patterns")]
    pub suspicious_path_patterns: Vec<String>,

    /// Exclude Linux kernel threads (names starting with '[' and ending with ']')
    #[serde(default = "def_exclude_kernel_threads")]
    pub exclude_kernel_threads: bool,

    /// Common system processes that legitimately run as root (UID 0)
    #[serde(default = "def_common_root_processes")]
    pub common_root_processes: Vec<String>,

    /// Penalize root processes that are NOT in common_root_processes list
    #[serde(default = "def_flag_unexpected_root")]
    pub flag_unexpected_root: bool,

    /// Enable debug output for detailed process information
    #[serde(default = "def_debug_display")]
    pub debug_display: bool,

    /// Exclude processes that are direct children of init/systemd (PPID = 1)
    #[serde(default = "def_exclude_init_children")]
    pub exclude_init_children: bool,

    /// Path whitelist patterns (glob-style wildcards: * and ?)
    #[serde(default = "def_whitelisted_path_patterns")]
    pub whitelisted_path_patterns: Vec<String>,

    /// **File analysis only:** Rust regex patterns matched against the full file path. Matching
    /// rows are **never** merged into `MachineFileProfile` (counts, mtimes, TF-IDF, etc.); use
    /// patterns such as `^/proc/` or `^/var/cache/` to drop whole directory trees.
    #[serde(default)]
    pub file_excluded_path_regexes: Vec<String>,

    /// **File analysis only:** Rust regex patterns matched against the basename (last `/` segment
    /// only). Matching rows are **never** merged into file profiles.
    #[serde(default)]
    pub file_excluded_filename_regexes: Vec<String>,

    /// When true, suppress progress and verbose output (for use by scripts/pipelines)
    #[serde(default)]
    pub quiet: bool,

    /// **File analysis:** recent modification vs access-time heuristic (`recently_modified` flag).
    #[serde(default)]
    pub file_recent_mtime: FileRecentMtimeConfig,

    /// When **false** (default), `size` is ignored for fleet **equivalence** (rare-file counting and
    /// TF‑IDF / DBSCAN feature keys). Reduces false splits from log noise.
    #[serde(default)]
    pub file_rare_signature_includes_size: bool,

    /// When **false** (default), `permissions`, `owner`, `group`, and writable flags are ignored for
    /// fleet equivalence (same as [`Self::file_rare_signature_includes_size`] scope).
    #[serde(default)]
    pub file_rare_signature_includes_metadata: bool,

    /// When **false** (default), `recently_modified` is cleared for fleet equivalence so different
    /// access timestamps across hosts do not split the same path+uid into separate features.
    #[serde(default)]
    pub file_rare_signature_includes_recent_mtime: bool,
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
            file_recent_mtime: FileRecentMtimeConfig::default(),
            file_rare_signature_includes_size: false,
            file_rare_signature_includes_metadata: false,
            file_rare_signature_includes_recent_mtime: false,
        }
    }
}

// Serde per-field defaults for partial persisted configs.
// These must match `DetectionConfig::default()` to avoid surprise behavior.
fn def_entropy_threshold() -> f64 {
    DetectionConfig::default().entropy_threshold
}

fn def_minority_cluster_ratio() -> f64 {
    DetectionConfig::default().minority_cluster_ratio
}

fn def_dbscan_tolerance() -> f64 {
    DetectionConfig::default().dbscan_tolerance
}

fn def_dbscan_min_samples() -> usize {
    DetectionConfig::default().dbscan_min_samples
}

fn def_normalize_features() -> bool {
    DetectionConfig::default().normalize_features
}

fn def_suspicious_path_patterns() -> Vec<String> {
    DetectionConfig::default().suspicious_path_patterns
}

fn def_exclude_kernel_threads() -> bool {
    DetectionConfig::default().exclude_kernel_threads
}

fn def_common_root_processes() -> Vec<String> {
    DetectionConfig::default().common_root_processes
}

fn def_flag_unexpected_root() -> bool {
    DetectionConfig::default().flag_unexpected_root
}

fn def_debug_display() -> bool {
    DetectionConfig::default().debug_display
}

fn def_exclude_init_children() -> bool {
    DetectionConfig::default().exclude_init_children
}

fn def_whitelisted_path_patterns() -> Vec<String> {
    DetectionConfig::default().whitelisted_path_patterns
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
        log::info!(
            "File recent-mtime: skew={}m, max_h (critical/system/suspicious)={}/{}/{}, volatile_prefixes={}",
            self.file_recent_mtime.clock_skew_minutes,
            self.file_recent_mtime.max_hours_critical_paths,
            self.file_recent_mtime.max_hours_system_elevated,
            self.file_recent_mtime.max_hours_suspicious_only,
            self.file_recent_mtime.volatile_path_prefixes.len()
        );
        log::info!(
            "File fleet signature equivalence includes: size={}, metadata={}, recent_mtime={}",
            self.file_rare_signature_includes_size,
            self.file_rare_signature_includes_metadata,
            self.file_rare_signature_includes_recent_mtime
        );
    }
}
