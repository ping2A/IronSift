//! IronSift: fleet-wide anomaly detection for process and file access logs.

mod config;
mod utils;
mod types;
mod report;
mod json_parse;
mod builder;
mod analysis;
mod file_analysis;
mod temporal;
mod loaders;

// Re-export public API
pub use config::DetectionConfig;
pub use types::{
    FileSignature, MachineFileProfile, MachineProfile, ProcessEntry, ProcessSignature,
    RawConnectionEntry, RawFileEntry, RawLogEntry,
};
pub use report::{
    AnalysisReport, AnalysisType, AnomalyDetails, AnomalyLevel,
};
pub use utils::{
    calculate_shannon_entropy, is_path_suspicious, is_path_whitelisted, matches_wildcard,
    parse_command_line,
};
pub use json_parse::{parse_files_json_logs, parse_json_log, parse_json_logs};
pub use builder::{build_profiles, resolve_parent_names, ProcessBuilder};
pub use analysis::{analyze_fleet, analyze_fleet2};
pub use file_analysis::{analyze_files_fleet, build_file_profiles};
pub use temporal::{
    build_machine_snapshot, compare_temporal, compare_temporal_series,
    MachineSnapshot, TemporalDiff,
};
pub use loaders::{
    build_profiles_simple, generate_mock_data, load_csv_data, load_files_csv_data,
    load_files_json_data, load_json_data,
};

#[cfg(test)]
mod tests;
