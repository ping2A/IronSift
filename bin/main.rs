use std::error::Error;
use std::path::Path;
use std::env;
use std::fs;

use env_logger::Env;
use log;

use ironsift::{
    load_csv_data, load_json_data, load_jsonl_data, generate_mock_data, analyze_fleet,
    load_files_csv_data, load_files_json_data, analyze_files_fleet,
    DetectionConfig
};

const DEFAULT_INPUT_CSV: &str = "test_dataset.csv";
const DEFAULT_INPUT_JSON: &str = "test_dataset.json";
const DEFAULT_INPUT_FILES_CSV: &str = "test_files_dataset.csv";
const DEFAULT_INPUT_FILES_JSON: &str = "test_files_dataset.json";
const CONFIG_FILE: &str = "ironsift_config.json";
const REPORT_OUTPUT: &str = "forensic_report.json";

fn print_usage() {
    println!("Usage: ironsift [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --input <file>        Input file (can be repeated); each JSONL file = one machine");
    println!("  --files               Analyze file access logs (instead of process logs)");
    println!("  --config <file>       Load configuration from JSON file");
    println!("  --export-json [path]  Export forensic report as JSON (default: forensic_report.json)");
    println!("                        Use '-' to write JSON to stdout (script-friendly)");
    println!("  -q, --quiet           Minimal output: one-line summary only (for pipelines)");
    println!("  --tolerance <value>   Override DBSCAN tolerance (default: 0.05)");
    println!("  --help                Show this help message");
    println!();
    println!("Supported Input Formats:");
    println!("  • CSV files (.csv)    - Process logs (RawLogEntry) or file logs (RawFileEntry)");
    println!("  • JSON files (.json)  - JSON array, NDJSON, or single object");
    println!("  • JSONL files (.jsonl) - One JSON object per line (timestamp, user, command, pid, ppid)");
    println!();
    println!("Examples:");
    println!("  ironsift                           # Run with defaults (auto-detect input)");
    println!("  ironsift --input logs.json         # Process JSON log file");
    println!("  ironsift --input events.jsonl      # Process JSONL (one machine = one file)");
    println!("  ironsift --input a.jsonl --input b.jsonl  # Multiple JSONL = multiple machines");
    println!("  ironsift --files --input files.csv # Analyze file access logs");
    println!("  ironsift -q                        # Quiet: one-line summary only (script-friendly)");
    println!("  ironsift --export-json -           # Write JSON report to stdout (for piping)");
    println!("  ironsift --export-json report.json # Write JSON report to file");
    println!("  ironsift --tolerance 0.08          # Run with custom tolerance");
    println!("  ironsift --config custom.json      # Run with custom config");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Set log level to ERROR when quiet so progress is suppressed (must be before init)
    let quiet = args.iter().any(|a| a == "-q" || a == "--quiet")
        || args.windows(2).any(|w| {
            let a0 = w.get(0).and_then(|s| Some(s.as_str()));
            let a1 = w.get(1).and_then(|s| Some(s.as_str()));
            a0 == Some("--export-json") && a1 == Some("-")
        });
    if quiet {
        env::set_var("RUST_LOG", "error");
    }
    env_logger::Builder::from_env(Env::default().filter_or("RUST_LOG", if quiet { "error" } else { "info" }))
        .format_timestamp_secs()
        .format_target(false)
        .try_init()
        .ok();
    
    // Parse arguments
    let mut export_json_path: Option<String> = None; // None = don't export, Some(path) = export to path
    let mut analyze_files = false;
    let mut config = DetectionConfig::default();
    let mut config_path: Option<String> = None;
    let mut input_files: Vec<String> = Vec::new();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" => {
                print_usage();
                return Ok(());
            }
            "-q" | "--quiet" => {
                config.quiet = true;
            }
            "--export-json" => {
                i += 1;
                if i < args.len() && (args[i] == "-" || !args[i].starts_with('-')) {
                    export_json_path = Some(args[i].clone());
                } else {
                    if i < args.len() {
                        i -= 1;
                    }
                    export_json_path = Some(REPORT_OUTPUT.to_string());
                }
            }
            "--files" => {
                analyze_files = true;
            }
            "--input" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--input requires a file path");
                    return Err("Missing input file path".into());
                }
                input_files.push(args[i].clone());
            }
            "--tolerance" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--tolerance requires a value");
                    return Err("Missing tolerance value".into());
                }
                config.dbscan_tolerance = args[i].parse()
                    .map_err(|_| "Invalid tolerance value")?;
            }
            "--config" => {
                i += 1;
                if i >= args.len() {
                    log::error!("--config requires a file path");
                    return Err("Missing config file path".into());
                }
                config_path = Some(args[i].clone());
            }
            other => {
                log::error!("Unknown option: {}", other);
                print_usage();
                return Err("Invalid argument".into());
            }
        }
        i += 1;
    }
    
    // When writing JSON to stdout, suppress all other stdout so pipes get only JSON
    if export_json_path.as_deref() == Some("-") {
        config.quiet = true;
    }
    
    // Load config from file if specified
    if let Some(path) = config_path {
        log::info!("Loading configuration from: {}", path);
        config = DetectionConfig::from_file(&path)?;
    }
    
    if !config.quiet {
        println!("{:=^60}", " IRONSIFT SECURITY ANALYZER ");
        println!();
        config.print();
        println!();
    }

    if analyze_files {
        // FILE-BASED ANALYSIS
        if !config.quiet {
            println!("📄 Analyzing FILE ACCESS logs");
            println!();
        }
        
        // 1. Ingest File Data - Support single/multiple CSV and JSON
        let file_profiles = if !input_files.is_empty() {
            let mut all: Vec<ironsift::MachineFileProfile> = Vec::new();
            for input in &input_files {
                if !Path::new(input).exists() {
                    return Err(format!("Input file not found: {}", input).into());
                }
                log::info!("Loading file data from: {}", input);
                if input.ends_with(".json") {
                    all.extend(load_files_json_data(input, &config)?);
                } else if input.ends_with(".csv") {
                    all.extend(load_files_csv_data(input, &config)?);
                } else {
                    return Err(format!("Unsupported file format for file analysis: {}. Use .csv or .json", input).into());
                }
            }
            all
        } else {
            // Auto-detect default files
            if Path::new(DEFAULT_INPUT_FILES_JSON).exists() {
                log::info!("Loading file data from: {}", DEFAULT_INPUT_FILES_JSON);
                load_files_json_data(DEFAULT_INPUT_FILES_JSON, &config)?
            } else if Path::new(DEFAULT_INPUT_FILES_CSV).exists() {
                log::info!("Loading file data from: {}", DEFAULT_INPUT_FILES_CSV);
                load_files_csv_data(DEFAULT_INPUT_FILES_CSV, &config)?
            } else {
                return Err("No file dataset found. Use --input to specify a file, or generate one with: cargo run --bin generator -- --files".into());
            }
        };

        log::info!("Loaded {} machine file profiles", file_profiles.len());
        log::info!("Running DBSCAN clustering analysis on file access patterns");
        let report = analyze_files_fleet(&file_profiles, &config)?;
        
        // 3. Display Results (skip when writing JSON to stdout so pipe gets only JSON)
        if export_json_path.as_deref() != Some("-") {
            report.print_detailed(None);
        }

        // 4. Export JSON if requested (file analysis: not yet supported)
        if export_json_path.is_some() {
            log::warn!("JSON export for file analysis is not yet fully supported");
        }
    } else {
        // PROCESS-BASED ANALYSIS (original code)
        // Auto-detect file vs process data if CSV
        if !config.quiet {
            println!("🔍 Analyzing PROCESS logs");
            println!();
        }
        
        // 1. Ingest Data - Support single/multiple CSV, JSON, JSONL
        let profiles = if !input_files.is_empty() {
            // User specified input file(s) — each JSONL file = one machine when multiple files
            let mut all_profiles: Vec<ironsift::MachineProfile> = Vec::new();
            for input in &input_files {
                if !Path::new(input).exists() {
                    return Err(format!("Input file not found: {}", input).into());
                }
                log::info!("Loading data from: {}", input);
                if input.ends_with(".jsonl") {
                    let file_profiles = load_jsonl_data(input, &config)?;
                    all_profiles.extend(file_profiles);
                } else if input.ends_with(".json") {
                    match load_json_data(input, &config) {
                        Ok(file_profiles) => all_profiles.extend(file_profiles),
                        Err(_) => {
                            log::info!("Detected file access data in JSON");
                            let file_profiles = load_files_json_data(input, &config)?;
                            log::info!("Loaded {} machine file profiles", file_profiles.len());
                            log::info!("Running DBSCAN clustering analysis on file access patterns");
                            let report = analyze_files_fleet(&file_profiles, &config)?;
                            if export_json_path.as_deref() != Some("-") {
                                report.print_detailed(None);
                            }
                            if export_json_path.is_some() {
                                log::warn!("JSON export for file analysis is not yet fully supported");
                            }
                            return Ok(());
                        }
                    }
                } else if input.ends_with(".csv") {
                    match detect_csv_type(input) {
                        Ok(true) => {
                            log::info!("Detected file access data in CSV");
                            let file_profiles = load_files_csv_data(input, &config)?;
                            log::info!("Loaded {} machine file profiles", file_profiles.len());
                            log::info!("Running DBSCAN clustering analysis on file access patterns");
                            let report = analyze_files_fleet(&file_profiles, &config)?;
                            if export_json_path.as_deref() != Some("-") {
                                report.print_detailed(None);
                            }
                            if export_json_path.is_some() {
                                log::warn!("JSON export for file analysis is not yet fully supported");
                            }
                            return Ok(());
                        }
                        Ok(false) => all_profiles.extend(load_csv_data(input, &config)?),
                        Err(e) => {
                            log::warn!("Could not detect CSV type, assuming process data: {}", e);
                            all_profiles.extend(load_csv_data(input, &config)?)
                        }
                    }
                } else {
                    return Err(format!("Unsupported file format: {}. Use .csv, .json, or .jsonl", input).into());
                }
            }
            if all_profiles.is_empty() {
                return Err("No valid machine profiles loaded from any input file".into());
            }
            all_profiles
        } else {
            // Auto-detect default files
            if Path::new(DEFAULT_INPUT_FILES_JSON).exists() {
                log::info!("Detected file access data: {}", DEFAULT_INPUT_FILES_JSON);
                let file_profiles = load_files_json_data(DEFAULT_INPUT_FILES_JSON, &config)?;
                log::info!("Loaded {} machine file profiles", file_profiles.len());
                log::info!("Running DBSCAN clustering analysis on file access patterns");
                let report = analyze_files_fleet(&file_profiles, &config)?;
                if export_json_path.as_deref() != Some("-") {
                    report.print_detailed(None);
                }
                if export_json_path.is_some() {
                    log::warn!("JSON export for file analysis is not yet fully supported");
                }
                return Ok(());
            } else if Path::new(DEFAULT_INPUT_FILES_CSV).exists() {
                log::info!("Detected file access data: {}", DEFAULT_INPUT_FILES_CSV);
                let file_profiles = load_files_csv_data(DEFAULT_INPUT_FILES_CSV, &config)?;
                log::info!("Loaded {} machine file profiles", file_profiles.len());
                log::info!("Running DBSCAN clustering analysis on file access patterns");
                let report = analyze_files_fleet(&file_profiles, &config)?;
                if export_json_path.as_deref() != Some("-") {
                    report.print_detailed(None);
                }
                if export_json_path.is_some() {
                    log::warn!("JSON export for file analysis is not yet fully supported");
                }
                return Ok(());
            } else if Path::new(DEFAULT_INPUT_JSON).exists() {
                log::info!("Loading data from: {}", DEFAULT_INPUT_JSON);
                load_json_data(DEFAULT_INPUT_JSON, &config)?
            } else if Path::new(DEFAULT_INPUT_CSV).exists() {
                log::info!("Loading data from: {}", DEFAULT_INPUT_CSV);
                match detect_csv_type(DEFAULT_INPUT_CSV) {
                    Ok(true) => {
                        log::info!("Detected file access data in CSV");
                        let file_profiles = load_files_csv_data(DEFAULT_INPUT_CSV, &config)?;
                        log::info!("Loaded {} machine file profiles", file_profiles.len());
                        log::info!("Running DBSCAN clustering analysis on file access patterns");
                        let report = analyze_files_fleet(&file_profiles, &config)?;
                        if export_json_path.as_deref() != Some("-") {
                            report.print_detailed(None);
                        }
                        if export_json_path.is_some() {
                            log::warn!("JSON export for file analysis is not yet fully supported");
                        }
                        return Ok(());
                    }
                    _ => load_csv_data(DEFAULT_INPUT_CSV, &config)?,
                }
            } else {
                log::info!("No dataset found, generating mock data");
                generate_mock_data(&config)
            }
        };

        log::info!("Loaded {} machine profiles", profiles.len());
        log::info!("Running DBSCAN clustering analysis");
        let report = analyze_fleet(&profiles, &config)?;
        
        if export_json_path.as_deref() != Some("-") {
            report.print_detailed(Some(&profiles));
        }
        if let Some(path) = &export_json_path {
            report.export_json(&profiles, path)?;
        }
    }

    if !Path::new(CONFIG_FILE).exists() {
        config.to_file(CONFIG_FILE)?;
        log::info!("Configuration saved to: {} (edit to customize detection parameters)", CONFIG_FILE);
    }

    Ok(())
}

/// Detect if a CSV file contains file entries or process entries by checking the header
fn detect_csv_type(path: &str) -> Result<bool, Box<dyn Error>> {
    use std::io::BufRead;
    use std::io::BufReader;
    
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    reader.read_line(&mut first_line)?;
    
    let header = first_line.trim().to_lowercase();
    
    // File entries have: machine_id,path,uid,timestamp (no pid, ppid, name, args)
    // Process entries have: machine_id,pid,ppid,name,uid,path,args,timestamp
    if header.contains("path") && !header.contains("pid") && !header.contains("name") && !header.contains("args") {
        Ok(true)  // File data
    } else if header.contains("pid") || header.contains("name") || header.contains("args") {
        Ok(false)  // Process data
    } else {
        // Default to process data for backward compatibility
        Ok(false)
    }
}