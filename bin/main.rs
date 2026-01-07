use std::error::Error;
use std::path::Path;
use std::env;

use ironsift::{load_csv_data, load_json_data, generate_mock_data, analyze_fleet, DetectionConfig};

const DEFAULT_INPUT_CSV: &str = "test_dataset.csv";
const DEFAULT_INPUT_JSON: &str = "test_dataset.json";
const CONFIG_FILE: &str = "ironsift_config.json";
const REPORT_OUTPUT: &str = "forensic_report.json";

fn print_usage() {
    println!("Usage: ironsift [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --input <file>        Specify input file (CSV or JSON)");
    println!("  --config <file>       Load configuration from JSON file");
    println!("  --export-json         Export detailed forensic report as JSON");
    println!("  --tolerance <value>   Override DBSCAN tolerance (default: 0.05)");
    println!("  --help                Show this help message");
    println!();
    println!("Supported Input Formats:");
    println!("  • CSV files (.csv)    - Standard CSV with RawLogEntry format");
    println!("  • JSON files (.json)  - JSON array, NDJSON, or single object");
    println!();
    println!("Examples:");
    println!("  ironsift                           # Run with defaults (auto-detect input)");
    println!("  ironsift --input logs.json         # Process JSON log file");
    println!("  ironsift --input data.csv          # Process CSV log file");
    println!("  ironsift --export-json             # Run and export JSON report");
    println!("  ironsift --tolerance 0.08          # Run with custom tolerance");
    println!("  ironsift --config custom.json      # Run with custom config");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Parse arguments
    let mut export_json = false;
    let mut config = DetectionConfig::default();
    let mut config_path: Option<String> = None;
    let mut input_file: Option<String> = None;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" => {
                print_usage();
                return Ok(());
            }
            "--export-json" => {
                export_json = true;
            }
            "--input" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --input requires a file path");
                    return Err("Missing input file path".into());
                }
                input_file = Some(args[i].clone());
            }
            "--tolerance" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --tolerance requires a value");
                    return Err("Missing tolerance value".into());
                }
                config.dbscan_tolerance = args[i].parse()
                    .map_err(|_| "Invalid tolerance value")?;
            }
            "--config" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --config requires a file path");
                    return Err("Missing config file path".into());
                }
                config_path = Some(args[i].clone());
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_usage();
                return Err("Invalid argument".into());
            }
        }
        i += 1;
    }
    
    // Load config from file if specified
    if let Some(path) = config_path {
        println!("• Loading configuration from: {}", path);
        config = DetectionConfig::from_file(&path)?;
    }
    
    println!("{:=^60}", " IRONSIFT SECURITY ANALYZER ");
    println!();
    
    // Display config
    println!("Configuration:");
    println!("  Entropy Threshold: {}", config.entropy_threshold);
    println!("  DBSCAN Tolerance: {}", config.dbscan_tolerance);
    println!("  Min Samples: {}", config.dbscan_min_samples);
    println!("  Minority Cluster Ratio: {}%", config.minority_cluster_ratio * 100.0);
    println!();

    // 1. Ingest Data - Support CSV and JSON with auto-detection
    let profiles = if let Some(input) = input_file {
        // User specified input file
        if !Path::new(&input).exists() {
            return Err(format!("Input file not found: {}", input).into());
        }
        
        println!("• Loading data from: {}", input);
        
        // Auto-detect format based on extension
        if input.ends_with(".json") {
            load_json_data(&input, &config)?
        } else if input.ends_with(".csv") {
            load_csv_data(&input, &config)?
        } else {
            return Err(format!("Unsupported file format: {}. Use .csv or .json", input).into());
        }
    } else {
        // Auto-detect default files
        if Path::new(DEFAULT_INPUT_JSON).exists() {
            println!("• Loading data from: {}", DEFAULT_INPUT_JSON);
            load_json_data(DEFAULT_INPUT_JSON, &config)?
        } else if Path::new(DEFAULT_INPUT_CSV).exists() {
            println!("• Loading data from: {}", DEFAULT_INPUT_CSV);
            load_csv_data(DEFAULT_INPUT_CSV, &config)?
        } else {
            println!("• No dataset found, generating mock data...");
            generate_mock_data(&config)
        }
    };

    println!("• Loaded {} machine profiles", profiles.len());

    // 2. Run Analysis
    println!("• Running DBSCAN clustering analysis...");
    let report = analyze_fleet(&profiles, &config)?;
    
    // 3. Display Results with detailed information
    report.print_detailed(Some(&profiles));

    // 4. Export JSON if requested
    if export_json {
        report.export_json(&profiles, REPORT_OUTPUT)?;
    }

    // 5. Save current config for future use
    if !Path::new(CONFIG_FILE).exists() {
        config.to_file(CONFIG_FILE)?;
        println!("\n💾 Configuration saved to: {}", CONFIG_FILE);
        println!("   Edit this file to customize detection parameters.");
    }

    Ok(())
}