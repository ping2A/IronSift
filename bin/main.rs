use std::error::Error;
use std::path::Path;
use std::env;
use std::fs;

use ironsift::{
    load_csv_data, load_json_data, generate_mock_data, analyze_fleet,
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
    println!("  --input <file>        Specify input file (CSV or JSON)");
    println!("  --files               Analyze file access logs (instead of process logs)");
    println!("  --config <file>       Load configuration from JSON file");
    println!("  --export-json         Export detailed forensic report as JSON");
    println!("  --tolerance <value>   Override DBSCAN tolerance (default: 0.05)");
    println!("  --help                Show this help message");
    println!();
    println!("Supported Input Formats:");
    println!("  • CSV files (.csv)    - Process logs (RawLogEntry) or file logs (RawFileEntry)");
    println!("  • JSON files (.json)  - JSON array, NDJSON, or single object");
    println!();
    println!("Examples:");
    println!("  ironsift                           # Run with defaults (auto-detect input)");
    println!("  ironsift --input logs.json         # Process JSON log file");
    println!("  ironsift --input data.csv          # Process CSV log file");
    println!("  ironsift --files --input files.csv # Analyze file access logs");
    println!("  ironsift --export-json             # Run and export JSON report");
    println!("  ironsift --tolerance 0.08          # Run with custom tolerance");
    println!("  ironsift --config custom.json      # Run with custom config");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Parse arguments
    let mut export_json = false;
    let mut analyze_files = false;
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
            "--files" => {
                analyze_files = true;
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
    
    // Display comprehensive config
    config.print();
    println!();

    if analyze_files {
        // FILE-BASED ANALYSIS
        println!("📄 Analyzing FILE ACCESS logs");
        println!();
        
        // 1. Ingest File Data - Support CSV and JSON with auto-detection
        let file_profiles = if let Some(input) = input_file {
            // User specified input file
            if !Path::new(&input).exists() {
                return Err(format!("Input file not found: {}", input).into());
            }
            
            println!("• Loading file data from: {}", input);
            
            // Auto-detect format based on extension
            if input.ends_with(".json") {
                load_files_json_data(&input, &config)?
            } else if input.ends_with(".csv") {
                load_files_csv_data(&input, &config)?
            } else {
                return Err(format!("Unsupported file format: {}. Use .csv or .json", input).into());
            }
        } else {
            // Auto-detect default files
            if Path::new(DEFAULT_INPUT_FILES_JSON).exists() {
                println!("• Loading file data from: {}", DEFAULT_INPUT_FILES_JSON);
                load_files_json_data(DEFAULT_INPUT_FILES_JSON, &config)?
            } else if Path::new(DEFAULT_INPUT_FILES_CSV).exists() {
                println!("• Loading file data from: {}", DEFAULT_INPUT_FILES_CSV);
                load_files_csv_data(DEFAULT_INPUT_FILES_CSV, &config)?
            } else {
                return Err("No file dataset found. Use --input to specify a file, or generate one with: cargo run --bin generator -- --files".into());
            }
        };

        println!("• Loaded {} machine file profiles", file_profiles.len());

        // 2. Run File Analysis
        println!("• Running DBSCAN clustering analysis on file access patterns...");
        let report = analyze_files_fleet(&file_profiles, &config)?;
        
        // 3. Display Results with detailed information
        report.print_detailed(None);

        // 4. Export JSON if requested
        if export_json {
            // Note: export_json expects MachineProfile, but we have MachineFileProfile
            // For now, we'll skip the detailed export for files
            println!("\n⚠️  JSON export for file analysis is not yet fully supported");
        }
    } else {
        // PROCESS-BASED ANALYSIS (original code)
        // Auto-detect file vs process data if CSV
        println!("🔍 Analyzing PROCESS logs");
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
                // JSON: try process first, fall back to files if it fails
                match load_json_data(&input, &config) {
                    Ok(profiles) => profiles,
                    Err(_) => {
                        // Try as file data
                        println!("• Detected file access data in JSON");
                        let file_profiles = load_files_json_data(&input, &config)?;
                        println!("• Loaded {} machine file profiles", file_profiles.len());
                        println!("• Running DBSCAN clustering analysis on file access patterns...");
                        let report = analyze_files_fleet(&file_profiles, &config)?;
                        report.print_detailed(None);
                        if export_json {
                            println!("\n⚠️  JSON export for file analysis is not yet fully supported");
                        }
                        return Ok(());
                    }
                }
            } else if input.ends_with(".csv") {
                // CSV: detect type from header
                match detect_csv_type(&input) {
                    Ok(true) => {
                        // File data detected
                        println!("• Detected file access data in CSV");
                        let file_profiles = load_files_csv_data(&input, &config)?;
                        println!("• Loaded {} machine file profiles", file_profiles.len());
                        println!("• Running DBSCAN clustering analysis on file access patterns...");
                        let report = analyze_files_fleet(&file_profiles, &config)?;
                        report.print_detailed(None);
                        if export_json {
                            println!("\n⚠️  JSON export for file analysis is not yet fully supported");
                        }
                        return Ok(());
                    }
                    Ok(false) => {
                        // Process data
                        load_csv_data(&input, &config)?
                    }
                    Err(e) => {
                        eprintln!("Warning: Could not detect CSV type, assuming process data: {}", e);
                        load_csv_data(&input, &config)?
                    }
                }
            } else {
                return Err(format!("Unsupported file format: {}. Use .csv or .json", input).into());
            }
        } else {
            // Auto-detect default files
            // Check for file datasets first
            if Path::new(DEFAULT_INPUT_FILES_JSON).exists() {
                println!("• Detected file access data: {}", DEFAULT_INPUT_FILES_JSON);
                let file_profiles = load_files_json_data(DEFAULT_INPUT_FILES_JSON, &config)?;
                println!("• Loaded {} machine file profiles", file_profiles.len());
                println!("• Running DBSCAN clustering analysis on file access patterns...");
                let report = analyze_files_fleet(&file_profiles, &config)?;
                report.print_detailed(None);
                if export_json {
                    println!("\n⚠️  JSON export for file analysis is not yet fully supported");
                }
                return Ok(());
            } else if Path::new(DEFAULT_INPUT_FILES_CSV).exists() {
                println!("• Detected file access data: {}", DEFAULT_INPUT_FILES_CSV);
                let file_profiles = load_files_csv_data(DEFAULT_INPUT_FILES_CSV, &config)?;
                println!("• Loaded {} machine file profiles", file_profiles.len());
                println!("• Running DBSCAN clustering analysis on file access patterns...");
                let report = analyze_files_fleet(&file_profiles, &config)?;
                report.print_detailed(None);
                if export_json {
                    println!("\n⚠️  JSON export for file analysis is not yet fully supported");
                }
                return Ok(());
            } else if Path::new(DEFAULT_INPUT_JSON).exists() {
                println!("• Loading data from: {}", DEFAULT_INPUT_JSON);
                load_json_data(DEFAULT_INPUT_JSON, &config)?
            } else if Path::new(DEFAULT_INPUT_CSV).exists() {
                println!("• Loading data from: {}", DEFAULT_INPUT_CSV);
                // Check if it's actually file data
                match detect_csv_type(DEFAULT_INPUT_CSV) {
                    Ok(true) => {
                        println!("• Detected file access data in CSV");
                        let file_profiles = load_files_csv_data(DEFAULT_INPUT_CSV, &config)?;
                        println!("• Loaded {} machine file profiles", file_profiles.len());
                        println!("• Running DBSCAN clustering analysis on file access patterns...");
                        let report = analyze_files_fleet(&file_profiles, &config)?;
                        report.print_detailed(None);
                        if export_json {
                            println!("\n⚠️  JSON export for file analysis is not yet fully supported");
                        }
                        return Ok(());
                    }
                    _ => {
                        load_csv_data(DEFAULT_INPUT_CSV, &config)?
                    }
                }
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
    }

    // 5. Save current config for future use
    if !Path::new(CONFIG_FILE).exists() {
        config.to_file(CONFIG_FILE)?;
        println!("\n💾 Configuration saved to: {}", CONFIG_FILE);
        println!("   Edit this file to customize detection parameters.");
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