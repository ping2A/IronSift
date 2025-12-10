use std::error::Error;
use std::path::Path;

// Import the high-level functions
use ironsift::{load_csv_data, generate_mock_data, analyze_fleet};

const INPUT_CSV: &str = "large_dataset.csv";

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== IRONSIFT ENGINE ===");

    // 1. Ingest
    let profiles = if Path::new(INPUT_CSV).exists() {
        println!("• Loading data from disk...");
        load_csv_data(INPUT_CSV)?
    } else {
        println!("• generating mock data...");
        generate_mock_data()
    };

    // 2. Analyze & Report
    println!("• Running DBSCAN clustering analysis...");
    let report = analyze_fleet(&profiles, 0.05)?;
    
    // 3. Display
    report.print();

    Ok(())
}