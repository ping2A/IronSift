// Simple example showing the easiest way to use IronSift

use ironsift::{build_profiles_simple, analyze_fleet, DetectionConfig};

fn main() {
    // 1. Create default configuration
    let config = DetectionConfig::default();
    
    // 2. Define processes: (machine_id, process_name, parent_name)
    //    No PIDs needed - they're assigned automatically!
    let processes = vec![
        // Normal machines
        ("web-server-1".to_string(), "systemd".to_string(), "init".to_string()),
        ("web-server-1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("web-server-1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("web-server-1".to_string(), "postgres".to_string(), "systemd".to_string()),
        
        ("web-server-2".to_string(), "systemd".to_string(), "init".to_string()),
        ("web-server-2".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("web-server-2".to_string(), "postgres".to_string(), "systemd".to_string()),
        
        ("web-server-3".to_string(), "systemd".to_string(), "init".to_string()),
        ("web-server-3".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("web-server-3".to_string(), "postgres".to_string(), "systemd".to_string()),
        
        // Compromised machine - running a cryptominer!
        ("web-server-4".to_string(), "systemd".to_string(), "init".to_string()),
        ("web-server-4".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("web-server-4".to_string(), "xmrig".to_string(), "systemd".to_string()),  // ⚠️ Anomaly!
    ];
    
    // 3. Build profiles (PIDs assigned automatically)
    let profiles = build_profiles_simple(processes, &config);
    
    // 4. Analyze for anomalies
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // 5. Print detailed results
    report.print_detailed(Some(&profiles));
    
    // Optional: Export detailed JSON report
    // report.export_json(&profiles, "report.json").unwrap();
}