// Example showing ProcessBuilder for more control

use ironsift::{ProcessBuilder, ProcessEntry, build_profiles, analyze_fleet, DetectionConfig};

fn main() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Method 1: Simple add_process for quick entries
    builder
        .add_process("server1", "systemd", "init")
        .add_process("server1", "nginx", "systemd")
        .add_process("server1", "nginx", "systemd");
    
    // Method 2: Fluent API with full control over attributes
    builder.add(
        ProcessEntry::new("server1".to_string(), "worker".to_string())
            .parent("nginx")
            .uid(33)
            .path("/usr/sbin/nginx")
            .args("worker process")
    );
    
    // Normal server 2
    builder
        .add_process("server2", "systemd", "init")
        .add_process("server2", "nginx", "systemd")
        .add_process("server2", "postgres", "systemd");
    
    // Suspicious server 3 - cryptominer detected!
    builder
        .add_process("server3", "systemd", "init")
        .add_process("server3", "nginx", "systemd");
    
    // Add suspicious process with detailed attributes
    builder.add(
        ProcessEntry::new("server3".to_string(), "xmrig".to_string())
            .parent("systemd")
            .uid(0)  // Running as root - suspicious!
            .path("/tmp/.hidden/miner")  // Suspicious path!
            .args("--url stratum+tcp://pool.minexmr.com:4444 --user wallet")  // High entropy!
    );
    
    // Collect logs over time example
    println!("Simulating log collection over 24 hours...");
    for hour in 0..24 {
        // In real scenario, you'd collect actual logs here
        builder.add_process("server4", "nginx", "systemd");
        
        // At hour 12, a suspicious process appears
        if hour == 12 {
            builder.add(
                ProcessEntry::new("server4".to_string(), "malware".to_string())
                    .parent("bash")
                    .uid(0)
                    .path("/dev/shm/backdoor")
                    .args("--reverse-shell 192.168.1.100:4444")
            );
        }
    }
    
    // Build profiles with automatic PID assignment
    let raw_entries = builder.build();
    println!("Collected {} process entries", raw_entries.len());
    
    let profiles = build_profiles(raw_entries, &config);
    println!("Built {} machine profiles\n", profiles.len());
    
    // Analyze
    let report = analyze_fleet(&profiles, &config).unwrap();
    report.print_detailed(Some(&profiles));
    
    // Export detailed forensic report
    println!("\nExporting forensic report...");
    report.export_json(&profiles, "forensic_report.json").unwrap();
}