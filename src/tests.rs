use ironsift::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_full_pipeline_with_csv() {
    let dir = tempdir().unwrap();
    let csv_path = dir.path().join("test_data.csv");
    
    // Create a test CSV
    let mut wtr = csv::Writer::from_path(&csv_path).unwrap();
    
    // 5 normal machines
    for i in 0..5 {
        for _ in 0..100 {
            wtr.serialize(RawLogEntry {
                machine_id: format!("normal_{}", i),
                name: "nginx".to_string(),
                parent: "systemd".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "-c /etc/nginx.conf".to_string(),
                timestamp: None,
            }).unwrap();
        }
    }
    
    // 1 compromised machine
    for _ in 0..100 {
        wtr.serialize(RawLogEntry {
            machine_id: "compromised".to_string(),
            name: "miner".to_string(),
            parent: "systemd".to_string(),
            uid: 0,
            path: "/tmp/kworker".to_string(),
            args: "XkzL1^s09f87aH@9#kzL1^s09f87".to_string(),
            timestamp: None,
        }).unwrap();
    }
    
    wtr.flush().unwrap();
    
    // Load and analyze
    let config = DetectionConfig::default();
    let profiles = load_csv_data(csv_path.to_str().unwrap(), &config).unwrap();
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Verify
    assert_eq!(profiles.len(), 6);
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "compromised"));
}

#[test]
fn test_json_export() {
    let dir = tempdir().unwrap();
    let json_path = dir.path().join("report.json");
    
    let config = DetectionConfig::default();
    let profiles = generate_mock_data(&config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Export JSON
    report.export_json(&profiles, json_path.to_str().unwrap()).unwrap();
    
    // Verify file exists and is valid JSON
    let contents = fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    
    assert!(parsed.get("report_timestamp").is_some());
    assert!(parsed.get("fleet_size").is_some());
    assert!(parsed.get("investigation_targets").is_some());
}

#[test]
fn test_config_save_load() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    
    let mut config = DetectionConfig::default();
    config.dbscan_tolerance = 0.08;
    config.entropy_threshold = 5.0;
    
    // Save
    config.to_file(config_path.to_str().unwrap()).unwrap();
    
    // Load
    let loaded = DetectionConfig::from_file(config_path.to_str().unwrap()).unwrap();
    
    assert_eq!(loaded.dbscan_tolerance, 0.08);
    assert_eq!(loaded.entropy_threshold, 5.0);
}

#[test]
fn test_anomaly_severity_classification() {
    let critical = AnomalyDetails {
        machine_id: "test".to_string(),
        severity: AnomalyLevel::Critical,
        distance_score: 1.5,
        cluster_assignment: None,
        anomalous_features: vec![],
        process_count: 100,
        suspicious_process_count: 50,
    };
    
    assert!(matches!(critical.severity, AnomalyLevel::Critical));
}

#[test]
fn test_large_fleet_performance() {
    use std::time::Instant;
    
    let config = DetectionConfig::default();
    let mut profiles = Vec::new();
    
    // Simulate 500 machines
    for i in 0..500 {
        let mut p = MachineProfile::new(&format!("machine_{}", i));
        
        // Normal traffic
        for _ in 0..100 {
            p.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, None);
        }
        
        // Add anomaly to a few machines
        if i % 100 == 13 {
            p.add("miner", "systemd", 0, "/tmp/miner", "XkzL1^s09f87", &config, None);
        }
        
        profiles.push(p);
    }
    
    let start = Instant::now();
    let report = analyze_fleet(&profiles, &config).unwrap();
    let elapsed = start.elapsed();
    
    println!("Analyzed {} machines in {:?}", profiles.len(), elapsed);
    
    assert!(elapsed.as_secs() < 10, "Performance regression: took {:?}", elapsed);
    assert!(!report.anomalies.is_empty());
}

#[test]
fn test_temporal_tracking() {
    use chrono::{Utc, Duration};
    
    let config = DetectionConfig::default();
    let mut profile = MachineProfile::new("test");
    
    let t1 = Utc::now();
    let t2 = t1 + Duration::hours(1);
    
    profile.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, Some(t1));
    profile.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, Some(t2));
    
    assert_eq!(profile.first_seen.unwrap(), t1);
    assert_eq!(profile.last_seen.unwrap(), t2);
}

#[test]
fn test_new_process_detection() {
    let config = DetectionConfig::default();
    
    let mut baseline = MachineProfile::new("machine");
    baseline.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, None);
    
    let mut current = MachineProfile::new("machine");
    current.add("nginx", "systemd", 33, "/usr/bin/nginx", "conf", &config, None);
    current.add("miner", "systemd", 0, "/tmp/miner", "pool", &config, None);
    
    let new_procs = current.find_new_processes(&baseline);
    
    assert_eq!(new_procs.len(), 1);
    assert_eq!(new_procs[0].name, "miner");
}