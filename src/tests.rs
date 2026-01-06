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
        // systemd
        wtr.serialize(RawLogEntry {
            machine_id: format!("normal_{}", i),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        }).unwrap();
        
        for j in 0..100 {
            wtr.serialize(RawLogEntry {
                machine_id: format!("normal_{}", i),
                pid: 100 + j,
                ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "-c /etc/nginx.conf".to_string(),
                timestamp: None,
            }).unwrap();
        }
    }
    
    // 1 compromised machine
    wtr.serialize(RawLogEntry {
        machine_id: "compromised".to_string(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "--system".to_string(),
        timestamp: None,
    }).unwrap();
    
    for j in 0..100 {
        wtr.serialize(RawLogEntry {
            machine_id: "compromised".to_string(),
            pid: 666 + j,
            ppid: 1,
            name: "miner".to_string(),
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
    
    let entries: Vec<RawLogEntry> = (0..500).flat_map(|i| {
        let machine_id = format!("machine_{}", i);
        let mut logs = vec![
            RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "--system".to_string(),
                timestamp: None,
            }
        ];
        
        // Normal traffic
        for j in 0..100 {
            logs.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 100 + j,
                ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/bin/nginx".to_string(),
                args: "conf".to_string(),
                timestamp: None,
            });
        }
        
        // Add anomaly to a few machines
        if i % 100 == 13 {
            logs.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid: 666,
                ppid: 1,
                name: "miner".to_string(),
                uid: 0,
                path: "/tmp/miner".to_string(),
                args: "XkzL1^s09f87".to_string(),
                timestamp: None,
            });
        }
        
        logs
    }).collect();
    
    let start = Instant::now();
    let profiles = build_profiles(entries, &config);
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
    
    let t1 = Utc::now();
    let t2 = t1 + Duration::hours(1);
    
    let entries = vec![
        RawLogEntry {
            machine_id: "test".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: Some(t1.to_rfc3339()),
        },
        RawLogEntry {
            machine_id: "test".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: Some(t2.to_rfc3339()),
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    assert_eq!(profile.first_seen.unwrap(), t1);
    assert_eq!(profile.last_seen.unwrap(), t2);
}

#[test]
fn test_new_process_detection() {
    let config = DetectionConfig::default();
    
    let baseline_entries = vec![
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: None,
        },
    ];
    
    let current_entries = vec![
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "machine".to_string(),
            pid: 666,
            ppid: 1,
            name: "miner".to_string(),
            uid: 0,
            path: "/tmp/miner".to_string(),
            args: "pool".to_string(),
            timestamp: None,
        },
    ];
    
    let baseline = &build_profiles(baseline_entries, &config)[0];
    let current = &build_profiles(current_entries, &config)[0];
    
    let new_procs = current.find_new_processes(baseline);
    
    assert_eq!(new_procs.len(), 1);
    assert_eq!(new_procs[0].name, "miner");
}

#[test]
fn test_parent_resolution() {
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "-c /etc/nginx.conf".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 200,
            ppid: 100,
            name: "worker".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "worker process".to_string(),
            timestamp: None,
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    // Check that parent names are resolved correctly
    let nginx_sig = profile.counts.keys()
        .find(|s| s.name == "nginx")
        .unwrap();
    assert_eq!(nginx_sig.parent_name, "systemd");
    
    let worker_sig = profile.counts.keys()
        .find(|s| s.name == "worker")
        .unwrap();
    assert_eq!(worker_sig.parent_name, "nginx");
}

#[test]
fn test_unknown_parent_handling() {
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 999, // Parent doesn't exist
            name: "orphan".to_string(),
            uid: 33,
            path: "/usr/bin/orphan".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    let profiles = build_profiles(entries, &config);
    let profile = &profiles[0];
    
    let sig = profile.counts.keys().next().unwrap();
    assert!(sig.parent_name.starts_with("[unknown:"));
}

#[test]
fn test_process_builder_simple() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add processes without knowing PIDs upfront
    builder
        .add_process("machine1", "systemd", "init")
        .add_process("machine1", "nginx", "systemd")
        .add_process("machine1", "worker", "nginx");
    
    let raw_entries = builder.build();
    
    // Verify PIDs were assigned
    assert_eq!(raw_entries.len(), 3);
    
    // Find systemd entry
    let systemd = raw_entries.iter().find(|e| e.name == "systemd").unwrap();
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    let worker = raw_entries.iter().find(|e| e.name == "worker").unwrap();
    
    // Verify parent relationships were resolved
    assert_eq!(nginx.ppid, systemd.pid);
    assert_eq!(worker.ppid, nginx.pid);
    
    // Build profiles and verify
    let profiles = build_profiles(raw_entries, &config);
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, "machine1");
}

#[test]
fn test_process_builder_fluent_api() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Use fluent API
    builder.add(
        ProcessEntry::new("machine1".to_string(), "nginx".to_string())
            .parent("systemd")
            .uid(33)
            .path("/usr/sbin/nginx")
            .args("-c /etc/nginx.conf")
    );
    
    builder.add(
        ProcessEntry::new("machine1".to_string(), "systemd".to_string())
            .uid(0)
            .path("/usr/lib/systemd/systemd")
    );
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
    
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.uid, 33);
    assert_eq!(nginx.path, "/usr/sbin/nginx");
    assert_eq!(nginx.args, "-c /etc/nginx.conf");
}

#[test]
fn test_build_profiles_simple() {
    let config = DetectionConfig::default();
    
    // Super simple API - just name/parent tuples
    let processes = vec![
        ("m1".to_string(), "systemd".to_string(), "init".to_string()),
        ("m1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("m1".to_string(), "nginx".to_string(), "systemd".to_string()),
        ("m2".to_string(), "systemd".to_string(), "init".to_string()),
        ("m2".to_string(), "apache2".to_string(), "systemd".to_string()),
    ];
    
    let profiles = build_profiles_simple(processes, &config);
    
    assert_eq!(profiles.len(), 2);
    assert!(profiles.iter().any(|p| p.id == "m1"));
    assert!(profiles.iter().any(|p| p.id == "m2"));
}

#[test]
fn test_process_builder_multiple_machines() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add processes from multiple machines
    for i in 0..5 {
        let machine_id = format!("machine_{}", i);
        builder
            .add_process(&machine_id, "systemd", "init")
            .add_process(&machine_id, "nginx", "systemd");
    }
    
    let raw_entries = builder.build();
    let profiles = build_profiles(raw_entries, &config);
    
    assert_eq!(profiles.len(), 5);
}

#[test]
fn test_process_builder_no_parent_specified() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add process without specifying parent - should default to systemd
    builder.add(
        ProcessEntry::new("machine1".to_string(), "nginx".to_string())
            .uid(33)
            .path("/usr/sbin/nginx")
    );
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 1);
    
    let nginx = &raw_entries[0];
    assert_eq!(nginx.ppid, 1); // Should default to PID 1 (systemd)
}

#[test]
fn test_parse_command_line() {
    // Full path with args
    let (name, path, args) = parse_command_line("/usr/bin/nginx -c /etc/nginx.conf");
    assert_eq!(name, "nginx");
    assert_eq!(path, "/usr/bin/nginx");
    assert_eq!(args, "-c /etc/nginx.conf");
    
    // Just executable name
    let (name, path, args) = parse_command_line("postgres");
    assert_eq!(name, "postgres");
    assert_eq!(path, "postgres");
    assert_eq!(args, "");
    
    // With multiple args
    let (name, path, args) = parse_command_line("/usr/bin/python3 script.py --debug --verbose");
    assert_eq!(name, "python3");
    assert_eq!(path, "/usr/bin/python3");
    assert_eq!(args, "script.py --debug --verbose");
    
    // Relative path
    let (name, path, args) = parse_command_line("./myscript --flag");
    assert_eq!(name, "myscript");
    assert_eq!(path, "./myscript");
    assert_eq!(args, "--flag");
    
    // Suspicious path
    let (name, path, args) = parse_command_line("/tmp/.hidden/miner --pool stratum+tcp://pool.xmr.com:4444");
    assert_eq!(name, "miner");
    assert_eq!(path, "/tmp/.hidden/miner");
    assert_eq!(args, "--pool stratum+tcp://pool.xmr.com:4444");
    
    // With quotes
    let (name, path, args) = parse_command_line(r#"/bin/sh -c "echo hello world""#);
    assert_eq!(name, "sh");
    assert_eq!(path, "/bin/sh");
    assert_eq!(args, r#"-c echo hello world"#);
    
    // Empty
    let (name, path, args) = parse_command_line("");
    assert_eq!(name, "");
    assert_eq!(path, "");
    assert_eq!(args, "");
}

#[test]
fn test_process_entry_from_command_line() {
    let entry = ProcessEntry::from_command_line(
        "server1".to_string(),
        "/usr/bin/nginx -c /etc/nginx.conf",
        Some("systemd")
    );
    
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.name, "nginx");
    assert_eq!(entry.path, "/usr/bin/nginx");
    assert_eq!(entry.args, "-c /etc/nginx.conf");
    assert_eq!(entry.parent_name, Some("systemd".to_string()));
    
    // Can still override with fluent API
    let entry2 = ProcessEntry::from_command_line(
        "server1".to_string(),
        "/usr/bin/nginx -c /etc/nginx.conf",
        None
    ).uid(33).parent("systemd");
    
    assert_eq!(entry2.uid, 33);
    assert_eq!(entry2.parent_name, Some("systemd".to_string()));
}

#[test]
fn test_builder_add_command() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Add processes using full command lines
    builder
        .add_command("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"))
        .add_command("server1", "/usr/bin/postgres -D /var/lib/postgresql/data", Some("systemd"))
        .add_command("server1", "python3 app.py --port 8000", Some("bash"));
    
    let raw_entries = builder.build();
    
    assert_eq!(raw_entries.len(), 3);
    
    // Check nginx
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.path, "/usr/bin/nginx");
    assert_eq!(nginx.args, "-c /etc/nginx.conf");
    
    // Check postgres
    let postgres = raw_entries.iter().find(|e| e.name == "postgres").unwrap();
    assert_eq!(postgres.path, "/usr/bin/postgres");
    assert_eq!(postgres.args, "-D /var/lib/postgresql/data");
    
    // Check python3
    let python = raw_entries.iter().find(|e| e.name == "python3").unwrap();
    assert_eq!(python.path, "python3");
    assert_eq!(python.args, "app.py --port 8000");
}

#[test]
fn test_builder_add_command_with_uid() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Normal process
    builder.add_command_with_uid("server1", "/usr/bin/nginx -c /etc/nginx.conf", Some("systemd"), 33);
    
    // Suspicious root process
    builder.add_command_with_uid("server1", "/tmp/miner --pool xmr", Some("bash"), 0);
    
    let raw_entries = builder.build();
    
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.uid, 33);
    
    let miner = raw_entries.iter().find(|e| e.name == "miner").unwrap();
    assert_eq!(miner.uid, 0);
    assert_eq!(miner.path, "/tmp/miner");
}

#[test]
fn test_full_workflow_with_command_parsing() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    // Simulate parsing raw command lines from logs
    let log_lines = vec![
        ("server1", "/usr/sbin/sshd -D", "systemd"),
        ("server1", "/usr/bin/nginx -c /etc/nginx.conf", "systemd"),
        ("server1", "/usr/bin/nginx worker process", "nginx"),
        ("server2", "/usr/sbin/sshd -D", "systemd"),
        ("server2", "/usr/bin/nginx -c /etc/nginx.conf", "systemd"),
        ("server3", "/tmp/.hidden/kworker --url stratum+tcp://pool.minexmr.com:4444", "systemd"),
    ];
    
    for (machine, command, parent) in log_lines {
        builder.add_command_with_uid(machine, command, Some(parent), if command.contains("/tmp") { 0 } else { 33 });
    }
    
    let raw_entries = builder.build();
    let profiles = build_profiles(raw_entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Should detect server3 as anomalous
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "server3"));
}

#[test]
fn test_command_parsing_edge_cases() {
    // Leading/trailing whitespace
    let (name, path, args) = parse_command_line("  /usr/bin/nginx -c /etc/nginx.conf  ");
    assert_eq!(name, "nginx");
    assert_eq!(path, "/usr/bin/nginx");
    
    // Multiple spaces
    let (name, path, args) = parse_command_line("/usr/bin/python3    script.py    --flag");
    assert_eq!(name, "python3");
    assert_eq!(args, "script.py --flag");
    
    // Process name with numbers
    let (name, path, args) = parse_command_line("/usr/bin/node16 app.js");
    assert_eq!(name, "node16");
    
    // Dots in name
    let (name, path, args) = parse_command_line("/usr/bin/systemd-resolved --config");
    assert_eq!(name, "systemd-resolved");
    assert_eq!(path, "/usr/bin/systemd-resolved");
}

#[test]
fn test_bare_command_parsing() {
    // Common case: "ls /etc/" not "/bin/ls /etc/"
    let (name, path, args) = parse_command_line("ls /etc/");
    assert_eq!(name, "ls");
    assert_eq!(path, "ls");
    assert_eq!(args, "/etc/");
    
    // Multiple bare commands
    let (name, path, args) = parse_command_line("grep pattern file.txt");
    assert_eq!(name, "grep");
    assert_eq!(path, "grep");
    assert_eq!(args, "pattern file.txt");
    
    // ps output style
    let (name, path, args) = parse_command_line("nginx: worker process");
    assert_eq!(name, "nginx: worker process");
    assert_eq!(path, "nginx: worker process");
    assert_eq!(args, "");
    
    // Docker style
    let (name, path, args) = parse_command_line("node server.js");
    assert_eq!(name, "node");
    assert_eq!(path, "node");
    assert_eq!(args, "server.js");
}

#[test]
fn test_parse_json_log_docker_style() {
    let json = r#"{
        "host": "server1",
        "command": "/usr/bin/nginx -c /etc/nginx.conf",
        "uid": 33
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.name, "nginx");
    assert_eq!(entry.path, "/usr/bin/nginx");
    assert_eq!(entry.args, "-c /etc/nginx.conf");
    assert_eq!(entry.uid, 33);
}

#[test]
fn test_parse_json_log_kubernetes_style() {
    let json = r#"{
        "node": "worker-1",
        "cmd": "python3 app.py --port 8000",
        "userid": 1000,
        "timestamp": "2024-01-06T10:00:00Z"
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "worker-1");
    assert_eq!(entry.name, "python3");
    assert_eq!(entry.path, "python3");
    assert_eq!(entry.args, "app.py --port 8000");
    assert_eq!(entry.uid, 1000);
    assert_eq!(entry.timestamp, Some("2024-01-06T10:00:00Z".to_string()));
}

#[test]
fn test_parse_json_log_full_detail() {
    let json = r#"{
        "machine_id": "server1",
        "pid": 100,
        "ppid": 1,
        "name": "nginx",
        "path": "/usr/sbin/nginx",
        "args": "-c /etc/nginx.conf",
        "uid": 33,
        "timestamp": "2024-01-06T10:00:00Z"
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.pid, 100);
    assert_eq!(entry.ppid, 1);
    assert_eq!(entry.name, "nginx");
    assert_eq!(entry.path, "/usr/sbin/nginx");
    assert_eq!(entry.args, "-c /etc/nginx.conf");
    assert_eq!(entry.uid, 33);
}

#[test]
fn test_parse_json_log_bare_command() {
    let json = r#"{
        "hostname": "server1",
        "cmd": "ls /etc/",
        "uid": 0
    }"#;
    
    let entry = parse_json_log(json).unwrap();
    assert_eq!(entry.machine_id, "server1");
    assert_eq!(entry.name, "ls");
    assert_eq!(entry.path, "ls");
    assert_eq!(entry.args, "/etc/");
}

#[test]
fn test_parse_json_logs_array() {
    let json = r#"[
        {"host": "server1", "command": "/usr/bin/nginx"},
        {"host": "server2", "command": "python3 app.py"},
        {"host": "server3", "cmd": "/tmp/miner --pool xmr"}
    ]"#;
    
    let entries = parse_json_logs(json).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, "nginx");
    assert_eq!(entries[1].name, "python3");
    assert_eq!(entries[2].name, "miner");
}

#[test]
fn test_parse_json_logs_ndjson() {
    let ndjson = r#"
{"host": "server1", "command": "/usr/bin/nginx"}
{"host": "server2", "command": "python3 app.py"}
{"host": "server3", "cmd": "/tmp/miner --pool xmr"}
    "#;
    
    let entries = parse_json_logs(ndjson).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].machine_id, "server1");
    assert_eq!(entries[1].machine_id, "server2");
    assert_eq!(entries[2].machine_id, "server3");
}

#[test]
fn test_builder_add_json() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    builder.add_json(r#"{"host": "server1", "command": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33}"#);
    builder.add_json(r#"{"node": "server2", "cmd": "python3 app.py", "userid": 1000}"#);
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
    
    let nginx = raw_entries.iter().find(|e| e.name == "nginx").unwrap();
    assert_eq!(nginx.machine_id, "server1");
    assert_eq!(nginx.uid, 33);
}

#[test]
fn test_builder_add_json_batch() {
    let config = DetectionConfig::default();
    let mut builder = ProcessBuilder::new();
    
    builder.add_json_batch(r#"[
        {"host": "server1", "command": "/usr/bin/nginx"},
        {"host": "server2", "command": "python3 app.py"}
    ]"#);
    
    let raw_entries = builder.build();
    assert_eq!(raw_entries.len(), 2);
}

#[test]
fn test_json_parsing_with_analysis() {
    let config = DetectionConfig::default();
    
    // Simulate JSON logs from a monitoring system
    let json_logs = r#"[
        {"host": "web-1", "cmd": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33},
        {"host": "web-1", "cmd": "/usr/bin/postgres -D /var/lib/postgresql/data", "uid": 70},
        {"host": "web-2", "cmd": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33},
        {"host": "web-2", "cmd": "/usr/bin/postgres -D /var/lib/postgresql/data", "uid": 70},
        {"host": "web-3", "cmd": "/tmp/.hidden/xmrig --donate-level 1", "uid": 0}
    ]"#;
    
    let entries = parse_json_logs(json_logs).unwrap();
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    
    // Should detect web-3 as anomalous
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "web-3"));
}

// --- TESTS MOVED FROM LIB.RS ---

#[test]
fn test_entropy_calculation() {
    let low = calculate_shannon_entropy("aaaaaaaaaa");
    assert_eq!(low, 0.0);
    
    let high = calculate_shannon_entropy("X5O!aH@9#kzL1^s09f87");
    assert!(high > 3.0);
}

#[test]
fn test_config_default() {
    let config = DetectionConfig::default();
    assert_eq!(config.entropy_threshold, 4.5);
    assert_eq!(config.dbscan_min_samples, 2);
}

#[test]
fn test_suspicious_path_detection() {
    let patterns = vec![r"/tmp/".to_string(), r"/dev/shm/".to_string()];
    assert!(is_path_suspicious("/tmp/malware", &patterns));
    assert!(is_path_suspicious("/dev/shm/rootkit", &patterns));
    assert!(!is_path_suspicious("/usr/bin/nginx", &patterns));
}

#[test]
fn test_parent_resolution() {
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    let pid_map = resolve_parent_names(&entries);
    assert_eq!(pid_map.get(&("m1".to_string(), 1)), Some(&"systemd".to_string()));
}

#[test]
fn test_identical_machines_clean() {
    let config = DetectionConfig::default();
    let entries: Vec<RawLogEntry> = (0..5).flat_map(|i| {
        vec![
            RawLogEntry {
                machine_id: format!("m{}", i),
                pid: 1,
                ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: format!("m{}", i),
                pid: 100,
                ppid: 1,
                name: "test".to_string(),
                uid: 0,
                path: "/bin/test".to_string(),
                args: "args".to_string(),
                timestamp: None,
            },
        ]
    }).collect();
    
    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    assert!(report.anomalies.is_empty());
}

#[test]
fn test_detect_single_outlier() {
    let config = DetectionConfig::default();
    let mut entries = Vec::new();
    
    // 10 normal machines
    for i in 0..10 {
        entries.push(RawLogEntry {
            machine_id: format!("normal_{}", i),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "".to_string(),
            timestamp: None,
        });
        entries.push(RawLogEntry {
            machine_id: format!("normal_{}", i),
            pid: 100,
            ppid: 1,
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/bin/nginx".to_string(),
            args: "conf".to_string(),
            timestamp: None,
        });
    }
    
    // 1 compromised machine
    entries.push(RawLogEntry {
        machine_id: "compromised".to_string(),
        pid: 1,
        ppid: 0,
        name: "systemd".to_string(),
        uid: 0,
        path: "/usr/lib/systemd/systemd".to_string(),
        args: "".to_string(),
        timestamp: None,
    });
    entries.push(RawLogEntry {
        machine_id: "compromised".to_string(),
        pid: 666,
        ppid: 1,
        name: "miner".to_string(),
        uid: 0,
        path: "/tmp/kworker".to_string(),
        args: "XkzL1^s09f87".to_string(),
        timestamp: None,
    });

    let profiles = build_profiles(entries, &config);
    let report = analyze_fleet(&profiles, &config).unwrap();
    assert!(!report.anomalies.is_empty());
    assert!(report.anomalies.iter().any(|a| a.machine_id == "compromised"));
}

#[test]
fn test_process_risk_factors() {
    let sig = ProcessSignature {
        name: "malware".to_string(),
        parent_name: "bash".to_string(),
        uid: 0,
        path: "/tmp/hidden".to_string(),
        is_high_entropy: true,
        is_suspicious_path: true,
    };
    
    let risks = sig.risk_factors();
    assert!(!risks.is_empty());
    assert!(risks.iter().any(|r| r.contains("entropy")));
    assert!(risks.iter().any(|r| r.contains("Suspicious execution path")));
}

#[test]
fn test_ppid_resolution_comprehensive() {
    // Test comprehensive PPID resolution with multiple parent-child relationships
    let config = DetectionConfig::default();
    
    let entries = vec![
        // Machine 1: systemd -> nginx -> worker processes
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,  // Parent is systemd (PID 1)
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "master process".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 101,
            ppid: 100,  // Parent is nginx (PID 100)
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "worker process".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 102,
            ppid: 100,  // Another worker, parent is nginx (PID 100)
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "worker process".to_string(),
            timestamp: None,
        },
        // Machine 2: systemd -> sshd -> bash -> malicious process
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 200,
            ppid: 1,  // Parent is systemd
            name: "sshd".to_string(),
            uid: 0,
            path: "/usr/sbin/sshd".to_string(),
            args: "-D".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 201,
            ppid: 200,  // Parent is sshd (PID 200)
            name: "bash".to_string(),
            uid: 1000,
            path: "/bin/bash".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m2".to_string(),
            pid: 202,
            ppid: 201,  // Parent is bash (PID 201)
            name: "miner".to_string(),
            uid: 0,
            path: "/tmp/miner".to_string(),
            args: "--pool xmr".to_string(),
            timestamp: None,
        },
    ];
    
    // Build profiles with PPID resolution
    let profiles = build_profiles(entries.clone(), &config);
    
    // Verify we got 2 machine profiles
    assert_eq!(profiles.len(), 2);
    
    // Machine 1 verification
    let m1_profile = profiles.iter().find(|p| p.id == "m1").unwrap();
    
    // Check that nginx workers have nginx as parent
    let nginx_workers: Vec<_> = m1_profile.counts.iter()
        .filter(|(sig, _)| sig.name == "nginx" && sig.args == "worker process")
        .collect();
    
    assert!(!nginx_workers.is_empty(), "Should have nginx worker processes");
    
    for (sig, _) in nginx_workers {
        assert_eq!(sig.parent_name, "nginx", 
            "Worker process should have 'nginx' as parent, got '{}'", sig.parent_name);
    }
    
    // Check that master nginx has systemd as parent
    let nginx_master: Vec<_> = m1_profile.counts.iter()
        .filter(|(sig, _)| sig.name == "nginx" && sig.args == "master process")
        .collect();
    
    assert!(!nginx_master.is_empty(), "Should have nginx master process");
    
    for (sig, _) in nginx_master {
        assert_eq!(sig.parent_name, "systemd",
            "Master nginx should have 'systemd' as parent, got '{}'", sig.parent_name);
    }
    
    // Machine 2 verification
    let m2_profile = profiles.iter().find(|p| p.id == "m2").unwrap();
    
    // Check that miner has bash as parent
    let miner_procs: Vec<_> = m2_profile.counts.iter()
        .filter(|(sig, _)| sig.name == "miner")
        .collect();
    
    assert!(!miner_procs.is_empty(), "Should have miner process");
    
    for (sig, _) in miner_procs {
        assert_eq!(sig.parent_name, "bash",
            "Miner should have 'bash' as parent, got '{}'", sig.parent_name);
    }
    
    // Check that bash has sshd as parent
    let bash_procs: Vec<_> = m2_profile.counts.iter()
        .filter(|(sig, _)| sig.name == "bash")
        .collect();
    
    assert!(!bash_procs.is_empty(), "Should have bash process");
    
    for (sig, _) in bash_procs {
        assert_eq!(sig.parent_name, "sshd",
            "Bash should have 'sshd' as parent, got '{}'", sig.parent_name);
    }
    
    // Verify parent resolution worked correctly by checking the PID map
    let pid_map = resolve_parent_names(&entries);
    
    // Check specific parent resolutions
    assert_eq!(pid_map.get(&("m1".to_string(), 1)), Some(&"systemd".to_string()));
    assert_eq!(pid_map.get(&("m1".to_string(), 100)), Some(&"nginx".to_string()));
    assert_eq!(pid_map.get(&("m2".to_string(), 200)), Some(&"sshd".to_string()));
    assert_eq!(pid_map.get(&("m2".to_string(), 201)), Some(&"bash".to_string()));
    
    println!("✅ PPID resolution test passed!");
    println!("   - Multi-level parent-child relationships resolved correctly");
    println!("   - nginx master -> workers chain verified");
    println!("   - sshd -> bash -> miner chain verified");
}

#[test]
fn test_ppid_resolution_with_missing_parents() {
    // Test PPID resolution when parent processes are missing from logs
    let config = DetectionConfig::default();
    
    let entries = vec![
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 100,
            ppid: 1,  // Parent PID 1 (systemd) not in logs
            name: "nginx".to_string(),
            uid: 33,
            path: "/usr/sbin/nginx".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
        RawLogEntry {
            machine_id: "m1".to_string(),
            pid: 101,
            ppid: 50,  // Parent PID 50 not in logs at all
            name: "worker".to_string(),
            uid: 33,
            path: "/usr/bin/worker".to_string(),
            args: "".to_string(),
            timestamp: None,
        },
    ];
    
    // Should not panic, should handle missing parents gracefully
    let profiles = build_profiles(entries, &config);
    
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    
    // Check that processes exist even with missing parents
    assert!(profile.counts.iter().any(|(sig, _)| sig.name == "nginx"));
    assert!(profile.counts.iter().any(|(sig, _)| sig.name == "worker"));
    
    println!("✅ Missing parent PPID test passed!");
}