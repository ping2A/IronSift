// Example: Parsing JSON logs from modern systems

use ironsift::{ProcessBuilder, build_profiles, analyze_fleet, DetectionConfig};

fn main() {
    let config = DetectionConfig::default();
    
    println!("=== IronSift JSON Log Parsing Example ===\n");
    
    // Example 1: Docker-style JSON logs
    println!("Example 1: Docker Container Logs (JSON format)");
    println!("{:-<60}", "");
    
    let docker_logs = r#"
{"container": "web-prod-1", "command": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33, "timestamp": "2024-01-06T10:00:00Z"}
{"container": "web-prod-1", "command": "/usr/bin/postgres -D /var/lib/postgresql/data", "uid": 70}
{"container": "web-prod-2", "command": "/usr/bin/nginx -c /etc/nginx.conf", "uid": 33}
{"container": "web-prod-2", "command": "/usr/bin/postgres -D /var/lib/postgresql/data", "uid": 70}
{"container": "web-prod-3", "command": "/tmp/.hidden/xmrig --donate-level 1 -o pool.minexmr.com:4444", "uid": 0}
    "#;
    
    let mut builder = ProcessBuilder::new();
    builder.add_json_batch(docker_logs);
    
    println!("Parsed {} Docker container processes\n", builder.len());
    
    // Example 2: Kubernetes-style JSON
    println!("Example 2: Kubernetes Pod Logs");
    println!("{:-<60}", "");
    
    let k8s_logs = r#"[
        {"node": "worker-node-1", "pod": "nginx-7d8b", "cmd": "nginx: master process", "userid": 0},
        {"node": "worker-node-1", "pod": "nginx-7d8b", "cmd": "nginx: worker process", "userid": 33},
        {"node": "worker-node-2", "pod": "api-5c2a", "cmd": "node server.js", "userid": 1000},
        {"node": "worker-node-3", "pod": "suspicious-8f3b", "cmd": "/dev/shm/miner", "userid": 0}
    ]"#;
    
    builder.add_json_batch(k8s_logs);
    println!("Parsed {} Kubernetes pod processes\n", builder.len());
    
    // Example 3: CloudWatch/ElasticSearch-style structured logs
    println!("Example 3: CloudWatch/ElasticSearch Logs");
    println!("{:-<60}", "");
    
    let cloudwatch_logs = vec![
        r#"{"hostname": "ec2-10-0-1-50", "commandline": "/usr/sbin/sshd -D", "user_id": "0"}"#,
        r#"{"hostname": "ec2-10-0-1-50", "commandline": "python3 app.py --port 8080", "user_id": "1000"}"#,
        r#"{"hostname": "ec2-10-0-1-51", "commandline": "/usr/sbin/sshd -D", "user_id": "0"}"#,
        r#"{"hostname": "ec2-10-0-1-52", "commandline": "/tmp/suspicious ls -la", "user_id": "0"}"#,
    ];
    
    for log in cloudwatch_logs {
        builder.add_json(log);
    }
    
    println!("Parsed {} CloudWatch log entries\n", builder.len());
    
    // Example 4: Mixed format - bare commands
    println!("Example 4: Bare Commands (no full paths)");
    println!("{:-<60}", "");
    
    let bare_command_logs = r#"[
        {"server": "app-1", "cmd": "ls /etc/", "uid": 0},
        {"server": "app-1", "cmd": "grep error /var/log/app.log", "uid": 1000},
        {"server": "app-2", "cmd": "ps aux", "uid": 0},
        {"server": "app-2", "cmd": "netstat -tulpn", "uid": 0}
    ]"#;
    
    builder.add_json_batch(bare_command_logs);
    println!("Parsed {} bare command entries\n", builder.len());
    
    // Example 5: Custom monitoring system format
    println!("Example 5: Custom Monitoring System");
    println!("{:-<60}", "");
    
    // Simulate reading from a custom monitoring API
    let custom_logs = fetch_from_monitoring_api();
    builder.add_json_batch(&custom_logs);
    
    println!("Parsed {} custom monitoring entries\n", builder.len());
    
    // Build profiles and analyze
    println!("\n{:=^60}", " ANALYSIS ");
    println!("Total processes collected: {}", builder.len());
    
    let raw_entries = builder.build();
    let profiles = build_profiles(raw_entries, &config);
    
    println!("Built profiles for {} machines", profiles.len());
    println!("Running anomaly detection...\n");
    
    let report = analyze_fleet(&profiles, &config).unwrap();
    report.print_detailed(Some(&profiles));
    
    // Show what JSON formats are supported
    println!("\n{:=^60}", " SUPPORTED JSON FORMATS ");
    show_supported_formats();
}

fn fetch_from_monitoring_api() -> String {
    // Simulate fetching from a monitoring API
    r#"[
        {"machine_id": "monitor-1", "process": "telegraf", "executable": "/usr/bin/telegraf", "arguments": "--config /etc/telegraf/telegraf.conf", "uid": 1000},
        {"machine_id": "monitor-2", "process": "prometheus", "executable": "/usr/local/bin/prometheus", "arguments": "--config.file=/etc/prometheus/prometheus.yml", "uid": 1000},
        {"machine_id": "monitor-3", "process": "backdoor", "executable": "/tmp/.cache/bd", "arguments": "--connect-back 192.168.1.100:4444", "uid": 0}
    ]"#.to_string()
}

fn show_supported_formats() {
    println!("\nIronSift supports flexible JSON key names:\n");
    
    println!("Machine Identifier:");
    println!("  • machine_id, hostname, host, server, node, container, pod\n");
    
    println!("Process Command:");
    println!("  • command, cmd, cmdline, commandline\n");
    
    println!("Process Name:");
    println!("  • name, process, process_name, comm\n");
    
    println!("Process Path:");
    println!("  • path, exe, executable\n");
    
    println!("Arguments:");
    println!("  • args, arguments, params\n");
    
    println!("User ID:");
    println!("  • uid, user_id, userid\n");
    
    println!("Process IDs:");
    println!("  • pid, process_id");
    println!("  • ppid, parent_pid\n");
    
    println!("Timestamp:");
    println!("  • timestamp, time, datetime\n");
    
    println!("Formats Supported:");
    println!("  ✓ JSON Array: [{{...}}, {{...}}]");
    println!("  ✓ Newline-Delimited JSON (NDJSON): {{...}}\\n{{...}}\\n");
    println!("  ✓ Single JSON object: {{...}}\n");
    
    println!("Example Usage:");
    println!();
    println!("  // Single JSON log");
    println!(r##"  builder.add_json(r#"{{"host": "server1", "cmd": "nginx"}}"#);"##);
    println!();
    println!("  // Multiple logs (array or NDJSON)");
    println!("  builder.add_json_batch(json_logs);");
    println!();
    println!("  // Parse directly");
    println!("  let entry = parse_json_log(json_string)?;");
    println!("  let entries = parse_json_logs(json_batch)?;");
}