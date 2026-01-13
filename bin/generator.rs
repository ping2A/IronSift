use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::env;
use rand::Rng;
use chrono::{Utc, Duration};

use ironsift::RawLogEntry;

const NUM_MACHINES: u32 = 20;
const LOGS_PER_MACHINE: u32 = 100;

enum OutputFormat {
    Csv,
    Json,
}

fn print_usage() {
    println!("Usage: generator [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --json    Generate JSON output (test_dataset.json)");
    println!("  --csv     Generate CSV output (test_dataset.csv) [default]");
    println!("  --help    Show this help message");
    println!();
    println!("Examples:");
    println!("  generator           # Generate CSV (default)");
    println!("  generator --json    # Generate JSON");
    println!("  generator --csv     # Generate CSV (explicit)");
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    // Parse arguments
    let mut format = OutputFormat::Csv;
    
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            "--csv" => format = OutputFormat::Csv,
            "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_usage();
                return Err("Invalid argument".into());
            }
        }
    }
    
    let output_file = match format {
        OutputFormat::Csv => "test_dataset.csv",
        OutputFormat::Json => "test_dataset.json",
    };
    
    let format_name = match format {
        OutputFormat::Csv => "CSV",
        OutputFormat::Json => "JSON",
    };
    
    println!("{:=^60}", " IRONSIFT DATA GENERATOR ");
    println!();
    println!("Format: {}", format_name);
    println!("Generating {} logs for {} machines...", 
        NUM_MACHINES * LOGS_PER_MACHINE, NUM_MACHINES);
    println!("Output: {}", output_file);
    println!();
    
    // Generate all log entries
    let entries = generate_log_entries()?;
    
    // Write in the requested format
    match format {
        OutputFormat::Csv => write_csv(&entries, output_file)?,
        OutputFormat::Json => write_json(&entries, output_file)?,
    }
    
    println!();
    println!("✅ Done! Dataset written to '{}'", output_file);
    println!("   {} machines, {} total process logs", NUM_MACHINES, entries.len());
    println!();
    print_detection_instructions(output_file);
    
    Ok(())
}

fn generate_log_entries() -> Result<Vec<RawLogEntry>, Box<dyn Error>> {
    let mut rng = rand::thread_rng();
    let mut entries = Vec::new();
    
    // Start time: 7 days ago
    let mut current_time = Utc::now() - Duration::days(7);

    // Define normal processes
    let normal_processes = vec![
        ("nginx", 100, "/usr/sbin/nginx", "-c /etc/nginx/nginx.conf", 33),
        ("sshd", 101, "/usr/sbin/sshd", "-D", 0),
        ("postgres", 102, "/usr/lib/postgresql/14/bin/postgres", "-D /var/lib/postgresql/data", 70),
        ("node", 103, "/usr/bin/node", "server.js", 1000),
        ("python3", 104, "/usr/bin/python3", "app.py", 1000),
        ("cron", 105, "/usr/sbin/cron", "-f", 0),
        ("dockerd", 106, "/usr/bin/dockerd", "-H fd://", 0),
        ("redis-server", 107, "/usr/bin/redis-server", "/etc/redis/redis.conf", 999),
        ("apache2", 108, "/usr/sbin/apache2", "-k start", 33),
        ("mysqld", 109, "/usr/sbin/mysqld", "--defaults-file=/etc/mysql/my.cnf", 999),
    ];

    // Attack scenarios
    // Note: These are test patterns designed to trigger ML detection via high entropy
    // They are NOT actual malicious code and won't trigger antivirus
    let miner_processes = [
        ("kworker", "/tmp/.X11-unix/kworker", "--config XkzL9s0f8Ha@2#mK --server pool.example.test:4444", 0),
        ("systemd", "/var/tmp/.cache/systemd", "--threads 8 --algo rx/0 --url test.pool.local:3333", 0),
        ("[kthreadd]", "/dev/shm/.config/worker", "--benchmark QpR5tY8uI2#kL --port 14444", 0),
    ];
    
    // Web shell test patterns (high entropy, not actual code)
    let web_shell_payloads = [
        "proc_handler(req_decode('aGVsbG8gd29ybGQ='));",
        "execute_dynamic($_REQUEST['q']);",
        "<?method invoke_runtime($_DATA['z']);?>",
        "runtime_call(decode_param('ZWNobyBzeXN0ZW0='));",
        "<?dynamic_invoke(uncompress(decode_b64('K0ktSgEA')));?>",
        "run_shell('cmd /c type secrets.txt | encode');",
    ];
    
    let privesc_processes = [
        ("node", "/home/appuser/.npm/node", "suspicious_test.js", 0),
        ("python3", "/tmp/setup.py", "install --unsafe", 0),
        ("bash", "/home/ubuntu/.bashrc.d/init", "", 0),
    ];
    
    let lateral_movement = [
        ("ssh", "/usr/bin/ssh", "-o StrictHostKeyChecking=no root@10.0.1.5", 0),
        ("ssh", "/usr/bin/ssh", "root@192.168.1.10", 0),
        ("ssh", "/usr/bin/ssh", "-i /tmp/.ssh/id_rsa admin@172.16.0.50", 0),
        ("scp", "/usr/bin/scp", "-r /etc/config user@192.168.1.100:/tmp", 0),
        ("ssh", "/usr/bin/ssh", "root@10.0.2.15 'cat /tmp/data.txt'", 0),
    ];

    println!("Scenario Overview:");
    println!("  🔹 14 clean machines (normal operations)");
    println!("  🔸 2 cryptominers (machine_003, machine_017)");
    println!("  🔸 1 web shell (machine_009)");
    println!("  🔸 2 privilege escalation (machine_006, machine_015)");
    println!("  🔸 1 lateral movement (machine_012)");
    println!();
    println!("Malicious Machines Summary:");
    println!("  • machine_003: Cryptominer in /tmp/.X11-unix/kworker");
    println!("  • machine_006: Privilege escalation (node running as root)");
    println!("  • machine_009: Web shell (php-fpm with dynamic code execution)");
    println!("  • machine_012: Lateral movement (SSH to internal IPs)");
    println!("  • machine_015: Privilege escalation (python3 in /tmp)");
    println!("  • machine_017: Cryptominer in /dev/shm/.config/worker");
    println!();

    for i in 0..NUM_MACHINES {
        let machine_id = format!("machine_{:03}", i);
        
        if i % 10 == 0 {
            println!("📊 Processing batch: {}...", machine_id);
        }

        // Always create systemd as PID 1
        entries.push(RawLogEntry {
            machine_id: machine_id.clone(),
            pid: 1,
            ppid: 0,
            name: "systemd".to_string(),
            uid: 0,
            path: "/usr/lib/systemd/systemd".to_string(),
            args: "--system".to_string(),
            timestamp: Some(current_time.to_rfc3339()),
        });

        // ⭐ FIX: Use sequential PID counter per machine to avoid collisions
        let mut next_pid = 100u32;  // Start from PID 100
        
        // Track specific parent PIDs for attack scenarios
        let mut apache2_pid: Option<u32> = None;
        let mut node_pid: Option<u32> = None;
        let mut sshd_pid: Option<u32> = None;
        
        for _log_idx in 0..LOGS_PER_MACHINE {
            current_time = current_time + Duration::seconds(rng.gen_range(60..300));
            let timestamp = current_time.to_rfc3339();
            
            let template = normal_processes[rng.gen_range(0..normal_processes.len())];
            let (mut name, _base_pid, mut path, args_ref, mut uid) = template;
            let mut args = args_ref.to_string();
            let pid = next_pid;  // ⭐ Use sequential PID
            next_pid += 1;       // ⭐ Increment for next process
            let mut ppid = 1;
            
            // Track parent processes for later reference
            if name == "apache2" && apache2_pid.is_none() {
                apache2_pid = Some(pid);
            }
            if name == "node" && node_pid.is_none() {
                node_pid = Some(pid);
            }
            if name == "sshd" && sshd_pid.is_none() {
                sshd_pid = Some(pid);
            }

            // Inject attack scenarios
            
            // Cryptominers (Machines 3, 17)
            if (i == 3 || i == 17) && rng.gen_bool(0.15) {
                let miner = miner_processes[rng.gen_range(0..miner_processes.len())];
                name = miner.0;
                path = miner.1;
                args = miner.2.to_string();
                uid = miner.3;
                ppid = 1;
            }

            // Web Shells (Machine 9) - php-fpm with dynamic execution patterns
            if i == 9 && name == "apache2" {
                // Convert most apache2 to php-fpm (its child process)
                if rng.gen_bool(0.60) {
                    name = "php-fpm";
                    path = "/usr/sbin/php-fpm";
                    ppid = apache2_pid.unwrap_or(1); // ⭐ Use tracked apache2 PID or fallback to systemd
                    
                    // 50% of php-fpm processes get malicious payloads
                    if rng.gen_bool(0.50) {
                        args = web_shell_payloads[rng.gen_range(0..web_shell_payloads.len())].to_string();
                    } else {
                        args = "/usr/sbin/php-fpm --fpm-config /etc/php/fpm/php-fpm.conf".to_string();
                    }
                }
            }

            // Privilege Escalation (Machines 6, 15)
            if (i == 6 || i == 15) && rng.gen_bool(0.12) {
                let privesc = privesc_processes[rng.gen_range(0..privesc_processes.len())];
                name = privesc.0;
                path = privesc.1;
                args = privesc.2.to_string();
                uid = privesc.3;
                ppid = node_pid.unwrap_or(1); // ⭐ Use tracked node PID or fallback to systemd
            }

            // Lateral Movement (Machine 12) - SSH to internal IPs
            if i == 12 && rng.gen_bool(0.40) {
                // High frequency of SSH connections to internal IPs
                let lateral = lateral_movement[rng.gen_range(0..lateral_movement.len())];
                name = lateral.0;
                path = lateral.1;
                args = lateral.2.to_string();
                uid = lateral.3;
                ppid = sshd_pid.unwrap_or(1); // ⭐ Use tracked sshd PID or fallback to systemd
            }

            if rng.gen_bool(0.05) {
                args = format!("{} --debug", args);
            }

            entries.push(RawLogEntry {
                machine_id: machine_id.clone(),
                pid,
                ppid,
                name: name.to_string(),
                uid,
                path: path.to_string(),
                args,
                timestamp: Some(timestamp),
            });
        }
    }

    Ok(entries)
}

fn write_csv(entries: &[RawLogEntry], path: &str) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut wtr = csv::Writer::from_writer(file);
    
    for entry in entries {
        wtr.serialize(entry)?;
    }
    
    wtr.flush()?;
    Ok(())
}

fn write_json(entries: &[RawLogEntry], path: &str) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(path)?;
    
    // JSON Schema for IronSift:
    // 
    // REQUIRED KEYS (at least one from each group):
    //   Machine identifier: "machine_id", "hostname", "host", "server", "node", "container", "pod"
    //   Process info: EITHER:
    //     - "command", "cmd", "cmdline", "commandline" (full command line)
    //     OR
    //     - "name", "process", "process_name", "comm" (process name only)
    //
    // OPTIONAL KEYS (with defaults if missing):
    //   "pid", "process_id" (default: auto-generated)
    //   "ppid", "parent_pid" (default: 0)
    //   "uid", "user_id", "userid" (default: 1000)
    //   "path", "exe", "executable" (default: parsed from command or /usr/bin/{name})
    //   "args", "arguments", "params" (default: parsed from command or empty)
    //   "timestamp", "time", "datetime" (default: none)
    //
    // MINIMAL VALID EXAMPLE:
    //   {"host": "server1", "cmd": "nginx"}
    //
    // FULL EXAMPLE (what this generator produces):
    //   {"machine_id": "server1", "pid": 100, "ppid": 1, "name": "nginx", 
    //    "uid": 33, "path": "/usr/sbin/nginx", "args": "-c /etc/nginx.conf",
    //    "timestamp": "2025-01-06T10:00:00Z"}
    
    writeln!(file, "[")?;
    
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            writeln!(file, ",")?;
        }
        
        // Write all fields for complete compatibility
        // machine_id: REQUIRED - machine identifier
        // pid/ppid: OPTIONAL - will be auto-generated if not provided
        // name: REQUIRED (or can be derived from command)
        // uid: OPTIONAL - defaults to 1000 if not provided
        // path: OPTIONAL - can be parsed from command or name
        // args: OPTIONAL - can be parsed from command
        // timestamp: OPTIONAL - used for temporal analysis if provided
        write!(file, r#"  {{"machine_id": "{}", "pid": {}, "ppid": {}, "name": "{}", "uid": {}, "path": "{}", "args": "{}", "timestamp": "{}"}}"#,
            entry.machine_id,  // REQUIRED: machine identifier
            entry.pid,         // OPTIONAL: process ID (auto-generated if 0)
            entry.ppid,        // OPTIONAL: parent process ID (defaults to 0)
            entry.name,        // REQUIRED: process name
            entry.uid,         // OPTIONAL: user ID (defaults to 1000)
            entry.path,        // OPTIONAL: executable path
            entry.args.replace('"', "\\\""),  // OPTIONAL: command arguments
            entry.timestamp.as_ref().unwrap_or(&"".to_string())  // OPTIONAL: timestamp
        )?;
    }
    
    writeln!(file)?;
    writeln!(file, "]")?;
    
    Ok(())
}

fn print_detection_instructions(output_file: &str) {
    println!("{:=^80}", " DETECTION INSTRUCTIONS ");
    println!();
    println!("🎯 RECOMMENDED PARAMETERS FOR OPTIMAL DETECTION:");
    println!();
    println!("1. DEFAULT DETECTION (Good starting point):");
    println!("   cargo run --bin ironsift -- --input {}", output_file);
    println!();
    println!("2. SENSITIVE DETECTION (Catches more anomalies):");
    println!("   cargo run --bin ironsift -- --input {} --tolerance 0.05", output_file);
    println!("   • Lower tolerance = stricter clustering = more anomalies detected");
    println!("   • Should detect all 6 malicious machines");
    println!();
    println!("3. VERY SENSITIVE (May have false positives):");
    println!("   cargo run --bin ironsift -- --input {} --tolerance 0.03", output_file);
    println!("   • Very strict detection");
    println!("   • May flag some normal variations as anomalies");
    println!();
    println!("4. WITH JSON EXPORT:");
    println!("   cargo run --bin ironsift -- --input {} --tolerance 0.05 --export-json", output_file);
    println!("   • Creates detailed forensic report: forensic_report.json");
    println!();
    println!("{:-^80}", "");
    println!();
    println!("📊 EXPECTED RESULTS:");
    println!("   With --tolerance 0.05, you should detect:");
    println!();
    println!("   ⚠️  machine_003 (CRYPTOMINER)");
    println!("       • Process: kworker, systemd, [kthreadd] (fake kernel names)");
    println!("       • Path: /tmp/.X11-unix/kworker, /var/tmp/.cache/systemd");
    println!("       • Args: High entropy mining pool configs");
    println!("       • Risk: UID 0 (root), suspicious paths, high entropy");
    println!();
    println!("   ⚠️  machine_006 (PRIVILEGE ESCALATION)");
    println!("       • Process: node, python3, bash");
    println!("       • Path: /home/appuser/.npm/node, /tmp/setup.py");
    println!("       • Risk: Unexpected processes running as root (UID 0)");
    println!("       • Parent: node (PPID tracked)");
    println!();
    println!("   ⚠️  machine_009 (WEB SHELL) 🔴");
    println!("       • Process: php-fpm (child of apache2)");
    println!("       • Path: /usr/sbin/php-fpm");
    println!("       • Args: Dynamic code execution patterns");
    println!("       • Risk: High entropy payloads, runtime code execution");
    println!("       • Parent: apache2 (PPID tracked)");
    println!();
    println!("   ⚠️  machine_012 (LATERAL MOVEMENT)");
    println!("       • Process: ssh, scp");
    println!("       • Path: /usr/bin/ssh, /usr/bin/scp");
    println!("       • Args: Connections to internal IPs (10.0.x.x, 192.168.x.x)");
    println!("       • Risk: High frequency SSH to internal network");
    println!("       • Parent: sshd (PPID tracked)");
    println!();
    println!("   ⚠️  machine_015 (PRIVILEGE ESCALATION)");
    println!("       • Process: node, python3, bash");
    println!("       • Path: /home/appuser/.npm/node, /tmp/setup.py");
    println!("       • Risk: Unexpected processes running as root (UID 0)");
    println!("       • Parent: node (PPID tracked)");
    println!();
    println!("   ⚠️  machine_017 (CRYPTOMINER)");
    println!("       • Process: kworker, systemd, [kthreadd] (fake kernel names)");
    println!("       • Path: /dev/shm/.config/worker, /tmp/.X11-unix/kworker");
    println!("       • Args: High entropy mining pool configs");
    println!("       • Risk: UID 0 (root), suspicious paths, high entropy");
    println!();
    println!("💡 TIPS:");
    println!("   • Start with default, then lower tolerance if needed");
    println!("   • Check 'Attack Pattern Categorization' in output");
    println!("   • Export JSON for detailed forensic analysis");
    println!("   • All malicious processes have PPID correctly tracked");
    println!("   • Edit ironsift_config.json to customize detection");
    println!();
}