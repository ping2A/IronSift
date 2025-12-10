use std::error::Error;
use std::fs::File;
use rand::Rng;

// UPDATED IMPORT: Using the new project name 'ironsift'
use ironsift::RawLogEntry; 

const OUTPUT_FILE: &str = "large_dataset.csv";
const NUM_MACHINES: u32 = 100;
const LOGS_PER_MACHINE: u32 = 1_000;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== IRONSIFT GENERATOR ===");
    println!("Generating {} logs for {} machines...", NUM_MACHINES * LOGS_PER_MACHINE, NUM_MACHINES);
    
    let file = File::create(OUTPUT_FILE)?;
    let mut wtr = csv::Writer::from_writer(file);
    let mut rng = rand::thread_rng();

    // 1. Define Standard Traffic (The "Haystack")
    let normal_processes = vec![
        ("nginx", "systemd", 33, "/usr/sbin/nginx", "-c /etc/nginx/nginx.conf"),
        ("sshd", "systemd", 0, "/usr/sbin/sshd", "-D"),
        ("postgres", "systemd", 70, "/usr/lib/postgresql/bin/postgres", "-D /var/lib/postgresql/13/main"),
        ("node", "bash", 1000, "/usr/bin/node", "server.js"),
        ("cron", "systemd", 0, "/usr/sbin/cron", "-f"),
        ("dockerd", "systemd", 0, "/usr/bin/dockerd", "-H fd://"),
    ];

    // 2. Define Anomalies (The "Needles")
    let miner_bin = "/tmp/.X11-unix/kworker"; 
    let miner_args = "--url stratum+tcp://pool.mine.xmr";
    let web_shell_args = "eval(base64_decode('aGVsbG8gd29ybGQ='));"; 

    for i in 0..NUM_MACHINES {
        let machine_id = format!("machine_{:03}", i);
        // Visual progress indicator every 10 machines
        if i % 10 == 0 { println!("Processing batch starting at {}...", machine_id); }

        for _ in 0..LOGS_PER_MACHINE {
            let template = normal_processes[rng.gen_range(0..normal_processes.len())];
            let (mut name, mut parent, mut uid, mut path, mut args) = template;

            // --- INJECT ANOMALIES ---
            
            // Scenario A: Machine 13 is infected with a Miner
            if i == 13 && rng.gen_bool(0.05) {
                name = "kworker"; 
                path = miner_bin; 
                args = miner_args;
            }

            // Scenario B: Machine 88 has a Web Shell (High Entropy)
            if i == 88 && rng.gen_bool(0.02) {
                name = "php-fpm";
                args = web_shell_args;
            }

            // Scenario C: Machine 42 is running Rootkit
            if i == 42 && name == "node" && rng.gen_bool(0.10) {
                uid = 0; 
            }

            wtr.serialize(RawLogEntry {
                machine_id: machine_id.clone(),
                name: name.to_string(),
                parent: parent.to_string(),
                uid,
                path: path.to_string(),
                args: args.to_string(),
            })?;
        }
    }

    wtr.flush()?;
    println!("Done! Data written to '{}'.", OUTPUT_FILE);
    Ok(())
}