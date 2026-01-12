# Configuration Guide - IronSift

## 🎯 Overview

IronSift's behavior can be customized through the `DetectionConfig` structure. This guide explains each parameter, its impact on detection, and how to tune it for your environment.

---

## 📋 Configuration Parameters

### Core Detection Parameters

#### 1. `entropy_threshold` (default: `4.5`)

**What it does:** Sets the threshold for detecting obfuscated or encoded command arguments using Shannon entropy.

**Impact:**
- **Lower values** (3.0-4.0): More sensitive - catches more obfuscation but may flag complex legitimate commands
- **Higher values** (5.0-6.0): Less sensitive - only catches highly random/encoded strings
- **Default** (4.5): Balanced - catches base64, hex encoding, and random strings

**When to adjust:**
- **Decrease** if you have simple commands and want to catch even slightly obfuscated strings
- **Increase** if you have complex build paths or legitimate encoded data in arguments

**Examples:**
```rust
// Sensitive detection
config.entropy_threshold = 4.0;  // Catches more obfuscation

// Balanced (default)
config.entropy_threshold = 4.5;  // Good for most environments

// Relaxed detection  
config.entropy_threshold = 5.5;  // Only highly random strings
```

**What gets flagged:**
- Entropy < 3.0: Normal paths, simple commands
- Entropy 3.0-4.5: Complex paths, some base64
- Entropy 4.5-5.5: Obfuscated commands, base64, hex
- Entropy > 5.5: Highly random, encrypted, malicious

**Technical note:** Entropy is calculated on normalized arguments (path separators removed) to avoid false positives from long legitimate paths like `/home/ecbuilds/project/subproject/file`.

---

#### 2. `dbscan_tolerance` (default: `0.05`)

**What it does:** DBSCAN epsilon parameter - maximum distance between points in a cluster.

**Impact:**
- **Lower values** (0.01-0.03): Stricter clustering - more machines flagged as anomalies
- **Higher values** (0.10-0.15): Looser clustering - fewer anomalies detected
- **Default** (0.05): Balanced - catches outliers while minimizing false positives

**When to adjust:**
- **Decrease** to 0.03 when you want very strict detection (catches subtle differences)
- **Increase** to 0.10 when you have high legitimate variance in your fleet

**Visual guide:**
```
Tolerance: 0.01  ████████████████ (Very strict - many anomalies)
Tolerance: 0.03  ██████████       (Strict - sensitive detection)
Tolerance: 0.05  ██████           (Default - balanced) ⭐
Tolerance: 0.08  ████             (Relaxed - fewer flags)
Tolerance: 0.10  ██               (Very relaxed - obvious outliers only)
```

**Examples:**
```rust
// High security environment
config.dbscan_tolerance = 0.03;  // Catch subtle anomalies

// Production monitoring
config.dbscan_tolerance = 0.05;  // Balance false positives

// Heterogeneous fleet
config.dbscan_tolerance = 0.10;  // Reduce noise
```

**Rule of thumb:**
- Start with 0.05 (default)
- If too many false positives → increase by 0.02
- If missing known compromises → decrease by 0.02

---

#### 3. `dbscan_min_samples` (default: `2`)

**What it does:** Minimum number of machines to form a cluster.

**Impact:**
- **Lower values** (1-2): More sensitive - smaller groups considered normal
- **Higher values** (3-5): Less sensitive - requires larger groups for "normal" behavior

**When to adjust:**
- **Keep at 2** for most use cases (default works well)
- **Increase to 3-4** if you have 100+ machines and want to reduce noise
- **Rarely needs adjustment** - tolerance is more important

**Examples:**
```rust
// Small fleet (< 50 machines)
config.dbscan_min_samples = 2;  // Default

// Large fleet (100+ machines)  
config.dbscan_min_samples = 3;  // Require bigger clusters
```

---

#### 4. `minority_cluster_ratio` (default: `0.10`)

**What it does:** Cluster size threshold as percentage of fleet. Clusters smaller than this are flagged.

**Impact:**
- **Lower values** (0.05-0.08): Flag smaller clusters as anomalies
- **Higher values** (0.15-0.20): Only flag very small clusters
- **Default** (0.10): Clusters with < 10% of machines are suspicious

**When to adjust:**
- **Decrease** to catch smaller groups of compromised machines
- **Increase** if you have legitimate minority configurations

**Examples:**
```rust
// 100 machines, default 0.10
// Flags clusters with < 10 machines

// More sensitive
config.minority_cluster_ratio = 0.05;  // Flags clusters < 5 machines

// Less sensitive
config.minority_cluster_ratio = 0.15;  // Only flags clusters < 15 machines
```

---

### Path and Pattern Detection

#### 5. `suspicious_path_patterns` (default: see below)

**What it does:** Regex patterns matching suspicious execution paths.

**Default patterns:**
```rust
vec![
    r"/tmp/",                      // Temporary directory
    r"/dev/shm/",                  // Shared memory (common for miners)
    r"/var/tmp/",                  // Temp variant
    r"/home/[^/]+/\.[^/]+",       // Hidden dirs in home
    r"^\./",                       // Relative paths
]
```

**When to adjust:**
- **Add patterns** for your environment's unusual locations
- **Remove patterns** if they cause false positives

**Examples:**
```rust
// Add custom suspicious paths
config.suspicious_path_patterns.push(r"/opt/malware/".to_string());
config.suspicious_path_patterns.push(r"^\.\.\/".to_string());  // Parent directory

// Remove /tmp if it's legitimately used
config.suspicious_path_patterns.retain(|p| !p.contains("/tmp/"));
```

---

### Linux Kernel Thread Handling

#### 6. `exclude_kernel_threads` (default: `true`)

**What it does:** Filter out Linux kernel threads (names like `[kworker/1:0]`, `[migration/0]`).

**Impact:**
- **true**: Excludes kernel threads from analysis (recommended)
- **false**: Includes kernel threads (may add noise)

**When to adjust:**
- **Keep true** (default) for most cases
- **Set false** only if you specifically want to analyze kernel thread patterns

**Examples:**
```rust
// Default: exclude kernel threads
config.exclude_kernel_threads = true;

// Include everything (not recommended)
config.exclude_kernel_threads = false;
```

**What gets excluded:**
- `[kworker/1:0]` - Kernel worker threads
- `[migration/0]` - CPU migration threads
- `[ksoftirqd/1]` - Software interrupt daemon
- Any process name matching `[*]` pattern

---

### Advanced Filtering Features 🆕

#### 7. `exclude_init_children` (default: `false`)

**What it does:** Filter out processes that are direct children of init/systemd (PPID = 1).

**Impact:**
- **true**: Excludes system services started by init - reduces noise from legitimate daemons
- **false**: Includes all processes regardless of parent (default)

**When to adjust:**
- **Enable (true)** for workstations, containers, or CI/CD environments with many system services
- **Enable (true)** when you trust your system service configuration
- **Keep disabled (false)** for servers on first analysis
- **Keep disabled (false)** when system services might be compromised

**Examples:**
```rust
// Workstation/Container setup (reduce noise)
config.exclude_init_children = true;

// Server analysis (include everything)
config.exclude_init_children = false;
```

**What gets excluded when enabled:**
- `sshd` (PPID=1) - SSH daemon
- `cron` (PPID=1) - Cron daemon
- `dockerd` (PPID=1) - Docker daemon
- `nginx` (PPID=1) - Web server master process
- Any process with PPID = 1

**Impact on results:**
- Reduces process signatures by 30-50%
- Focuses analysis on user-space activity
- Significantly reduces false positives in specialized environments

**Debug output:** Enable `debug_ppid_resolution` to see what's being filtered.

---

#### 8. `whitelisted_path_patterns` (default: `[]`)

**What it does:** Glob-style patterns for paths that should NOT be flagged as suspicious, even if they match suspicious patterns.

**Impact:**
- Whitelisted paths take priority over `suspicious_path_patterns`
- Prevents false positives from known-good installations
- Supports wildcards: `*` (any characters) and `?` (single character)

**When to use:**
- Data science environments (conda, venv installations in unusual locations)
- Custom application deployments in `/tmp` or `/opt`
- Development containers with legitimate non-standard paths

**Examples:**
```rust
// Data science workstation
config.whitelisted_path_patterns = vec![
    "/opt/conda/*".to_string(),
    "/home/*/anaconda3/*".to_string(),
    "/home/*/venv/*".to_string(),
];

// Custom application in /opt
config.whitelisted_path_patterns = vec![
    "/opt/company-app/*".to_string(),
];

// Multiple patterns
config.whitelisted_path_patterns = vec![
    "/usr/local/*".to_string(),      // All of /usr/local
    "/opt/custom/*".to_string(),      // Custom directory
    "/home/*/workspace/*".to_string(), // User workspaces
];
```

**Wildcard examples:**
- `/opt/conda/*` → matches `/opt/conda/bin/python`, `/opt/conda/lib/libssl.so`
- `/home/*/venv/*` → matches `/home/alice/venv/bin/pip`, `/home/bob/venv/lib/python3`
- `/usr/local/bin/?` → matches `/usr/local/bin/x` but not `/usr/local/bin/ls`

**Priority:** Whitelist > Suspicious patterns (whitelisted paths are NEVER flagged)

**Impact on results:**
- Can reduce false positives by 90% in specialized environments
- Example: 100-machine fleet with data science tools
  - Without whitelist: 20 false positives
  - With whitelist: 2 false positives

**Best practices:**
- Be specific - whitelist only paths you control
- Test before production
- Document why each pattern is whitelisted
- Don't whitelist entire `/tmp/` or `/opt/` - be surgical

**See also:** `ADVANCED_FILTERING.md` for detailed examples and use cases.

---

### Root Process Detection

#### 9. `flag_unexpected_root` (default: `true`)

**What it does:** Flag processes running as root (UID 0) that aren't in the common list.

**Impact:**
- **true**: Unexpected root processes are flagged as suspicious
- **false**: Root processes are not considered suspicious

**When to adjust:**
- **Keep true** for security-focused environments
- **Set false** if your environment has many legitimate root processes

**Examples:**
```rust
// Security-focused (default)
config.flag_unexpected_root = true;

// Permissive environment
config.flag_unexpected_root = false;
```

---

#### 10. `common_root_processes` (default: system services)

**What it does:** List of process names that legitimately run as root and should not be flagged.

**Default list includes:**
- `systemd`, `init` - System initialization
- `sshd`, `cron`, `rsyslogd` - Standard daemons
- `dockerd`, `containerd`, `kubelet` - Container runtimes
- `systemd-*` - systemd components
- And 10+ more common services

**When to adjust:**
- **Add** your organization's legitimate root processes
- **Remove** entries if you want to flag them

**Examples:**
```rust
// Add custom root process
config.common_root_processes.push("custom-daemon".to_string());

// Add all processes starting with "corp-"
config.common_root_processes.push("corp-".to_string());

// Clear list and start fresh
config.common_root_processes = vec![
    "systemd".to_string(),
    "sshd".to_string(),
    // ... add only what you need
];
```

**Best practice:** Audit your root processes and add legitimate ones to reduce false positives.

---

### Debug and Analysis

#### 11. `debug_ppid_resolution` (default: `false`)

**What it does:** Enable detailed debugging output for parent process resolution.

**Impact:**
- **true**: Prints PPID resolution statistics and warnings
- **false**: Silent operation (normal)

**When to enable:**
- Troubleshooting parent-child relationship issues
- Understanding process tree resolution
- Debugging unresolved PPIDs

**Example output when enabled:**
```
🔍 PPID Resolution Debug Info:
   Total entries to process: 2020
   Resolved 2015 PID-to-name mappings
   Sample mappings:
     server1:100 -> nginx
     server1:200 -> postgres
     
   Kernel thread filtering:
     Before: 2020 entries
     After: 1850 entries
     Filtered out: 170 kernel threads
     
   Grouped into 20 machines

⚠️  Unresolved PPID for server5:miner (PPID: 9999)
```

**Examples:**
```rust
// Enable for debugging
config.debug_ppid_resolution = true;

// Normal operation (default)
config.debug_ppid_resolution = false;
```

---

#### 12. `normalize_features` (default: `true`)

**What it does:** Apply L2 normalization to feature vectors before clustering.

**Impact:**
- **true**: Normalizes feature vectors (recommended for distance-based clustering)
- **false**: Raw TF-IDF values (may bias toward high-frequency features)

**When to adjust:**
- **Keep true** (default) for DBSCAN and distance-based algorithms
- **Set false** only for experimentation or specific clustering algorithms

**Technical note:** L2 normalization makes feature vectors unit length, ensuring distance calculations aren't biased by vector magnitude.

---

## 🎯 Preset Configurations

### High Security (Strict Detection)

```rust
let config = DetectionConfig {
    entropy_threshold: 4.0,           // Lower threshold
    dbscan_tolerance: 0.03,           // Stricter clustering
    dbscan_min_samples: 2,
    minority_cluster_ratio: 0.05,     // Flag smaller clusters
    exclude_kernel_threads: true,
    exclude_init_children: false,     // Include init children
    flag_unexpected_root: true,       // Flag unexpected root
    debug_ppid_resolution: false,
    whitelisted_path_patterns: vec![], // No whitelist
    ..DetectionConfig::default()
};
```

**Use when:** Maximum security, can tolerate more false positives

---

### Balanced (Default)

```rust
let config = DetectionConfig::default();
```

**Use when:** General-purpose detection, good balance

---

### Production Monitoring (Fewer False Positives)

```rust
let config = DetectionConfig {
    entropy_threshold: 5.0,           // Higher threshold
    dbscan_tolerance: 0.08,           // Looser clustering
    minority_cluster_ratio: 0.15,     // Larger minority threshold
    exclude_kernel_threads: true,
    exclude_init_children: false,     // Include init children
    flag_unexpected_root: true,
    whitelisted_path_patterns: vec![], // Add as needed
    ..DetectionConfig::default()
};
```

**Use when:** Heterogeneous fleet, want to reduce alert fatigue

---

### Data Science Workstation 🆕

```rust
let config = DetectionConfig {
    entropy_threshold: 4.5,
    dbscan_tolerance: 0.05,
    exclude_kernel_threads: true,
    exclude_init_children: true,      // Exclude system services
    flag_unexpected_root: true,
    whitelisted_path_patterns: vec![
        "/opt/conda/*".to_string(),
        "/home/*/anaconda3/*".to_string(),
        "/home/*/venv/*".to_string(),
        "/home/*/jupyter/*".to_string(),
    ],
    ..DetectionConfig::default()
};
```

**Use when:** Data science environments with many Python installations

---

### Container Environment 🆕

```rust
let config = DetectionConfig {
    entropy_threshold: 4.5,
    dbscan_tolerance: 0.05,
    exclude_kernel_threads: true,
    exclude_init_children: true,      // Focus on container processes
    flag_unexpected_root: false,      // Many legitimate root processes
    whitelisted_path_patterns: vec![
        "/app/*".to_string(),
        "/opt/app/*".to_string(),
    ],
    ..DetectionConfig::default()
};
```

**Use when:** Analyzing containerized applications

---

### Permissive (Minimal False Positives)

```rust
let config = DetectionConfig {
    entropy_threshold: 5.5,           // Very high threshold
    dbscan_tolerance: 0.10,           // Very loose clustering
    minority_cluster_ratio: 0.20,     // Large minority threshold
    exclude_init_children: true,      // Exclude system services
    flag_unexpected_root: false,      // Don't flag root
    whitelisted_path_patterns: vec![], // Add as needed
    ..DetectionConfig::default()
};
```

**Use when:** Development environments, mixed workloads

---

## 📊 Tuning Workflow

### Step 1: Start with Defaults

```rust
let config = DetectionConfig::default();
```

Run analysis and observe results.

### Step 2: Adjust Based on Results

**Too many false positives?**
- Increase `dbscan_tolerance` by 0.02-0.03
- Increase `entropy_threshold` by 0.5
- Add legitimate root processes to `common_root_processes`
- Enable `exclude_init_children` for workstations/containers
- Add known-good paths to `whitelisted_path_patterns`

**Missing known compromises?**
- Decrease `dbscan_tolerance` by 0.01-0.02
- Decrease `entropy_threshold` by 0.5
- Disable `exclude_init_children` to include system services
- Enable `debug_ppid_resolution` to understand process relationships

### Step 3: Refine

Fine-tune parameters iteratively:
1. Adjust one parameter at a time
2. Test on known good/bad cases
3. Document your configuration

### Step 4: Save Configuration

```rust
// Save to file
config.to_file("ironsift_config.json")?;

// Load from file
let config = DetectionConfig::from_file("ironsift_config.json")?;
```

---

## 🎓 Understanding the Impact

### Entropy Threshold Impact

| Value | False Positives | False Negatives | Best For |
|-------|----------------|-----------------|----------|
| 3.5 | High | Very Low | High security |
| 4.0 | Medium | Low | Strict detection |
| **4.5** | **Low** | **Low** | **General use** ⭐ |
| 5.0 | Very Low | Medium | Production |
| 5.5+ | Minimal | High | Permissive |

### Tolerance Impact

| Value | Anomalies Detected | Precision | Best For |
|-------|-------------------|-----------|----------|
| 0.01 | Very High | Low | Research |
| 0.03 | High | Medium | Strict |
| **0.05** | **Medium** | **High** | **Balanced** ⭐ |
| 0.08 | Low | Very High | Production |
| 0.10+ | Very Low | Highest | Heterogeneous |

### Advanced Filtering Impact 🆕

| Configuration | Anomalies | False Positives | FP Reduction |
|---------------|-----------|-----------------|--------------|
| Default | 25 | 20 | 0% (baseline) |
| + Init filtering | 15 | 10 | 50% |
| + Path whitelist | 12 | 8 | 60% |
| **Both combined** | **5** | **2** | **90%** |

---

## 💡 Quick Tips

1. **Start conservative** - Use default config, then relax if needed
2. **Test on known data** - Validate with known good/bad machines
3. **One change at a time** - Easier to understand impact
4. **Document decisions** - Keep notes on why you chose values
5. **Monitor over time** - Revalidate as your fleet evolves
6. **Use filtering wisely** - `exclude_init_children` and `whitelisted_path_patterns` are powerful tools
7. **Check documentation** - See `ADVANCED_FILTERING.md` for detailed filtering examples

---

## 📝 Example: Custom Configuration

```rust
use ironsift::DetectionConfig;

fn main() {
    // Start with defaults
    let mut config = DetectionConfig::default();
    
    // Customize for your environment
    config.entropy_threshold = 4.8;  // Slightly higher
    config.dbscan_tolerance = 0.06;  // Slightly looser
    
    // Enable advanced filtering
    config.exclude_init_children = true;
    
    // Add your legitimate root processes
    config.common_root_processes.push("my-custom-daemon".to_string());
    config.common_root_processes.push("corp-agent".to_string());
    
    // Whitelist known-good paths
    config.whitelisted_path_patterns = vec![
        "/opt/company-app/*".to_string(),
        "/usr/local/*".to_string(),
    ];
    
    // Add suspicious paths
    config.suspicious_path_patterns.push(r"/opt/suspicious/".to_string());
    
    // Save for reuse
    config.to_file("my_config.json").unwrap();
    
    println!("Configuration saved!");
}
```

---

## 🔧 Configuration File Format

JSON format for easy editing:

```json
{
  "entropy_threshold": 4.5,
  "minority_cluster_ratio": 0.1,
  "dbscan_tolerance": 0.05,
  "dbscan_min_samples": 2,
  "normalize_features": true,
  "suspicious_path_patterns": [
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/"
  ],
  "exclude_kernel_threads": true,
  "exclude_init_children": false,
  "whitelisted_path_patterns": [
    "/opt/conda/*",
    "/home/*/venv/*"
  ],
  "common_root_processes": [
    "systemd",
    "init",
    "sshd",
    "dockerd"
  ],
  "flag_unexpected_root": true,
  "debug_ppid_resolution": false
}
```

---

**IronSift v0.3.0 - Tune It Your Way!** 🎯🔧