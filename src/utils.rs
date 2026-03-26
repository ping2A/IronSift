//! Utility functions: entropy, path matching, command-line parsing.

use std::collections::HashMap;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;

pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let normalized = s
        .replace('/', " ")
        .replace('.', " ")
        .replace('-', " ")
        .replace('_', " ");

    let mut counts = HashMap::new();
    for c in normalized.chars() {
        if !c.is_whitespace() {
            *counts.entry(c).or_insert(0) += 1;
        }
    }

    if counts.is_empty() {
        return 0.0;
    }

    let len = normalized.chars().filter(|c| !c.is_whitespace()).count() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let entropy = counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    });

    entropy
}

/// Check if a path matches a glob-style pattern with wildcards (* and ?)
pub fn matches_wildcard(path: &str, pattern: &str) -> bool {
    let mut regex_pattern = String::new();
    regex_pattern.push('^');

    for ch in pattern.chars() {
        match ch {
            '*' => regex_pattern.push_str(".*"),
            '?' => regex_pattern.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex_pattern.push('\\');
                regex_pattern.push(ch);
            }
            _ => regex_pattern.push(ch),
        }
    }

    regex_pattern.push('$');

    Regex::new(&regex_pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

/// Check if path matches any whitelisted pattern
pub fn is_path_whitelisted(path: &str, whitelist: &[String]) -> bool {
    whitelist.iter().any(|pattern| matches_wildcard(path, pattern))
}

pub fn is_path_suspicious(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        Regex::new(pattern)
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    })
}

/// Parse timestamps from RFC3339 or common `T`/space-separated naive datetimes (e.g. `date` / `timestamp` in JSONL).
pub fn parse_log_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&naive));
        }
    }
    None
}

/// Interpret `ls -l` style permission strings (e.g. `-rw-------.`) for group / world write bits.
pub fn unix_permission_flags(ls_perm: &str) -> (bool, bool) {
    let p = ls_perm.trim().trim_end_matches('.');
    let b = p.as_bytes();
    if b.len() < 10 {
        return (false, false);
    }
    let group_writable = b[5] == b'w';
    let world_writable = b[8] == b'w';
    (world_writable, group_writable)
}

/// Parse a command line into (name, path, args)
pub fn parse_command_line(command: &str) -> (String, String, String) {
    let command = command.trim();

    if command.is_empty() {
        return (String::new(), String::new(), String::new());
    }

    if command.starts_with('[') && command.ends_with(']') {
        return (command.to_string(), command.to_string(), String::new());
    }

    let parts = parse_command_parts(command);

    if parts.is_empty() {
        return (String::new(), String::new(), String::new());
    }

    let path = parts[0].clone();
    let args = if parts.len() > 1 {
        parts[1..].join(" ")
    } else {
        String::new()
    };

    let name = if let Some(pos) = path.rfind('/') {
        path[pos + 1..].to_string()
    } else {
        path.clone()
    };

    (name, path, args)
}

/// Parse command line respecting quotes
pub(crate) fn parse_command_parts(command: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}
