#!/usr/bin/env bash
# Test generator output and ironsift analysis to catch regressions.
# Run from repo root: ./scripts/test_generator_ironsift.sh
# Usage: ./scripts/test_generator_ironsift.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROCESS_CSV="test_dataset.csv"
PROCESS_JSON="test_dataset.json"
FILES_CSV="test_files_dataset.csv"
FILES_JSON="test_files_dataset.json"

# Must match bin/generator.rs defaults (NUM_MACHINES, LOGS_PER_MACHINE, entry layout)
EXPECTED_PROCESS_HEADER="machine_id,pid,ppid,name,uid,path,args,timestamp"
EXPECTED_PROCESS_CSV_LINES=2021
EXPECTED_FILES_HEADER="machine_id,path,uid,timestamp,mtime,permissions,owner,group,size"
EXPECTED_FILES_CSV_LINES=2001

# Must match `generate_file_entries()` in bin/generator.rs (injected scenarios only). Clean hosts may
# legitimately be absent from the anomaly list once fleet clustering matches them to the majority.
EXPECTED_FILE_SCENARIO_HOSTS=(
    machine_003 machine_005 machine_006 machine_007 machine_009
    machine_011 machine_012 machine_014 machine_015 machine_017
)

# Seeded process data (DATASET_RNG_SEED in bin/generator.rs): DBSCAN epsilon 0.40 flags exactly these six
# injected scenario hosts — no benign outliers. Must stay in sync with analysis (see tolerance sweep).
PROCESS_REGRESSION_TOLERANCE="0.40"
EXPECTED_PROCESS_ANOMALY_EXACT=(
    machine_003 machine_006 machine_009 machine_012 machine_015 machine_017
)

PASS=0
FAIL=0
GENERATOR_LOG="$REPO_ROOT/scripts/.generator_run.log"
PROCESS_REPORT="$REPO_ROOT/scripts/.ironsift_process_report.json"

run_step() {
    local name="$1"
    shift
    printf "  %s ... " "$name"
    if "$@" > "$REPO_ROOT/scripts/.ironsift_test_out" 2>&1; then
        echo "OK"
        ((PASS++)) || true
        return 0
    else
        echo "FAIL"
        ((FAIL++)) || true
        echo "--- output ---"
        cat "$REPO_ROOT/scripts/.ironsift_test_out"
        echo "--- end ---"
        return 1
    fi
}

run_step_quiet() {
    local name="$1"
    shift
    printf "  %s ... " "$name"
    if "$@" > "$REPO_ROOT/scripts/.ironsift_test_out" 2>&1; then
        echo "OK"
        ((PASS++)) || true
        return 0
    else
        echo "FAIL"
        ((FAIL++)) || true
        echo "--- output ---"
        cat "$REPO_ROOT/scripts/.ironsift_test_out"
        echo "--- end ---"
        return 1
    fi
}

expect_substrings_in_file() {
    local log_file="$1"
    shift
    local s
    for s in "$@"; do
        if ! grep -Fq "$s" "$log_file"; then
            echo "FAIL: generator output missing expected line:"
            echo "  → $s"
            echo "--- generator log (tail) ---"
            tail -n 40 "$log_file" || cat "$log_file"
            echo "--- end ---"
            return 1
        fi
    done
    return 0
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FAIL: jq is required to verify IronSift anomaly machine_id lists (install jq)."
        return 1
    fi
    return 0
}

# Forensic JSON uses investigation_targets[].machine_id (see src/report.rs export_json).
check_process_report_json() {
    local json_path="$1"
    local ids n
    ids=$(jq -r '.investigation_targets[].machine_id' "$json_path" | sort -u | tr '\n' ' ')
    n=$(jq '.investigation_targets | length' "$json_path")
    if [[ "$n" -ne ${#EXPECTED_PROCESS_ANOMALY_EXACT[@]} ]]; then
        echo "FAIL: expected exactly ${#EXPECTED_PROCESS_ANOMALY_EXACT[@]} process anomalies, got $n"
        echo "  machine_ids: $ids"
        return 1
    fi
    if ! jq -e '([.investigation_targets[].machine_id] | sort) == ["machine_003","machine_006","machine_009","machine_012","machine_015","machine_017"]' "$json_path" >/dev/null; then
        echo "FAIL: investigation_targets must match exactly the six seeded scenario hosts (no extras, no misses)"
        echo "  got: $ids"
        return 1
    fi
    return 0
}

# Heuristic checks on human-readable report. Buckets are derived from the first matching
# signature per machine (see print_attack_summary), so miner hosts can appear under
# "Suspicious Execution Paths" instead of "Cryptomining".
check_process_attack_patterns_stdout() {
    local out="$1"
    local block
    block=$(sed -n '/--- Detected Attack Patterns ---/,/Recommended Actions/p' <<< "$out")
    if [[ -z "$block" ]]; then
        echo "FAIL: missing Detected Attack Patterns section"
        return 1
    fi
    local h
    for h in machine_003 machine_006 machine_009 machine_015 machine_017; do
        if ! grep -Fq "$h" <<< "$block"; then
            echo "FAIL: $h not mentioned in attack-pattern summary (expected in categorization bullets)"
            return 1
        fi
    done
    # Lateral movement: SSH patterns rarely get their own bucket; still must be an outlier.
    if ! grep -Fq "machine_012 [" <<< "$out"; then
        echo "FAIL: machine_012 not listed as an anomaly in the report body"
        return 1
    fi
    return 0
}

# File report: require MTIME + METADATA signals, every generator scenario host flagged, each reported
# anomaly must exist in the CSV, and Suspicious Machines count must match severity-line entries.
check_file_regression_stdout() {
    local out="$1"
    local csv_path="$2"
    local csv_ids actual n sm h
    if [[ ! -f "$csv_path" ]]; then
        echo "FAIL: CSV not found: $csv_path"
        return 1
    fi
    csv_ids=$(tail -n +2 "$csv_path" | cut -d, -f1 | sort -u)
    if [[ -z "${csv_ids// }" ]]; then
        echo "FAIL: no machine_id values in $csv_path"
        return 1
    fi
    if ! grep -Fq "MTIME ANOMALY:" <<< "$out"; then
        echo "FAIL: expected at least one MTIME ANOMALY line in file report"
        return 1
    fi
    if ! grep -Fq "METADATA ANOMALY:" <<< "$out"; then
        echo "FAIL: expected at least one METADATA ANOMALY line (fleet owner/group/size outlier)"
        return 1
    fi
    actual=$(grep -E 'machine_[0-9]{3} \[(CRITICAL|HIGH|MEDIUM|LOW)\]' <<< "$out" | grep -oE 'machine_[0-9]{3}' | sort -u)
    n=0
    if [[ -n "$actual" ]]; then
        n=$(echo "$actual" | wc -l)
        n="${n// /}"
    fi
    local min_expected=${#EXPECTED_FILE_SCENARIO_HOSTS[@]}
    if [[ "$n" -lt "$min_expected" ]]; then
        echo "FAIL: expected at least $min_expected anomalous hosts (generator scenarios), got $n"
        echo "$actual"
        return 1
    fi
    for h in "${EXPECTED_FILE_SCENARIO_HOSTS[@]}"; do
        if ! grep -Fxq "$h" <<< "$actual"; then
            echo "FAIL: scenario host $h missing from anomaly list (generator ↔ analysis regression)"
            echo "anomalous machine_ids: $(echo "$actual" | tr '\n' ' ')"
            return 1
        fi
    done
    while IFS= read -r id; do
        [[ -z "${id// }" ]] && continue
        if ! grep -Fxq "$id" <<< "$csv_ids"; then
            echo "FAIL: reported anomaly machine_id '$id' not in generator CSV"
            return 1
        fi
    done <<< "$actual"
    if [[ "$out" =~ Suspicious\ Machines:\ ([0-9]+) ]]; then
        sm="${BASH_REMATCH[1]}"
        if [[ "$sm" != "$n" ]]; then
            echo "FAIL: Suspicious Machines: $sm does not match $n unique hosts in severity lines"
            return 1
        fi
    else
        echo "FAIL: missing 'Suspicious Machines:' line in report"
        return 1
    fi
    return 0
}

check_csv_shape() {
    local path="$1" name="$2" expected_header="$3" expected_lines="$4"
    if [[ ! -f "$path" ]]; then
        echo "FAIL: $name not found: $path"
        return 1
    fi
    local first
    first=$(head -n 1 "$path")
    if [[ "$first" != "$expected_header" ]]; then
        echo "FAIL: $name header mismatch"
        echo "  expected: $expected_header"
        echo "  got:      $first"
        return 1
    fi
    local n
    n=$(wc -l < "$path")
    if [[ "${n// /}" -ne "$expected_lines" ]]; then
        echo "FAIL: $name line count (expected $expected_lines including header)"
        echo "  got: $n"
        return 1
    fi
    return 0
}

# Cleanup on exit
cleanup() {
    rm -f "$REPO_ROOT/scripts/.ironsift_test_out" "$GENERATOR_LOG" "$PROCESS_REPORT"
}
trap cleanup EXIT

echo "=============================================="
echo " IronSift generator + ironsift regression test"
echo "=============================================="
echo ""

# Build once
echo "[1/4] Build"
run_step "cargo build --release" cargo build --release
echo ""

# Default generator: no CLI args => CSV process dataset (generator.rs default)
echo "[2/4] Default generator (no args → process CSV)"
printf "  generator (default CLI) ... "
rm -f "$REPO_ROOT/$PROCESS_CSV"
if ! cargo run --release --bin generator >"$GENERATOR_LOG" 2>&1; then
    echo "FAIL (non-zero exit)"
    ((FAIL++)) || true
    cat "$GENERATOR_LOG"
else
    if expect_substrings_in_file "$GENERATOR_LOG" \
        "Format: CSV" \
        "Type: process" \
        "Output: test_dataset.csv" \
        "Generating 2000 logs for 20 machines" \
        "20 machines, 2020 total process logs" \
        "Dataset written to 'test_dataset.csv'" &&
        check_csv_shape "$REPO_ROOT/$PROCESS_CSV" "$PROCESS_CSV" "$EXPECTED_PROCESS_HEADER" "$EXPECTED_PROCESS_CSV_LINES"; then
        echo "OK"
        ((PASS++)) || true
    else
        echo "FAIL"
        ((FAIL++)) || true
    fi
fi
echo ""

printf "  ironsift (process + JSON report) ... "
rm -f "$PROCESS_REPORT"
OUT=$(cargo run --release --bin ironsift -- --input "$PROCESS_CSV" --tolerance "$PROCESS_REGRESSION_TOLERANCE" --export-json "$PROCESS_REPORT" 2>&1) || true
echo "$OUT" > "$REPO_ROOT/scripts/.ironsift_test_out"
if echo "$OUT" | grep -q "Loaded.*machine profile" && echo "$OUT" | grep -q "ANOMALIES DETECTED" &&
    require_jq && [[ -f "$PROCESS_REPORT" ]] && check_process_report_json "$PROCESS_REPORT" &&
    check_process_attack_patterns_stdout "$OUT"; then
    echo "OK"
    ((PASS++)) || true
else
    echo "FAIL"
    ((FAIL++)) || true
    echo "--- output ---"
    cat "$REPO_ROOT/scripts/.ironsift_test_out"
    echo "--- end ---"
fi
echo ""

# File data: default file mode is still CSV unless --json
echo "[3/4] File data (generator --files → CSV + ironsift --files)"
printf "  generator (--files, default CSV) ... "
rm -f "$REPO_ROOT/$FILES_CSV"
if ! cargo run --release --bin generator -- --files >"$GENERATOR_LOG" 2>&1; then
    echo "FAIL (non-zero exit)"
    ((FAIL++)) || true
    cat "$GENERATOR_LOG"
else
    if expect_substrings_in_file "$GENERATOR_LOG" \
        "Format: CSV" \
        "Type: file access" \
        "Output: test_files_dataset.csv" \
        "Generating 2000 logs for 20 machines" \
        "20 machines, 2000 total file access logs" \
        "Dataset written to 'test_files_dataset.csv'" &&
        check_csv_shape "$REPO_ROOT/$FILES_CSV" "$FILES_CSV" "$EXPECTED_FILES_HEADER" "$EXPECTED_FILES_CSV_LINES"; then
        echo "OK"
        ((PASS++)) || true
    else
        echo "FAIL"
        ((FAIL++)) || true
    fi
fi
echo ""

printf "  ironsift --files ... "
OUT=$(cargo run --release --bin ironsift -- --files --input "$FILES_CSV" 2>&1) || true
echo "$OUT" > "$REPO_ROOT/scripts/.ironsift_test_out"
if echo "$OUT" | grep -q "Loaded.*machine file profile" && echo "$OUT" | grep -q "ANOMALIES DETECTED" &&
    check_file_regression_stdout "$OUT" "$REPO_ROOT/$FILES_CSV"; then
    echo "OK"
    ((PASS++)) || true
else
    echo "FAIL"
    ((FAIL++)) || true
    echo "--- output ---"
    cat "$REPO_ROOT/scripts/.ironsift_test_out"
    echo "--- end ---"
fi
echo ""

# Optional: JSON round-trip for process
echo "[4/4] Process JSON (generator --json -> ironsift)"
run_step_quiet "generator (process JSON)" cargo run --release --bin generator -- --json
if [[ -f "$REPO_ROOT/$PROCESS_JSON" ]]; then
    printf "  ironsift (process JSON) ... "
    rm -f "$PROCESS_REPORT"
    OUT=$(cargo run --release --bin ironsift -- --input "$PROCESS_JSON" --tolerance "$PROCESS_REGRESSION_TOLERANCE" --export-json "$PROCESS_REPORT" 2>&1) || true
    echo "$OUT" > "$REPO_ROOT/scripts/.ironsift_test_out"
    if echo "$OUT" | grep -q "Loaded.*machine profile" && echo "$OUT" | grep -q "ANOMALIES DETECTED" &&
        require_jq && [[ -f "$PROCESS_REPORT" ]] && check_process_report_json "$PROCESS_REPORT" &&
        check_process_attack_patterns_stdout "$OUT"; then
        echo "OK"
        ((PASS++)) || true
    else
        echo "FAIL"
        ((FAIL++)) || true
        echo "--- output ---"
        cat "$REPO_ROOT/scripts/.ironsift_test_out"
        echo "--- end ---"
    fi
else
    echo "  skip (no $PROCESS_JSON)"
fi
echo ""

echo "=============================================="
printf " Result: %s passed, %s failed\n" "$PASS" "$FAIL"
echo "=============================================="

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
