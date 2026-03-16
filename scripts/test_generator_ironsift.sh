#!/usr/bin/env bash
# Test generator output and ironsift analysis to catch regressions.
# Run from repo root: ./scripts/test_generator_ironsift.sh
# Usage: ./scripts/test_generator_ironsift.sh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROCESS_CSV="test_dataset.csv"
PROCESS_JSON="test_dataset.json"
FILES_CSV="test_files_dataset.csv"
FILES_JSON="test_files_dataset.json"

PASS=0
FAIL=0

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

# Cleanup on exit
cleanup() { rm -f "$REPO_ROOT/scripts/.ironsift_test_out"; }
trap cleanup EXIT

echo "=============================================="
echo " IronSift generator + ironsift regression test"
echo "=============================================="
echo ""

# Build once
echo "[1/4] Build"
run_step "cargo build --release" cargo build --release
echo ""

# Process data: generate CSV, then run ironsift
echo "[2/4] Process data (generator -> ironsift)"
run_step_quiet "generator (process CSV)" cargo run --release --bin generator -- --csv
if [[ ! -f "$REPO_ROOT/$PROCESS_CSV" ]]; then
    echo "  FAIL: $PROCESS_CSV not created"
    ((FAIL++)) || true
else
    run_step_quiet "generator created $PROCESS_CSV" test -f "$REPO_ROOT/$PROCESS_CSV"
fi

printf "  ironsift (process) ... "
OUT=$(cargo run --release --bin ironsift -- --input "$PROCESS_CSV" 2>&1) || true
echo "$OUT" > "$REPO_ROOT/scripts/.ironsift_test_out"
if echo "$OUT" | grep -q "Loaded.*machine profile" && echo "$OUT" | grep -q "ANOMALIES DETECTED"; then
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

# File data: generate file CSV, then run ironsift --files
echo "[3/4] File data (generator --files -> ironsift --files)"
run_step_quiet "generator (file CSV)" cargo run --release --bin generator -- --files --csv
if [[ ! -f "$REPO_ROOT/$FILES_CSV" ]]; then
    echo "  FAIL: $FILES_CSV not created"
    ((FAIL++)) || true
else
    run_step_quiet "generator created $FILES_CSV" test -f "$REPO_ROOT/$FILES_CSV"
fi

printf "  ironsift --files ... "
OUT=$(cargo run --release --bin ironsift -- --files --input "$FILES_CSV" 2>&1) || true
echo "$OUT" > "$REPO_ROOT/scripts/.ironsift_test_out"
if echo "$OUT" | grep -q "Loaded.*machine file profile" && echo "$OUT" | grep -q "ANOMALIES DETECTED"; then
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
echo "[4/4] Process JSON (generator -> ironsift)"
run_step_quiet "generator (process JSON)" cargo run --release --bin generator -- --json
if [[ -f "$REPO_ROOT/$PROCESS_JSON" ]]; then
    printf "  ironsift (process JSON) ... "
    OUT=$(cargo run --release --bin ironsift -- --input "$PROCESS_JSON" 2>&1) || true
    echo "$OUT" > "$REPO_ROOT/scripts/.ironsift_test_out"
    if echo "$OUT" | grep -q "Loaded.*machine profile" && echo "$OUT" | grep -q "ANOMALIES DETECTED"; then
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
