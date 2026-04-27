#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/auto_pipeline.sh --dir <data_dir> [options]

Options:
  --dir <path>              Directory with .csv/.json/.jsonl files (required)
  --baseline-tag <tag>      Baseline tag (default: baseline)
  --candidate-tag <tag>     Candidate tag (default: candidate)
  --enable-anomark          Enable AnoMark (in-process anomark crate) when a model is configured
  --server-url <url>        API base URL (default: http://localhost:8080)
  --help                    Show this help

Examples:
  scripts/auto_pipeline.sh --dir ./data
  scripts/auto_pipeline.sh --dir ./data --enable-anomark
EOF
}

DATA_DIR=""
BASELINE_TAG="baseline"
CANDIDATE_TAG="candidate"
ENABLE_ANOMARK=false
SERVER_URL="http://localhost:8080"
STARTUP_TIMEOUT_SEC=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      DATA_DIR="${2:-}"
      shift 2
      ;;
    --baseline-tag)
      BASELINE_TAG="${2:-}"
      shift 2
      ;;
    --candidate-tag)
      CANDIDATE_TAG="${2:-}"
      shift 2
      ;;
    --enable-anomark)
      ENABLE_ANOMARK=true
      shift
      ;;
    --server-url)
      SERVER_URL="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$DATA_DIR" ]]; then
  echo "Error: --dir is required" >&2
  usage
  exit 1
fi

if [[ ! -d "$DATA_DIR" ]]; then
  echo "Error: directory not found: $DATA_DIR" >&2
  exit 1
fi

wait_for_server() {
  local health_url="${SERVER_URL%/}/api/health"
  local waited=0
  while true; do
    if curl -fsS "$health_url" >/dev/null 2>&1; then
      return 0
    fi
    if (( waited >= STARTUP_TIMEOUT_SEC )); then
      echo "Error: timed out waiting for server readiness (${STARTUP_TIMEOUT_SEC}s)." >&2
      return 1
    fi
    sleep 1
    waited=$((waited + 1))
  done
}

start_server_foreground() {
  echo
  echo "Starting ironsift-server in foreground..."
  echo "Press Ctrl+C to stop."
  exec cargo run --bin ironsift-server
}

echo "[1/4] Waiting for server readiness..."
if ! wait_for_server; then
  echo "Server is not running yet."
  echo "Skipping pipeline execution and starting server in foreground."
  start_server_foreground
fi

echo "[2/4] Running automatic pipeline..."
PAYLOAD=$(cat <<EOF
{
  "directory": "$DATA_DIR",
  "baseline_tag": "$BASELINE_TAG",
  "candidate_tag": "$CANDIDATE_TAG",
  "enable_anomark": $ENABLE_ANOMARK
}
EOF
)

RESP=$(curl -sS -X POST "$SERVER_URL/api/pipeline/auto" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

echo "$RESP"

RUN_ID=$(printf '%s' "$RESP" | python3 -c 'import sys, json; d=json.load(sys.stdin); print(d.get("result",{}).get("run_id",""))' 2>/dev/null || true)
if [[ -z "$RUN_ID" ]]; then
  API_ERROR=$(printf '%s' "$RESP" | python3 -c 'import sys, json; d=json.load(sys.stdin); print(d.get("error",""))' 2>/dev/null || true)
  if [[ "$API_ERROR" == "no importable files found (csv/json/jsonl)" ]]; then
    echo
    echo "No log files found in '$DATA_DIR' yet."
    echo "Server is running; open the UI and upload CSV/JSON/JSONL when ready."
    echo "Open UI: $SERVER_URL"
    exit 0
  fi
  echo "Error: could not extract run_id from response" >&2
  if [[ -n "$API_ERROR" ]]; then
    echo "API error: $API_ERROR" >&2
  fi
  exit 1
fi

echo "[3/4] Fetching detections..."
curl -sS "$SERVER_URL/api/runs/$RUN_ID/detections" | python3 -m json.tool

echo "[4/4] Fetching honeycomb cells..."
curl -sS "$SERVER_URL/api/fleet/honeycomb?run_id=$RUN_ID" | python3 -m json.tool

echo
echo "Done. Run ID: $RUN_ID"
echo "Open UI: $SERVER_URL"
