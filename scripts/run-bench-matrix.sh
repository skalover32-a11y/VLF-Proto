#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run-bench-matrix.sh [--duration 10s] [--reports-dir reports] [-- <extra proto_bench args>]

Examples:
  ./scripts/run-bench-matrix.sh
  ./scripts/run-bench-matrix.sh --duration 20s
  ./scripts/run-bench-matrix.sh --reports-dir ./reports -- --prefer-quic
EOF
}

DURATION="10s"
REPORTS_DIR="$ROOT/reports"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)
      [[ $# -ge 2 ]] || { echo "missing value for --duration" >&2; exit 2; }
      DURATION="$2"
      shift 2
      ;;
    --reports-dir)
      [[ $# -ge 2 ]] || { echo "missing value for --reports-dir" >&2; exit 2; }
      REPORTS_DIR="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_ARGS=("$@")
      break
      ;;
    *)
      echo "unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
RUN_ROOT="${REPORTS_DIR%/}/${TIMESTAMP}"
mkdir -p "$RUN_ROOT"

CLIENTS=(1 2)
UDP_PPS=(300 600 900 1200)
UDP_PAYLOAD=(256 1200)

RESULTS_FILE="$RUN_ROOT/summary.tsv"
: > "$RESULTS_FILE"
FIRST_FAILURE=""
TOTAL=0
FAILED=0

for c in "${CLIENTS[@]}"; do
  for pps in "${UDP_PPS[@]}"; do
    for payload in "${UDP_PAYLOAD[@]}"; do
      TOTAL=$((TOTAL + 1))
      RUN_ID="c${c}_pps${pps}_pl${payload}"
      RUN_DIR="$RUN_ROOT/$RUN_ID"
      LOG_FILE="$RUN_DIR/console.log"
      JSON_FILE="$RUN_DIR/proto_bench_report.json"
      MD_FILE="$RUN_DIR/proto_bench_report.md"
      mkdir -p "$RUN_DIR"

      CMD=(
        ./scripts/run-bench.sh
        --clients "$c"
        --duration "$DURATION"
        --tcp-flows 1
        --tcp-total-mb 8
        --udp-pps "$pps"
        --udp-payload-bytes "$payload"
        --udp-burst 10
        --udp-max-loss 0.05
        --udp-max-jitter-ms 50
        --tcp-min-mbps 1
        --report-json "$JSON_FILE"
        --report-md "$MD_FILE"
      )
      if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
        CMD+=("${EXTRA_ARGS[@]}")
      fi

      echo ""
      echo ">>> RUN $RUN_ID (duration=$DURATION)"
      set +e
      "${CMD[@]}" 2>&1 | tee "$LOG_FILE"
      EXIT_CODE=${PIPESTATUS[0]}
      set -e

      STATUS="PASS"
      if [[ $EXIT_CODE -ne 0 ]]; then
        STATUS="FAIL"
        FAILED=$((FAILED + 1))
        if [[ -z "$FIRST_FAILURE" ]]; then
          FIRST_FAILURE="$RUN_ID (exit=$EXIT_CODE)"
        fi
      fi

      printf "%s\t%s\t%s\t%s\t%s\n" "$RUN_ID" "$STATUS" "$EXIT_CODE" "$RUN_DIR" "$DURATION" >> "$RESULTS_FILE"
    done
  done
done

echo ""
echo "Bench matrix reports: $RUN_ROOT"
echo "Summary:"
printf "%-20s %-6s %-6s %s\n" "run_id" "status" "exit" "report_dir"
printf "%-20s %-6s %-6s %s\n" "--------------------" "------" "------" "----------"
while IFS=$'\t' read -r run_id status exit_code run_dir _duration; do
  printf "%-20s %-6s %-6s %s\n" "$run_id" "$status" "$exit_code" "$run_dir"
done < "$RESULTS_FILE"

echo ""
echo "Total runs: $TOTAL"
echo "Failed: $FAILED"
if [[ -n "$FIRST_FAILURE" ]]; then
  echo "First failure: $FIRST_FAILURE"
else
  echo "All matrix runs passed."
fi

if [[ $FAILED -ne 0 ]]; then
  exit 1
fi
