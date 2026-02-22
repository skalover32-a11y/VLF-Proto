#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
BASE_URL="${2:-http://127.0.0.1:8080}"
OUT_PREFIX="${3:-/tmp/vlf_metrics}"

BEFORE_FILE="${OUT_PREFIX}_before.prom"
AFTER_FILE="${OUT_PREFIX}_after.prom"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/metrics-diff.sh before [base_url] [outfile_prefix]
  ./scripts/metrics-diff.sh after  [base_url] [outfile_prefix]
  ./scripts/metrics-diff.sh diff   [base_url] [outfile_prefix]

Defaults:
  base_url=http://127.0.0.1:8080
  outfile_prefix=/tmp/vlf_metrics
EOF
}

capture_metrics() {
  local out_file="$1"
  local url="${BASE_URL%/}/metrics"
  curl -fsS "$url" | awk '
    /^vlf_recv_datagrams_total / ||
    /^vlf_udp_forwarded_total / ||
    /^vlf_udp_dst_rx_total / ||
    /^vlf_udp_to_client_total / ||
    /^vlf_udp_to_client_fail_total / ||
    /^vlf_dropped_datagrams_total\{/ { print }
  ' | sort > "$out_file"
}

metric_value() {
  local file="$1"
  local metric="$2"
  awk -v m="$metric" '
    $1 == m { print $2; found=1; exit }
    END { if (!found) print 0 }
  ' "$file"
}

drop_reason_value() {
  local file="$1"
  local reason="$2"
  awk -v target="$reason" '
    $1 ~ /^vlf_dropped_datagrams_total\{/ {
      if (match($1, /reason=\"[^\"]+\"/)) {
        r = substr($1, RSTART + 8, RLENGTH - 9)
        if (r == target) {
          print $2
          found = 1
          exit
        }
      }
    }
    END { if (!found) print 0 }
  ' "$file"
}

list_drop_reasons() {
  local file_a="$1"
  local file_b="$2"
  awk '
    $1 ~ /^vlf_dropped_datagrams_total\{/ {
      if (match($1, /reason=\"[^\"]+\"/)) {
        print substr($1, RSTART + 8, RLENGTH - 9)
      }
    }
  ' "$file_a" "$file_b" | sort -u
}

print_delta_line() {
  local name="$1"
  local before="$2"
  local after="$3"
  local delta
  delta="$(awk -v a="$after" -v b="$before" 'BEGIN{printf "%.0f", (a-b)}')"
  printf "%-40s before=%-10s after=%-10s delta=%s\n" "$name" "$before" "$after" "$delta"
}

case "$MODE" in
  before)
    capture_metrics "$BEFORE_FILE"
    echo "Captured BEFORE snapshot: $BEFORE_FILE"
    ;;
  after)
    capture_metrics "$AFTER_FILE"
    echo "Captured AFTER snapshot: $AFTER_FILE"
    ;;
  diff)
    [[ -f "$BEFORE_FILE" ]] || { echo "Missing BEFORE snapshot: $BEFORE_FILE" >&2; exit 1; }
    [[ -f "$AFTER_FILE" ]] || { echo "Missing AFTER snapshot: $AFTER_FILE" >&2; exit 1; }

    echo "=== Unified diff ==="
    diff -u "$BEFORE_FILE" "$AFTER_FILE" || true
    echo ""
    echo "=== Counter deltas (after - before) ==="

    for metric in \
      vlf_recv_datagrams_total \
      vlf_udp_forwarded_total \
      vlf_udp_dst_rx_total \
      vlf_udp_to_client_total \
      vlf_udp_to_client_fail_total; do
      b="$(metric_value "$BEFORE_FILE" "$metric")"
      a="$(metric_value "$AFTER_FILE" "$metric")"
      print_delta_line "$metric" "$b" "$a"
    done

    while IFS= read -r reason; do
      [[ -n "$reason" ]] || continue
      b="$(drop_reason_value "$BEFORE_FILE" "$reason")"
      a="$(drop_reason_value "$AFTER_FILE" "$reason")"
      print_delta_line "vlf_dropped_datagrams_total{reason=\"$reason\"}" "$b" "$a"
    done < <(list_drop_reasons "$BEFORE_FILE" "$AFTER_FILE")
    ;;
  ""|--help|-h)
    usage
    [[ -z "$MODE" ]] && exit 1 || exit 0
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage
    exit 1
    ;;
esac
