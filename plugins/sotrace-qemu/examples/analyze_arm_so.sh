#!/usr/bin/env bash
# analyze_arm_so.sh — end-to-end example: trace an Android ARM64 SO with qemu-user,
# upload to sotrace-server, then query race-condition analysis.
#
# Requirements:
#   apt install qemu-user-static
#   pip install requests
#   # sotrace-server running at SOTRACE_URL
#
# Usage:
#   SOTRACE_URL=http://192.168.1.83:3000 ./analyze_arm_so.sh

set -euo pipefail

SOTRACE_URL="${SOTRACE_URL:-http://127.0.0.1:3000}"
SO_NAME="libfoo.so"
HARNESS="./harness_aarch64"   # test harness that loads and calls libfoo.so
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== Step 1: Collect trace with qemu-aarch64 ==="
python "$SCRIPT_DIR/sotrace-qemu.py" \
    --server "$SOTRACE_URL" \
    --so "$SO_NAME" \
    --arch aarch64 \
    --verbose \
    -- "$HARNESS"

echo ""
echo "=== Step 2: (Optional) Save to file for offline replay ==="
python "$SCRIPT_DIR/sotrace-qemu.py" \
    --output /tmp/libfoo-trace.jsonl \
    --so "$SO_NAME" \
    --arch aarch64 \
    -- "$HARNESS"
echo "Trace saved to /tmp/libfoo-trace.jsonl"

echo ""
echo "=== Step 3: Import the saved file with sotrace-cli ==="
echo "  sotrace-cli trace-save --file /tmp/libfoo-trace.jsonl"

echo ""
echo "=== Step 4: Query analysis via curl ==="
# Assumes the trace_id printed in step 1 is stored in TRACE_ID
# TRACE_ID=<paste from step 1>
# curl -s "$SOTRACE_URL/api/v1/traces/$TRACE_ID/analyze/threads/races" | jq .

echo "  curl -s \$SOTRACE_URL/api/v1/traces/\$TRACE_ID/analyze/threads/races | jq ."
echo "  curl -s \$SOTRACE_URL/api/v1/traces/\$TRACE_ID/analyze/threads/deadlocks | jq ."
echo "  curl -s \$SOTRACE_URL/api/v1/traces/\$TRACE_ID/analyze/threads/contentions | jq ."
