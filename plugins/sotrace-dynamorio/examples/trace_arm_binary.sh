#!/usr/bin/env bash
# trace_arm_binary.sh — end-to-end DynamoRIO trace example
#
# Prerequisites:
#   - DynamoRIO installed (https://dynamorio.org/page_releases.html)
#   - sotrace-server running
#   - Target binary compiled for the host architecture (x86_64 or AArch64)
#
# Usage:
#   DYNAMORIO_DIR=/opt/DynamoRIO SOTRACE_SERVER=http://host:3000 \
#     TARGET=./my_binary SO_NAME=libfoo.so bash trace_arm_binary.sh

DYNAMORIO_DIR="${DYNAMORIO_DIR:-/opt/DynamoRIO}"
SOTRACE_SERVER="${SOTRACE_SERVER:-http://192.168.1.83:3000}"
TARGET="${TARGET:-./libfoo_harness}"
SO_NAME="${SO_NAME:-libfoo.so}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -e

echo "=== Step 1: Build DynamoRIO client ==="
python "$SCRIPT_DIR/sotrace-dynamorio.py" build \
    --dynamorio-dir "$DYNAMORIO_DIR"

echo ""
echo "=== Step 2: Run under DynamoRIO and upload trace ==="
python "$SCRIPT_DIR/sotrace-dynamorio.py" run \
    --client "$SCRIPT_DIR/build/libsotrace_client.so" \
    --server "$SOTRACE_SERVER" \
    --so "$SO_NAME" \
    -- "$TARGET"

echo ""
echo "=== Done — check $SOTRACE_SERVER for analysis results ==="

# Optional: also save a local copy of the trace
# python "$SCRIPT_DIR/sotrace-dynamorio.py" run \
#     --client "$SCRIPT_DIR/build/libsotrace_client.so" \
#     --output trace.jsonl \
#     --so "$SO_NAME" \
#     -- "$TARGET"
