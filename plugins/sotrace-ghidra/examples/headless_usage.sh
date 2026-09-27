#!/usr/bin/env bash
# Headless Ghidra analysis via PyGhidra → sotrace-server
# Usage: ./headless_usage.sh /opt/ghidra /data/libnative.so http://192.168.1.83:3000

GHIDRA_HOME=${1:-/opt/ghidra}
BINARY=${2:-/data/libnative.so}
SERVER=${3:-http://localhost:3000}

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[1/3] Installing PyGhidra..."
pip install pyghidra --quiet

echo "[2/3] Running analysis..."
python "$SCRIPT_DIR/sotrace-ghidra.py" \
    --ghidra-home "$GHIDRA_HOME" \
    --server "$SERVER" \
    "$BINARY"

echo "[3/3] Done. Check $SERVER for the uploaded trace."

# Save to file instead:
# python "$SCRIPT_DIR/sotrace-ghidra.py" \
#     --ghidra-home "$GHIDRA_HOME" \
#     --output /tmp/trace.jsonl \
#     "$BINARY"
