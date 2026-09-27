#!/usr/bin/env bash
# End-to-end example: disassemble an ARM64 SO and upload to sotrace-server.
#
# Prerequisites
# -------------
# Cross-compiled objdump for ARM64 targets:
#   sudo apt-get install binutils-aarch64-linux-gnu
#
# sotrace-server must be running and reachable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="${1:-libfoo.so}"
SERVER="${2:-http://192.168.1.83:3000}"

echo "=== sotrace-objdump end-to-end example ==="
echo "Binary : $BINARY"
echo "Server : $SERVER"
echo ""

# ── Option A: stream directly to sotrace-server ─────────────────────────────
echo "--- Uploading to $SERVER ---"
python "$PLUGIN_DIR/sotrace-objdump.py" "$BINARY" \
    --objdump aarch64-linux-gnu-objdump \
    --server "$SERVER"

# ── Option B: save to JSONL for offline inspection / CLI import ──────────────
echo ""
echo "--- Saving to trace.jsonl ---"
python "$PLUGIN_DIR/sotrace-objdump.py" "$BINARY" \
    --objdump aarch64-linux-gnu-objdump \
    --output trace.jsonl

echo ""
echo "Saved $(wc -l < trace.jsonl) line(s) to trace.jsonl"
echo "Inspect with:  python -m json.tool trace.jsonl | head -80"

# ── Option C: only disassemble .text, auto-detect arch ──────────────────────
echo ""
echo "--- .text section only, arch auto-detected ---"
python "$PLUGIN_DIR/sotrace-objdump.py" "$BINARY" \
    --section .text \
    --output trace-text-only.jsonl

echo "Done."
