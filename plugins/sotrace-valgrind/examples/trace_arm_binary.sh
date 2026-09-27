#!/usr/bin/env bash
# sotrace-valgrind — end-to-end example
#
# Prerequisites:
#   apt-get install valgrind
#   pip install requests   # optional — only needed if using requests-based transport
#
# This script assumes you have a test harness that loads libfoo.so.

set -euo pipefail

SOTRACE_SERVER="http://192.168.1.83:3000"
HARNESS="./libfoo_harness"
SO_NAME="libfoo.so"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# 1. lackey mode — instruction + memory trace, upload to sotrace-server
# ---------------------------------------------------------------------------
echo "=== lackey mode (real-time upload) ==="
python "$SCRIPT_DIR/sotrace-valgrind.py" \
    --tool lackey \
    --so "$SO_NAME" \
    --server "$SOTRACE_SERVER" \
    -- "$HARNESS"

# ---------------------------------------------------------------------------
# 2. lackey mode — save to JSONL file for later import via sotrace-cli
# ---------------------------------------------------------------------------
echo "=== lackey mode (save to file) ==="
python "$SCRIPT_DIR/sotrace-valgrind.py" \
    --tool lackey \
    --so "$SO_NAME" \
    --output /tmp/trace-lackey.jsonl \
    -- "$HARNESS"

echo "JSONL saved to /tmp/trace-lackey.jsonl"
echo "Import with: sotrace-cli trace-import --file /tmp/trace-lackey.jsonl"

# ---------------------------------------------------------------------------
# 3. callgrind mode — call-graph trace (lighter overhead)
# ---------------------------------------------------------------------------
echo "=== callgrind mode ==="
python "$SCRIPT_DIR/sotrace-valgrind.py" \
    --tool callgrind \
    --server "$SOTRACE_SERVER" \
    -- "$HARNESS"

# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------
# • Valgrind lackey is Linux x86/x86_64 only; ARM64 has limited support.
# • For Android ARM SO analysis, run the harness under qemu-user first:
#     qemu-aarch64 ./libfoo_harness
#   then use sotrace-qemu for instruction trace instead.
# • lackey --trace-mem=yes generates ~10-100× the normal instruction count
#   in I/O. Use only on small, bounded inputs.
# • callgrind is cheaper and provides a clean call graph suitable for
#   sotrace's function-safety and producer-consumer analyses.
