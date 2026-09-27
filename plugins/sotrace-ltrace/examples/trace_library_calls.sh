#!/usr/bin/env bash
# sotrace-ltrace — end-to-end example
#
# Prerequisites:
#   apt-get install ltrace          # or: sudo apt-get install ltrace
#   python3 sotrace-ltrace.py --help
#
# This script assumes you have a test harness binary (libfoo_harness) that
# loads and exercises libfoo.so via pthread synchronisation primitives.
#
# For Android SO analysis on a Linux host, run the SO through a JNI harness
# compiled for your host architecture, or use an Android emulator with
# ltrace cross-compiled for arm64.

set -euo pipefail

SOTRACE_SERVER="http://192.168.1.83:3000"
HARNESS="./libfoo_harness"
SO_NAME="libfoo.so"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# 1. Inline run — trace the harness, upload to sotrace-server in one step
# ---------------------------------------------------------------------------
echo "=== inline run (real-time upload) ==="
python3 "$SCRIPT_DIR/sotrace-ltrace.py" \
    --run \
    --so "$SO_NAME" \
    --server "$SOTRACE_SERVER" \
    -- "$HARNESS"

# ---------------------------------------------------------------------------
# 2. Inline run — save raw ltrace log first, then parse offline
# ---------------------------------------------------------------------------
echo "=== inline run (save JSONL) ==="
python3 "$SCRIPT_DIR/sotrace-ltrace.py" \
    --run \
    --so "$SO_NAME" \
    --output /tmp/ltrace-trace.jsonl \
    -- "$HARNESS"

echo "Envelope saved to /tmp/ltrace-trace.jsonl"
echo "Upload later with:"
echo "  python3 $SCRIPT_DIR/sotrace-ltrace.py \\"
echo "      --input /tmp/ltrace-trace.jsonl \\"
echo "      --server $SOTRACE_SERVER"

# ---------------------------------------------------------------------------
# 3. Parse a pre-existing ltrace log (e.g. captured on device)
# ---------------------------------------------------------------------------
echo "=== parse existing log ==="
# Capture on the target (Android/Linux):
#   ltrace -f -tt -T -e 'pthread_*+dlopen+dlsym+malloc+free' \
#          -o /sdcard/trace.log ./my_binary
# Pull the log:
#   adb pull /sdcard/trace.log /tmp/trace.log

if [ -f /tmp/trace.log ]; then
    python3 "$SCRIPT_DIR/sotrace-ltrace.py" \
        --input /tmp/trace.log \
        --so "$SO_NAME" \
        --server "$SOTRACE_SERVER"
else
    echo "(skipped — /tmp/trace.log not found)"
fi

# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------
# • ltrace -f follows threads; each line is prefixed with the thread PID.
# • ltrace -tt adds HH:MM:SS.usec timestamps used for step ordering.
# • ltrace -T appends <elapsed_sec> per call for latency analysis.
# • The -e filter limits overhead to the functions sotrace-ltrace understands.
# • Memory events (malloc/free) are parsed but not currently added to the
#   sotrace envelope — they contribute to the step counter only.
# • For high-throughput SO analysis, capture to file and parse offline to
#   avoid adding ltrace output latency to the traced process's hot path.
