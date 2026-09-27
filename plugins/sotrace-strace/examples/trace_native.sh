#!/usr/bin/env bash
# Trace a native binary harness for libfoo.so and upload to sotrace-server
#
# Usage: ./trace_native.sh http://192.168.1.83:3000 /path/to/libfoo_harness [args...]
#
# Requirements:
#   - strace or ltrace installed (sudo apt-get install strace ltrace)
#   - sotrace-server running

SERVER=${1:-http://localhost:3000}
BINARY=${2:-./libfoo_harness}
shift 2 2>/dev/null
ARGS="$@"

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[sotrace] tracing with strace..."
python "$SCRIPT_DIR/sotrace-strace.py" run \
    --tool strace \
    --server "$SERVER" \
    -- "$BINARY" $ARGS

echo ""
echo "[sotrace] tracing with ltrace (pthread only)..."
python "$SCRIPT_DIR/sotrace-strace.py" run \
    --tool ltrace \
    --server "$SERVER" \
    -- "$BINARY" $ARGS

# Attach to a running process (example)
# python "$SCRIPT_DIR/sotrace-strace.py" attach \
#     --pid $(pgrep libfoo_harness) \
#     --server "$SERVER"
