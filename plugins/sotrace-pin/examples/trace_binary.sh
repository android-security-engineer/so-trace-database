#!/usr/bin/env bash
# sotrace-pin complete usage example
# Prerequisites: Intel Pin installed, g++ available, sotrace-server running

set -euo pipefail

PIN_ROOT="${PIN_ROOT:-/opt/pin}"
SOTRACE_SERVER="${SOTRACE_SERVER:-http://192.168.1.83:3000}"
SO_NAME="${SO_NAME:-libfoo.so}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Step 1: Download Intel Pin (if not already installed) ==="
# Intel Pin is available at https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html
# Example for Pin 3.30 on Linux x86_64:
#
#   wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.30-98830-g1d7b601b3-gcc-linux.tar.gz
#   tar xzf pin-3.30-*.tar.gz
#   export PIN_ROOT=$PWD/pin-3.30-98830-g1d7b601b3-gcc-linux

if [ ! -f "$PIN_ROOT/pin" ] && [ ! -f "$PIN_ROOT/pin.sh" ]; then
    echo "ERROR: Intel Pin not found at PIN_ROOT=$PIN_ROOT"
    echo "Set PIN_ROOT to your Pin installation directory."
    exit 1
fi

echo "=== Step 2: Build the Pintool ==="
python "$SCRIPT_DIR/sotrace-pin.py" build --pin-root "$PIN_ROOT"
echo "Built: $SCRIPT_DIR/libsotrace_pintool.so"

echo ""
echo "=== Step 3: Trace an x86_64 binary (instruction-only, fast) ==="
python "$SCRIPT_DIR/sotrace-pin.py" run \
    --pin-root "$PIN_ROOT" \
    --pintool  "$SCRIPT_DIR/libsotrace_pintool.so" \
    --server   "$SOTRACE_SERVER" \
    --so       "$SO_NAME" \
    -- /bin/ls /tmp

echo ""
echo "=== Step 4: Trace with memory reads/writes (slower) ==="
python "$SCRIPT_DIR/sotrace-pin.py" run \
    --pin-root      "$PIN_ROOT" \
    --pintool       "$SCRIPT_DIR/libsotrace_pintool.so" \
    --enable-memory \
    --output        /tmp/trace-with-mem.jsonl \
    --server        "$SOTRACE_SERVER" \
    --so            "$SO_NAME" \
    -- /bin/ls /tmp

echo ""
echo "=== Step 5: Save trace to file only (no server needed) ==="
python "$SCRIPT_DIR/sotrace-pin.py" run \
    --pintool "$SCRIPT_DIR/libsotrace_pintool.so" \
    --output  /tmp/sotrace-demo.jsonl \
    -- /bin/echo hello
echo "Trace saved to /tmp/sotrace-demo.jsonl"
echo "Import with: sotrace-cli trace-import --file /tmp/sotrace-demo.jsonl"

echo ""
echo "=== Done ==="
echo "View analysis at: $SOTRACE_SERVER"
