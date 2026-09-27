#!/usr/bin/env bash
# Compile a C/C++ binary with TSan, run it, and upload the report to sotrace-server
#
# Usage: ./tsan_android_ndk.sh /path/to/ndk http://192.168.1.83:3000

NDK=${1:-/opt/android-ndk}
SERVER=${2:-http://localhost:3000}
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# 1. Compile with TSan (NDK CMake)
# In CMakeLists.txt add:
#   target_compile_options(libfoo PRIVATE -fsanitize=thread)
#   target_link_options(libfoo PRIVATE -fsanitize=thread)

# 2. Run harness with TSan logging enabled
echo "[1/3] Running TSan-instrumented harness..."
TSAN_OPTIONS="log_path=/tmp/sotrace_tsan" ./libfoo_harness

# 3. Find and parse TSan log files
echo "[2/3] Parsing TSan reports..."
for log in /tmp/sotrace_tsan.*; do
    [ -f "$log" ] || continue
    echo "  Processing $log"
    python "$SCRIPT_DIR/sotrace-tsan.py" \
        --log "$log" \
        --server "$SERVER"
done

echo "[3/3] Done. Check $SERVER for uploaded traces."

# Android NDK example:
# adb shell TSAN_OPTIONS="log_path=/data/local/tmp/tsan" /data/local/tmp/libfoo_harness
# for log in $(adb shell ls /data/local/tmp/tsan.*); do
#     adb pull "$log" /tmp/
#     python sotrace-tsan.py --log "/tmp/$(basename $log)" --server "$SERVER"
# done
