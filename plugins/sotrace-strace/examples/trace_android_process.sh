#!/usr/bin/env bash
# trace_android_process.sh — end-to-end strace capture from Android via adb
#
# Prerequisites on the Android device:
#   - strace binary available (default: /data/local/tmp/strace)
#   - adb connected to the device (adb devices should list it)
#
# Usage:
#   SO_NAME=libfoo.so TARGET_CMD=/data/local/tmp/harness ./trace_android_process.sh
#
# Override any variable below via environment:
#   TARGET_CMD   — command to run on device
#   SO_NAME      — SO filename filter (passed to --so)
#   SERVER_URL   — sotrace-server base URL
#   LOCAL_LOG    — local path to save the pulled strace log
#   STRACE_BIN   — path to strace on the Android device
#   EXTRA_ARGS   — additional args forwarded to sotrace-strace.py parse

set -euo pipefail

TARGET_CMD="${TARGET_CMD:-/data/local/tmp/harness}"
SO_NAME="${SO_NAME:-libfoo.so}"
SERVER_URL="${SERVER_URL:-http://192.168.1.83:3000}"
LOCAL_LOG="${LOCAL_LOG:-trace.log}"
REMOTE_LOG="/data/local/tmp/sotrace-strace.log"
STRACE_BIN="${STRACE_BIN:-strace}"
EXTRA_ARGS="${EXTRA_ARGS:-}"

# Resolve paths relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "${SCRIPT_DIR}")"

# ---------------------------------------------------------------------------
# Step 1: Run strace on the device
# ---------------------------------------------------------------------------

echo "[sotrace] Tracing '${TARGET_CMD}' on device …"

adb shell "${STRACE_BIN} \
    -f \
    -tt \
    -T \
    -o ${REMOTE_LOG} \
    -e trace=mmap,mmap2,futex,clone,openat,open \
    ${TARGET_CMD}" || true  # allow non-zero exit from traced process

echo "[sotrace] Trace complete."

# ---------------------------------------------------------------------------
# Step 2: Pull the log from the device
# ---------------------------------------------------------------------------

echo "[sotrace] Pulling ${REMOTE_LOG} -> ${LOCAL_LOG} …"
adb pull "${REMOTE_LOG}" "${LOCAL_LOG}"
LINE_COUNT=$(wc -l < "${LOCAL_LOG}")
echo "[sotrace] Pulled ${LINE_COUNT} lines."

# ---------------------------------------------------------------------------
# Step 3: Parse and upload to sotrace-server
# ---------------------------------------------------------------------------

echo "[sotrace] Uploading to ${SERVER_URL} (SO filter: '${SO_NAME}') …"

python3 "${PLUGIN_DIR}/sotrace-strace.py" parse \
    --log "${LOCAL_LOG}" \
    --server "${SERVER_URL}" \
    --so "${SO_NAME}" \
    ${EXTRA_ARGS}

echo "[sotrace] Done."
