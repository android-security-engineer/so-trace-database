#!/usr/bin/env bash
# profile_android.sh — End-to-end example: profile an Android binary with
# simpleperf and upload the call trace to sotrace-server.
#
# Prerequisites on host:
#   - Android NDK (for simpleperf scripts)
#   - adb connected to a rooted device or a profiling-enabled build
#   - sotrace-server running (e.g. http://192.168.1.83:3000)
#   - Python 3.8+
#
# simpleperf is Android's equivalent of Linux perf (ships with the NDK).
# It supports call-graph recording (-g) and can export text output compatible
# with the format expected by sotrace-perf.py.

set -euo pipefail

DEVICE_BIN="/data/local/tmp/harness"  # binary on the device
PERF_DATA_DEVICE="/data/local/tmp/perf.data"
PERF_DATA_HOST="./perf.data"
PERF_SCRIPT_HOST="./perf.script"
SO_FILTER="${SO_FILTER:-libfoo.so}"   # set to your target SO
SOTRACE_SERVER="${SOTRACE_SERVER:-http://192.168.1.83:3000}"

# ── Step 1: Record on device ─────────────────────────────────────────────────
echo "[1/4] Recording call graph on device …"
adb shell simpleperf record \
    -g \
    --call-graph dwarf \
    -o "${PERF_DATA_DEVICE}" \
    "${DEVICE_BIN}"

# ── Step 2: Pull perf.data to host ───────────────────────────────────────────
echo "[2/4] Pulling ${PERF_DATA_DEVICE} → ${PERF_DATA_HOST} …"
adb pull "${PERF_DATA_DEVICE}" "${PERF_DATA_HOST}"

# ── Step 3: Convert to text (simpleperf report --show-callchain) ──────────────
# simpleperf produces a text format that is compatible with perf script output.
# If you have the NDK simpleperf Python scripts available:
#
#   python "$ANDROID_NDK_HOME/simpleperf/report_sample.py" \
#       --show-callchain -i perf.data > perf.script
#
# Or use simpleperf directly on the host (if installed):
echo "[3/4] Converting perf.data → ${PERF_SCRIPT_HOST} …"
simpleperf report \
    --show-callchain \
    --full-callgraph \
    -i "${PERF_DATA_HOST}" \
    > "${PERF_SCRIPT_HOST}"

# ── Step 4: Upload to sotrace-server ─────────────────────────────────────────
echo "[4/4] Uploading call trace to ${SOTRACE_SERVER} …"
python "$(dirname "$0")/../sotrace-perf.py" \
    --input "${PERF_SCRIPT_HOST}" \
    --server "${SOTRACE_SERVER}" \
    --so "${SO_FILTER}" \
    --verbose

echo "Done. Visit ${SOTRACE_SERVER} to inspect the uploaded trace."
