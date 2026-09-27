#!/usr/bin/env bash
# decompile_apk.sh — end-to-end sotrace-apktool example
#
# Prerequisites:
#   - Java JDK (required by apktool): sudo apt install default-jdk
#   - apktool (installed below if missing)
#   - sotrace-server running at SOTRACE_SERVER
#
# Usage:
#   APK=/path/to/app.apk SOTRACE_SERVER=http://192.168.1.83:3000 \
#     SO_NAME=libtarget bash examples/decompile_apk.sh

set -e

APK="${APK:-./app.apk}"
SOTRACE_SERVER="${SOTRACE_SERVER:-http://192.168.1.83:3000}"
SO_NAME="${SO_NAME:-}"        # optional: filter by loaded SO name
OUTPUT_FILE="trace.jsonl"
APKTOOL_VERSION="2.9.3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# Step 0: Install apktool if it's not on PATH
# ---------------------------------------------------------------------------
if ! command -v apktool &>/dev/null; then
    echo "=== Installing apktool ${APKTOOL_VERSION} ==="

    JAR_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
    WRAPPER_URL="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"

    sudo mkdir -p /usr/local/bin
    sudo curl -sL "$JAR_URL"     -o /usr/local/bin/apktool.jar
    sudo curl -sL "$WRAPPER_URL" -o /usr/local/bin/apktool
    sudo chmod +x /usr/local/bin/apktool

    echo "apktool installed at /usr/local/bin/apktool"
fi

echo ""
echo "apktool version: $(apktool --version 2>&1 | head -1)"
echo ""

# Build optional --so argument
SO_ARGS=()
if [ -n "$SO_NAME" ]; then
    SO_ARGS=(--so "$SO_NAME")
fi

# ---------------------------------------------------------------------------
# Step 1: Upload trace to sotrace-server
# ---------------------------------------------------------------------------
echo "=== Step 1: Decompile + upload trace to server ==="
python "$SCRIPT_DIR/sotrace-apktool.py" \
    --apk "$APK" \
    --server "$SOTRACE_SERVER" \
    "${SO_ARGS[@]}"

echo ""

# ---------------------------------------------------------------------------
# Step 2: Save trace to a local file (offline / no server)
# ---------------------------------------------------------------------------
echo "=== Step 2: Save trace to ${OUTPUT_FILE} (offline mode) ==="
python "$SCRIPT_DIR/sotrace-apktool.py" \
    --apk "$APK" \
    --output "$OUTPUT_FILE" \
    "${SO_ARGS[@]}"

echo ""

# ---------------------------------------------------------------------------
# Step 3: Both upload and save, and keep the apktool output directory
# ---------------------------------------------------------------------------
echo "=== Step 3: Upload + save + keep decompiled directory ==="
python "$SCRIPT_DIR/sotrace-apktool.py" \
    --apk "$APK" \
    --server "$SOTRACE_SERVER" \
    --output "${OUTPUT_FILE%.jsonl}_full.jsonl" \
    --keep-dir \
    "${SO_ARGS[@]}"

echo ""
echo "=== Done ==="
echo "  Trace file : $OUTPUT_FILE"
echo "  Server     : $SOTRACE_SERVER"
