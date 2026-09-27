#!/usr/bin/env bash
# analyze_dex.sh — End-to-end example: parse a DEX/APK with dexdump, save + upload.
#
# Prerequisites:
#   - Android SDK build-tools installed (provides dexdump)
#   - Python 3.8+ on PATH
#   - sotrace-server running (optional — omit SERVER_URL to save-only)
#
# Usage:
#   bash analyze_dex.sh <classes.dex|app.apk|classes.jar> [http://server:3000]
#
# Environment variables:
#   ANDROID_HOME  — path to Android SDK root (e.g. $HOME/Android/Sdk)
#   DEXDUMP_PATH  — explicit path to dexdump binary (skips auto-detection)
#   FILTER_CLASS  — class name substring filter (e.g. "com/example")
#
# Examples:
#   # Requires Android SDK build-tools
#   export ANDROID_HOME=$HOME/Android/Sdk
#   python sotrace-dexdump.py classes.dex \
#       --server http://192.168.1.83:3000 \
#       --filter-class com/example
#   # Direct APK support:
#   python sotrace-dexdump.py app.apk --output trace.jsonl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"

DEX_FILE="${1:-}"
SERVER_URL="${2:-}"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
info()  { echo -e "\033[1;34m[sotrace-dexdump]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[sotrace-dexdump]\033[0m $*" >&2; }
error() { echo -e "\033[1;31m[sotrace-dexdump]\033[0m $*" >&2; }

# ---------------------------------------------------------------------------
# Step 0 — Sanity checks
# ---------------------------------------------------------------------------
if [ -z "$DEX_FILE" ]; then
    error "Usage: $0 <classes.dex|app.apk|classes.jar> [http://server:3000]"
    error ""
    error "Examples:"
    error "  $0 classes.dex http://192.168.1.83:3000"
    error "  $0 app.apk --output trace.jsonl"
    error ""
    error "Environment variables:"
    error "  ANDROID_HOME  — path to Android SDK root"
    error "  DEXDUMP_PATH  — explicit path to dexdump binary"
    error "  FILTER_CLASS  — class name substring filter (e.g. com/example)"
    exit 1
fi

if [ ! -f "$DEX_FILE" ]; then
    error "File not found: $DEX_FILE"
    exit 1
fi

DEX_FILE="$(realpath "$DEX_FILE")"
info "Target: $DEX_FILE"

# ---------------------------------------------------------------------------
# Step 1 — Resolve dexdump
# ---------------------------------------------------------------------------
DEXDUMP_ARG=""
if [ -n "${DEXDUMP_PATH:-}" ] && [ -x "$DEXDUMP_PATH" ]; then
    DEXDUMP_ARG="--dexdump $DEXDUMP_PATH"
    info "Using dexdump: $DEXDUMP_PATH"
elif [ -n "${ANDROID_HOME:-}" ]; then
    info "ANDROID_HOME=$ANDROID_HOME (will auto-detect dexdump)"
else
    info "ANDROID_HOME not set — will search PATH and common locations"
fi

FILTER_ARG=""
if [ -n "${FILTER_CLASS:-}" ]; then
    FILTER_ARG="--filter-class $FILTER_CLASS"
    info "Class filter: $FILTER_CLASS"
fi

# ---------------------------------------------------------------------------
# Step 2 — Check Python
# ---------------------------------------------------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    error "python3 not found — install Python 3.8+"
    exit 1
fi
info "Python: $("$PYTHON" --version 2>&1)"

# ---------------------------------------------------------------------------
# Step 3 — Save mode: parse and write JSONL
# ---------------------------------------------------------------------------
OUTPUT_FILE="dex_trace_$(date +%Y%m%d_%H%M%S).jsonl"
info "Parsing $DEX_FILE → $OUTPUT_FILE (save mode)"

(
    cd "$PLUGIN_DIR"
    # shellcheck disable=SC2086
    "$PYTHON" sotrace-dexdump.py "$DEX_FILE" \
        ${DEXDUMP_ARG} \
        ${FILTER_ARG} \
        --output "$OUTPUT_FILE"
)

if [ -f "$PLUGIN_DIR/$OUTPUT_FILE" ]; then
    LINE_COUNT="$(wc -l < "$PLUGIN_DIR/$OUTPUT_FILE")"
    info "Saved $LINE_COUNT envelope(s) to $PLUGIN_DIR/$OUTPUT_FILE"
else
    warn "Output file not created — no methods found?"
fi

# ---------------------------------------------------------------------------
# Step 4 — Upload mode (optional)
# ---------------------------------------------------------------------------
if [ -n "$SERVER_URL" ]; then
    info "Uploading to $SERVER_URL ..."
    TRACE_OUTPUT="$(
        cd "$PLUGIN_DIR"
        # shellcheck disable=SC2086
        "$PYTHON" sotrace-dexdump.py "$DEX_FILE" \
            ${DEXDUMP_ARG} \
            ${FILTER_ARG} \
            --server "$SERVER_URL" 2>&1
    )"
    echo "$TRACE_OUTPUT"

    TRACE_ID="$(echo "$TRACE_OUTPUT" | grep -oP 'trace_id=\K[0-9]+' | head -1 || true)"
    if [ -n "$TRACE_ID" ]; then
        info "Upload successful — trace_id=${TRACE_ID}"

        # -------------------------------------------------------------------
        # Step 5 — Fetch scheduling analysis from server
        # -------------------------------------------------------------------
        ANALYSIS_URL="${SERVER_URL}/api/v1/traces/${TRACE_ID}/analyze/threads/scheduling"
        info "Fetching scheduling analysis: $ANALYSIS_URL"

        if command -v curl &>/dev/null; then
            curl -fsSL "$ANALYSIS_URL" | "$PYTHON" -m json.tool 2>/dev/null \
                || curl -fsSL "$ANALYSIS_URL"
        elif command -v wget &>/dev/null; then
            wget -qO- "$ANALYSIS_URL"
        else
            info "Install curl or wget to fetch analysis results automatically"
        fi
    else
        warn "Could not extract trace_id from upload output"
    fi
else
    info "No server URL given — skipping upload."
    info "To upload:"
    echo "  cd $PLUGIN_DIR && python3 sotrace-dexdump.py \"$DEX_FILE\" --server http://HOST:3000"
fi

info "Done."
