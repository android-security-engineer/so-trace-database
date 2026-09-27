#!/usr/bin/env bash
# analyze_apk.sh — End-to-end example: install jadx, run plugin, save + upload.
#
# Prerequisites:
#   - Java 11+ on PATH (required by jadx)
#   - Python 3.8+ on PATH
#   - sotrace-server running (or skip the upload step)
#
# Usage:
#   bash analyze_apk.sh [/path/to/target.apk] [http://sotrace-server-host:3000]
#
# Environment variables:
#   JADX_PATH  — path to an existing jadx binary (skips download step)
#   JADX_VERSION — jadx release to download (default: 1.5.0)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"

APK="${1:-}"
SERVER_URL="${2:-}"

JADX_VERSION="${JADX_VERSION:-1.5.0}"
JADX_DIR="${HOME}/.cache/sotrace-jadx/jadx-${JADX_VERSION}"

# ---------------------------------------------------------------------------
# Helper: print a coloured section header
# ---------------------------------------------------------------------------
info()  { echo -e "\033[1;34m[sotrace-jadx]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[sotrace-jadx]\033[0m $*" >&2; }
error() { echo -e "\033[1;31m[sotrace-jadx]\033[0m $*" >&2; }

# ---------------------------------------------------------------------------
# Step 0 — Sanity checks
# ---------------------------------------------------------------------------
if [ -z "$APK" ]; then
    error "Usage: $0 <target.apk> [http://server:3000]"
    error "  Example: $0 app-debug.apk http://192.168.1.83:3000"
    exit 1
fi

if [ ! -f "$APK" ]; then
    error "APK/DEX file not found: $APK"
    exit 1
fi

# Resolve to absolute path
APK="$(realpath "$APK")"
info "Target: $APK"

# ---------------------------------------------------------------------------
# Step 1 — Install jadx (if not already present)
# ---------------------------------------------------------------------------
if [ -n "${JADX_PATH:-}" ] && [ -x "$JADX_PATH" ]; then
    info "Using pre-configured jadx: $JADX_PATH"
else
    JADX_BIN="$JADX_DIR/bin/jadx"
    if [ -x "$JADX_BIN" ]; then
        info "jadx ${JADX_VERSION} already cached at $JADX_BIN"
    else
        info "Downloading jadx ${JADX_VERSION} …"
        ZIP_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
        ZIP_TMP="$(mktemp /tmp/jadx-XXXXXX.zip)"

        # Try wget first, fall back to curl
        if command -v wget &>/dev/null; then
            wget -q -O "$ZIP_TMP" "$ZIP_URL"
        elif command -v curl &>/dev/null; then
            curl -fsSL -o "$ZIP_TMP" "$ZIP_URL"
        else
            error "Neither wget nor curl found — install one or set JADX_PATH"
            exit 1
        fi

        mkdir -p "$JADX_DIR"
        unzip -q "$ZIP_TMP" -d "$JADX_DIR"
        rm -f "$ZIP_TMP"
        chmod +x "$JADX_BIN"
        info "jadx installed to $JADX_BIN"
    fi
    export JADX_PATH="$JADX_BIN"
fi

# ---------------------------------------------------------------------------
# Step 2 — Check Python
# ---------------------------------------------------------------------------
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    error "python3 not found — install Python 3.8+"
    exit 1
fi

PY_VERSION="$("$PYTHON" --version 2>&1)"
info "Python: $PY_VERSION"

# ---------------------------------------------------------------------------
# Step 3 — Save mode: extract and write JSONL
# ---------------------------------------------------------------------------
OUTPUT_FILE="jni_methods_$(date +%Y%m%d_%H%M%S).jsonl"
info "Extracting JNI methods → $OUTPUT_FILE (save mode)"

(
    cd "$PLUGIN_DIR"
    "$PYTHON" sotrace-jadx.py jadx \
        --apk "$APK" \
        --output "$OUTPUT_FILE"
)

if [ -f "$PLUGIN_DIR/$OUTPUT_FILE" ]; then
    METHOD_COUNT="$(wc -l < "$PLUGIN_DIR/$OUTPUT_FILE")"
    info "Saved $METHOD_COUNT envelope(s) to $PLUGIN_DIR/$OUTPUT_FILE"
else
    warn "Output file not created — no native methods found?"
fi

# ---------------------------------------------------------------------------
# Step 4 — Upload mode (optional)
# ---------------------------------------------------------------------------
if [ -n "$SERVER_URL" ]; then
    info "Uploading to $SERVER_URL …"
    (
        cd "$PLUGIN_DIR"
        TRACE_OUTPUT="$("$PYTHON" sotrace-jadx.py jadx \
            --apk "$APK" \
            --server "$SERVER_URL" 2>&1)"
        echo "$TRACE_OUTPUT"
        TRACE_ID="$(echo "$TRACE_OUTPUT" | grep -oP 'trace_id=\K[0-9]+')"
        if [ -n "$TRACE_ID" ]; then
            info "Upload successful — trace_id=${TRACE_ID}"

            # ---------------------------------------------------------------------------
            # Step 5 — Fetch JNI boundary analysis from server
            # ---------------------------------------------------------------------------
            ANALYSIS_URL="${SERVER_URL}/api/v1/traces/${TRACE_ID}/analyze/threads/jni_boundary"
            info "Fetching JNI boundary analysis: $ANALYSIS_URL"

            if command -v curl &>/dev/null; then
                curl -fsSL "$ANALYSIS_URL" | python3 -m json.tool 2>/dev/null || \
                    curl -fsSL "$ANALYSIS_URL"
            elif command -v wget &>/dev/null; then
                wget -qO- "$ANALYSIS_URL"
            else
                info "Install curl or wget to auto-fetch analysis results"
            fi
        fi
    )
else
    info "No --server specified — skipping upload."
    info "To upload, run:"
    echo "  cd $PLUGIN_DIR && python3 sotrace-jadx.py jadx --apk \"$APK\" --server http://HOST:3000"
fi

info "Done."
