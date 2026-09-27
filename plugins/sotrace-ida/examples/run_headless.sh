#!/usr/bin/env bash
# examples/run_headless.sh
# ========================
# Run the sotrace IDA plugin in fully headless (batch) mode.
#
# IDA Pro's text-mode binary (idat64) can execute a script with -A (no GUI)
# and -S (script to run after auto-analysis completes).
#
# Usage
# -----
#   chmod +x examples/run_headless.sh
#   ./examples/run_headless.sh /path/to/libfoo.so http://192.168.1.83:3000
#
# Or set environment variables and run idat64 directly:
#   export SOTRACE_URL=http://192.168.1.83:3000
#   idat64 -A -Ssotrace_ida.py /path/to/libfoo.so
#
# Arguments
#   $1  Path to the target binary / SO file (required)
#   $2  sotrace-server URL, e.g. http://localhost:3000
#       Omit or set to "" to save output to /tmp/sotrace_ida_trace.jsonl instead.

set -euo pipefail

BINARY="${1:-}"
SOTRACE_URL="${2:-${SOTRACE_URL:-}}"

if [[ -z "$BINARY" ]]; then
    echo "Usage: $0 <binary> [server-url]" >&2
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "Error: file not found: $BINARY" >&2
    exit 1
fi

# Locate sotrace_ida.py relative to this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_SCRIPT="$SCRIPT_DIR/../sotrace_ida.py"

if [[ ! -f "$PLUGIN_SCRIPT" ]]; then
    echo "Error: sotrace_ida.py not found at $PLUGIN_SCRIPT" >&2
    exit 1
fi

export SOTRACE_URL

echo "[sotrace] Analysing: $BINARY"
if [[ -n "$SOTRACE_URL" ]]; then
    echo "[sotrace] Upload target: $SOTRACE_URL"
else
    OUT="${SOTRACE_OUTPUT_FILE:-/tmp/sotrace_ida_trace.jsonl}"
    export SOTRACE_OUTPUT_FILE="$OUT"
    echo "[sotrace] No server URL — saving to: $OUT"
fi

# -A          : autonomous mode (no GUI, no user prompts from IDA itself)
# -S<script>  : run script after auto-analysis; no space between -S and path
# -c          : disassemble a new database (discard existing .i64 if any)
# -L/dev/null : suppress IDA's own log output (optional, remove to keep it)
idat64 -A -c "-S${PLUGIN_SCRIPT}" "$BINARY"

echo "[sotrace] Done."

# -----------------------------------------------------------------------
# Interactive (GUI) usage reminder
# -----------------------------------------------------------------------
#
#   1. Copy sotrace_ida.py and the sotrace_ida/ folder to your IDA plugins dir:
#        Linux/macOS:  ~/.idapro/plugins/
#        Windows:      %APPDATA%\Hex-Rays\IDA Pro\plugins\
#
#   2. Restart IDA Pro.
#
#   3. Open the target SO/binary and wait for auto-analysis to finish.
#
#   4. Trigger the plugin:
#        Menu:   Edit > Plugins > sotrace
#        Hotkey: Ctrl-Alt-S
#
#   A dialog will ask for the sotrace-server URL.  Leave it blank to save
#   to a JSONL file instead of uploading.
