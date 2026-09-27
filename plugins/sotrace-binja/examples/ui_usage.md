# sotrace-binja — UI Usage Guide

## Installation

Copy (or symlink) the `sotrace-binja/` directory to your Binary Ninja plugins folder:

```bash
# Linux / macOS
ln -s /path/to/so-trace-database/plugins/sotrace-binja \
      ~/.binaryninja/plugins/sotrace-binja

# Windows (PowerShell, run as Administrator)
New-Item -ItemType Junction `
  -Path "$env:APPDATA\Binary Ninja\plugins\sotrace-binja" `
  -Target "C:\path\to\so-trace-database\plugins\sotrace-binja"
```

Restart Binary Ninja. The plugin loads automatically.

## Menu Commands

| Command | Location | What it does |
|---|---|---|
| `sotrace › Upload All Functions` | Plugins menu | Analyzes every function in the open binary and uploads to sotrace-server |
| `sotrace › Upload This Function` | Right-click on a function | Analyzes only the selected function |
| `sotrace › Save Trace to File` | Plugins menu | Saves trace to a JSONL file (import later with `sotrace-cli`) |

## Workflow

1. Open your Android SO in Binary Ninja.
2. Wait for auto-analysis to complete (progress bar in the bottom-left).
3. **Plugins → sotrace → Upload All Functions**.
4. Enter your sotrace-server URL when prompted (default: `http://localhost:3000`).
5. A dialog shows the `trace_id` and a direct link to the race-condition analysis.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SOTRACE_URL` | `http://localhost:3000` | Pre-fill the URL dialog |

Set it in your shell before launching Binary Ninja:
```bash
export SOTRACE_URL=http://192.168.1.83:3000
/Applications/Binary\ Ninja.app/Contents/MacOS/binaryninja
```

## Notes

- Static analysis only (no runtime tracing). The `is_branch` field is derived from LLIL operation types; `branch_taken` is always `false` because execution order is not known statically.
- Headless mode (no UI) requires a Binary Ninja commercial license — see `examples/headless_analysis.py`.
- Sync events are not collected (not available statically).
