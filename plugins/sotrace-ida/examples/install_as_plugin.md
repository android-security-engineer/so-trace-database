# Installing sotrace as a persistent IDA Pro plugin

## Requirements

- IDA Pro 7.4 or newer (Python 3 required)
- Network access to sotrace-server (or write access for file output)

## Installation

### Step 1 — Copy files

```bash
# Linux / macOS
PLUGINS="$HOME/.idapro/plugins"          # user plugin directory (preferred)
# or: PLUGINS="<IDA install dir>/plugins"

cp plugins/sotrace-ida/sotrace_ida.py   "$PLUGINS/"
cp -r plugins/sotrace-ida/sotrace_ida/  "$PLUGINS/sotrace_ida/"
```

```bat
rem Windows
set PLUGINS=%APPDATA%\Hex-Rays\IDA Pro\plugins
copy plugins\sotrace-ida\sotrace_ida.py "%PLUGINS%\"
xcopy /e plugins\sotrace-ida\sotrace_ida\ "%PLUGINS%\sotrace_ida\"
```

### Step 2 — Restart IDA

The plugin loads automatically on startup.

### Step 3 — Use

- **Menu**: Edit → Plugins → sotrace
- **Hotkey**: `Ctrl + Alt + S`

Both methods open the same dialog asking for a sotrace-server URL.

---

## Headless / batch mode

Run IDA without a GUI and execute the script immediately:

```bash
# Analyse libfoo.so and save JSONL (no GUI)
idat64 -A -S"sotrace_ida.py" -c libfoo.so
```

For headless use the script detects the absence of interactive dialogs and
reads the server URL from the environment variable `SOTRACE_URL`:

```bash
export SOTRACE_URL=http://192.168.1.83:3000
idat64 -A -Ssotrace_ida.py libfoo.so
```

_(Set `SOTRACE_URL` to an empty string or omit it to fall back to saving
`/tmp/sotrace_ida_trace.jsonl` instead of uploading.)_

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| "ModuleNotFoundError: sotrace\_ida" | Ensure `sotrace_ida/` folder is next to `sotrace_ida.py` in the plugins dir |
| Upload timeout | Increase timeout in `client.py` or check firewall rules |
| Empty instructions list | Wait for IDA auto-analysis to finish before running the plugin |
| Python 2 errors | Upgrade to IDA 7.4+; the plugin requires Python 3 |
