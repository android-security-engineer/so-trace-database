"""
sotrace IDA Plugin / Script
===========================
Two usage modes:

  Script mode  — File -> Script File -> sotrace_ida.py
                 Runs main() immediately; prompts for server URL or output file.

  Plugin mode  — Copy sotrace_ida.py + sotrace_ida/ to <IDA>/plugins/
                 Registers "sotrace" in Edit -> Plugins (hotkey Ctrl-Alt-S).

Requires IDA Pro 7.4+ (Python 3).  For older IDA (Python 2.7) replace
f-strings with .format() calls.
"""

import os
import sys

# Ensure the package directory is on sys.path whether loaded as script or plugin.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Guard IDA imports so the module can be imported outside IDA (tests, CI).
try:
    import idaapi    # type: ignore
    import idc       # type: ignore
    import idautils  # type: ignore
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False

PLUGIN_NAME   = "sotrace"
PLUGIN_HOTKEY = "Ctrl-Alt-S"


# ---------------------------------------------------------------------------
# Core upload logic
# ---------------------------------------------------------------------------

def upload_all(server_url: str, output_file: str = "") -> None:
    """Analyse every function in the current IDB and push the envelope.

    Args:
        server_url:  If non-empty, POST to sotrace-server and show trace_id.
        output_file: If non-empty, write the envelope as JSONL to this path.
    """
    from sotrace_ida.analyzer import IDAAnalyzer
    from sotrace_ida.client import SoTraceClient

    analyzer = IDAAnalyzer()

    if IDA_AVAILABLE:
        idaapi.show_wait_box("sotrace: analysing functions…")
    try:
        envelope = analyzer.analyze_all()
    finally:
        if IDA_AVAILABLE:
            idaapi.hide_wait_box()

    n_insns = len(envelope.get("instructions", []))
    n_calls = len(envelope.get("calls", []))

    if server_url:
        client = SoTraceClient(server_url)
        try:
            trace_id = client.import_trace(envelope)
            msg = (
                "sotrace upload complete!\n\n"
                "trace_id     = {}\n"
                "instructions = {}\n"
                "calls        = {}\n\n"
                "Races: {}/api/v1/traces/{}/analyze/threads/races".format(
                    trace_id, n_insns, n_calls, server_url.rstrip("/"), trace_id
                )
            )
            if IDA_AVAILABLE:
                idaapi.info(msg)
            else:
                print(msg)
        except Exception as exc:
            if IDA_AVAILABLE:
                idaapi.warning("sotrace upload failed: {}".format(exc))
            else:
                print("[warning] sotrace upload failed: {}".format(exc))

    if output_file:
        import json
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope) + "\n")
        msg = "sotrace saved to {}\n({} instructions, {} calls)".format(
            output_file, n_insns, n_calls)
        if IDA_AVAILABLE:
            idaapi.info(msg)
        else:
            print(msg)


# ---------------------------------------------------------------------------
# Interactive entry point (script mode or plugin.run)
# ---------------------------------------------------------------------------

def main() -> None:
    """Ask for destination, run analysis, upload/save."""
    from sotrace_ida.ui import ask_server_url, ask_output_file

    server_url = ask_server_url()
    output_file = ""

    if not server_url:
        output_file = ask_output_file()
        if not output_file:
            return  # user cancelled

    upload_all(server_url, output_file)


# ---------------------------------------------------------------------------
# Plugin wrapper
# ---------------------------------------------------------------------------

def PLUGIN_ENTRY():  # noqa: N802  (IDA naming convention)
    try:
        return SoTracePlugin()
    except Exception:
        return None


class SoTracePlugin:
    """IDA plugin_t — registered in Edit > Plugins as 'sotrace' (Ctrl-Alt-S)."""

    flags       = 0   # updated to PLUGIN_UNL in init()
    comment     = "Upload instruction trace to sotrace-database for thread analysis"
    help        = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        if IDA_AVAILABLE:
            self.flags = idaapi.PLUGIN_UNL
            return idaapi.PLUGIN_OK
        return 0  # PLUGIN_SKIP

    def term(self):
        pass

    def run(self, _arg):
        main()


# ---------------------------------------------------------------------------
# Auto-run when executed as a script (File -> Script File)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Standalone / headless: read URL from env or prompt via ui helpers.
    from sotrace_ida.ui import ask_server_url, ask_output_file
    _url = ask_server_url()
    _out = "" if _url else ask_output_file()
    upload_all(_url, _out)
else:
    # Loaded inside IDA as a script (not as a plugin).
    try:
        if IDA_AVAILABLE and not getattr(idaapi, "_sotrace_loaded_as_plugin", False):
            main()
    except Exception:
        pass

