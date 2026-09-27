"""IDA Pro plugin_t implementation."""
import json
import os

try:
    import idaapi  # type: ignore
    HAS_IDA = True
except ImportError:
    HAS_IDA = False

from .analyzer import analyze_static
from .client import SoTraceClient
from .commands import ask_server_url, ask_output_file, show_info, show_warning

ACTION_ID = "sotrace:upload"
ACTION_LABEL = "Upload to sotrace-server"
ACTION_HOTKEY = "Ctrl+Shift+T"


def _do_upload() -> None:
    server_url = ask_server_url()
    output_file = ""

    if not server_url:
        output_file = ask_output_file()
        if not output_file:
            return

    print("[sotrace] Collecting instructions (may take a moment)…")
    try:
        envelope = analyze_static()
    except Exception as exc:
        show_warning(f"sotrace: analysis failed: {exc}")
        return

    n_insn = len(envelope.get("instructions", []))
    n_call = len(envelope.get("calls", []))
    print(f"[sotrace] Collected {n_insn} instructions, {n_call} calls")

    if server_url:
        try:
            client = SoTraceClient(server_url)
            trace_id = client.import_trace(envelope)
            msg = (
                f"sotrace upload done!\n"
                f"trace_id = {trace_id}\n"
                f"instructions = {n_insn}\n"
                f"calls = {n_call}\n\n"
                f"Races: {server_url}/api/v1/traces/{trace_id}/analyze/threads/races"
            )
            show_info(msg)
        except Exception as exc:
            show_warning(f"sotrace: upload failed: {exc}")

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(envelope) + "\n")
            show_info(f"sotrace: saved to {output_file}")
        except Exception as exc:
            show_warning(f"sotrace: save failed: {exc}")


if HAS_IDA:
    class _SoTraceAction(idaapi.action_handler_t):
        def activate(self, ctx):
            _do_upload()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    class SoTracePlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_UNL
        comment = "Upload trace to sotrace-server for analysis"
        help = "Ctrl+Shift+T — upload current binary analysis to sotrace-server"
        wanted_name = "sotrace"
        wanted_hotkey = ""

        def init(self):
            desc = idaapi.action_desc_t(
                ACTION_ID,
                ACTION_LABEL,
                _SoTraceAction(),
                ACTION_HOTKEY,
                "Upload instructions/calls to sotrace-server",
                -1,
            )
            idaapi.register_action(desc)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/", ACTION_ID, idaapi.SETMENU_APP
            )
            print(f"[sotrace] loaded — press {ACTION_HOTKEY} to upload")
            return idaapi.PLUGIN_KEEP

        def run(self, arg):
            _do_upload()

        def term(self):
            idaapi.unregister_action(ACTION_ID)

    def PLUGIN_ENTRY():
        return SoTracePlugin()

else:
    class SoTracePlugin:  # type: ignore
        pass
