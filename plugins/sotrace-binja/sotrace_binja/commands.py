"""Binary Ninja UI commands — registered via PluginCommand on plugin load."""

import json
import os

from .analyzer import SoTraceAnalyzer
from .client import SoTraceClient

_DEFAULT_URL = os.environ.get("SOTRACE_URL", "http://localhost:3000")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _upload_all_functions(bv) -> None:
    """Analyze all functions and upload to sotrace-server."""
    import binaryninja as bn

    raw = bn.get_text_line_input("sotrace-server URL", "URL")
    url = (raw.decode() if isinstance(raw, bytes) else raw or "").strip() or _DEFAULT_URL

    analyzer = SoTraceAnalyzer(bv)
    envelope = analyzer.analyze_static()

    client = SoTraceClient(url)
    try:
        trace_id = client.import_trace(envelope)
        bn.show_message_box(
            "sotrace Upload Complete",
            (
                f"trace_id = {trace_id}\n\n"
                f"Instructions : {len(envelope['instructions'])}\n"
                f"Calls        : {len(envelope['calls'])}\n\n"
                f"Races analysis:\n{url}/traces/{trace_id}/analyze/threads/races"
            ),
            bn.MessageBoxButtonSet.OKButtonSet,
        )
    except Exception as exc:
        bn.show_message_box(
            "sotrace Error", str(exc), bn.MessageBoxButtonSet.OKButtonSet
        )


def _upload_current_function(bv, func) -> None:
    """Analyze only the right-clicked function and upload to sotrace-server."""
    import binaryninja as bn

    raw = bn.get_text_line_input("sotrace-server URL", "URL")
    url = (raw.decode() if isinstance(raw, bytes) else raw or "").strip() or _DEFAULT_URL

    analyzer = SoTraceAnalyzer(bv)
    envelope = analyzer.analyze_function(func)

    client = SoTraceClient(url)
    try:
        trace_id = client.import_trace(envelope)
        bn.show_message_box(
            "sotrace Upload Complete",
            f"Function : {func.name}\ntrace_id = {trace_id}",
            bn.MessageBoxButtonSet.OKButtonSet,
        )
    except Exception as exc:
        bn.show_message_box(
            "sotrace Error", str(exc), bn.MessageBoxButtonSet.OKButtonSet
        )


def _save_to_file(bv) -> None:
    """Save trace to a JSONL file (import later with sotrace-cli)."""
    import binaryninja as bn

    raw_path = bn.get_save_filename_input(
        "Save trace as JSONL", "*.jsonl", "trace.jsonl"
    )
    if not raw_path:
        return
    path = raw_path.decode() if isinstance(raw_path, bytes) else raw_path

    analyzer = SoTraceAnalyzer(bv)
    envelope = analyzer.analyze_static()

    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(envelope) + "\n")

    bn.show_message_box(
        "sotrace Saved",
        f"Saved {len(envelope['instructions'])} instructions to:\n{path}",
        bn.MessageBoxButtonSet.OKButtonSet,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_commands() -> None:
    """Register all sotrace commands in Binary Ninja's plugin menu."""
    try:
        from binaryninja.plugin import PluginCommand

        PluginCommand.register(
            r"sotrace\Upload All Functions",
            "Analyze all functions and upload trace to sotrace-server",
            _upload_all_functions,
        )
        PluginCommand.register_for_function(
            r"sotrace\Upload This Function",
            "Analyze this function and upload to sotrace-server",
            _upload_current_function,
        )
        PluginCommand.register(
            r"sotrace\Save Trace to File",
            "Save trace to JSONL file for later import with sotrace-cli",
            _save_to_file,
        )
    except ImportError:
        pass  # Outside Binary Ninja — skip silently
