"""UI helpers for the sotrace IDA plugin.

All functions gracefully degrade to stdin/stdout when IDA's GUI is unavailable
(e.g. headless batch mode or plain Python unit tests).
"""

try:
    import idaapi  # type: ignore
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


def ask_server_url(default: str = "http://localhost:3000") -> str:
    """Prompt the user for a sotrace-server URL.

    Returns the entered string, or an empty string if the user cancels or
    leaves the field blank (caller should fall back to file output).
    """
    if IDA_AVAILABLE:
        try:
            url = idaapi.ask_str(default, 0,
                                 "sotrace-server URL (leave empty to save to file):")
            return (url or "").strip()
        except Exception:
            pass
    # Headless / test fallback
    try:
        import os
        env = os.environ.get("SOTRACE_URL", "").strip()
        if env:
            return env
        return input(f"sotrace-server URL [{default}]: ").strip() or default
    except Exception:
        return default


def ask_output_file(default: str = "/tmp/sotrace_ida_trace.jsonl") -> str:
    """Prompt the user for an output JSONL file path.

    Returns the entered path, or an empty string if the user cancels.
    """
    if IDA_AVAILABLE:
        try:
            path = idaapi.ask_file(True, "*.jsonl", "Save trace as JSONL:")
            return path or ""
        except Exception:
            pass
    # Headless / test fallback
    try:
        import os
        env = os.environ.get("SOTRACE_OUTPUT_FILE", "").strip()
        if env:
            return env
        return input(f"Output file [{default}]: ").strip() or default
    except Exception:
        return default


def show_info(msg: str) -> None:
    """Display an informational message box (or print to stdout)."""
    if IDA_AVAILABLE:
        try:
            idaapi.info(msg)
            return
        except Exception:
            pass
    print(msg)


def show_warning(msg: str) -> None:
    """Display a warning message box (or print to stderr)."""
    if IDA_AVAILABLE:
        try:
            idaapi.warning(msg)
            return
        except Exception:
            pass
    import sys
    print(f"[warning] {msg}", file=sys.stderr)
