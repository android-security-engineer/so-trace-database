"""UI helpers for the IDA Pro plugin."""


def ask_server_url(default: str = "http://localhost:3000") -> str:
    try:
        import idaapi  # type: ignore
        url = idaapi.ask_str(default, 0, "sotrace-server URL (leave empty to save to file):")
        return (url or "").strip()
    except Exception:
        return ""


def ask_output_file() -> str:
    try:
        import idaapi  # type: ignore
        path = idaapi.ask_file(True, "*.jsonl", "Save trace as JSONL:")
        return path or ""
    except Exception:
        return ""


def show_info(msg: str) -> None:
    try:
        import idaapi  # type: ignore
        idaapi.info(msg)
    except Exception:
        print(msg)


def show_warning(msg: str) -> None:
    try:
        import idaapi  # type: ignore
        idaapi.warning(msg)
    except Exception:
        print(f"[warning] {msg}")
