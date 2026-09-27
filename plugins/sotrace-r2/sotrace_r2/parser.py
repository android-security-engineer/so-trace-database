"""Helper functions to parse radare2 JSON command output."""


def parse_sections(r2) -> list:
    """Return list of section dicts from iSj."""
    try:
        return r2.cmdj("iSj") or []
    except Exception:
        return []


def find_text_section(r2) -> tuple:
    """Return (vaddr, size) of the .text / CODE section, or (0, 0)."""
    for sec in parse_sections(r2):
        name = sec.get("name", "")
        if ".text" in name or "CODE" in name.upper():
            vaddr = sec.get("vaddr", 0)
            size = sec.get("vsize", sec.get("size", 0))
            if vaddr:
                return vaddr, size
    return 0, 0


def parse_imports(r2) -> list:
    """Return import entries from iij."""
    try:
        return r2.cmdj("iij") or []
    except Exception:
        return []


def parse_exports(r2) -> list:
    """Return export entries from iEj."""
    try:
        return r2.cmdj("iEj") or []
    except Exception:
        return []


def get_base_addr(r2) -> int:
    """Return binary base address from ij (baddr field)."""
    try:
        info = r2.cmdj("ij") or {}
        return info.get("bin", {}).get("baddr", 0)
    except Exception:
        return 0
