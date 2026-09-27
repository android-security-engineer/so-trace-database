"""Parse ltrace output into a list of typed event dicts.

Supported ltrace invocation flags: -f -tt -T
Output line format:
    PID  HH:MM:SS.usec  FUNC(ARGS) = RETVAL <elapsed_sec>

Parsed event kinds:
    sync       — pthread mutex/cond primitives → sync_events
    thread_create — pthread_create
    dlopen     — dynamic library load (SO name + base address)
    dlsym      — dynamic symbol lookup
    malloc / free — heap allocations (optional)
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Matches a full ltrace line.  Groups:
#   1 — PID (decimal)
#   2 — timestamp (HH:MM:SS.usec)
#   3 — function name
#   4 — raw argument string (everything inside the outer parentheses)
#   5 — raw return value (may include trailing <elapsed>, stripped below)
_LINE = re.compile(
    r'^(\d+)\s+([\d:.]+)\s+(\w+)\(([^)]*)\)\s*(?:=\s*(.+))?$'
)

# Trailing timing annotation appended by -T flag: <digits.digits>
_TIMING = re.compile(r'\s*<[\d.]+>\s*$')

# Hex address anywhere in a string
_HEX = re.compile(r'0x[0-9a-fA-F]+')

# Quoted string literal (first match)
_QUOTED = re.compile(r'"([^"]*)"')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_addr(s: str) -> int:
    """Return first hex address found in *s*, or 0."""
    m = _HEX.search(s)
    return int(m.group(0), 16) if m else 0


def _all_addrs(s: str) -> list:
    """Return all hex addresses found in *s* (in order)."""
    return [int(v, 16) for v in _HEX.findall(s)]


def _first_string(s: str) -> str:
    """Return the first double-quoted string content found in *s*, or ''."""
    m = _QUOTED.search(s)
    return m.group(1) if m else ""


def _clean_retval(raw: str) -> str:
    """Strip trailing <elapsed> timing annotation from the raw retval string."""
    return _TIMING.sub("", raw).strip()


# ---------------------------------------------------------------------------
# Line interpreter
# ---------------------------------------------------------------------------

def _interpret(
    pid: int,
    timestamp: str,
    func: str,
    args_raw: str,
    retval_raw: str,
) -> Optional[dict]:
    """Map one parsed ltrace line to a typed event dict, or None to skip."""
    base = {
        "pid": pid,
        "timestamp": timestamp,
        "func": func,
    }

    # --- mutex ---
    if func == "pthread_mutex_lock":
        addr = _first_addr(args_raw)
        return {**base, "kind": "sync",
                "event_type": "Acquire", "sync_kind": "Mutex",
                "sync_addr": addr}

    if func == "pthread_mutex_unlock":
        addr = _first_addr(args_raw)
        return {**base, "kind": "sync",
                "event_type": "Release", "sync_kind": "Mutex",
                "sync_addr": addr}

    if func == "pthread_mutex_trylock":
        # Only record successful trylock (retval == 0)
        addr = _first_addr(args_raw)
        try:
            if int(retval_raw) == 0:
                return {**base, "kind": "sync",
                        "event_type": "Acquire", "sync_kind": "Mutex",
                        "sync_addr": addr}
        except (ValueError, TypeError):
            pass
        return None

    # --- condvar ---
    if func == "pthread_cond_wait":
        # Args: cond_ptr, mutex_ptr
        addrs = _all_addrs(args_raw)
        cond_addr  = addrs[0] if len(addrs) > 0 else 0
        mutex_addr = addrs[1] if len(addrs) > 1 else 0
        return {**base, "kind": "sync",
                "event_type": "Wait", "sync_kind": "Condvar",
                "sync_addr": cond_addr, "mutex_addr": mutex_addr}

    if func in ("pthread_cond_signal", "pthread_cond_broadcast"):
        addr = _first_addr(args_raw)
        return {**base, "kind": "sync",
                "event_type": "Signal", "sync_kind": "Condvar",
                "sync_addr": addr}

    # --- rwlock (map to Mutex semantics) ---
    if func in ("pthread_rwlock_rdlock", "pthread_rwlock_wrlock"):
        addr = _first_addr(args_raw)
        return {**base, "kind": "sync",
                "event_type": "Acquire", "sync_kind": "Mutex",
                "sync_addr": addr}

    if func == "pthread_rwlock_unlock":
        addr = _first_addr(args_raw)
        return {**base, "kind": "sync",
                "event_type": "Release", "sync_kind": "Mutex",
                "sync_addr": addr}

    # --- thread lifecycle ---
    if func == "pthread_create":
        return {**base, "kind": "thread_create"}

    # --- dynamic loading ---
    if func == "dlopen":
        so_name  = _first_string(args_raw)
        base_addr = _first_addr(retval_raw)
        return {**base, "kind": "dlopen",
                "so_name": so_name, "base_addr": base_addr}

    if func == "dlsym":
        symbol   = _first_string(args_raw)
        sym_addr = _first_addr(retval_raw)
        return {**base, "kind": "dlsym",
                "symbol": symbol, "sym_addr": sym_addr}

    # --- heap (optional) ---
    if func in ("malloc", "calloc", "realloc"):
        alloc_addr = _first_addr(retval_raw)
        return {**base, "kind": "malloc", "alloc_addr": alloc_addr}

    if func == "free":
        free_addr = _first_addr(args_raw)
        return {**base, "kind": "free", "free_addr": free_addr}

    # Unrecognised function — skip silently
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class LtraceParser:
    """Parse ltrace log content into a list of typed event dicts."""

    def parse(self, log_content: str) -> list:
        """Return a list of event dicts for every recognised ltrace line."""
        events = []
        for line in log_content.splitlines():
            line = line.strip()
            if not line:
                continue

            m = _LINE.match(line)
            if not m:
                continue

            pid        = int(m.group(1))
            timestamp  = m.group(2)
            func       = m.group(3)
            args_raw   = m.group(4) or ""
            retval_raw = _clean_retval(m.group(5) or "")

            event = _interpret(pid, timestamp, func, args_raw, retval_raw)
            if event is not None:
                events.append(event)

        return events


# Convenience function matching the spec interface
def parse(log_content: str) -> list:
    """Parse *log_content* and return a list of event dicts."""
    return LtraceParser().parse(log_content)
