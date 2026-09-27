"""Parse strace -f -tt -T and ltrace output into sotrace import data structures.

Supported inputs:
  strace -f -tt -T     PID  HH:MM:SS.usec  syscall(args) = retval <duration>
  strace -f            [pid PID] syscall(args) = retval          (no timestamp)
  strace (single)      syscall(args) = retval
  ltrace -f            [pid PID] lib->symbol(args) = retval

Syscalls tracked from strace:
  futex              → sync events (Acquire / Release / Signal)
  mmap / mmap2       → memory range records (SO detection via openat correlation)
  clone              → thread creation
  openat / open      → file descriptor tracking (for SO name → fd mapping)

Library calls tracked from ltrace:
  pthread_mutex_lock / unlock / trylock
  pthread_rwlock_rdlock / wrlock / unlock
  pthread_cond_wait / signal / broadcast
  sem_wait / sem_post
  pthread_barrier_wait
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Retval token: hex addresses MUST come before plain integers to avoid
# matching just the leading '0' of '0x7f...' with the '-?\d+' branch.
_RETVAL = r"(0x[0-9a-fA-F]+|-?\d+|MAP_FAILED|ERESTART\w*)"
_RETVAL_SUFFIX = r"(?:\s+\w+)?(?:\s+<[\d.e+-]+>)?"  # optional errno + duration

# strace -f -tt [-T]:  PID  HH:MM:SS.usec  syscall(args) = retval [<duration>]
# This is the canonical format produced by the recommended invocation.
_RE_STRACE_TT = re.compile(
    r"^(\d+)\s+"       # PID
    r"[\d:.]+\s+"      # HH:MM:SS.usec timestamp
    r"(\w+)\("         # syscall_name(
    r"([^)]*)\)"       # args — no nested parens in target syscalls
    r"\s*=\s*" + _RETVAL + _RETVAL_SUFFIX
)

# strace -f (no timestamp):  [pid PID] syscall(args) = retval
_RE_STRACE_PID = re.compile(
    r"^\[pid\s+(\d+)\]\s+"
    r"(\w+)\("
    r"([^)]*)\)"
    r"\s*=\s*" + _RETVAL + _RETVAL_SUFFIX
)

# strace single-threaded (no PID, no timestamp):  syscall(args) = retval
_RE_STRACE_SIMPLE = re.compile(
    r"^(\w+)\("
    r"([^)]*)\)"
    r"\s*=\s*" + _RETVAL + _RETVAL_SUFFIX
)

# ltrace -f:  [pid PID] [lib->]symbol(args) = retval
_RE_LTRACE = re.compile(
    r"^\[pid\s+(\d+)\]\s+"
    r"(?:[\w.]+->)?(\w+)"    # [lib->]symbol
    r"\("
    r"([^)]*)\)"
    r"\s*=\s*(0x[0-9a-fA-F]+|-?\d+)"
)

# Quoted string (for openat path extraction)
_RE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')

# Hex address in args
_RE_HEX = re.compile(r"0x([0-9a-fA-F]+)")


# ---------------------------------------------------------------------------
# Futex operation classification
# ---------------------------------------------------------------------------

_FUTEX_ACQUIRE: frozenset = frozenset({
    "FUTEX_WAIT",
    "FUTEX_WAIT_PRIVATE",
    "FUTEX_WAIT_BITSET",
    "FUTEX_WAIT_BITSET_PRIVATE",
    "FUTEX_LOCK_PI",
    "FUTEX_LOCK_PI2",
    "FUTEX_LOCK_PI_PRIVATE",
})
_FUTEX_RELEASE: frozenset = frozenset({
    "FUTEX_UNLOCK_PI",
    "FUTEX_UNLOCK_PI_PRIVATE",
})
_FUTEX_SIGNAL: frozenset = frozenset({
    "FUTEX_WAKE",
    "FUTEX_WAKE_PRIVATE",
    "FUTEX_WAKE_BITSET",
    "FUTEX_WAKE_BITSET_PRIVATE",
    "FUTEX_REQUEUE",
    "FUTEX_REQUEUE_PRIVATE",
    "FUTEX_CMP_REQUEUE",
    "FUTEX_CMP_REQUEUE_PRIVATE",
    "FUTEX_WAKE_OP",
})

# ltrace pthread symbol → (sync_object_kind, event_type)
_PTHREAD_SYNC: Dict[str, Tuple[str, str]] = {
    "pthread_mutex_lock":     ("Mutex",   "Acquire"),
    "pthread_mutex_trylock":  ("Mutex",   "Acquire"),
    "pthread_mutex_unlock":   ("Mutex",   "Release"),
    "pthread_rwlock_rdlock":  ("RwLock",  "Acquire"),
    "pthread_rwlock_wrlock":  ("RwLock",  "Acquire"),
    "pthread_rwlock_unlock":  ("RwLock",  "Release"),
    "pthread_cond_wait":      ("CondVar", "Acquire"),
    "pthread_cond_signal":    ("CondVar", "Signal"),
    "pthread_cond_broadcast": ("CondVar", "Signal"),
    "sem_wait":               ("Semaphore", "Acquire"),
    "sem_post":               ("Semaphore", "Release"),
    "pthread_barrier_wait":   ("Barrier",  "Signal"),
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ParsedEvent:
    seq: int
    thread_id: int
    kind: str           # "sync" | "memory" | "thread"

    # sync event fields
    event_type: str = ""          # "Acquire" | "Release" | "Signal"
    sync_object_addr: int = 0
    sync_object_kind: str = ""    # "Futex" | "Mutex" | "RwLock" | ...

    # memory range fields (mmap)
    mem_addr: int = 0
    mem_size: int = 0
    mem_prot: str = ""
    mem_is_so: bool = False

    # thread creation fields (clone)
    parent_thread_id: int = 0
    stack_base: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_hex(args: str) -> int:
    """Return the first hex address in *args*, or 0."""
    m = _RE_HEX.search(args)
    return int(m.group(1), 16) if m else 0


def _parse_addr(s: str) -> int:
    """Parse a hex (0x…) or decimal address; returns 0 on failure."""
    s = s.strip().rstrip(",")
    if s in ("NULL", "0", "(null)"):
        return 0
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return 0


def _parse_retval_int(s: str) -> int:
    """Parse a retval string to int; returns -1 on failure."""
    s = s.strip().split()[0]
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return -1


def _split_args(args_raw: str) -> List[str]:
    """Split syscall arg string by top-level commas (respects brackets and quotes)."""
    result: List[str] = []
    buf: List[str] = []
    depth = 0
    in_str = False
    escape = False
    for ch in args_raw:
        if escape:
            buf.append(ch)
            escape = False
        elif ch == "\\" and in_str:
            buf.append(ch)
            escape = True
        elif ch == '"':
            in_str = not in_str
            buf.append(ch)
        elif not in_str and ch in "([{":
            depth += 1
            buf.append(ch)
        elif not in_str and ch in ")]}":
            depth -= 1
            buf.append(ch)
        elif not in_str and ch == "," and depth == 0:
            result.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        result.append("".join(buf).strip())
    return result


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class StraceParser:
    """
    Parse strace -f -tt -T (or ltrace -f) output.

    Args:
        so_name:      Case-insensitive SO filename filter for mmap ranges.
                      When set, only mmap ranges whose fd was opened for this SO
                      are flagged as is_so=True; other ranges are still recorded.
        skip_futex:   Discard futex() sync events.
        skip_mmap:    Discard mmap()/mmap2() memory-range events.
        so_base:      Optional base address for address normalisation (subtracted
                      from recorded mmap/memory addresses).
    """

    def __init__(
        self,
        so_name: str = "",
        skip_futex: bool = False,
        skip_mmap: bool = False,
        so_base: int = 0,
    ) -> None:
        self._so_name = so_name.lower()
        self._skip_futex = skip_futex
        self._skip_mmap = skip_mmap
        self._so_base = so_base

        self._seq: int = 0
        # PID (int) → internal sequential thread_id
        self._pid_to_tid: Dict[int, int] = {}
        self._next_tid: int = 1
        # (pid, fd) → filename — for SO detection via openat
        self._open_fds: Dict[Tuple[int, int], str] = {}
        # thread_id → parent_thread_id  (from clone events)
        self._parent_map: Dict[int, int] = {}
        # thread_id → child_stack (from clone events)
        self._stack_map: Dict[int, int] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, path: str) -> List[ParsedEvent]:
        """Parse a strace/ltrace log file; return events in trace order."""
        events: List[ParsedEvent] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                ev = self.parse_line(line)
                if ev is not None:
                    events.append(ev)
        return events

    def parse_line(self, line: str) -> Optional[ParsedEvent]:
        """Parse a single strace/ltrace output line. Returns None if irrelevant."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        # Skip unfinished / resumed / signal lines
        if "<unfinished" in line or "<..." in line:
            return None
        if line.startswith("---") or line.startswith("+++"):
            return None

        # 1. strace -f -tt format: PID  TIMESTAMP  syscall(args) = retval
        m = _RE_STRACE_TT.match(line)
        if m:
            pid, name, args, retval = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            return self._handle_syscall(pid, name, args, retval)

        # 2. strace -f without timestamp: [pid PID] syscall(args) = retval
        m = _RE_STRACE_PID.match(line)
        if m:
            pid, name, args, retval = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            return self._handle_syscall(pid, name, args, retval)

        # 3. ltrace -f: [pid PID] [lib->]symbol(args) = retval
        m = _RE_LTRACE.match(line)
        if m:
            pid, name, args, retval = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            return self._handle_ltrace(pid, name, args, retval)

        # 4. strace single-threaded: syscall(args) = retval
        m = _RE_STRACE_SIMPLE.match(line)
        if m:
            name, args, retval = m.group(1), m.group(2), m.group(3)
            return self._handle_syscall(1, name, args, retval)

        return None

    def events_to_envelope(self, events: List[ParsedEvent]) -> Dict[str, Any]:
        """Convert a list of ParsedEvent into a sotrace import envelope dict."""
        threads: List[Dict[str, Any]] = []
        seen_tids: set = set()
        sync_events: List[Dict[str, Any]] = []
        memory_reads: List[Dict[str, Any]] = []

        for ev in events:
            if ev.thread_id not in seen_tids:
                seen_tids.add(ev.thread_id)
                threads.append({
                    "thread_id":        ev.thread_id,
                    "create_step":      ev.seq if ev.kind == "thread" else 0,
                    "parent_thread_id": self._parent_map.get(ev.thread_id, 0),
                    "stack_base":       self._stack_map.get(ev.thread_id, 0),
                    "stack_size":       0,
                    "tls_addr":         0,
                    "is_jni_attached":  False,
                })

            if ev.kind == "sync":
                sync_events.append({
                    "step":             ev.seq,
                    "thread_id":        ev.thread_id,
                    "event_type":       ev.event_type,
                    "sync_object_addr": ev.sync_object_addr,
                    "sync_object_kind": ev.sync_object_kind,
                })
            elif ev.kind == "memory" and ev.mem_size > 0:
                memory_reads.append({
                    "step":      ev.seq,
                    "thread_id": ev.thread_id,
                    "address":   ev.mem_addr,
                    "size":      ev.mem_size,
                })

        if not threads:
            threads = [{
                "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                "stack_base": 0, "stack_size": 0, "tls_addr": 0,
                "is_jni_attached": False,
            }]

        return {
            "trace_id":      0,
            "threads":       threads,
            "instructions":  [],
            "calls":         [],
            "memory_writes": [],
            "memory_reads":  memory_reads,
            "sync_events":   sync_events,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_tid(self, pid: int) -> int:
        if pid not in self._pid_to_tid:
            self._pid_to_tid[pid] = self._next_tid
            self._next_tid += 1
        return self._pid_to_tid[pid]

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # ------------------------------------------------------------------
    # Per-syscall handlers
    # ------------------------------------------------------------------

    def _handle_syscall(
        self, pid: int, name: str, args: str, retval: str
    ) -> Optional[ParsedEvent]:
        tid = self._get_tid(pid)

        if name in ("open", "openat"):
            self._handle_open(pid, name, args, retval)
            return None

        if name == "clone":
            return self._handle_clone(pid, tid, args, retval)

        if name in ("mmap", "mmap2") and not self._skip_mmap:
            return self._handle_mmap(pid, tid, args, retval)

        if name == "futex" and not self._skip_futex:
            return self._handle_futex(tid, args)

        return None

    def _handle_open(self, pid: int, name: str, args: str, retval: str) -> None:
        fd = _parse_retval_int(retval)
        if fd < 0:
            return
        qm = _RE_QUOTED.search(args)
        if qm:
            self._open_fds[(pid, fd)] = qm.group(1)

    def _handle_clone(
        self, pid: int, tid: int, args: str, retval: str
    ) -> Optional[ParsedEvent]:
        child_pid = _parse_retval_int(retval)
        if child_pid <= 0:
            return None
        child_tid = self._get_tid(child_pid)
        self._parent_map[child_tid] = tid

        # Extract child_stack from named or positional arg
        split = _split_args(args)
        child_stack = 0
        for arg in split:
            if arg.startswith("child_stack="):
                child_stack = _parse_addr(arg.split("=", 1)[1])
                break
        if not child_stack and split:
            child_stack = _parse_addr(split[0])
        if child_stack:
            self._stack_map[child_tid] = child_stack

        return ParsedEvent(
            seq=self._next_seq(),
            thread_id=child_tid,
            kind="thread",
            parent_thread_id=tid,
            stack_base=child_stack,
        )

    def _handle_mmap(
        self, pid: int, tid: int, args: str, retval: str
    ) -> Optional[ParsedEvent]:
        if retval in ("MAP_FAILED", "-1") or retval.startswith("-1 "):
            return None

        addr = _parse_addr(retval)
        if addr == 0:
            return None

        split = _split_args(args)
        if len(split) < 6:
            return None

        try:
            size = int(split[1].strip(), 0)
        except ValueError:
            return None

        prot = split[2].strip()
        try:
            fd = int(split[4].strip(), 0)
        except ValueError:
            fd = -1

        is_so = False
        if self._so_name and fd >= 0:
            filename = self._open_fds.get((pid, fd), "")
            if self._so_name in filename.lower():
                is_so = True

        return ParsedEvent(
            seq=self._next_seq(),
            thread_id=tid,
            kind="memory",
            mem_addr=addr - self._so_base if self._so_base else addr,
            mem_size=size,
            mem_prot=prot,
            mem_is_so=is_so,
        )

    def _handle_futex(self, tid: int, args: str) -> Optional[ParsedEvent]:
        split = _split_args(args)
        if len(split) < 2:
            return None

        addr = _parse_addr(split[0])
        # Normalise: FUTEX_WAIT|FUTEX_PRIVATE_FLAG → take first pipe segment
        base_op = split[1].strip().split("|")[0].strip()

        if base_op in _FUTEX_ACQUIRE:
            event_type = "Acquire"
        elif base_op in _FUTEX_RELEASE:
            event_type = "Release"
        elif base_op in _FUTEX_SIGNAL:
            event_type = "Signal"
        else:
            return None

        return ParsedEvent(
            seq=self._next_seq(),
            thread_id=tid,
            kind="sync",
            event_type=event_type,
            sync_object_addr=addr,
            sync_object_kind="Futex",
        )

    def _handle_ltrace(
        self, pid: int, name: str, args: str, retval: str
    ) -> Optional[ParsedEvent]:
        mapping = _PTHREAD_SYNC.get(name)
        if not mapping:
            return None
        tid = self._get_tid(pid)
        sync_kind, event_type = mapping
        addr = _first_hex(args)
        return ParsedEvent(
            seq=self._next_seq(),
            thread_id=tid,
            kind="sync",
            event_type=event_type,
            sync_object_addr=addr,
            sync_object_kind=sync_kind,
        )
