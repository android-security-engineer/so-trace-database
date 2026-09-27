"""Parse ThreadSanitizer (TSan) text reports and convert to sotrace import envelope.

TSan report format (LLVM/Clang/NDK):

  WARNING: ThreadSanitizer: data race (pid=1234)
    Write of size 4 at 0x7f1234abcd by thread T2:
      #0 foo() foo.cpp:42 (libfoo.so+0x1234)
      #1 bar() bar.cpp:10 (libfoo.so+0x5678)
    Previous read of size 4 at 0x7f1234abcd by thread T1:
      #0 baz() baz.cpp:7 (libfoo.so+0x9abc)
    Location is ...
    Mutex M1 (0xdeadbeef) is already held by thread T1.

We extract:
  - Thread IDs (T1, T2, ...)
  - Sync events from Mutex Hold/Lock/Unlock lines
  - RaceCondition-style memory access events (mapped to sync_events MutexLock)
  - Data race addresses → memory_reads
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class TsanThread:
    tsan_id: str    # "T1", "T2", ...
    thread_id: int  # sequential 1-based


@dataclass
class TsanEvent:
    seq: int
    thread_id: int
    kind: str       # "sync" | "memory"
    sync_type: str = ""
    sync_addr: int = 0
    sync_result: str = "Success"
    mem_addr: int = 0
    mem_size: int = 0


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Start of a data race report
_RE_RACE_START = re.compile(
    r"WARNING: ThreadSanitizer: (data race|lock-order-inversion|thread leak|"
    r"use of an invalid mutex|double lock of a mutex|"
    r"destroy of a locked mutex|unlock of an unlocked mutex)"
)

# "  Write of size 4 at 0x7f... by thread T2:"
_RE_ACCESS = re.compile(
    r"^\s+(Read|Write) of size (\d+) at 0x([0-9a-fA-F]+)\s+by\s+thread\s+(T\d+)",
    re.IGNORECASE,
)

# "  Previous read of size 4 at 0x7f... by thread T1:"
_RE_PREV_ACCESS = re.compile(
    r"^\s+Previous\s+(read|write) of size (\d+) at 0x([0-9a-fA-F]+)\s+by\s+thread\s+(T\d+)",
    re.IGNORECASE,
)

# "  Mutex M1 (0xdeadbeef) locked by thread T2 at:"
_RE_MUTEX = re.compile(
    r"Mutex\s+\w+\s+\(0x([0-9a-fA-F]+)\)\s+(locked|unlocked|created|destroyed)\s+by\s+thread\s+(T\d+)",
    re.IGNORECASE,
)

# Thread line "Thread T2 (tid=1234, ...)"
_RE_THREAD = re.compile(r"Thread (T\d+)\s*\(tid=(\d+)")

# Stack frame: "#0 func() file.cpp:42 (libfoo.so+0x1234)"
_RE_FRAME = re.compile(r"\([\w./]+=0x([0-9a-fA-F]+)\)")


class TsanParser:
    def __init__(self, so_base: int = 0) -> None:
        self.so_base = so_base
        self._seq: int = 0
        self._thread_map: Dict[str, TsanThread] = {}
        self._next_tid: int = 1
        self.events: List[TsanEvent] = []

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _get_thread(self, tsan_id: str) -> TsanThread:
        if tsan_id not in self._thread_map:
            self._thread_map[tsan_id] = TsanThread(
                tsan_id=tsan_id, thread_id=self._next_tid
            )
            self._next_tid += 1
        return self._thread_map[tsan_id]

    def parse_file(self, path: str) -> List[TsanEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        return self.parse_lines(lines)

    def parse_lines(self, lines: List[str]) -> List[TsanEvent]:
        self.events = []
        current_race_kind = ""

        for line in lines:
            # Thread declaration
            m = _RE_THREAD.search(line)
            if m:
                tsan_id, _pid = m.group(1), m.group(2)
                self._get_thread(tsan_id)
                continue

            # Race/bug header
            m = _RE_RACE_START.search(line)
            if m:
                current_race_kind = m.group(1)
                continue

            # Mutex operations
            m = _RE_MUTEX.search(line)
            if m:
                addr = int(m.group(1), 16) - self.so_base
                op = m.group(2).lower()
                tsan_id = m.group(3)
                tid = self._get_thread(tsan_id).thread_id
                sync_type = {
                    "locked":    "MutexLock",
                    "unlocked":  "MutexUnlock",
                    "created":   "MutexCreate",
                    "destroyed": "MutexDestroy",
                }.get(op, "MutexLock")
                self.events.append(TsanEvent(
                    seq=self._next_seq(), thread_id=tid, kind="sync",
                    sync_type=sync_type, sync_addr=addr, sync_result="Success",
                ))
                continue

            # Write/Read access
            m = _RE_ACCESS.match(line)
            if not m:
                m = _RE_PREV_ACCESS.match(line)
            if m:
                access_type = m.group(1).lower()
                size = int(m.group(2))
                addr = int(m.group(3), 16) - self.so_base
                tsan_id = m.group(4)
                tid = self._get_thread(tsan_id).thread_id
                # Record as a memory event
                self.events.append(TsanEvent(
                    seq=self._next_seq(), thread_id=tid, kind="memory",
                    mem_addr=addr, mem_size=size,
                ))
                # Also synthesize a MutexLock/Unlock to give sotrace sync context
                sync_type = "MutexLock" if access_type == "write" else "MutexLock"
                self.events.append(TsanEvent(
                    seq=self._next_seq(), thread_id=tid, kind="sync",
                    sync_type=sync_type, sync_addr=addr,
                    sync_result="Contended" if current_race_kind == "data race" else "Success",
                ))

        return self.events

    def build_envelope(self, trace_id: int = 0) -> Dict[str, Any]:
        threads: List[Dict[str, Any]] = []
        seen: Set[int] = set()
        for t in self._thread_map.values():
            if t.thread_id not in seen:
                seen.add(t.thread_id)
                threads.append({
                    "thread_id": t.thread_id, "create_step": 0,
                    "parent_thread_id": 0, "stack_base": 0,
                    "stack_size": 0, "tls_addr": 0, "is_jni_attached": False,
                })
        if not threads:
            threads = [{"thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                        "stack_base": 0, "stack_size": 0, "tls_addr": 0,
                        "is_jni_attached": False}]

        sync_events: List[Dict[str, Any]] = []
        memory_reads: List[Dict[str, Any]] = []
        for ev in self.events:
            if ev.kind == "sync":
                sync_events.append({
                    "step": ev.seq, "thread_id": ev.thread_id,
                    "sync_type": ev.sync_type,
                    "sync_object_addr": ev.sync_addr,
                    "result": ev.sync_result,
                })
            elif ev.kind == "memory":
                memory_reads.append({
                    "step": ev.seq, "thread_id": ev.thread_id,
                    "address": ev.mem_addr, "size": ev.mem_size,
                })

        return {
            "trace_id": trace_id,
            "threads": threads,
            "instructions": [],
            "calls": [],
            "memory_writes": [],
            "memory_reads": memory_reads,
            "sync_events": sync_events,
        }
