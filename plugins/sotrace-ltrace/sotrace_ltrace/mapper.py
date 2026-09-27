"""Map parsed ltrace events to a sotrace-server import envelope.

The import envelope schema:
    {
        "trace_id": 0,
        "threads": [ThreadRecord ...],
        "instructions": [],
        "memory_reads": [],
        "memory_writes": [],
        "sync_events": [SyncEvent ...],
        "calls": [CallRecord ...],
    }

Step assignment:
    Events are processed in log order (already chronological from ltrace -tt).
    Each event that produces a sotrace record is assigned the next sequential step.
    This means sync_events, calls, and thread-create markers all share one
    monotonically-increasing step counter.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ts_sort_key(ts: str) -> tuple:
    """Convert HH:MM:SS.usec timestamp to a sortable tuple of ints."""
    # Format: HH:MM:SS.usec  (from ltrace -tt)
    m = re.match(r'^(\d+):(\d+):(\d+)\.(\d+)$', ts)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
    return (0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Mapper
# ---------------------------------------------------------------------------

class LtraceMapper:
    """Convert parsed ltrace event dicts into a sotrace import envelope."""

    def __init__(self, so_filter: str = ""):
        """
        Parameters
        ----------
        so_filter:
            When non-empty, only sync events that occur after a ``dlopen`` for a
            matching SO name are included.  An empty string disables filtering.
        """
        self.so_filter = so_filter

    def map(self, events: list) -> dict:
        """Return a sotrace import envelope built from *events*."""

        # ------------------------------------------------------------------
        # Pass 1 — discover threads (PIDs) in order of first appearance
        # ------------------------------------------------------------------
        pid_order: list = []          # PIDs in first-seen order
        pid_seen: set = set()

        for ev in events:
            pid = ev["pid"]
            if pid not in pid_seen:
                pid_seen.add(pid)
                pid_order.append(pid)

        # Main thread = first PID observed.  Others are children.
        main_pid = pid_order[0] if pid_order else 0

        # ------------------------------------------------------------------
        # Pass 2 — determine whether SO filter is active and which dlopen
        #           events establish the known-SO set.
        # ------------------------------------------------------------------
        # Collect SO base addresses that match so_filter (empty = any)
        known_so_bases: set = set()
        so_active = bool(self.so_filter)

        for ev in events:
            if ev["kind"] == "dlopen":
                name = ev.get("so_name", "")
                if not so_active or self.so_filter in name:
                    base = ev.get("base_addr", 0)
                    if base:
                        known_so_bases.add(base)

        # When so_filter is set but no dlopen was found, we still emit all events
        # (best-effort — the filter may have been applied at ltrace -e level).
        filter_active = so_active and bool(known_so_bases)

        # ------------------------------------------------------------------
        # Pass 3 — assign steps and build envelope lists
        # ------------------------------------------------------------------
        step = 0

        # Track per-thread first-step for the threads list
        pid_first_step: dict = {}
        pid_create_count: dict = {main_pid: 0}  # count of pthread_create per caller

        sync_events: list = []
        calls: list = []

        for ev in events:
            pid  = ev["pid"]
            kind = ev["kind"]

            if kind == "sync":
                step += 1
                pid_first_step.setdefault(pid, step)

                sync_events.append({
                    "step":             step,
                    "thread_id":        pid,
                    "event_type":       ev["event_type"],
                    "sync_object_addr": ev["sync_addr"],
                    "sync_object_kind": ev["sync_kind"],
                })

            elif kind == "thread_create":
                step += 1
                pid_first_step.setdefault(pid, step)
                pid_create_count[pid] = pid_create_count.get(pid, 0) + 1

            elif kind in ("dlopen", "dlsym"):
                step += 1
                pid_first_step.setdefault(pid, step)

                sym_or_name = (
                    ev.get("so_name") or ev.get("symbol") or ""
                )
                addr = ev.get("base_addr") or ev.get("sym_addr") or 0

                calls.append({
                    "seq":             step,
                    "thread_id":       pid,
                    "caller_address":  0,
                    "callee_address":  addr,
                    "depth":           0,
                    "event_type":      "Call",
                    "symbol":          sym_or_name,
                })

            # malloc/free: record step but do not add to the envelope (optional)
            elif kind in ("malloc", "free"):
                step += 1
                pid_first_step.setdefault(pid, step)

        # ------------------------------------------------------------------
        # Build threads list
        # ------------------------------------------------------------------
        threads: list = []
        for i, pid in enumerate(pid_order):
            parent_pid = main_pid if i > 0 else 0
            threads.append({
                "thread_id":       pid,
                "create_step":     pid_first_step.get(pid, 0),
                "parent_thread_id": parent_pid,
                "stack_base":      0,
                "stack_size":      0,
                "tls_addr":        0,
                "is_jni_attached": False,
            })

        # Ensure at least one thread entry even for empty logs
        if not threads:
            threads.append({
                "thread_id":       1,
                "create_step":     0,
                "parent_thread_id": 0,
                "stack_base":      0,
                "stack_size":      0,
                "tls_addr":        0,
                "is_jni_attached": False,
            })

        return {
            "trace_id":      0,
            "threads":       threads,
            "instructions":  [],
            "memory_reads":  [],
            "memory_writes": [],
            "sync_events":   sync_events,
            "calls":         calls,
        }
