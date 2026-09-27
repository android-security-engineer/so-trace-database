"""Convert a ParseResult into a sotrace import envelope dict.

The envelope is the JSON body accepted by POST /api/v1/traces/import.

Thread fields:     thread_id, create_step, parent_thread_id,
                   stack_base, stack_size, tls_addr, is_jni_attached
Sync event fields: step, thread_id, event_type, sync_object_addr, sync_object_kind
"""

from __future__ import annotations

from typing import Any, Dict, List

from .parser import ParseResult, ThreadEvent


class StraceMapper:
    """Convert a :class:`ParseResult` to a sotrace import envelope."""

    def to_envelope(self, result: ParseResult, trace_name: str = "strace") -> Dict[str, Any]:
        """Return an import envelope dict ready for POST /api/v1/traces/import."""
        threads = self._build_threads(result)
        sync_events = self._build_sync_events(result)

        return {
            "trace_id": 0,       # 0 = server auto-assigns on first import
            "name": trace_name,
            "threads": threads,
            "instructions": [],  # strace does not provide instruction-level data
            "memory_reads": [],
            "memory_writes": [],
            "sync_events": sync_events,
            "calls": [],
        }

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def _build_threads(self, result: ParseResult) -> List[Dict[str, Any]]:
        """
        Build one thread entry per unique PID.

        clone() events supply parent_thread_id and stack_base for child threads.
        All other PIDs (including the initial process) get default values.
        """
        # Initialise every known PID with default values
        thread_map: Dict[int, Dict[str, Any]] = {
            pid: {
                "thread_id": pid,
                "create_step": 0,
                "parent_thread_id": 0,
                "stack_base": 0,
                "stack_size": 0,
                "tls_addr": 0,
                "is_jni_attached": False,
            }
            for pid in result.all_pids
        }

        # Overlay info from clone() events
        for ev in result.threads:
            # Ensure the child PID is registered even if it had no other lines
            if ev.pid not in thread_map:
                thread_map[ev.pid] = {
                    "thread_id": ev.pid,
                    "create_step": ev.step,
                    "parent_thread_id": ev.parent_pid,
                    "stack_base": ev.child_stack,
                    "stack_size": 0,
                    "tls_addr": 0,
                    "is_jni_attached": False,
                }
            else:
                entry = thread_map[ev.pid]
                entry["create_step"] = ev.step
                entry["parent_thread_id"] = ev.parent_pid
                if ev.child_stack:
                    entry["stack_base"] = ev.child_stack

        # Sort by thread_id for deterministic output
        return sorted(thread_map.values(), key=lambda t: t["thread_id"])

    def _build_sync_events(self, result: ParseResult) -> List[Dict[str, Any]]:
        """Convert SyncEvent records to envelope dicts."""
        return [
            {
                "step": ev.step,
                "thread_id": ev.pid,
                "event_type": ev.event_type,
                "sync_object_addr": ev.sync_object_addr,
                "sync_object_kind": "Futex",
            }
            for ev in result.sync_events
        ]
