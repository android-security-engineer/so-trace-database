"""
GDB event-driven trace collector.

Does NOT import gdb at module level so this file can be imported in tests
outside a GDB session. The caller (sotrace-gdb.py) passes gdb as a parameter.
"""

import json
import logging

logger = logging.getLogger(__name__)


def find_so_base(gdb, so_name: str):
    """
    Return (base_addr, size) for so_name.
    Tries 'info sharedlibrary' first, then /proc/PID/maps.
    """
    try:
        output = gdb.execute("info sharedlibrary", to_string=True)
        for line in output.splitlines():
            if so_name in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        start = int(parts[0], 16)
                        end = int(parts[1], 16)
                        return start, end - start
                    except ValueError:
                        pass
    except Exception:
        pass

    try:
        pid = gdb.inferiors()[0].pid
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if so_name in line:
                    rng = line.split()[0]
                    start_s, end_s = rng.split("-")
                    start = int(start_s, 16)
                    end = int(end_s, 16)
                    return start, end - start
    except Exception:
        pass

    return 0, 0


class SoTraceCollector:
    """
    Collects instructions (and optionally memory / sync events) from a GDB
    session by stepping one instruction at a time and recording each PC that
    falls inside the target SO's address range.
    """

    def __init__(self, gdb, batcher, so_base: int, so_size: int,
                 max_steps: int = 10000, target_tid: int = None):
        self._gdb = gdb
        self.batcher = batcher
        self.so_base = so_base
        self.so_size = so_size
        self.max_steps = max_steps
        self.target_tid = target_tid

        self.steps_done = 0
        self._prev_pc = {}     # tid -> last pc
        self._call_depth = {}  # tid -> int
        self._running = False
        self._on_exit_cb = None  # set by caller

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def start(self, on_finish=None):
        self._on_exit_cb = on_finish
        self._running = True

        # Record already-known threads
        try:
            for t in self._gdb.inferiors()[0].threads():
                self._record_thread(t)
        except Exception:
            pass

        self._gdb.events.stop.connect(self._on_stop)
        self._gdb.events.exited.connect(self._on_exit)
        try:
            self._gdb.events.new_thread.connect(self._on_new_thread)
        except Exception:
            pass

        # Kick off stepping
        self._gdb.post_event(lambda: self._safe_step())

    def stop(self):
        self._running = False
        self._disconnect()

    # ------------------------------------------------------------------
    # GDB event handlers
    # ------------------------------------------------------------------

    def _on_stop(self, event):
        if not self._running:
            return

        if self.steps_done >= self.max_steps:
            self._finish()
            return

        self._collect_current_state()
        self.steps_done += 1

        if self._running:
            self._gdb.post_event(lambda: self._safe_step())

    def _on_exit(self, event):
        self._finish()

    def _on_new_thread(self, event):
        try:
            t = event.inferior_thread
            self._record_thread(t)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def _collect_current_state(self):
        try:
            thread = self._gdb.selected_thread()
            if thread is None:
                return
            tid = thread.ptid[1]

            if self.target_tid is not None and tid != self.target_tid:
                return

            pc = int(self._gdb.parse_and_eval("$pc"))

            if not (self.so_base <= pc < self.so_base + self.so_size):
                return

            offset = pc - self.so_base
            seq = self.batcher.next_seq()

            prev = self._prev_pc.get(tid)
            # Heuristic: if delta > 8 bytes from previous PC, likely a branch
            is_branch = prev is not None and abs(pc - prev) > 8
            branch_taken = is_branch
            self._prev_pc[tid] = pc

            self.batcher.add_instruction({
                "seq": seq,
                "thread_id": tid,
                "address": offset,
                "is_branch": is_branch,
                "branch_taken": branch_taken,
            })
        except Exception:
            pass  # never interrupt GDB

    def _record_thread(self, t):
        try:
            tid = t.ptid[1]
            self.batcher.add_thread({
                "thread_id": tid,
                "create_step": self.batcher.next_seq(),
                "parent_thread_id": 0,
                "stack_base": 0,
                "stack_size": 0,
                "tls_addr": 0,
                "is_jni_attached": False,
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _safe_step(self):
        try:
            self._gdb.execute("stepi")
        except Exception:
            self._finish()

    def _finish(self):
        if not self._running:
            return
        self._running = False
        self._disconnect()
        logger.info(f"[sotrace] Collector finished after {self.steps_done} steps")
        if self._on_exit_cb:
            try:
                self._on_exit_cb()
            except Exception as e:
                logger.warning(f"[sotrace] on_finish callback failed: {e}")

    def _disconnect(self):
        for ev, cb in [
            (self._gdb.events.stop, self._on_stop),
            (self._gdb.events.exited, self._on_exit),
        ]:
            try:
                ev.disconnect(cb)
            except Exception:
                pass
        try:
            self._gdb.events.new_thread.disconnect(self._on_new_thread)
        except Exception:
            pass
