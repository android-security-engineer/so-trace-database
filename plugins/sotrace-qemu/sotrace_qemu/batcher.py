"""Simple event buffer for sotrace-qemu."""

import threading
from typing import List, Optional


class EventBatcher:
    """Thread-safe event accumulator."""

    def __init__(self, batch_size: int = 10000):
        self._lock = threading.Lock()
        self._seq = 0
        self.batch_size = batch_size
        self.instructions: List[dict] = []
        self.memory_writes: List[dict] = []
        self.memory_reads: List[dict] = []
        self.sync_events: List[dict] = []
        self.calls: List[dict] = []

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def add_instruction(self, rec: dict):
        with self._lock:
            self.instructions.append(rec)

    def add_memory_write(self, rec: dict):
        with self._lock:
            self.memory_writes.append(rec)

    def add_memory_read(self, rec: dict):
        with self._lock:
            self.memory_reads.append(rec)

    def is_empty(self) -> bool:
        with self._lock:
            return not any([self.instructions, self.memory_writes,
                            self.memory_reads, self.sync_events, self.calls])

    def size(self) -> int:
        with self._lock:
            return (len(self.instructions) + len(self.memory_writes) +
                    len(self.memory_reads) + len(self.sync_events) + len(self.calls))

    def drain(self, trace_id: int) -> dict:
        """Build import envelope and clear all buffers."""
        with self._lock:
            envelope = {
                "trace_id": trace_id,
                "threads": [{
                    "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                    "stack_base": 0, "stack_size": 0, "tls_addr": 0,
                    "is_jni_attached": False,
                }],
                "instructions": list(self.instructions),
                "memory_writes": list(self.memory_writes),
                "memory_reads": list(self.memory_reads),
                "sync_events": list(self.sync_events),
                "calls": list(self.calls),
            }
            self.instructions.clear()
            self.memory_writes.clear()
            self.memory_reads.clear()
            self.sync_events.clear()
            self.calls.clear()
            return envelope
