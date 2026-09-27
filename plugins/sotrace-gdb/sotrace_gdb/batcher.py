"""EventBatcher: thread-safe buffer for sotrace import events."""

import threading


class EventBatcher:
    def __init__(self, batch_size: int = 5000):
        self._lock = threading.Lock()
        self._seq = 0
        self.batch_size = batch_size
        self.instructions = []
        self.memory_writes = []
        self.memory_reads = []
        self.sync_events = []
        self.calls = []
        self.threads = []

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def add_instruction(self, ev: dict):
        with self._lock:
            self.instructions.append(ev)

    def add_memory_write(self, ev: dict):
        with self._lock:
            self.memory_writes.append(ev)

    def add_memory_read(self, ev: dict):
        with self._lock:
            self.memory_reads.append(ev)

    def add_sync(self, ev: dict):
        with self._lock:
            self.sync_events.append(ev)

    def add_call(self, ev: dict):
        with self._lock:
            self.calls.append(ev)

    def add_thread(self, ev: dict):
        with self._lock:
            if not any(t["thread_id"] == ev["thread_id"] for t in self.threads):
                self.threads.append(ev)

    def size(self) -> int:
        with self._lock:
            return (len(self.instructions) + len(self.memory_writes)
                    + len(self.memory_reads) + len(self.sync_events) + len(self.calls))

    def is_empty(self) -> bool:
        return self.size() == 0

    def drain(self, trace_id: int) -> dict:
        with self._lock:
            threads = list(self.threads) or [{
                "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                "stack_base": 0, "stack_size": 0, "tls_addr": 0, "is_jni_attached": False,
            }]
            envelope = {
                "trace_id": trace_id,
                "threads": threads,
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
