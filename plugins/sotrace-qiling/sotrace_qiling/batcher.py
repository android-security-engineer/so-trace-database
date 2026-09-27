import threading


class EventBatcher:
    """Thread-safe event buffer with auto-flush support."""

    def __init__(self, batch_size: int = 5000):
        self._seq = 0
        self._lock = threading.Lock()
        self.batch_size = batch_size
        self.instructions = []
        self.memory_writes = []
        self.memory_reads = []
        self.sync_events = []
        self.calls = []

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def add_instruction(self, event: dict):
        self.instructions.append(event)

    def add_memory_write(self, event: dict):
        self.memory_writes.append(event)

    def add_memory_read(self, event: dict):
        self.memory_reads.append(event)

    def add_sync(self, event: dict):
        self.sync_events.append(event)

    def add_call(self, event: dict):
        self.calls.append(event)

    def size(self) -> int:
        return (len(self.instructions) + len(self.memory_writes) +
                len(self.memory_reads) + len(self.sync_events) + len(self.calls))

    def is_empty(self) -> bool:
        return self.size() == 0

    def drain(self, trace_id: int) -> dict:
        """Build import envelope and clear all buffers."""
        envelope = {
            "trace_id": trace_id,
            "threads": [{
                "thread_id": 1,
                "create_step": 0,
                "parent_thread_id": 0,
                "stack_base": 0,
                "stack_size": 0,
                "tls_addr": 0,
                "is_jni_attached": False,
            }],
            "instructions": list(self.instructions),
            "memory_writes": list(self.memory_writes),
            "memory_reads": list(self.memory_reads),
            "sync_events": list(self.sync_events),
            "calls": list(self.calls),
            "context_switches": [],
            "state_changes": [],
            "jni_calls": [],
        }
        self.instructions.clear()
        self.memory_writes.clear()
        self.memory_reads.clear()
        self.sync_events.clear()
        self.calls.clear()
        return envelope
