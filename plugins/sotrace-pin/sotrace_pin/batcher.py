"""EventBatcher for sotrace-pin."""


class EventBatcher:
    def __init__(self):
        self._seq = 0
        self.threads       = []
        self.instructions  = []
        self.memory_reads  = []
        self.memory_writes = []
        self.calls         = []
        self.sync_events   = []

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def add_thread(self, e):       self.threads.append(e)
    def add_instruction(self, e):  self.instructions.append(e)
    def add_memory_read(self, e):  self.memory_reads.append(e)
    def add_memory_write(self, e): self.memory_writes.append(e)
    def add_call(self, e):         self.calls.append(e)

    def size(self) -> int:
        return (len(self.instructions) + len(self.memory_reads) +
                len(self.memory_writes) + len(self.calls))

    def is_empty(self) -> bool:
        return self.size() == 0

    def drain(self, trace_id: int = 0) -> dict:
        threads = list(self.threads) or [{
            "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
            "stack_base": 0, "stack_size": 0, "tls_addr": 0,
            "is_jni_attached": False,
        }]
        envelope = {
            "trace_id":      trace_id,
            "threads":       threads,
            "instructions":  list(self.instructions),
            "memory_reads":  list(self.memory_reads),
            "memory_writes": list(self.memory_writes),
            "sync_events":   list(self.sync_events),
            "calls":         list(self.calls),
        }
        self.threads.clear()
        self.instructions.clear()
        self.memory_reads.clear()
        self.memory_writes.clear()
        self.sync_events.clear()
        self.calls.clear()
        return envelope
