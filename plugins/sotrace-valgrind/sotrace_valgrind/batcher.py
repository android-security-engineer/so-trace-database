"""EventBatcher — accumulate events and drain into a sotrace import envelope."""


class EventBatcher:
    def __init__(self):
        self._seq = 0
        self.instructions: list = []
        self.memory_reads: list = []
        self.memory_writes: list = []
        self.calls: list = []
        self.sync_events: list = []

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def add_instruction(self, e: dict):
        self.instructions.append(e)

    def add_memory_read(self, e: dict):
        self.memory_reads.append(e)

    def add_memory_write(self, e: dict):
        self.memory_writes.append(e)

    def add_call(self, e: dict):
        self.calls.append(e)

    def size(self) -> int:
        return (
            len(self.instructions)
            + len(self.memory_reads)
            + len(self.memory_writes)
            + len(self.calls)
        )

    def is_empty(self) -> bool:
        return self.size() == 0

    def drain(self, trace_id: int = 0) -> dict:
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
            "memory_reads": list(self.memory_reads),
            "memory_writes": list(self.memory_writes),
            "sync_events": list(self.sync_events),
            "calls": list(self.calls),
        }
        self.instructions.clear()
        self.memory_reads.clear()
        self.memory_writes.clear()
        self.sync_events.clear()
        self.calls.clear()
        return envelope
