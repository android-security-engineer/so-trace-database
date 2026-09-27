"""EventBatcher — accumulates sotrace events and drains to an import envelope."""


class EventBatcher:
    def __init__(self):
        self._seq = 0
        self.instructions: list = []
        self.calls: list = []

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def add_instruction(self, e: dict) -> None:
        self.instructions.append(e)

    def add_call(self, e: dict) -> None:
        self.calls.append(e)

    def size(self) -> int:
        return len(self.instructions) + len(self.calls)

    def is_empty(self) -> bool:
        return self.size() == 0

    def drain(self, trace_id: int = 0) -> dict:
        """Return a complete import envelope and clear all buffers."""
        envelope = {
            "trace_id": trace_id,
            "threads": [
                {
                    "thread_id": 1,
                    "create_step": 0,
                    "parent_thread_id": 0,
                    "stack_base": 0,
                    "stack_size": 0,
                    "tls_addr": 0,
                    "is_jni_attached": False,
                }
            ],
            "instructions": list(self.instructions),
            "memory_writes": [],
            "memory_reads": [],
            "sync_events": [],
            "calls": list(self.calls),
        }
        self.instructions.clear()
        self.calls.clear()
        self._seq = 0
        return envelope
