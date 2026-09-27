"""Simple event batcher for accumulating trace events before upload."""
from typing import Any, Dict, List


class EventBatcher:
    def __init__(self) -> None:
        self._seq: int = 0
        self.instructions: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def add_instruction(self, e: Dict[str, Any]) -> None:
        self.instructions.append(e)

    def add_call(self, e: Dict[str, Any]) -> None:
        self.calls.append(e)

    def size(self) -> int:
        return len(self.instructions) + len(self.calls)

    def is_empty(self) -> bool:
        return self.size() == 0

    def drain(self, trace_id: int = 0) -> Dict[str, Any]:
        envelope: Dict[str, Any] = {
            "trace_id": trace_id,
            "threads": [{
                "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                "stack_base": 0, "stack_size": 0, "tls_addr": 0,
                "is_jni_attached": False,
            }],
            "instructions": list(self.instructions),
            "calls": list(self.calls),
            "memory_writes": [],
            "memory_reads": [],
            "sync_events": [],
        }
        self.instructions.clear()
        self.calls.clear()
        return envelope
