"""Event accumulator for sotrace import envelope."""
from typing import Any, Dict, List


class EventBatcher:
    def __init__(self) -> None:
        self._seq: int = 0
        self.instructions: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []

    def next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def add_instruction(self, seq: int, address: int, is_branch: bool, is_call: bool) -> None:
        self.instructions.append({
            "seq": seq,
            "thread_id": 1,
            "address": address,
            "is_branch": is_branch or is_call,
            "branch_taken": False,
        })

    def add_call(self, seq: int, caller: int, callee: int) -> None:
        self.calls.append({
            "seq": seq,
            "thread_id": 1,
            "caller_address": caller,
            "callee_address": callee,
            "depth": 0,
            "event_type": "Call",
        })

    def size(self) -> int:
        return len(self.instructions) + len(self.calls)

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
        self._seq = 0
        return envelope
