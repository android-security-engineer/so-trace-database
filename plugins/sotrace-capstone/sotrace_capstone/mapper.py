"""CapstoneMapper — converts DisasmResult into a sotrace import envelope."""

from __future__ import annotations

from .disassembler import DisasmResult


class CapstoneMapper:
    """
    Converts a DisasmResult (from CapstoneDisassembler) into the JSON envelope
    accepted by POST /api/v1/traces/import.

    address stored in the envelope = insn.address - base_addr
    so the values are SO-relative offsets when base_addr is the load address.
    """

    def __init__(self, base_addr: int = 0, trace_id: int = 0):
        """
        base_addr: SO load base address; subtracted from every VA to get SO offset.
                   Pass 0 to keep raw VAs as-is (e.g. for position-independent analysis).
        trace_id:  hint for the server; the server may assign a different id on import.
        """
        self.base_addr = base_addr
        self.trace_id = trace_id

    def to_envelope(self, result: DisasmResult) -> dict:
        """Build and return the full import envelope dict."""
        seq = 0

        # Build instruction list — every disassembled instruction gets a seq entry
        instructions = []
        # Map from caller_address (VA) to the seq it was seen, for call records
        addr_to_seq: dict[int, int] = {}

        for rec in result.instructions:
            seq += 1
            offset = rec.address - self.base_addr
            instructions.append({
                "seq": seq,
                "thread_id": 1,
                "address": offset,
                "is_branch": rec.is_branch,
                "branch_taken": False,  # static analysis — branch direction unknown
            })
            addr_to_seq[rec.address] = seq

        # Build call list — only call instructions
        calls = []
        for call in result.calls:
            caller_seq = addr_to_seq.get(call.caller_address, 0)
            caller_offset = call.caller_address - self.base_addr
            callee_offset = (call.callee_address - self.base_addr
                             if call.callee_address != 0 else 0)
            calls.append({
                "seq": caller_seq,
                "thread_id": 1,
                "caller_address": caller_offset,
                "callee_address": callee_offset,
                "depth": 0,
                "event_type": "Call",
            })

        return {
            "trace_id": self.trace_id,
            "threads": [{
                "thread_id": 1,
                "create_step": 0,
                "parent_thread_id": 0,
                "stack_base": 0,
                "stack_size": 0,
                "tls_addr": 0,
                "is_jni_attached": False,
            }],
            "instructions": instructions,
            "calls": calls,
            "memory_reads": [],
            "memory_writes": [],
            "sync_events": [],
        }
