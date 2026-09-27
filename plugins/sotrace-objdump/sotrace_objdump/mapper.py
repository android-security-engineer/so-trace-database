"""Map ObjdumpParser results to a sotrace /api/v1/traces/import envelope."""

from .parser import ParseResult


class ObjdumpMapper:
    """Convert a :class:`ParseResult` into a sotrace trace import payload.

    The resulting envelope can be POSTed to ``/api/v1/traces/import``
    or written to a JSONL file for later CLI import.

    Static disassembly is modelled as a single-threaded execution
    (thread_id=1) with no memory or sync events.
    """

    THREAD_ID = 1

    def build_envelope(self, result: ParseResult, trace_id: int = 0) -> dict:
        """Build the JSON envelope from a ``ParseResult``.

        Args:
            result:   Output of :meth:`ObjdumpParser.parse`.
            trace_id: Hint for the server (0 = auto-assign).

        Returns:
            A dict ready for ``json.dumps`` and upload.
        """
        thread = {
            "thread_id": self.THREAD_ID,
            "create_step": 0,
            "parent_thread_id": 0,
            "stack_base": 0,
            "stack_size": 0,
            "tls_addr": 0,
            "is_jni_attached": False,
        }

        instructions = [
            {
                "seq": insn.seq,
                "thread_id": self.THREAD_ID,
                "address": insn.address,
                "is_branch": insn.is_branch,
                "branch_taken": insn.branch_taken,
            }
            for insn in result.instructions
        ]

        calls = [
            {
                "seq": call.seq,
                "thread_id": self.THREAD_ID,
                "caller_address": call.caller_address,
                "callee_address": call.callee_address,
                "depth": call.depth,
                "event_type": "Call",
            }
            for call in result.calls
        ]

        return {
            "trace_id": trace_id,
            "threads": [thread],
            "instructions": instructions,
            "memory_reads": [],
            "memory_writes": [],
            "sync_events": [],
            "calls": calls,
        }
