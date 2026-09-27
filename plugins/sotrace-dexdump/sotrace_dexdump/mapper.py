"""Convert DexdumpParser results to a sotrace /api/v1/traces/import envelope.

Addressing model
----------------
Dalvik method offsets restart at 0 for every method, so they are not globally
unique.  We use a global *seq* counter that increments monotonically across all
instructions in all methods.

  - ``address`` in each instruction record = the method-local Dalvik offset.
  - ``callee_address`` in call records = the *seq* of the callee method's first
    instruction (globally unique), enabling the server's nested-set call model
    to reconstruct call graphs.  0 means the callee was not found in the parsed
    methods (e.g. it belongs to a system class or was filtered out).
"""

from __future__ import annotations

import re
from typing import Any

from .parser import ParseResult

# Extract callee class + method + descriptor from invoke operand strings.
# Format: "..., Lcom/example/Foo;->bar(I)V ..."
_RE_INVOKE_TARGET = re.compile(r"(L[^;]+;)->([^(]+)(\([^)]*\)\S+)")


class DexdumpMapper:
    """Convert a :class:`~sotrace_dexdump.parser.ParseResult` to a sotrace
    trace import envelope.

    Usage::

        mapper = DexdumpMapper()
        envelope = mapper.build_envelope(result)
    """

    THREAD_ID = 1

    def build_envelope(
        self,
        result: ParseResult,
        trace_id: int = 0,
        trace_name: str = "dexdump-trace",
    ) -> dict[str, Any]:
        """Build the JSON envelope for POST /api/v1/traces/import.

        Args:
            result:     Output of :meth:`DexdumpParser.parse`.
            trace_id:   0 = let sotrace-server auto-assign.
            trace_name: Human-readable label stored in the engine.

        Returns:
            A ``dict`` suitable for ``json.dumps`` and HTTP upload.
        """
        # ------------------------------------------------------------------
        # Pass 1 — assign start seq for every method's first instruction.
        # Build the method-name → start_seq index for call-target resolution.
        # ------------------------------------------------------------------
        method_start_seq: dict[str, int] = {}
        seq = 1
        for method in result.methods:
            if method.instructions:
                method_start_seq[method.full_name] = seq
                seq += len(method.instructions)

        # ------------------------------------------------------------------
        # Pass 2 — emit instruction and call records.
        # ------------------------------------------------------------------
        instructions: list[dict[str, Any]] = []
        calls: list[dict[str, Any]] = []

        seq = 1
        for method in result.methods:
            for insn in method.instructions:
                insn_seq = seq
                seq += 1

                instructions.append({
                    "seq":          insn_seq,
                    "thread_id":    self.THREAD_ID,
                    "address":      insn.offset,          # method-local dalvik PC
                    "is_branch":    insn.is_branch or insn.is_invoke,
                    "branch_taken": False,                # static analysis: unknown
                })

                if insn.is_invoke:
                    callee_addr = _resolve_callee(insn.operands, method_start_seq)
                    calls.append({
                        "seq":            insn_seq,
                        "thread_id":      self.THREAD_ID,
                        "caller_address": insn.offset,
                        "callee_address": callee_addr,
                        "depth":          0,
                        "event_type":     "Call",
                    })

        return {
            "trace_id":     trace_id,
            "name":         trace_name,
            "threads":      [_thread_record(self.THREAD_ID)],
            "instructions": instructions,
            "calls":        calls,
            "memory_reads":  [],
            "memory_writes": [],
            "sync_events":   [],
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _thread_record(thread_id: int) -> dict[str, Any]:
    """Single synthetic thread representing the Dalvik execution context."""
    return {
        "thread_id":        thread_id,
        "create_step":      0,
        "parent_thread_id": 0,
        "stack_base":       0,
        "stack_size":       0,
        "tls_addr":         0,
        "is_jni_attached":  False,
    }


def _resolve_callee(operands: str, method_start_seq: dict[str, int]) -> int:
    """Parse an invoke instruction's operands and return the callee's start seq.

    Returns 0 if the callee is not in the index (external / filtered class).
    """
    m = _RE_INVOKE_TARGET.search(operands)
    if not m:
        return 0
    raw_class = m.group(1)      # e.g. "Lcom/example/Foo;"
    method_name = m.group(2)    # e.g. "bar"
    descriptor = m.group(3)     # e.g. "(I)V"

    # Strip L...;  → "com/example/Foo"
    class_name = raw_class[1:-1]

    full_name = f"{class_name}->{method_name}{descriptor}"
    return method_start_seq.get(full_name, 0)
