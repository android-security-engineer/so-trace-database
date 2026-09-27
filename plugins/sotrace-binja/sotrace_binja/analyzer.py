"""Static analyzer — walks Binary Ninja LLIL/MLIL to build a sotrace import envelope."""

from .batcher import EventBatcher

# Imported lazily to allow this module to be imported outside Binary Ninja
# (e.g. for unit tests that mock binaryninja).


class SoTraceAnalyzer:
    """Collect instruction and call events from a BinaryView via LLIL/MLIL."""

    def __init__(self, bv):
        """
        Args:
            bv: binaryninja.BinaryView (opened and analysis-complete)
        """
        self.bv = bv
        self.base = bv.start  # 0 for PIE SOs

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_static(self) -> dict:
        """Analyze every function in the BinaryView."""
        batcher = EventBatcher()
        for func in self.bv.functions:
            self._analyze_function_into(func, batcher)
        return batcher.drain(trace_id=0)

    def analyze_function(self, func) -> dict:
        """Analyze a single binaryninja.Function."""
        batcher = EventBatcher()
        self._analyze_function_into(func, batcher)
        return batcher.drain(trace_id=0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _analyze_function_into(self, func, batcher: EventBatcher) -> None:
        try:
            self._collect_instructions(func, batcher)
        except Exception:
            pass
        try:
            self._collect_calls(func, batcher)
        except Exception:
            pass

    def _collect_instructions(self, func, batcher: EventBatcher) -> None:
        """Walk LLIL basic blocks and emit one instruction event per LLIL insn."""
        try:
            from binaryninja import LowLevelILOperation as Op
        except ImportError:
            return

        llil = func.llil
        if llil is None:
            return

        branch_ops = frozenset(
            [
                Op.LLIL_JUMP,
                Op.LLIL_JUMP_TO,
                Op.LLIL_IF,
                Op.LLIL_CALL,
                Op.LLIL_TAILCALL,
                Op.LLIL_RET,
                Op.LLIL_GOTO,
            ]
        )

        for block in llil.basic_blocks:
            for insn in block:
                try:
                    addr = insn.address
                    offset = addr - self.base
                    is_branch = insn.operation in branch_ops
                    seq = batcher.next_seq()
                    batcher.add_instruction(
                        {
                            "seq": seq,
                            "thread_id": 1,
                            "address": offset,
                            "is_branch": is_branch,
                            "branch_taken": False,
                        }
                    )
                except Exception:
                    continue

    def _collect_calls(self, func, batcher: EventBatcher) -> None:
        """Walk MLIL and emit one call event per MLIL_CALL / MLIL_TAILCALL."""
        try:
            from binaryninja import MediumLevelILOperation as MOp
        except ImportError:
            return

        mlil = func.mlil
        if mlil is None:
            return

        call_ops = frozenset([MOp.MLIL_CALL, MOp.MLIL_TAILCALL])

        for block in mlil.basic_blocks:
            for insn in block:
                try:
                    if insn.operation not in call_ops:
                        continue

                    caller_addr = insn.address - self.base

                    # Try to resolve a concrete callee address from the dest operand
                    callee_addr = 0
                    try:
                        callee_addr = insn.dest.constant - self.base
                    except (AttributeError, TypeError):
                        pass

                    seq = batcher.next_seq()
                    batcher.add_call(
                        {
                            "seq": seq,
                            "thread_id": 1,
                            "caller_address": caller_addr,
                            "callee_address": callee_addr,
                            "depth": 0,
                            "event_type": "Call",
                        }
                    )
                except Exception:
                    continue
