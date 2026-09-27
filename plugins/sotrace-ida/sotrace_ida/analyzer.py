"""IDA Pro static analysis using IDAPython APIs."""
from typing import Any, Dict, List, Optional, Tuple

from .batcher import EventBatcher

try:
    import idaapi    # type: ignore
    import idautils  # type: ignore
    import idc       # type: ignore
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


def _get_image_base() -> int:
    try:
        import idaapi  # type: ignore
        return idaapi.get_imagebase()
    except Exception:
        return 0


def _iter_func_instructions(func_ea: int) -> List[Tuple[int, bool, bool, List[int]]]:
    """Return (ea, is_branch, is_call, call_targets) for every instruction in func_ea."""
    if not IDA_AVAILABLE:
        return []

    CF_CALL = idaapi.CF_CALL
    CF_JUMP = idaapi.CF_JUMP
    CF_STOP = idaapi.CF_STOP

    results: List[Tuple[int, bool, bool, List[int]]] = []
    insn = idaapi.insn_t()

    for ea in idautils.FuncItems(func_ea):
        if idaapi.decode_insn(insn, ea) == 0:
            continue
        features = insn.get_canon_feature()
        is_call = bool(features & CF_CALL)
        is_jump = bool(features & CF_JUMP)
        is_ret  = bool(features & CF_STOP)
        is_branch = is_call or is_jump or is_ret

        call_targets: List[int] = []
        if is_call:
            for ref in idautils.CodeRefsFrom(ea, flow=False):
                call_targets.append(ref)

        results.append((ea, is_branch, is_call, call_targets))
    return results


def _iter_all_instructions() -> List[Tuple[int, bool, bool, List[int]]]:
    """Return (ea, is_branch, is_call, call_targets) for every instruction in the IDB."""
    if not IDA_AVAILABLE:
        return []

    results: List[Tuple[int, bool, bool, List[int]]] = []
    for func_ea in idautils.Functions():
        results.extend(_iter_func_instructions(func_ea))
    return results


def analyze_static(server_url: str = "", output_file: str = "") -> Dict[str, Any]:
    """Collect all instructions/calls from the current IDB and return the envelope."""
    base = _get_image_base()
    batcher = EventBatcher()

    for ea, is_branch, is_call, targets in _iter_all_instructions():
        offset = ea - base
        seq = batcher.next_seq()
        batcher.add_instruction(seq, offset, is_branch, is_call)
        for tgt in targets:
            seq = batcher.next_seq()
            batcher.add_call(seq, offset, tgt - base)

    return batcher.drain()


class IDAAnalyzer:
    """High-level analyser interface used by scripts and the plugin UI.

    Wraps the low-level IDAPython helpers and returns a sotrace import envelope
    (the same JSON structure accepted by POST /api/v1/traces/import).
    """

    def __init__(self) -> None:
        self._base: int = _get_image_base()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        """Alias for analyze_all() — matches the interface described in the spec."""
        return self.analyze_all()

    def analyze_all(self) -> Dict[str, Any]:
        """Collect every function in the current IDB and return the envelope."""
        batcher = EventBatcher()
        base = self._base

        for ea, is_branch, is_call, targets in _iter_all_instructions():
            offset = ea - base
            seq = batcher.next_seq()
            batcher.add_instruction(seq, offset, is_branch, is_call)
            for tgt in targets:
                batcher.add_call(batcher.next_seq(), offset, tgt - base)

        return batcher.drain()

    def analyze_function(self, func_ea: int) -> Dict[str, Any]:
        """Collect only the function at *func_ea* and return the envelope."""
        batcher = EventBatcher()
        base = self._base

        for ea, is_branch, is_call, targets in _iter_func_instructions(func_ea):
            offset = ea - base
            seq = batcher.next_seq()
            batcher.add_instruction(seq, offset, is_branch, is_call)
            for tgt in targets:
                batcher.add_call(batcher.next_seq(), offset, tgt - base)

        return batcher.drain()
