"""
mapper.py — convert SmaliScanner results into a sotrace import envelope.

Smali bytecode has no real memory addresses, so we assign sequential
synthetic addresses: 0x0, 0x4, 0x8, ... (4-byte step, like ARM Thumb-2).

Layout
------
- Native method declarations → instruction + depth-0 Call (JNI boundary marker)
- invoke-* instructions      → instruction + depth-1 Call

Memory events and sync events are always empty for smali-derived traces.
A single thread (thread_id=1, is_jni_attached=True) represents the Dalvik VM
thread executing the smali code.
"""

from .scanner import InvokeCall, NativeMethod, ScanResult

_THREAD_ID    = 1
_ADDR_STEP    = 4          # bytes per synthetic instruction slot
# invoke-interface is a polymorphic dispatch — mark as branch
_BRANCH_OPS   = frozenset({"invoke-interface", "invoke-interface/range"})


class SmaliMapper:
    """Build a sotrace import envelope from a :class:`ScanResult`."""

    def build_envelope(self, result: ScanResult, so_name: str = "") -> dict:
        """
        Convert *result* into the JSON envelope accepted by
        ``POST /api/v1/traces/import``.

        Parameters
        ----------
        result:
            Output of :meth:`SmaliScanner.scan_dir`.
        so_name:
            Optional SO name used only for documentation in the returned
            dict (not currently a server field, included as metadata comment).

        Returns
        -------
        dict ready for ``json.dumps`` and HTTP upload.
        """
        instructions: list = []
        calls:        list = []
        seq = 0

        # -- Native method declarations as JNI boundary markers (depth=0) ----
        for nm in result.native_methods:
            addr = seq * _ADDR_STEP
            instructions.append(_make_insn(seq, addr, is_branch=False))
            calls.append(_make_call(seq, addr, addr, depth=0, event_type="Call"))
            seq += 1

        # -- invoke-* instructions -------------------------------------------
        for ic in result.invoke_calls:
            addr      = seq * _ADDR_STEP
            is_branch = ic.smali_opcode in _BRANCH_OPS
            caller_addr = max(0, (seq - 1) * _ADDR_STEP)
            instructions.append(_make_insn(seq, addr, is_branch=is_branch))
            calls.append(_make_call(seq, caller_addr, addr,
                                    depth=1, event_type="Call"))
            seq += 1

        return {
            "trace_id": 0,
            "threads": [
                {
                    "thread_id":        _THREAD_ID,
                    "create_step":      0,
                    "parent_thread_id": 0,
                    "stack_base":       0,
                    "stack_size":       0,
                    "tls_addr":         0,
                    # Dalvik/ART thread is always a JNI-attached context
                    "is_jni_attached":  True,
                }
            ],
            "instructions":  instructions,
            "memory_reads":  [],
            "memory_writes": [],
            "sync_events":   [],
            "calls":         calls,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_insn(seq: int, address: int, *, is_branch: bool) -> dict:
    return {
        "seq":          seq,
        "thread_id":    _THREAD_ID,
        "address":      address,
        "is_branch":    is_branch,
        "branch_taken": is_branch,
    }


def _make_call(seq: int, caller_address: int, callee_address: int,
               *, depth: int, event_type: str) -> dict:
    return {
        "seq":            seq,
        "thread_id":      _THREAD_ID,
        "caller_address": caller_address,
        "callee_address": callee_address,
        "depth":          depth,
        "event_type":     event_type,
    }
