"""
mapper.py — Convert JniMethod list into a sotrace-server import envelope.

Since JADX works at the bytecode/source level (no runtime addresses), we use
synthetic sequential addresses spaced 8 bytes apart so that the call-store
nested-set model works correctly.
"""

from __future__ import annotations

from typing import Any, Optional

from .scanner import JniMethod


_ADDR_STEP = 8  # bytes between synthetic native function addresses


class JniMapper:
    """Convert a list of JniMethod into a sotrace import envelope dict."""

    def build_envelope(
        self,
        methods: list[JniMethod],
        trace_id: int = 0,
        so_filter: Optional[str] = None,
        trace_name: str = "jadx-jni-trace",
    ) -> dict[str, Any]:
        """Build the full import envelope for POST /api/v1/traces/import.

        Args:
            methods:    Extracted JniMethod list from JadxScanner.
            trace_id:   Use 0 to let sotrace-server auto-assign.
            so_filter:  If set, only include methods whose so_name matches.
            trace_name: Human-readable label (stored in the engine).
        """
        if so_filter:
            methods = [m for m in methods if m.so_name == so_filter]

        threads = self._build_threads()
        instructions = self._build_instructions(methods)
        calls = self._build_calls(methods)
        jni_calls = self._build_jni_calls(methods)

        return {
            "trace_id":    trace_id,
            "name":        trace_name,
            "threads":     threads,
            "instructions":    instructions,
            "calls":           calls,
            "jni_calls":       jni_calls,
            "sync_events":     [],
            "context_switches": [],
            "state_changes":   [],
            "memory_writes":   [],
            "memory_reads":    [],
            "register_deltas": [],
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_threads() -> list[dict[str, Any]]:
        """Single synthetic thread representing the JNI caller thread."""
        return [
            {
                "thread_id":       1,
                "create_step":     0,
                "parent_thread_id": 0,
                "stack_base":      0,
                "stack_size":      0,
                "tls_addr":        0,
                "is_jni_attached": True,   # this thread crosses the JNI boundary
            }
        ]

    @staticmethod
    def _build_instructions(methods: list[JniMethod]) -> list[dict[str, Any]]:
        """One synthetic instruction per native method (the call site)."""
        instructions = []
        for idx, method in enumerate(methods):
            seq = idx * 2          # even steps = instruction, odd steps = call event
            address = idx * _ADDR_STEP
            instructions.append({
                "seq":          seq,
                "thread_id":    1,
                "address":      address,
                "is_branch":    True,    # JNI call behaves like a branch
                "branch_taken": True,
            })
        return instructions

    @staticmethod
    def _build_calls(methods: list[JniMethod]) -> list[dict[str, Any]]:
        """One Call event per native method using sequential synthetic addresses."""
        calls = []
        for idx, method in enumerate(methods):
            caller_addr = idx * _ADDR_STEP
            callee_addr = idx * _ADDR_STEP  # same position — no runtime callee known
            seq = idx * 2 + 1              # odd steps = call event
            calls.append({
                "seq":            seq,
                "thread_id":      1,
                "caller_address": caller_addr,
                "callee_address": callee_addr,
                "depth":          0,
                "event_type":     "Call",
            })
        return calls

    @staticmethod
    def _build_jni_calls(methods: list[JniMethod]) -> list[dict[str, Any]]:
        """One JNI call record per native method (Java→Native direction)."""
        jni_calls = []
        for idx, method in enumerate(methods):
            # Derive a canonical Java class path (e.g. "com.example.Foo" → "com/example/Foo")
            jni_class = method.class_name.replace(".", "/")
            native_address = idx * _ADDR_STEP
            jni_calls.append({
                "id":             idx + 1,
                "seq":            idx * 2 + 1,
                "thread_id":      1,
                "direction":      "JavaToNative",
                "java_class":     jni_class,
                "java_method":    method.method_name,
                "java_signature": method.signature,
                "native_func_id": None,
                "native_address": native_address,
                "jni_env_address": None,
            })
        return jni_calls
