"""Main SoTracePlugin class — one-line integration for Qiling emulation."""

import json
import logging
import os

from .batcher import EventBatcher
from .client import SoTraceClient
from .hooks import (
    make_code_hook,
    make_mem_write_hook,
    make_mem_read_hook,
    make_futex_hook,
    try_hook_pthread_symbols,
)

logger = logging.getLogger(__name__)


class SoTracePlugin:
    """
    Integrates Qiling emulation with sotrace-server for trace collection and analysis.

    Minimal usage::

        from qiling import Qiling
        from sotrace_qiling import SoTracePlugin

        ql = Qiling(["./libfoo.so"], "rootfs/")
        plugin = SoTracePlugin(ql, server_url="http://192.168.1.83:3000")
        plugin.attach()
        ql.run()
        trace_id = plugin.flush()
        print(f"Analyze: http://192.168.1.83:3000/traces/{trace_id}/analyze/threads/races")

    File-output mode (import later with sotrace-cli)::

        plugin = SoTracePlugin(ql, output_file="trace.jsonl")
        plugin.attach()
        ql.run()
        plugin.save("trace.jsonl")
    """

    def __init__(
        self,
        ql,
        server_url: str = None,
        trace_id: int = 0,
        so_base: int = 0,
        enable_instructions: bool = True,
        enable_memory: bool = True,
        enable_sync: bool = True,
        batch_size: int = 5000,
        output_file: str = None,
    ):
        """
        Args:
            ql: Qiling instance
            server_url: sotrace-server base URL (None = file-only mode)
            trace_id: initial trace ID (0 = server assigns)
            so_base: SO load address for computing offsets; 0 = use raw VA
            enable_instructions: collect instruction events
            enable_memory: collect memory read/write events
            enable_sync: collect sync (mutex/futex) events
            batch_size: auto-flush threshold (events in buffer)
            output_file: if set, also save collected events to this JSONL file
        """
        self.ql = ql
        self.server_url = (server_url or os.environ.get('SOTRACE_URL', '')).rstrip('/')
        self._trace_id = trace_id
        self.so_base = so_base
        self.enable_instructions = enable_instructions
        self.enable_memory = enable_memory
        self.enable_sync = enable_sync
        self.batch_size = batch_size
        self.output_file = output_file or os.environ.get('SOTRACE_FILE', '')

        self.batcher = EventBatcher(batch_size=batch_size)
        self._client = SoTraceClient(self.server_url) if self.server_url else None
        self._attached = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def attach(self):
        """Register all hooks on the Qiling instance. Call before ql.run()."""
        if self._attached:
            raise RuntimeError("SoTracePlugin is already attached")
        self._attached = True

        if self.enable_instructions:
            self.ql.hook_code(make_code_hook(self))
            logger.info("[sotrace] Instruction hook registered")

        if self.enable_memory:
            try:
                self.ql.hook_mem_write(make_mem_write_hook(self))
                self.ql.hook_mem_read(make_mem_read_hook(self))
                logger.info("[sotrace] Memory hooks registered")
            except Exception as e:
                logger.warning(f"[sotrace] Memory hooks unavailable: {e}")

        if self.enable_sync:
            self._install_sync_hooks()

        logger.info(
            f"[sotrace] Attached  server={self.server_url or '(none)'}  "
            f"so_base=0x{self.so_base:x}  batch_size={self.batch_size}"
        )

    def flush(self) -> int:
        """
        Send buffered events to sotrace-server (blocking).

        Returns the trace_id confirmed by the server (or the local trace_id
        if running in file-only mode).
        """
        if self.batcher.is_empty():
            return self._trace_id

        envelope = self.batcher.drain(self._trace_id)

        if self._client:
            try:
                assigned = self._client.import_trace(envelope)
                self._trace_id = assigned
                logger.info(
                    f"[sotrace] Flushed  trace_id={assigned}  "
                    f"instructions={len(envelope['instructions'])}  "
                    f"mem_writes={len(envelope['memory_writes'])}  "
                    f"mem_reads={len(envelope['memory_reads'])}  "
                    f"sync={len(envelope['sync_events'])}"
                )
            except Exception as e:
                logger.error(f"[sotrace] flush failed: {e}")

        if self.output_file:
            self._append_jsonl(self.output_file, envelope)

        # Recursive flush if buffer filled again while we were flushing
        if self.batcher.size() >= self.batch_size:
            return self.flush()

        return self._trace_id

    def save(self, path: str):
        """
        Drain buffered events and save to a JSONL file without uploading.
        Can be imported later with: ``sotrace-cli trace-import --file path``
        """
        if self.batcher.is_empty():
            logger.info("[sotrace] Nothing to save — buffer is empty")
            return
        envelope = self.batcher.drain(self._trace_id)
        self._append_jsonl(path, envelope)
        logger.info(f"[sotrace] Saved trace to {path}")

    def detach(self):
        """Flush remaining events and mark as detached."""
        if not self.batcher.is_empty():
            self.flush()
        self._attached = False
        logger.info(f"[sotrace] Detached  trace_id={self._trace_id}")

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    @property
    def trace_id(self) -> int:
        """The trace_id last confirmed by the server (0 before first flush)."""
        return self._trace_id

    def analyze(self, endpoint: str) -> dict:
        """
        Fetch an analysis result from sotrace-server.

        endpoint: one of 'races', 'deadlocks', 'contentions', 'critical-sections',
                  'jni-boundary', 'scheduling', 'data-flows', 'producer-consumer',
                  'lifecycle', 'states', 'function-safety', 'function-assoc'
        """
        if not self._client:
            raise RuntimeError("server_url is not configured — cannot call analyze()")
        if not self._trace_id:
            raise RuntimeError("trace_id is 0 — call flush() first")
        return self._client.get_analysis(self._trace_id, endpoint)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _auto_flush(self):
        try:
            self.flush()
        except Exception as e:
            logger.warning(f"[sotrace] auto-flush failed: {e}")

    def _install_sync_hooks(self):
        # Strategy 1: futex syscall hook
        try:
            self.ql.os.set_syscall('futex', make_futex_hook(self))
            logger.info("[sotrace] futex syscall hook registered")
        except Exception as e:
            logger.debug(f"[sotrace] futex hook unavailable: {e}")

        # Strategy 2: hook named pthread symbols (if linker has them)
        try_hook_pthread_symbols(self.ql, self)

    @staticmethod
    def _append_jsonl(path: str, envelope: dict):
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(envelope) + '\n')
