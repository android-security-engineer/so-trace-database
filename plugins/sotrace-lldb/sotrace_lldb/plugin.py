"""
SoTracePlugin: high-level interface for programmatic use in LLDB Python scripts.

Usage in an LLDB Python script::

    import lldb
    from sotrace_lldb import SoTracePlugin

    def run_trace(debugger, command, exe_ctx, result, internal_dict):
        plugin = SoTracePlugin(
            debugger,
            server_url="http://192.168.1.83:3000",
            so_name="libfoo.so",
            max_steps=5000,
        )
        plugin.attach()
        plugin.run()
        trace_id = plugin.flush()
        result.AppendMessage(f"[sotrace] trace_id={trace_id}")
"""

import json
import logging

from .batcher   import EventBatcher
from .client    import SoTraceClient
from .collector import SoTraceCollector, find_so_base

logger = logging.getLogger(__name__)


class SoTracePlugin:
    def __init__(self, debugger, server_url: str = None, trace_id: int = 0,
                 so_name: str = '', so_base: int = 0, so_size: int = 0,
                 max_steps: int = 10000, target_tid=None,
                 output_file: str = ''):
        """
        debugger:   lldb.SBDebugger
        server_url: sotrace-server URL (None = file-only mode)
        so_name:    SO filename for auto base resolution (e.g. "libfoo.so")
        so_base:    explicit load address (overrides so_name lookup)
        so_size:    explicit SO size in bytes (used with so_base)
        max_steps:  maximum stepi iterations
        target_tid: restrict collection to this thread ID (None = selected thread)
        output_file: if set, also save envelope to JSONL
        """
        self.debugger    = debugger
        self._trace_id   = trace_id
        self.so_name     = so_name
        self.so_base     = so_base
        self.so_size     = so_size
        self.max_steps   = max_steps
        self.target_tid  = target_tid
        self.output_file = output_file

        self.batcher  = EventBatcher()
        self._client  = SoTraceClient(server_url) if server_url else None
        self._collector: SoTraceCollector = None

    def attach(self):
        """Resolve SO base (if needed) and prepare the collector."""
        if self.so_base == 0 and self.so_name:
            base, size = find_so_base(self.debugger, self.so_name)
            if base:
                self.so_base = base
                self.so_size = size
                logger.info(f"[sotrace] {self.so_name} @ 0x{base:x}  size=0x{size:x}")
            else:
                logger.warning(f"[sotrace] Could not locate {self.so_name} — collecting all addresses")

        self._collector = SoTraceCollector(
            self.debugger, self.batcher,
            self.so_base, self.so_size,
            self.max_steps, self.target_tid,
        )

    def run(self):
        """Start the step loop (blocking until max_steps or process exits)."""
        if self._collector is None:
            self.attach()
        self._collector.start()

    def flush(self) -> int:
        """Send buffered events to sotrace-server, return trace_id."""
        if self.batcher.is_empty():
            return self._trace_id

        envelope = self.batcher.drain(self._trace_id)

        if self._client:
            try:
                assigned = self._client.import_trace(envelope)
                self._trace_id = assigned
                logger.info(
                    f"[sotrace] Flushed  trace_id={assigned}  "
                    f"instructions={len(envelope['instructions'])}"
                )
            except Exception as e:
                logger.error(f"[sotrace] flush failed: {e}")

        if self.output_file:
            self._append_jsonl(self.output_file, envelope)

        return self._trace_id

    def save(self, path: str):
        """Drain buffer and write JSONL without uploading."""
        if self.batcher.is_empty():
            return
        envelope = self.batcher.drain(self._trace_id)
        self._append_jsonl(path, envelope)
        logger.info(f"[sotrace] Saved to {path}")

    def analyze(self, endpoint: str) -> dict:
        """Query analysis from sotrace-server (requires prior flush)."""
        if not self._client:
            raise RuntimeError("server_url not configured")
        if not self._trace_id:
            raise RuntimeError("trace_id is 0 — call flush() first")
        return self._client.get_analysis(self._trace_id, endpoint)

    @property
    def trace_id(self) -> int:
        return self._trace_id

    @staticmethod
    def _append_jsonl(path: str, envelope: dict):
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(envelope) + '\n')
