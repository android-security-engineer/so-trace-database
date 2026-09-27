"""Main SoTracePlugin — collects angr symbolic execution events for sotrace-database."""

import json
import logging
import os

import angr

from .batcher import EventBatcher
from .client import SoTraceClient

logger = logging.getLogger(__name__)


class SoTracePlugin:
    """
    Integrates angr symbolic/concrete execution with sotrace-server.

    Minimal usage::

        import angr
        from sotrace_angr import SoTracePlugin

        proj = angr.Project("libfoo.so", load_options={'auto_load_libs': False})
        state = proj.factory.blank_state(addr=proj.loader.main_object.min_addr + 0x1234)

        plugin = SoTracePlugin(proj, server_url="http://192.168.1.83:3000")
        plugin.attach(state)

        simgr = proj.factory.simgr(state)
        simgr.run(n=1000)

        trace_id = plugin.flush()
        result = plugin.analyze("races")

    File-only mode (import later with sotrace-cli)::

        plugin = SoTracePlugin(proj, output_file="trace.jsonl")
        plugin.attach(state)
        simgr.run(n=1000)
        plugin.save("trace.jsonl")
    """

    def __init__(
        self,
        proj,
        server_url: str = None,
        trace_id: int = 0,
        max_events: int = 50_000,
        output_file: str = None,
    ):
        """
        Args:
            proj: angr.Project instance
            server_url: sotrace-server base URL; None = file-only mode
            trace_id: initial trace ID (0 = server assigns)
            max_events: auto-flush threshold (prevents unbounded memory use during
                        large symbolic exploration)
            output_file: if set, also append collected events to this JSONL file
        """
        self.proj = proj
        self.base = proj.loader.main_object.min_addr
        so_max = proj.loader.main_object.max_addr
        self.so_size = max(so_max - self.base, 1)

        self._trace_id = trace_id
        self.max_events = max_events
        self.output_file = output_file or os.environ.get('SOTRACE_FILE', '')

        url = (server_url or os.environ.get('SOTRACE_URL', '')).rstrip('/')
        self._client = SoTraceClient(url) if url else None

        self.batcher = EventBatcher()
        self._call_depth = 0

        logger.info(
            f"[sotrace-angr] Project loaded: base=0x{self.base:x}  "
            f"server={'yes' if self._client else 'no'}  max_events={max_events}"
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def attach(self, state):
        """Register angr inspect breakpoints on *state*.

        angr automatically propagates inspect breakpoints to successor states,
        so attaching to the initial state covers all execution paths.
        """
        state.inspect.b('instruction', when=angr.BP_BEFORE, action=self._on_instruction)
        state.inspect.b('mem_read',    when=angr.BP_BEFORE, action=self._on_mem_read)
        state.inspect.b('mem_write',   when=angr.BP_BEFORE, action=self._on_mem_write)

        try:
            state.inspect.b('call',   when=angr.BP_BEFORE, action=self._on_call)
            state.inspect.b('return', when=angr.BP_AFTER,  action=self._on_return)
        except Exception as e:
            logger.debug(f"[sotrace-angr] call/return hooks unavailable: {e}")

        logger.info(f"[sotrace-angr] Attached to state at pc=0x{state.addr:x}")

    def flush(self) -> int:
        """Send buffered events to sotrace-server (blocking). Returns trace_id."""
        if self.batcher.is_empty():
            return self._trace_id

        envelope = self.batcher.drain(self._trace_id)

        if self._client:
            try:
                assigned = self._client.import_trace(envelope)
                self._trace_id = assigned
                logger.info(
                    f"[sotrace-angr] Flushed  trace_id={assigned}  "
                    f"instructions={len(envelope['instructions'])}  "
                    f"mem_writes={len(envelope['memory_writes'])}  "
                    f"mem_reads={len(envelope['memory_reads'])}  "
                    f"calls={len(envelope['calls'])}"
                )
            except Exception as e:
                logger.error(f"[sotrace-angr] flush failed: {e}")

        if self.output_file:
            self._append_jsonl(self.output_file, envelope)

        # Recursive flush if buffer filled again while we were sending
        if self.batcher.size() >= self.max_events:
            return self.flush()

        return self._trace_id

    def save(self, path: str):
        """Drain buffered events to a JSONL file without uploading.

        The file can be imported later::

            sotrace-cli trace-import --file trace.jsonl
        """
        if self.batcher.is_empty():
            logger.info("[sotrace-angr] Nothing to save — buffer is empty")
            return
        envelope = self.batcher.drain(self._trace_id)
        self._append_jsonl(path, envelope)
        logger.info(f"[sotrace-angr] Saved trace to {path}")

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    @property
    def trace_id(self) -> int:
        """The trace_id last confirmed by the server (0 before first flush)."""
        return self._trace_id

    def analyze(self, endpoint: str) -> dict:
        """Fetch an analysis result from sotrace-server.

        endpoint: 'races', 'deadlocks', 'contentions', 'critical-sections',
                  'jni-boundary', 'scheduling', 'data-flows', 'producer-consumer',
                  'lifecycle', 'states', 'function-safety', 'function-assoc'

        Raises RuntimeError if server_url is not set or trace hasn't been flushed.
        """
        if not self._client:
            raise RuntimeError("server_url is not configured")
        if not self._trace_id:
            raise RuntimeError("trace_id is 0 — call flush() first")
        return self._client.get_analysis(self._trace_id, endpoint)

    # ------------------------------------------------------------------
    # Inspect callbacks
    # ------------------------------------------------------------------

    def _on_instruction(self, state):
        try:
            addr = state.inspect.instruction
            addr = self._concretize(state, addr)
            if not self._in_so(addr):
                return
            is_branch = self._is_branch(addr)
            self.batcher.add_instruction({
                "seq": self.batcher.next_seq(),
                "thread_id": 1,
                "address": self._offset(addr),
                "is_branch": is_branch,
                "branch_taken": False,
            })
            if self.batcher.size() >= self.max_events:
                self._auto_flush()
        except Exception:
            pass

    def _on_mem_read(self, state):
        try:
            addr = self._concretize(state, state.inspect.mem_read_address)
            size = state.inspect.mem_read_length
            if size is None:
                size = 4
            size = int(size)
            if size <= 0:
                return
            self.batcher.add_memory_read({
                "step": self.batcher.next_seq(),
                "thread_id": 1,
                "address": self._offset(addr) if self._in_so(addr) else addr,
                "size": size,
            })
        except Exception:
            pass

    def _on_mem_write(self, state):
        try:
            addr = self._concretize(state, state.inspect.mem_write_address)
            size = state.inspect.mem_write_length or 4
            size = int(size)
            expr = state.inspect.mem_write_expr
            try:
                val = self._concretize(state, expr)
                data = list(val.to_bytes(size, 'little'))
            except Exception:
                data = [0] * size
            self.batcher.add_memory_write({
                "step": self.batcher.next_seq(),
                "thread_id": 1,
                "address": self._offset(addr) if self._in_so(addr) else addr,
                "data": data,
            })
        except Exception:
            pass

    def _on_call(self, state):
        try:
            caller = self._concretize(state, state.inspect.instruction)
            callee = self._concretize(state, state.regs.pc)
            self.batcher.add_call({
                "seq": self.batcher.next_seq(),
                "thread_id": 1,
                "caller_address": self._offset(caller) if self._in_so(caller) else caller,
                "callee_address": self._offset(callee) if self._in_so(callee) else callee,
                "depth": self._call_depth,
                "event_type": "Call",
            })
            self._call_depth += 1
        except Exception:
            pass

    def _on_return(self, state):
        try:
            self._call_depth = max(0, self._call_depth - 1)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _in_so(self, addr: int) -> bool:
        return self.base <= addr < self.base + self.so_size

    def _offset(self, addr: int) -> int:
        return addr - self.base

    def _is_branch(self, addr: int) -> bool:
        """Use angr's Capstone lifter to check if instruction is a branch."""
        try:
            block = self.proj.factory.block(addr, num_inst=1)
            if block.capstone.insns:
                cs_insn = block.capstone.insns[0]
                from capstone import CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
                return any(g in cs_insn.groups
                           for g in (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET))
        except Exception:
            pass
        return False

    @staticmethod
    def _concretize(state, val) -> int:
        if isinstance(val, int):
            return val
        try:
            return state.solver.eval(val)
        except Exception:
            return 0

    def _auto_flush(self):
        try:
            self.flush()
        except Exception as e:
            logger.warning(f"[sotrace-angr] auto-flush failed: {e}")

    @staticmethod
    def _append_jsonl(path: str, envelope: dict):
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(envelope) + '\n')
