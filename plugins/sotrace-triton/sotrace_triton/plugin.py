"""SoTracePlugin for Triton — concrete and symbolic execution trace collection."""

import json
import logging
import os
from typing import Optional

from .batcher import EventBatcher
from .client import SoTraceClient
from .loader import load_elf_segments

logger = logging.getLogger(__name__)

_ARCH_MAP = {
    "aarch64": "AARCH64",
    "arm":     "ARM32",
    "x86":     "X86",
    "x86_64":  "X86_64",
}

# AArch64 instruction size is always 4 bytes
_INSN_SIZE_AARCH64 = 4
# ARM32 Thumb uses 2 or 4; we default to 4 (Thumb2) and handle exceptions
_INSN_SIZE_DEFAULT = 4


class SoTracePlugin:
    """
    Collects instruction/memory/call trace data from a Triton emulation session
    and uploads it to sotrace-server.

    Minimal usage::

        from sotrace_triton import SoTracePlugin

        plugin = SoTracePlugin(
            arch="aarch64",
            server_url="http://192.168.1.83:3000",
            so_path="libfoo.so",
            entry_offset=0x1234,
            max_steps=5000,
        )
        # Optionally customise Triton context before running:
        plugin.ctx.setConcreteRegisterValue(plugin.ctx.registers.x0, 0x1)

        plugin.run()
        trace_id = plugin.flush()
        print(f"trace_id={trace_id}")
        print(plugin.analyze("races"))
    """

    def __init__(
        self,
        arch: str = "aarch64",
        server_url: Optional[str] = None,
        so_path: Optional[str] = None,
        entry_offset: int = 0,
        so_base: int = 0x400000,
        max_steps: int = 10000,
        output_file: Optional[str] = None,
    ):
        """
        Args:
            arch: target architecture ("aarch64", "arm", "x86", "x86_64")
            server_url: sotrace-server base URL; None = file-only mode
            so_path: path to the SO/ELF file to load
            entry_offset: entry-point offset relative to so_base
            so_base: virtual base address to map the SO at
            max_steps: maximum number of instructions to emulate
            output_file: if set, append JSONL envelope to this file
        """
        try:
            from triton import TritonContext, ARCH, MODE  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "Triton is not installed. "
                "Install it from https://github.com/JonathanSalwan/Triton or via pip."
            ) from exc

        triton_arch = getattr(ARCH, _ARCH_MAP.get(arch, "AARCH64"))
        self.ctx = TritonContext(triton_arch)
        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        self.ctx.setMode(MODE.AST_OPTIMIZATIONS, True)

        self._arch     = arch
        self.so_base   = so_base
        self.so_size   = 0
        self.entry_addr = so_base + entry_offset
        self.max_steps  = max_steps
        self._trace_id  = 0
        self.output_file = output_file or os.environ.get("SOTRACE_FILE", "")

        url = (server_url or os.environ.get("SOTRACE_URL", "")).rstrip("/")
        self._client = SoTraceClient(url) if url else None

        self.batcher = EventBatcher()
        self._call_depth = 0

        if so_path:
            self.so_size = load_elf_segments(self.ctx, so_path, so_base)
            logger.info(f"[sotrace-triton] Loaded {so_path} @ 0x{so_base:x}  size={self.so_size:#x}")

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self):
        """
        Emulate from entry_addr for up to max_steps instructions, collecting
        trace events into the internal batcher.

        Set up any custom register/memory state on self.ctx before calling.
        """
        try:
            from triton import Instruction  # type: ignore
        except ImportError:
            raise RuntimeError("Triton not available")

        # Set up a minimal stack
        stack_base = 0x7ffe0000
        self.ctx.setConcreteMemoryAreaValue(stack_base, b"\x00" * 0x10000)
        self._set_sp(stack_base + 0x8000)

        pc = self.entry_addr
        logger.info(f"[sotrace-triton] Starting emulation @ 0x{pc:x}  max_steps={self.max_steps}")

        for step in range(self.max_steps):
            try:
                opcodes = bytes(self.ctx.getConcreteMemoryAreaValue(pc, _INSN_SIZE_DEFAULT))

                inst = Instruction()
                inst.setAddress(pc)
                inst.setOpcode(opcodes)

                ok = self.ctx.processing(inst)
                if not ok:
                    logger.debug(f"[sotrace-triton] processing() returned False @ 0x{pc:x} — stopping")
                    break

                self._record_instruction(inst, pc)
                self._record_memory(inst)
                next_pc = self._read_pc()
                self._record_call(inst, pc, next_pc)

                if next_pc == pc:
                    logger.debug(f"[sotrace-triton] infinite loop detected @ 0x{pc:x}")
                    break
                pc = next_pc

            except Exception as exc:
                logger.debug(f"[sotrace-triton] step {step} error @ 0x{pc:x}: {exc}")
                break

        logger.info(f"[sotrace-triton] Emulation done  instructions={len(self.batcher.instructions)}")

    # ------------------------------------------------------------------
    # Flush / Save / Analyze
    # ------------------------------------------------------------------

    def flush(self) -> int:
        """Upload buffered events to sotrace-server. Returns trace_id."""
        if self.batcher.is_empty():
            return self._trace_id

        envelope = self.batcher.drain(self._trace_id)

        if self._client:
            try:
                self._trace_id = self._client.import_trace(envelope)
                logger.info(
                    f"[sotrace-triton] Flushed  trace_id={self._trace_id}"
                    f"  instructions={len(envelope['instructions'])}"
                    f"  mem_writes={len(envelope['memory_writes'])}"
                    f"  mem_reads={len(envelope['memory_reads'])}"
                )
            except Exception as exc:
                logger.error(f"[sotrace-triton] flush failed: {exc}")

        if self.output_file:
            self._append_jsonl(self.output_file, envelope)

        return self._trace_id

    def save(self, path: str):
        """Drain buffered events and save to a JSONL file (no upload)."""
        if self.batcher.is_empty():
            logger.info("[sotrace-triton] Nothing to save — buffer is empty")
            return
        envelope = self.batcher.drain(self._trace_id)
        self._append_jsonl(path, envelope)
        logger.info(f"[sotrace-triton] Saved trace to {path}")

    def analyze(self, endpoint: str) -> dict:
        """
        Query a sotrace analysis endpoint.

        endpoint: 'races', 'deadlocks', 'contentions', 'critical-sections',
                  'jni-boundary', 'scheduling', 'lifecycle', 'states',
                  'function-safety', 'data-flows', 'producer-consumer', 'function-assoc'
        """
        if not self._client:
            raise RuntimeError("server_url not configured")
        if not self._trace_id:
            raise RuntimeError("trace_id is 0 — call flush() first")
        return self._client.get_analysis(self._trace_id, endpoint)

    @property
    def trace_id(self) -> int:
        return self._trace_id

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _in_so(self, addr: int) -> bool:
        return self.so_base <= addr < self.so_base + self.so_size

    def _offset(self, addr: int) -> int:
        return addr - self.so_base

    def _read_pc(self) -> int:
        regs = self.ctx.registers
        pc_reg = getattr(regs, "pc", None) or getattr(regs, "rip", None) or getattr(regs, "eip", None)
        if pc_reg is None:
            return 0
        return self.ctx.getConcreteRegisterValue(pc_reg)

    def _set_sp(self, value: int):
        regs = self.ctx.registers
        sp_reg = getattr(regs, "sp", None) or getattr(regs, "rsp", None) or getattr(regs, "esp", None)
        if sp_reg is not None:
            self.ctx.setConcreteRegisterValue(sp_reg, value)

    def _record_instruction(self, inst, pc: int):
        if not self._in_so(pc):
            return
        seq = self.batcher.next_seq()
        is_branch = False
        branch_taken = False
        try:
            is_branch = inst.isBranch()
        except Exception:
            pass
        try:
            if is_branch and hasattr(inst, "isConditionTaken"):
                branch_taken = inst.isConditionTaken()
            elif is_branch:
                branch_taken = True
        except Exception:
            branch_taken = is_branch

        self.batcher.add_instruction({
            "seq": seq,
            "thread_id": 1,
            "address": self._offset(pc),
            "is_branch": is_branch,
            "branch_taken": branch_taken,
        })

    def _record_memory(self, inst):
        try:
            for mem, _ in inst.getLoadAccess():
                self.batcher.add_memory_read({
                    "step": self.batcher.next_seq(),
                    "thread_id": 1,
                    "address": mem.getAddress(),
                    "size": mem.getSize(),
                })
        except Exception:
            pass

        try:
            for mem, _expr in inst.getStoreAccess():
                size = mem.getSize()
                try:
                    val = self.ctx.getConcreteMemoryValue(mem)
                    data = list(val.to_bytes(size, "little"))
                except Exception:
                    data = [0] * size
                self.batcher.add_memory_write({
                    "step": self.batcher.next_seq(),
                    "thread_id": 1,
                    "address": mem.getAddress(),
                    "data": data,
                })
        except Exception:
            pass

    def _record_call(self, inst, pc: int, next_pc: int):
        try:
            disasm = inst.getDisassembly().strip().lower()
        except Exception:
            return

        if disasm.startswith("bl ") or disasm.startswith("blr") \
                or disasm.startswith("call"):
            self.batcher.add_call({
                "seq": self.batcher.next_seq(),
                "thread_id": 1,
                "caller_address": self._offset(pc) if self._in_so(pc) else pc,
                "callee_address": self._offset(next_pc) if self._in_so(next_pc) else next_pc,
                "depth": self._call_depth,
                "event_type": "Call",
            })
            self._call_depth += 1
        elif disasm.startswith("ret") or disasm == "ret":
            self.batcher.add_call({
                "seq": self.batcher.next_seq(),
                "thread_id": 1,
                "caller_address": self._offset(pc) if self._in_so(pc) else pc,
                "callee_address": self._offset(next_pc) if self._in_so(next_pc) else next_pc,
                "depth": self._call_depth,
                "event_type": "Return",
            })
            self._call_depth = max(0, self._call_depth - 1)

    @staticmethod
    def _append_jsonl(path: str, envelope: dict):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(envelope) + "\n")
