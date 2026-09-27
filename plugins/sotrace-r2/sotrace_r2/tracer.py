"""R2Tracer — wraps r2pipe to collect instruction/call trace in static or dynamic mode."""

import logging

from .batcher import EventBatcher

logger = logging.getLogger(__name__)

# r2 instruction type strings that indicate branch/call/return
_BRANCH_TYPES = frozenset({"jmp", "cjmp", "ujmp", "call", "ucall", "rcall", "ret", "rjmp"})
_CALL_TYPES = frozenset({"call", "ucall", "rcall"})


class R2Tracer:
    def __init__(self, r2, so_base: int = 0, so_size: int = 0):
        """
        r2: open r2pipe handle
        so_base: SO load address for computing offsets; 0 = use raw VA
        so_size: SO size in bytes for address range filtering; 0 = no filter
        """
        self.r2 = r2
        self.so_base = so_base
        self.so_size = so_size
        self.batcher = EventBatcher()

    # ------------------------------------------------------------------
    # Static mode
    # ------------------------------------------------------------------

    def trace_static(self) -> tuple:
        """
        Iterate all functions via aflj, disassemble each, collect instructions+calls.
        Returns (instructions, calls) lists ready for the import envelope.
        """
        logger.info("[sotrace-r2] Running static analysis (aaa + aflj)...")
        try:
            self.r2.cmd("aaa")
        except Exception as e:
            logger.warning(f"[sotrace-r2] aaa failed: {e}")

        try:
            funcs = self.r2.cmdj("aflj") or []
        except Exception:
            funcs = []

        logger.info(f"[sotrace-r2] Found {len(funcs)} functions")

        for func in funcs:
            addr = func.get("offset", 0)
            size = func.get("size", 0)
            if not addr or size <= 0:
                continue
            self._disassemble_function(addr, size)

        instructions = list(self.batcher.instructions)
        calls = list(self.batcher.calls)
        logger.info(f"[sotrace-r2] Collected {len(instructions)} instructions, {len(calls)} calls")
        return instructions, calls

    def _disassemble_function(self, addr: int, size: int):
        max_insns = max(size // 2, 16)
        try:
            insns = self.r2.cmdj(f"pdj {max_insns} @ {addr}") or []
        except Exception:
            return

        for insn in insns:
            if not isinstance(insn, dict):
                continue
            iaddr = insn.get("offset", 0)
            if not iaddr:
                continue
            if self.so_size and self.so_base:
                if not (self.so_base <= iaddr < self.so_base + self.so_size):
                    continue

            mnem_type = insn.get("type", "")
            is_branch = mnem_type in _BRANCH_TYPES
            is_call = mnem_type in _CALL_TYPES
            offset = iaddr - self.so_base if self.so_base else iaddr
            seq = self.batcher.next_seq()

            self.batcher.add_instruction({
                "seq": seq, "thread_id": 1,
                "address": offset,
                "is_branch": is_branch,
                "branch_taken": False,
            })

            if is_call:
                target = insn.get("jump", 0)
                if target:
                    callee = target - self.so_base if self.so_base else target
                    self.batcher.add_call({
                        "seq": seq, "thread_id": 1,
                        "caller_address": offset,
                        "callee_address": callee,
                        "depth": 0,
                        "event_type": "Call",
                    })

    # ------------------------------------------------------------------
    # Dynamic mode
    # ------------------------------------------------------------------

    def trace_dynamic(self, max_steps: int = 5000) -> tuple:
        """
        Use r2's trace session (dts+) to step max_steps instructions and collect trace.
        Requires r2 opened in debug mode: r2pipe.open("dbg://./binary") or pid://PID.
        Falls back to manual ds 1 loop if dtsj is unavailable.
        Returns (instructions, calls) lists.
        """
        logger.info(f"[sotrace-r2] Dynamic trace: {max_steps} steps")

        # Try dts+ approach first
        try:
            self.r2.cmd("dts+")
            self.r2.cmd(f"ds {max_steps}")
            trace_data = self.r2.cmdj("dtsj") or []
            if trace_data:
                return self._process_dts(trace_data)
        except Exception as e:
            logger.debug(f"[sotrace-r2] dtsj unavailable ({e}), falling back to ds 1 loop")

        # Fallback: manual step loop
        return self._step_loop(max_steps)

    def _process_dts(self, trace_data: list) -> tuple:
        for entry in trace_data:
            addr = entry.get("addr", 0)
            if not addr:
                continue
            if self.so_size and self.so_base:
                if not (self.so_base <= addr < self.so_base + self.so_size):
                    continue
            offset = addr - self.so_base if self.so_base else addr
            seq = self.batcher.next_seq()
            self.batcher.add_instruction({
                "seq": seq, "thread_id": 1,
                "address": offset,
                "is_branch": False,
                "branch_taken": False,
            })
        instructions = list(self.batcher.instructions)
        logger.info(f"[sotrace-r2] Collected {len(instructions)} instructions from dts")
        return instructions, []

    def _step_loop(self, max_steps: int) -> tuple:
        for _ in range(max_steps):
            try:
                self.r2.cmd("ds")
                pc_str = self.r2.cmd("dr PC").strip()
                if not pc_str:
                    break
                addr = int(pc_str, 16)
            except Exception:
                break

            if self.so_size and self.so_base:
                if not (self.so_base <= addr < self.so_base + self.so_size):
                    continue

            offset = addr - self.so_base if self.so_base else addr
            seq = self.batcher.next_seq()
            self.batcher.add_instruction({
                "seq": seq, "thread_id": 1,
                "address": offset,
                "is_branch": False,
                "branch_taken": False,
            })

        instructions = list(self.batcher.instructions)
        logger.info(f"[sotrace-r2] Collected {len(instructions)} instructions from step loop")
        return instructions, []

    # ------------------------------------------------------------------
    # Envelope builder
    # ------------------------------------------------------------------

    def build_envelope(self, instructions: list, calls: list, trace_id: int = 0) -> dict:
        return {
            "trace_id": trace_id,
            "threads": [{
                "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                "stack_base": 0, "stack_size": 0, "tls_addr": 0,
                "is_jni_attached": False,
            }],
            "instructions": instructions,
            "calls": calls,
            "memory_writes": [],
            "memory_reads": [],
            "sync_events": [],
        }
