"""Parse Valgrind lackey and callgrind output into sotrace import envelopes."""

import re
from typing import Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_envelope() -> dict:
    return {
        "trace_id": 0,
        "threads": [{
            "thread_id": 1,
            "create_step": 0,
            "parent_thread_id": 0,
            "stack_base": 0,
            "stack_size": 0,
            "tls_addr": 0,
            "is_jni_attached": False,
        }],
        "instructions": [],
        "memory_reads": [],
        "memory_writes": [],
        "sync_events": [],
        "calls": [],
    }


# ---------------------------------------------------------------------------
# Lackey parser
# ---------------------------------------------------------------------------

# Matches:  ==PID== X  ADDR,SIZE
_LACKEY_WITH_PID = re.compile(r"^==\d+==\s+([A-Z])\s+([0-9a-fA-F]+),(\d+)")
# Matches:  X  ADDR,SIZE  (without pid prefix, some valgrind versions)
_LACKEY_NO_PID = re.compile(r"^\s*([A-Z])\s+([0-9a-fA-F]+),(\d+)")


class LackeyParser:
    """
    Parse ``valgrind --tool=lackey --trace-mem=yes`` output.

    Record types:
        I  ADDR,SIZE   instruction fetch
        L  ADDR,SIZE   memory load (read)
        S  ADDR,SIZE   memory store (write)
        M  ADDR,SIZE   memory modify (read + write)
    """

    def __init__(self, so_base: int = 0, so_size: int = 0):
        self.so_base = so_base
        self.so_size = so_size

    def parse(self, log_content: str) -> dict:
        envelope = _base_envelope()
        instructions = envelope["instructions"]
        memory_reads = envelope["memory_reads"]
        memory_writes = envelope["memory_writes"]
        seq = 0

        for line in log_content.splitlines():
            line = line.strip()
            m = _LACKEY_WITH_PID.match(line) or _LACKEY_NO_PID.match(line)
            if not m:
                continue

            rec_type = m.group(1)
            try:
                addr = int(m.group(2), 16)
                size = int(m.group(3))
            except ValueError:
                continue

            # Apply SO address filter when configured
            if self.so_base and not (self.so_base <= addr < self.so_base + self.so_size):
                continue

            offset = addr - self.so_base if self.so_base else addr
            seq += 1

            if rec_type == "I":
                instructions.append({
                    "seq": seq,
                    "thread_id": 1,
                    "address": offset,
                    "is_branch": False,   # lackey does not expose branch info
                    "branch_taken": False,
                })

            elif rec_type == "L":
                memory_reads.append({
                    "step": seq,
                    "thread_id": 1,
                    "address": offset,
                    "size": size,
                })

            elif rec_type == "S":
                memory_writes.append({
                    "step": seq,
                    "thread_id": 1,
                    "address": offset,
                    "data": [0] * min(size, 8),  # actual data not available
                })

            elif rec_type == "M":
                # Modify = load then store at the same address
                memory_reads.append({
                    "step": seq,
                    "thread_id": 1,
                    "address": offset,
                    "size": size,
                })
                seq += 1
                memory_writes.append({
                    "step": seq,
                    "thread_id": 1,
                    "address": offset,
                    "data": [0] * min(size, 8),
                })

        return envelope


# ---------------------------------------------------------------------------
# Callgrind parser
# ---------------------------------------------------------------------------

# Callgrind cost line: decimal address followed by one or more cost columns
_CG_COST = re.compile(r"^([0-9a-fA-F]+)\s+\d")


class CallgrindParser:
    """
    Parse ``callgrind.out.<pid>`` to extract call-graph edges.

    The parser only extracts:
      - One instruction record per unique cost-line address (execution order
        is unknown in callgrind, so seq is assigned in file order).
      - One call record per ``calls=`` directive.
    """

    def __init__(self, so_name: str = ""):
        self.so_name = so_name

    def parse(self, callgrind_path: str) -> dict:
        envelope = _base_envelope()
        instructions = envelope["instructions"]
        calls = envelope["calls"]
        seq = 0

        current_fn_addr = 0
        pending_callee_addr = 0

        with open(callgrind_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()

                # ob= / fl= / fn= directives
                if line.startswith("fn="):
                    # Reset function context; actual address comes from first cost line
                    current_fn_addr = 0
                    pending_callee_addr = 0
                    continue

                # Called function name
                if line.startswith("cfn="):
                    pending_callee_addr = 0  # address comes from next calls= line
                    continue

                # calls=COUNT ADDR
                if line.startswith("calls="):
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pending_callee_addr = int(parts[1], 16)
                        except ValueError:
                            pending_callee_addr = 0
                    continue

                # Cost line: ADDR  col1 col2 ...
                m = _CG_COST.match(line)
                if m:
                    try:
                        addr = int(m.group(1), 16)
                    except ValueError:
                        continue

                    seq += 1

                    if pending_callee_addr:
                        # This cost line is the call-site cost; record the call edge
                        calls.append({
                            "seq": seq,
                            "thread_id": 1,
                            "caller_address": current_fn_addr,
                            "callee_address": pending_callee_addr,
                            "depth": 0,
                            "event_type": "Call",
                        })
                        pending_callee_addr = 0
                    else:
                        if current_fn_addr == 0:
                            current_fn_addr = addr
                        instructions.append({
                            "seq": seq,
                            "thread_id": 1,
                            "address": addr,
                            "is_branch": False,
                            "branch_taken": False,
                        })

        return envelope
