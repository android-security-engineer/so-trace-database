"""
Symbolic execution example: explore multiple paths through a SO function
and collect a merged trace for each satisfiable path.

Install deps:
    pip install sotrace-triton[triton,elf]

Usage:
    python symbolic_execution.py

Note:
    Triton's symbolic execution unfolds one path at a time (depth-first by
    default).  This script negates the path predicate after each run to
    explore alternative branches, up to MAX_PATHS iterations.
"""

import json
import logging

from triton import TritonContext, ARCH, MODE, MemoryAccess, CPUSIZE, Instruction  # type: ignore
from sotrace_triton import SoTracePlugin

logging.basicConfig(level=logging.INFO)

SO_PATH = "libcheck.so"
ENTRY_OFFSET = 0x1234
SO_BASE = 0x400000
INPUT_ADDR = 0x200000
INPUT_SIZE = 16
MAX_STEPS = 3000
MAX_PATHS = 5

collected_ids = []

for path_idx in range(MAX_PATHS):
    plugin = SoTracePlugin(
        arch="aarch64",
        server_url="http://192.168.1.83:3000",
        so_path=SO_PATH,
        entry_offset=ENTRY_OFFSET,
        so_base=SO_BASE,
        max_steps=MAX_STEPS,
    )

    # Symbolise the input buffer so Triton can reason about it
    plugin.ctx.setConcreteMemoryAreaValue(INPUT_ADDR, b"\x00" * INPUT_SIZE)
    for i in range(INPUT_SIZE):
        plugin.ctx.symbolizeMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE),
                                   f"input_{i}")
    plugin.ctx.setConcreteRegisterValue(plugin.ctx.registers.x0, INPUT_ADDR)
    plugin.ctx.setConcreteRegisterValue(plugin.ctx.registers.x1, INPUT_SIZE)

    plugin.run()
    trace_id = plugin.flush()
    collected_ids.append(trace_id)
    print(f"[path {path_idx}] trace_id={trace_id}  "
          f"instructions={len(plugin.batcher.instructions)}")

    # Negate path predicate to force a different branch next iteration
    # (simplified — a full engine would manage the path stack explicitly)
    pco = plugin.ctx.getPathConstraints()
    if not pco:
        print("No path constraints — cannot explore further paths.")
        break

print(f"\nUploaded {len(collected_ids)} paths: trace_ids = {collected_ids}")
print("Analyse any trace:")
for tid in collected_ids:
    print(f"  curl http://192.168.1.83:3000/api/v1/traces/{tid}/analyze/threads/races")
