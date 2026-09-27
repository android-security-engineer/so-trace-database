"""
Concrete execution example: run a crackme SO with taint tracking.

Install deps:
    pip install sotrace-triton[triton,elf]

Usage:
    python concrete_execution.py
"""

from triton import MemoryAccess, CPUSIZE
from sotrace_triton import SoTracePlugin

SO_PATH = "libcrackme.so"
INPUT_ADDR = 0x100000
INPUT = b"password123\x00"

plugin = SoTracePlugin(
    arch="aarch64",
    server_url="http://192.168.1.83:3000",
    so_path=SO_PATH,
    entry_offset=0x1000,   # offset of the function to analyse
    max_steps=5000,
)

# Place the input string in emulated memory
plugin.ctx.setConcreteMemoryAreaValue(INPUT_ADDR, INPUT)

# Pass as first argument (x0 in AArch64 calling convention)
plugin.ctx.setConcreteRegisterValue(plugin.ctx.registers.x0, INPUT_ADDR)

# Mark input bytes as tainted for downstream taint analysis
for i in range(len(INPUT)):
    plugin.ctx.taintMemory(MemoryAccess(INPUT_ADDR + i, CPUSIZE.BYTE))

# Run emulation
plugin.run()

# Upload to sotrace-server and query results
trace_id = plugin.flush()
print(f"trace_id = {trace_id}")
print(f"Analyze → http://192.168.1.83:3000/traces/{trace_id}/analyze/threads/races")

# Pull race-condition analysis
result = plugin.analyze("races")
print(result)
