"""Dynamic debug mode: attach r2 to a running process (or launch under debugger),
step through execution, and upload the trace to sotrace-server."""

import r2pipe
from sotrace_r2 import R2Tracer, SoTraceClient

# Option A: attach to running process by PID
PID    = 12345
SERVER = "http://192.168.1.83:3000"

# Option B: launch binary under r2 debugger
# r2 = r2pipe.open("dbg:///path/to/binary")

r2 = r2pipe.open(f"pid://{PID}")

# Set a breakpoint at the SO entry and run to it
# r2.cmd("db 0x71001234")
# r2.cmd("dc")

# Find SO base from /proc/maps via r2
try:
    maps_raw = r2.cmd("dm")
    so_base = 0
    for line in maps_raw.splitlines():
        if "libfoo.so" in line and "r-x" in line:
            so_base = int(line.split()[0].split('-')[0], 16)
            break
    print(f"[*] SO base: 0x{so_base:x}")
except Exception:
    so_base = 0

tracer = R2Tracer(r2, so_base=so_base)

# Collect 2000 steps of dynamic trace
instructions, calls = tracer.trace_dynamic(max_steps=2000)
r2.quit()

print(f"[*] Collected {len(instructions)} instructions, {len(calls)} calls")

# Upload and analyze
envelope = tracer.build_envelope(instructions, calls)
client = SoTraceClient(SERVER)
trace_id = client.import_trace(envelope)
print(f"[*] trace_id = {trace_id}")

# Check for race conditions
result = client.get_analysis(trace_id, "races")
races = result.get("races", [])
print(f"[*] Race conditions: {len(races)}")
for race in races[:3]:
    print(f"    {race}")
