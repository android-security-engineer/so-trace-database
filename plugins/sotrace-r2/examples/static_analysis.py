"""Static analysis mode: disassemble all functions in an Android ARM64 SO
and upload the trace to sotrace-server for security analysis."""

import sys
import r2pipe
from sotrace_r2 import R2Tracer, SoTraceClient
from sotrace_r2.parser import get_base_addr, parse_exports

SO_PATH   = "libtarget.so"
SERVER    = "http://192.168.1.83:3000"

r2 = r2pipe.open(SO_PATH)

# Resolve base address (PIE SO usually starts at 0)
base = get_base_addr(r2)
print(f"[*] SO base: 0x{base:x}")

# List JNI exports for reference
exports = parse_exports(r2)
jni_exports = [e for e in exports if e.get("name", "").startswith("Java_")]
print(f"[*] JNI exports: {len(jni_exports)}")
for exp in jni_exports[:5]:
    print(f"    {exp['name']} @ 0x{exp['offset']:x}")

# Collect trace
tracer = R2Tracer(r2, so_base=base)
instructions, calls = tracer.trace_static()
r2.quit()

print(f"[*] Collected {len(instructions)} instructions, {len(calls)} calls")

# Upload to sotrace-server
envelope = tracer.build_envelope(instructions, calls)
client = SoTraceClient(SERVER)
trace_id = client.import_trace(envelope)
print(f"[*] trace_id = {trace_id}")

# Fetch security analysis
try:
    result = client.get_analysis(trace_id, "function-safety")
    unsafe = [r for r in result.get("results", []) if r.get("safety") == "Unsafe"]
    print(f"[*] Unsafe functions: {len(unsafe)}")
    for fn in unsafe[:5]:
        print(f"    {fn}")
except Exception as e:
    print(f"[!] Analysis failed: {e}")
