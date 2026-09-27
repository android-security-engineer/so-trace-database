"""
sotrace-lldb usage examples.

Prerequisites:
    NDK lldb-server pushed to device:
        adb push $NDK/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/*/lib/linux/aarch64/lldb-server /data/local/tmp/
        adb shell "chmod +x /data/local/tmp/lldb-server"

    Start lldb-server on device:
        adb shell "/data/local/tmp/lldb-server platform --listen '*:4444' --server"

    Forward port:
        adb forward tcp:4444 tcp:4444
"""

# ---------------------------------------------------------------------------
# Example 1: Remote Android process via NDK lldb-server
# ---------------------------------------------------------------------------
EXAMPLE_REMOTE = """
# Start LLDB on the host
$ lldb

# Connect to device
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:4444

# Attach to running process
(lldb) process attach --name com.example.app

# Load sotrace plugin
(lldb) command script import /path/to/plugins/sotrace-lldb/sotrace-lldb.py

# Trace 3000 instructions in libfoo.so, upload to server
(lldb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 3000

# Or save locally and import later
(lldb) sotrace-trace --output /tmp/trace.jsonl --so libfoo.so --steps 3000
"""

# ---------------------------------------------------------------------------
# Example 2: Local ARM binary under qemu-user + LLDB gdbstub
# ---------------------------------------------------------------------------
EXAMPLE_QEMU_GDB = """
# Terminal 1 — run ARM binary in qemu-user with GDB server
$ qemu-aarch64 -g 1234 ./libfoo_test_harness

# Terminal 2 — connect LLDB
$ lldb
(lldb) gdb-remote 1234
(lldb) command script import /path/to/plugins/sotrace-lldb/sotrace-lldb.py
(lldb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo_test_harness --steps 5000
"""

# ---------------------------------------------------------------------------
# Example 3: Programmatic use in an LLDB Python script
# ---------------------------------------------------------------------------
EXAMPLE_PROGRAMMATIC = """
# myanalysis.py — run with: lldb --source myanalysis.lldb
import lldb
import sys
sys.path.insert(0, '/path/to/plugins/sotrace-lldb')

from sotrace_lldb import SoTracePlugin

def run(debugger, command, exe_ctx, result, internal_dict):
    plugin = SoTracePlugin(
        debugger,
        server_url = 'http://192.168.1.83:3000',
        so_name    = 'libcrypto.so',
        max_steps  = 10000,
    )
    plugin.attach()
    plugin.run()
    trace_id = plugin.flush()

    # Query analysis immediately
    races = plugin.analyze('races')
    print(f"Race conditions found: {len(races.get('races', []))}")
    print(f"Full analysis: http://192.168.1.83:3000/traces/{trace_id}/analyze/threads/races")
"""

if __name__ == '__main__':
    print("sotrace-lldb examples — see comments in this file.")
    print(EXAMPLE_REMOTE)
    print(EXAMPLE_QEMU_GDB)
    print(EXAMPLE_PROGRAMMATIC)
