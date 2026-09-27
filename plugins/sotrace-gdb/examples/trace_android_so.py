"""
sotrace-gdb usage examples.

This file is meant to be read, not executed directly.
Copy the relevant snippet into your GDB session or GDB init script.
"""

# ============================================================
# Example 1: Android process via gdbserver (adb + gdbserver)
# ============================================================
#
# On device:
#   adb push gdbserver /data/local/tmp/
#   adb shell /data/local/tmp/gdbserver :5039 /data/local/tmp/target_binary
#
# On host (in GDB):
#   $ gdb-multiarch /path/to/unstripped/libfoo.so
#   (gdb) target remote :5039          # after adb forward tcp:5039 tcp:5039
#   (gdb) source /path/to/sotrace-gdb.py
#
#   # Auto-detect SO base from /proc/maps:
#   (gdb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 10000
#
#   # Or specify base explicitly:
#   (gdb) sotrace-trace --server http://192.168.1.83:3000 \
#                       --so-base 0x71a00000 --so-size 0x200000 \
#                       --steps 10000


# ============================================================
# Example 2: Local ARM binary via qemu-user + GDB stub
# ============================================================
#
# Start qemu-user with gdbstub on port 1234:
#   qemu-aarch64 -g 1234 ./libfoo_harness
#
# In GDB (on the same host):
#   $ gdb-multiarch ./libfoo_harness
#   (gdb) target remote :1234
#   (gdb) source /path/to/sotrace-gdb.py
#   (gdb) sotrace-trace --server http://127.0.0.1:3000 --so libfoo.so --steps 5000


# ============================================================
# Example 3: Save to file, import later with CLI
# ============================================================
#
#   (gdb) source /path/to/sotrace-gdb.py
#   (gdb) sotrace-trace --output /tmp/my_trace.jsonl --so libfoo.so --steps 20000
#
# Import with CLI:
#   $ sotrace-cli trace-import --file /tmp/my_trace.jsonl
#
# Or use the Rust adapter (JSONL format matches sotrace-core unidbg adapter):
#   $ cat /tmp/my_trace.jsonl | sotrace-cli import --format jsonl


# ============================================================
# Example 4: Restrict to one thread + breakpoint-triggered start
# ============================================================
#
#   (gdb) source /path/to/sotrace-gdb.py
#   (gdb) break JNI_OnLoad
#   (gdb) run
#   # GDB stops at JNI_OnLoad; now start tracing thread 12345
#   (gdb) sotrace-trace --server http://192.168.1.83:3000 \
#                       --so libfoo.so --steps 3000 --thread 12345


# ============================================================
# Example 5: GDB init script (.gdbinit)
# ============================================================
#
# Add to ~/.gdbinit or project .gdbinit:
#
#   define sotrace-android
#     source /opt/sotrace-gdb/sotrace-gdb.py
#     sotrace-trace --server http://192.168.1.83:3000 --so $arg0 --steps $arg1
#   end
#
# Usage:
#   (gdb) sotrace-android libfoo.so 5000
