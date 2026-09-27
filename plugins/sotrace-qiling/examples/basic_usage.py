"""
sotrace-qiling usage examples.

Three patterns:
  1. Real-time upload to sotrace-server
  2. Save to file for offline import via sotrace-cli
  3. Combined: upload and save locally as backup
"""

# ---------------------------------------------------------------------------
# Pattern 1: Real-time upload
# ---------------------------------------------------------------------------
def example_realtime():
    """Emulate a binary and stream trace events to sotrace-server."""
    from qiling import Qiling
    from sotrace_qiling import SoTracePlugin

    ql = Qiling(
        argv=["./examples/libfoo.so"],
        rootfs="./examples/rootfs_arm64",
    )

    plugin = SoTracePlugin(
        ql,
        server_url="http://192.168.1.83:3000",
        so_base=0x40000000,          # load address of the SO under analysis
        enable_instructions=True,
        enable_memory=True,
        enable_sync=True,
        batch_size=5000,
    )
    plugin.attach()

    ql.run()

    trace_id = plugin.flush()
    print(f"[+] Trace uploaded  trace_id={trace_id}")
    print(f"[+] Race analysis:  http://192.168.1.83:3000/api/v1/traces/{trace_id}/analyze/threads/races")
    print(f"[+] Deadlocks:      http://192.168.1.83:3000/api/v1/traces/{trace_id}/analyze/threads/deadlocks")

    # Fetch analysis result directly
    races = plugin.analyze("races")
    print(f"[+] Race conditions found: {len(races.get('races', []))}")


# ---------------------------------------------------------------------------
# Pattern 2: File output (import later with sotrace-cli)
# ---------------------------------------------------------------------------
def example_file_output():
    """Collect a trace to disk; import it later with sotrace-cli."""
    from qiling import Qiling
    from sotrace_qiling import SoTracePlugin

    ql = Qiling(
        argv=["./examples/libbar.so"],
        rootfs="./examples/rootfs_arm",
    )

    plugin = SoTracePlugin(
        ql,
        server_url=None,          # no live server needed
        so_base=0,                # keep raw virtual addresses
        enable_memory=False,      # skip memory events for smaller trace
    )
    plugin.attach()

    ql.run()

    plugin.save("libbar_trace.jsonl")
    print("[+] Trace saved to libbar_trace.jsonl")
    print("[+] Import with: sotrace-cli trace-import --file libbar_trace.jsonl")


# ---------------------------------------------------------------------------
# Pattern 3: Combined upload + local backup
# ---------------------------------------------------------------------------
def example_combined():
    """Upload to server AND keep a local file copy."""
    from qiling import Qiling
    from sotrace_qiling import SoTracePlugin

    ql = Qiling(
        argv=["./examples/libbaz.so"],
        rootfs="./examples/rootfs_arm64",
    )

    plugin = SoTracePlugin(
        ql,
        server_url="http://192.168.1.83:3000",
        output_file="libbaz_backup.jsonl",   # also writes to disk
        so_base=0x7F000000,
    )
    plugin.attach()

    ql.run()

    plugin.detach()   # flushes automatically on detach
    print(f"[+] Trace uploaded (trace_id={plugin.trace_id}) and backed up to libbaz_backup.jsonl")


# ---------------------------------------------------------------------------
# Pattern 4: Android SO reverse engineering workflow
# ---------------------------------------------------------------------------
def example_android_so_analysis():
    """
    Typical Android SO analysis workflow:
      - Load the target SO with Qiling using an Android rootfs
      - Collect the trace while exercising a specific function
      - Upload to sotrace-server
      - Print a link to the web UI for further analysis
    """
    from qiling import Qiling
    from qiling.const import QL_VERBOSE
    from sotrace_qiling import SoTracePlugin

    TARGET_SO = "./target/libnative.so"
    ROOTFS    = "./rootfs/android_arm64"
    SERVER    = "http://192.168.1.83:3000"
    SO_BASE   = 0x71000000   # typical Android SO load address

    ql = Qiling(
        argv=[TARGET_SO],
        rootfs=ROOTFS,
        verbose=QL_VERBOSE.DEFAULT,
    )

    plugin = SoTracePlugin(
        ql,
        server_url=SERVER,
        so_base=SO_BASE,
        batch_size=10000,
    )
    plugin.attach()

    # Set up entry point / call target as needed:
    # ql.hook_address(my_setup_hook, SO_BASE + 0x1234)
    ql.run(begin=SO_BASE + 0x1000, end=SO_BASE + 0x2000)

    trace_id = plugin.flush()

    print(f"\n=== sotrace Analysis Links ===")
    for dim in ["races", "deadlocks", "contentions", "critical-sections",
                "scheduling", "data-flows", "jni-boundary"]:
        url = f"{SERVER}/api/v1/traces/{trace_id}/analyze/threads/{dim}"
        print(f"  {dim:20s}: {url}")


if __name__ == "__main__":
    import sys

    examples = {
        "realtime": example_realtime,
        "file":     example_file_output,
        "combined": example_combined,
        "android":  example_android_so_analysis,
    }

    choice = sys.argv[1] if len(sys.argv) > 1 else "realtime"
    fn = examples.get(choice)
    if fn is None:
        print(f"Usage: python basic_usage.py [{' | '.join(examples)}]")
        sys.exit(1)

    fn()
