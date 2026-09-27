"""
sotrace-angr usage examples.

Prerequisites:
    pip install sotrace-angr[angr]
    # or: pip install angr requests  &&  pip install -e plugins/sotrace-angr/

Start sotrace-server:
    cargo run -p sotrace-server -- --port 3000
"""

import angr
from sotrace_angr import SoTracePlugin

SERVER = "http://192.168.1.83:3000"
SO_PATH = "libfoo.so"   # replace with your target SO


# ──────────────────────────────────────────────────────────────────────────────
# Example 1: Concrete execution (blank state with concrete inputs)
# ──────────────────────────────────────────────────────────────────────────────
def example_concrete():
    proj = angr.Project(SO_PATH, load_options={'auto_load_libs': False})
    base = proj.loader.main_object.min_addr

    # Start at function offset 0x1234 with concrete stack/registers
    state = proj.factory.blank_state(addr=base + 0x1234)
    state.regs.x0 = 0xDEADBEEF   # first argument (AArch64)

    plugin = SoTracePlugin(proj, server_url=SERVER, max_events=100_000)
    plugin.attach(state)

    simgr = proj.factory.simgr(state)
    simgr.run(n=500)   # step up to 500 basic blocks

    trace_id = plugin.flush()
    print(f"[concrete] trace_id={trace_id}")

    # Query analysis
    races = plugin.analyze("races")
    print(f"[concrete] Race conditions: {races}")


# ──────────────────────────────────────────────────────────────────────────────
# Example 2: Symbolic execution — explore all paths
# ──────────────────────────────────────────────────────────────────────────────
def example_symbolic():
    proj = angr.Project(SO_PATH, load_options={'auto_load_libs': False})
    base = proj.loader.main_object.min_addr
    target_offset = 0x5678   # address we want to reach

    state = proj.factory.blank_state(addr=base + 0x1234)
    # Leave x0 symbolic — angr will explore both branches
    state.regs.x0 = state.solver.BVS('arg0', 64)

    plugin = SoTracePlugin(proj, server_url=SERVER, max_events=200_000)
    plugin.attach(state)

    simgr = proj.factory.simgr(state)
    simgr.explore(find=base + target_offset)

    if simgr.found:
        print(f"[symbolic] Found {len(simgr.found)} paths reaching 0x{target_offset:x}")
        trace_id = plugin.flush()
        print(f"[symbolic] trace_id={trace_id}")
        # Deadlock analysis across all explored paths
        deadlocks = plugin.analyze("deadlocks")
        print(f"[symbolic] Deadlock risks: {deadlocks}")
    else:
        print("[symbolic] Target address not reached")


# ──────────────────────────────────────────────────────────────────────────────
# Example 3: File mode — save JSONL for later import with sotrace-cli
# ──────────────────────────────────────────────────────────────────────────────
def example_file_mode():
    proj = angr.Project(SO_PATH, load_options={'auto_load_libs': False})
    base = proj.loader.main_object.min_addr

    state = proj.factory.blank_state(addr=base + 0x1234)

    # No server_url — events go to a local JSONL file
    plugin = SoTracePlugin(proj, output_file="trace.jsonl")
    plugin.attach(state)

    simgr = proj.factory.simgr(state)
    simgr.run(n=500)

    plugin.save("trace.jsonl")
    print("[file] Saved to trace.jsonl")
    print("[file] Import with:  sotrace-cli trace-import --file trace.jsonl")
    print("[file] Then analyze: sotrace-cli analyze --trace-id <id> --dimension races")


# ──────────────────────────────────────────────────────────────────────────────
# Run all examples
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    example = sys.argv[1] if len(sys.argv) > 1 else "concrete"
    if example == "concrete":
        example_concrete()
    elif example == "symbolic":
        example_symbolic()
    elif example == "file":
        example_file_mode()
    else:
        print(f"Unknown example '{example}'. Choose: concrete | symbolic | file")
