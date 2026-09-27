"""sotrace-valgrind: run Valgrind (lackey/callgrind), parse output, upload to sotrace-server."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

# Allow running from the plugin directory without installing the package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# SO address-range helpers
# ---------------------------------------------------------------------------

def _so_range_from_log(log_content: str):
    """Estimate SO VA range by scanning all 'I' record addresses in lackey log."""
    addrs = []
    for line in log_content.splitlines():
        m = re.match(r'^==\d+==\s+I\s+([0-9a-fA-F]+),', line)
        if m:
            try:
                addrs.append(int(m.group(1), 16))
            except ValueError:
                pass
    if not addrs:
        return 0, 0
    addrs.sort()
    return addrs[0], addrs[-1] - addrs[0] + 4


def _so_range_from_maps(pid: int, so_name: str):
    """Read /proc/<pid>/maps to find the SO's executable segment."""
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                if so_name in line and "r-xp" in line:
                    parts = line.split()
                    start, end = parts[0].split("-")
                    return int(start, 16), int(end, 16) - int(start, 16)
    except OSError:
        pass
    return 0, 0


# ---------------------------------------------------------------------------
# Lackey mode
# ---------------------------------------------------------------------------

def run_lackey(cmds, so_name: str, server: str, output: str):
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as tf:
        log_path = tf.name

    cmd = [
        "valgrind",
        "--tool=lackey",
        "--trace-mem=yes",
        f"--log-file={log_path}",
    ] + cmds

    print(f"[sotrace] running: {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd)

    with open(log_path, "r", errors="replace") as f:
        log_content = f.read()

    so_base, so_size = 0, 0
    if so_name:
        so_base, so_size = _so_range_from_log(log_content)

    from sotrace_valgrind.parser import LackeyParser
    envelope = LackeyParser(so_base, so_size).parse(log_content)

    _deliver(envelope, server, output)
    os.unlink(log_path)


# ---------------------------------------------------------------------------
# Callgrind mode
# ---------------------------------------------------------------------------

def run_callgrind(cmds, so_name: str, server: str, output: str):
    cg_out = "/tmp/sotrace-callgrind.out"

    cmd = [
        "valgrind",
        "--tool=callgrind",
        f"--callgrind-out-file={cg_out}",
    ] + cmds

    print(f"[sotrace] running: {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd)

    from sotrace_valgrind.parser import CallgrindParser
    envelope = CallgrindParser(so_name).parse(cg_out)

    _deliver(envelope, server, output)


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def _deliver(envelope: dict, server: str, output: str):
    n_insns = len(envelope["instructions"])
    n_calls = len(envelope["calls"])
    n_mw = len(envelope["memory_writes"])
    n_mr = len(envelope["memory_reads"])

    if server:
        from sotrace_valgrind.client import SoTraceClient
        client = SoTraceClient(server)
        trace_id = client.import_trace(envelope)
        print(
            f"[sotrace] uploaded  trace_id={trace_id}"
            f"  instructions={n_insns}  calls={n_calls}"
            f"  mem_writes={n_mw}  mem_reads={n_mr}"
        )

    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write(json.dumps(envelope) + "\n")
        print(f"[sotrace] saved to {output}")

    if not server and not output:
        print(json.dumps(envelope, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Run Valgrind (lackey/callgrind) and upload trace to sotrace-server."
    )
    parser.add_argument(
        "--tool", default="lackey", choices=["lackey", "callgrind"],
        help="Valgrind tool to use (default: lackey)",
    )
    parser.add_argument("--server", default="", metavar="URL",
                        help="sotrace-server base URL")
    parser.add_argument("--output", default="", metavar="FILE",
                        help="save trace as JSONL file")
    parser.add_argument("--so", default="", metavar="NAME",
                        help="SO filename for address filtering (e.g. libfoo.so)")
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="-- <binary> [args...]")

    args = parser.parse_args()

    # Strip leading '--' separator
    cmds = args.cmd
    if cmds and cmds[0] == "--":
        cmds = cmds[1:]

    if not cmds:
        parser.error("Provide the target binary after --")

    if args.tool == "lackey":
        run_lackey(cmds, args.so, args.server, args.output)
    else:
        run_callgrind(cmds, args.so, args.server, args.output)


if __name__ == "__main__":
    main()
