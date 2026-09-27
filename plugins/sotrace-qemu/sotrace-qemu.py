#!/usr/bin/env python3
"""
sotrace-qemu — wrap qemu-user to collect instruction traces for sotrace-database.

Usage:
    python sotrace-qemu.py [OPTIONS] -- <binary> [args...]

Options:
    --server URL     Upload trace to sotrace-server
    --output FILE    Save trace as JSONL (importable with sotrace-cli)
    --so NAME        Filter to instructions from this SO (e.g. libfoo.so)
    --arch ARCH      Target arch: aarch64 (default), arm, x86_64, x86
    --qemu PATH      Path to qemu-user binary (auto-detected if omitted)
    --trace-id N     Use this trace_id (default 0 = server assigns)
    --keep-log       Keep the raw QEMU log file after processing
    --verbose        Print per-step progress

Examples:
    # Analyze libfoo.so called through a test harness
    python sotrace-qemu.py --server http://192.168.1.83:3000 \\
        --so libfoo.so -- ./harness_aarch64 arg1

    # Save to file for offline analysis
    python sotrace-qemu.py --output trace.jsonl \\
        --arch arm -- ./harness_arm

    # Full pipeline with analysis output
    python sotrace-qemu.py --server http://192.168.1.83:3000 \\
        --so libfoo.so --verbose -- ./harness && echo "done"
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from sotrace_qemu.parser import QemuLogParser, estimate_so_range_from_log
from sotrace_qemu.client import SoTraceClient


# ---------------------------------------------------------------------------
# qemu-user discovery
# ---------------------------------------------------------------------------

_QEMU_CANDIDATES = {
    "aarch64": ["qemu-aarch64", "qemu-aarch64-static"],
    "arm":     ["qemu-arm",     "qemu-arm-static"],
    "x86_64":  ["qemu-x86_64",  "qemu-x86_64-static"],
    "x86":     ["qemu-i386",    "qemu-i386-static"],
}


def find_qemu(arch: str) -> str:
    for name in _QEMU_CANDIDATES.get(arch, []):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError(
        f"qemu-user for '{arch}' not found in PATH. "
        f"Install qemu-user-static or pass --qemu <path>."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Wrap qemu-user to collect sotrace instruction traces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server",   default="", metavar="URL",
                        help="sotrace-server base URL (upload trace on exit)")
    parser.add_argument("--output",   default="", metavar="FILE",
                        help="save trace as JSONL file")
    parser.add_argument("--so",       default="", metavar="NAME",
                        help="filter to this SO name (e.g. libfoo.so)")
    parser.add_argument("--arch",     default="aarch64",
                        choices=["aarch64", "arm", "x86_64", "x86"])
    parser.add_argument("--qemu",     default="", metavar="PATH",
                        help="path to qemu-user binary")
    parser.add_argument("--trace-id", default=0, type=int, metavar="N")
    parser.add_argument("--keep-log", action="store_true",
                        help="keep raw QEMU log file")
    parser.add_argument("--verbose",  action="store_true")
    parser.add_argument("cmd", nargs=argparse.REMAINDER,
                        help="binary and args after '--'")
    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("Specify at least one of --server or --output.")

    # Strip leading '--' from cmd
    cmd_args = args.cmd
    if cmd_args and cmd_args[0] == "--":
        cmd_args = cmd_args[1:]
    if not cmd_args:
        parser.error("No binary specified after '--'.")

    # Locate qemu binary
    qemu_bin = args.qemu or find_qemu(args.arch)
    if args.verbose:
        print(f"[sotrace] qemu: {qemu_bin}", file=sys.stderr)

    # Run qemu with instruction + exec tracing
    log_fd, log_path = tempfile.mkstemp(suffix=".qemu.log", prefix="sotrace-")
    os.close(log_fd)

    qemu_cmd = [qemu_bin, "-d", "in_asm,exec", "-D", log_path] + cmd_args
    if args.verbose:
        print(f"[sotrace] running: {' '.join(qemu_cmd)}", file=sys.stderr)

    try:
        result = subprocess.run(qemu_cmd)
    except FileNotFoundError:
        print(f"[sotrace] ERROR: cannot execute '{qemu_bin}'. "
              f"Is qemu-user installed?", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[sotrace] qemu exit code: {result.returncode}", file=sys.stderr)

    # Estimate SO base address from the log
    so_base, so_size = 0, 0
    if args.so:
        so_base, so_size = estimate_so_range_from_log(log_path, args.so)
        if args.verbose:
            print(f"[sotrace] SO range: 0x{so_base:x} – 0x{so_base + so_size:x} "
                  f"({so_size >> 10} KiB)", file=sys.stderr)

    # Parse log → instruction records
    qemu_parser = QemuLogParser(so_base=so_base, so_size=so_size, so_name=args.so)
    instructions = qemu_parser.parse(log_path)

    if args.verbose:
        print(f"[sotrace] parsed {len(instructions)} instructions", file=sys.stderr)

    if not args.keep_log:
        os.unlink(log_path)
    else:
        print(f"[sotrace] raw QEMU log kept at: {log_path}", file=sys.stderr)

    # Build import envelope
    envelope = {
        "trace_id": args.trace_id,
        "threads": [{
            "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
            "stack_base": 0, "stack_size": 0, "tls_addr": 0,
            "is_jni_attached": False,
        }],
        "instructions": instructions,
        "memory_writes": [],
        "memory_reads": [],
        "sync_events": [],
        "calls": [],
    }

    trace_id = args.trace_id

    # Upload to server
    if args.server:
        client = SoTraceClient(args.server)
        try:
            trace_id = client.import_trace(envelope)
            print(f"[sotrace] uploaded  trace_id={trace_id}  "
                  f"instructions={len(instructions)}")
            print(f"[sotrace] analyze:  "
                  f"{args.server.rstrip('/')}/api/v1/traces/{trace_id}/analyze/threads/races")
        except Exception as e:
            print(f"[sotrace] upload failed: {e}", file=sys.stderr)

    # Save to file
    if args.output:
        with open(args.output, "a", encoding="utf-8") as f:
            f.write(json.dumps(envelope) + "\n")
        print(f"[sotrace] saved to {args.output}  "
              f"({len(instructions)} instructions)")

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
