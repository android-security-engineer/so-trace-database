#!/usr/bin/env python3
"""
sotrace-pin.py — Build, run, and upload Intel Pin traces to sotrace-database.

Subcommands:
  build   Compile SoTracePintool.cpp into libsotrace_pintool.so
  run     Run a binary under Pin, collect the JSONL trace, upload to server

Examples:
  # Build the pintool
  python sotrace-pin.py build --pin-root /opt/pin

  # Trace a binary and upload
  python sotrace-pin.py run \\
      --pintool ./libsotrace_pintool.so \\
      --server http://192.168.1.83:3000 \\
      --so libfoo.so \\
      -- ./target_binary arg1 arg2

  # Also save the raw JSONL
  python sotrace-pin.py run \\
      --pintool ./libsotrace_pintool.so \\
      --server http://192.168.1.83:3000 \\
      --output /tmp/trace.jsonl \\
      -- ./target_binary
"""

import argparse
import os
import subprocess
import sys
import tempfile

from sotrace_pin.client import parse_jsonl, SoTraceClient


# ---------------------------------------------------------------------------
# build subcommand
# ---------------------------------------------------------------------------

def cmd_build(args):
    pin_root = args.pin_root or os.environ.get("PIN_ROOT", "/opt/pin")
    src_dir  = os.path.dirname(os.path.abspath(__file__))

    print(f"[sotrace] Building pintool  PIN_ROOT={pin_root}")
    result = subprocess.run(
        ["make", f"PIN_ROOT={pin_root}", "-C", src_dir],
        check=False,
    )
    if result.returncode != 0:
        print("[sotrace] Build failed. Check PIN_ROOT and compiler availability.")
        sys.exit(result.returncode)
    so_path = os.path.join(src_dir, "libsotrace_pintool.so")
    print(f"[sotrace] Built: {so_path}")


# ---------------------------------------------------------------------------
# run subcommand
# ---------------------------------------------------------------------------

def cmd_run(args):
    pintool  = args.pintool or os.path.join(os.path.dirname(__file__),
                                            "libsotrace_pintool.so")
    pin_root = args.pin_root or os.environ.get("PIN_ROOT", "/opt/pin")
    pin_bin  = _find_pin(pin_root)

    if not os.path.isfile(pintool):
        print(f"[sotrace] Pintool not found: {pintool}\n"
              "  Run: python sotrace-pin.py build --pin-root /opt/pin")
        sys.exit(1)

    if not args.cmd:
        print("[sotrace] No command given after '--'")
        sys.exit(1)

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        jsonl_path = tf.name

    try:
        pin_cmd = [
            pin_bin, "-t", pintool,
            "-o", jsonl_path,
        ]
        if args.so:
            pin_cmd += ["-so", args.so]
        if args.enable_memory:
            pin_cmd += ["-mem", "1"]
        pin_cmd += ["--"] + args.cmd

        print(f"[sotrace] Running: {' '.join(pin_cmd)}")
        result = subprocess.run(pin_cmd, check=False)
        if result.returncode not in (0, 1):
            print(f"[sotrace] Pin exited with code {result.returncode}")

        if not os.path.isfile(jsonl_path) or os.path.getsize(jsonl_path) == 0:
            print("[sotrace] No trace output produced.")
            sys.exit(1)

        envelope = parse_jsonl(jsonl_path)

        if args.output:
            import json, shutil
            if args.output != jsonl_path:
                shutil.copy(jsonl_path, args.output)
            print(f"[sotrace] Saved JSONL: {args.output}")

        if args.server:
            client   = SoTraceClient(args.server)
            trace_id = client.import_trace(envelope)
            print(f"[sotrace] Uploaded  trace_id={trace_id}"
                  f"  instructions={len(envelope['instructions'])}"
                  f"  mem_reads={len(envelope['memory_reads'])}"
                  f"  mem_writes={len(envelope['memory_writes'])}")
            print(f"[sotrace] Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")
        elif not args.output:
            print("[sotrace] No --server or --output specified; trace discarded.")

    finally:
        if os.path.isfile(jsonl_path) and jsonl_path != getattr(args, "output", None):
            os.unlink(jsonl_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_pin(pin_root: str) -> str:
    import shutil
    for candidate in [
        os.path.join(pin_root, "pin"),
        os.path.join(pin_root, "pin.sh"),
        shutil.which("pin") or "",
    ]:
        if candidate and os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError(
        f"pin binary not found in {pin_root}. "
        "Set PIN_ROOT or specify --pin-root."
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="sotrace-pin: Intel Pin trace collector for sotrace-database"
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    # -- build --
    p_build = sub.add_parser("build", help="Compile SoTracePintool.cpp")
    p_build.add_argument("--pin-root", default="", help="Path to Intel Pin installation")

    # -- run --
    p_run = sub.add_parser("run", help="Trace a binary and upload")
    p_run.add_argument("--pin-root",      default="", help="Path to Intel Pin installation")
    p_run.add_argument("--pintool",       default="", help="Path to libsotrace_pintool.so")
    p_run.add_argument("--server",        default="", help="sotrace-server URL")
    p_run.add_argument("--output",        default="", help="Save raw JSONL to this path")
    p_run.add_argument("--so",            default="", help="SO name to filter (e.g. libfoo.so)")
    p_run.add_argument("--enable-memory", action="store_true",
                       help="Enable memory read/write tracing (high overhead)")
    p_run.add_argument("cmd", nargs=argparse.REMAINDER,
                       help="Binary and arguments (after --)")

    args = parser.parse_args()

    # strip leading '--' from remainder
    if args.subcmd == "run" and args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]

    if args.subcmd == "build":
        cmd_build(args)
    elif args.subcmd == "run":
        cmd_run(args)


if __name__ == "__main__":
    main()
