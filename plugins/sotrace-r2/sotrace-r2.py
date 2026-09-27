#!/usr/bin/env python3
"""sotrace-r2: r2pipe integration CLI for sotrace-database.

Usage:
  # Static analysis mode (no runtime needed)
  python sotrace-r2.py --server http://192.168.1.83:3000 --mode static libfoo.so

  # Dynamic debug mode (attach to pid)
  python sotrace-r2.py --server http://192.168.1.83:3000 --mode dynamic --pid 1234 --steps 5000

  # Save to file for later CLI import
  python sotrace-r2.py --output trace.jsonl --mode static libfoo.so
"""

import argparse
import json
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s")


def main():
    parser = argparse.ArgumentParser(
        description="Collect a radare2 trace and upload to sotrace-server"
    )
    parser.add_argument("target", nargs="?", help="Binary path (static mode)")
    parser.add_argument("--mode", choices=["static", "dynamic"], default="static",
                        help="static: disassemble all functions; dynamic: debug step trace")
    parser.add_argument("--pid", type=int, default=0,
                        help="Process PID to attach (dynamic mode)")
    parser.add_argument("--steps", type=int, default=5000,
                        help="Max steps in dynamic mode (default: 5000)")
    parser.add_argument("--server", default="",
                        help="sotrace-server base URL, e.g. http://192.168.1.83:3000")
    parser.add_argument("--output", default="",
                        help="Save trace to JSONL file")
    parser.add_argument("--so-base", type=lambda x: int(x, 0), default=0,
                        help="SO load address for offset calculation (e.g. 0x71000000)")
    parser.add_argument("--so-size", type=lambda x: int(x, 0), default=0,
                        help="SO size in bytes for address range filter")
    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("Provide --server and/or --output")

    try:
        import r2pipe
    except ImportError:
        sys.exit("r2pipe not installed. Run: pip install r2pipe")

    # Open r2pipe handle
    if args.mode == "dynamic":
        if args.pid:
            r2_target = f"pid://{args.pid}"
        elif args.target:
            r2_target = f"dbg://{args.target}"
        else:
            parser.error("Dynamic mode requires --pid or a target binary")
        r2 = r2pipe.open(r2_target)
    else:
        if not args.target:
            parser.error("Static mode requires a target binary path")
        r2 = r2pipe.open(args.target)

    # Resolve so_base from r2 if not supplied
    so_base = args.so_base
    so_size = args.so_size
    if not so_base:
        try:
            info = r2.cmdj("ij") or {}
            so_base = info.get("bin", {}).get("baddr", 0)
        except Exception:
            so_base = 0

    from sotrace_r2 import R2Tracer, SoTraceClient

    tracer = R2Tracer(r2, so_base=so_base, so_size=so_size)

    try:
        if args.mode == "static":
            instructions, calls = tracer.trace_static()
        else:
            instructions, calls = tracer.trace_dynamic(max_steps=args.steps)
    finally:
        try:
            r2.quit()
        except Exception:
            pass

    envelope = tracer.build_envelope(instructions, calls)

    if args.server:
        client = SoTraceClient(args.server)
        trace_id = client.import_trace(envelope)
        print(f"[sotrace] trace_id={trace_id}  instructions={len(instructions)}  calls={len(calls)}")
        print(f"[sotrace] Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")

    if args.output:
        with open(args.output, "w") as f:
            f.write(json.dumps(envelope) + "\n")
        print(f"[sotrace] Saved to {args.output}")


if __name__ == "__main__":
    main()
