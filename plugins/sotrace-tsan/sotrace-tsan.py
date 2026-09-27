#!/usr/bin/env python3
"""
sotrace-tsan.py — parse ThreadSanitizer reports and upload to sotrace-server.

TSan is built into Android NDK (clang -fsanitize=thread) and LLVM/GCC.
This tool parses TSan's text output and converts race conditions, mutex
lock/unlock sequences into a sotrace import envelope for deeper analysis.

Usage:
  # Parse TSan output from a log file
  python sotrace-tsan.py --log tsan.log --server http://192.168.1.83:3000

  # Run a TSan-instrumented binary and capture its output
  TSAN_OPTIONS="log_path=/tmp/tsan.log" ./libfoo_harness
  python sotrace-tsan.py --log /tmp/tsan.log.1234 --server http://192.168.1.83:3000

  # Android NDK TSan binary via adb
  adb shell TSAN_OPTIONS="log_path=/data/local/tmp/tsan" /data/local/tmp/libfoo_harness
  adb pull /data/local/tmp/tsan.1234 /tmp/tsan.log
  python sotrace-tsan.py --log /tmp/tsan.log --server http://192.168.1.83:3000

  # Save to JSONL instead of uploading
  python sotrace-tsan.py --log tsan.log --output trace.jsonl

  # Pipe TSan stderr directly
  TSAN_OPTIONS="verbosity=1" ./libfoo_harness 2>&1 | python sotrace-tsan.py --stdin \
      --server http://192.168.1.83:3000
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from sotrace_tsan.parser import TsanParser
from sotrace_tsan.client import SoTraceClient

logger = logging.getLogger("sotrace-tsan")


def _parse_and_upload(lines: list, so_base: int, server_url: str, output_file: str) -> int:
    parser = TsanParser(so_base=so_base)
    events = parser.parse_lines(lines)

    n_sync = sum(1 for e in events if e.kind == "sync")
    n_mem  = sum(1 for e in events if e.kind == "memory")
    n_threads = len(parser._thread_map)
    logger.info("Parsed %d threads, %d sync events, %d memory accesses",
                n_threads, n_sync, n_mem)

    if not events:
        logger.warning("No TSan events found — check log format")
        return 0

    envelope = parser.build_envelope()

    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope) + "\n")
        logger.info("Saved to %s", output_file)

    if server_url:
        client = SoTraceClient(server_url)
        trace_id = client.import_trace(envelope)
        logger.info("Uploaded — trace_id=%d", trace_id)
        print(f"trace_id={trace_id}")
        print(f"Races:     {server_url}/api/v1/traces/{trace_id}/analyze/threads/races")
        print(f"Deadlocks: {server_url}/api/v1/traces/{trace_id}/analyze/threads/deadlocks")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sotrace-tsan",
        description="Parse ThreadSanitizer reports and upload to sotrace-server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[1] if "Usage:" in __doc__ else "",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--server", default="", metavar="URL",
                        help="sotrace-server base URL")
    parser.add_argument("--output", default="", metavar="FILE",
                        help="Append import envelope as JSONL to this file")
    parser.add_argument("--log", default="", metavar="FILE",
                        help="TSan log file to parse")
    parser.add_argument("--stdin", action="store_true",
                        help="Read TSan output from stdin")
    parser.add_argument("--so-base", type=lambda x: int(x, 0), default=0,
                        metavar="HEX",
                        help="SO load base for address normalization (default 0)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.server and not args.output:
        parser.error("Provide --server, --output, or both")

    if args.stdin:
        lines = sys.stdin.readlines()
    elif args.log:
        if not os.path.isfile(args.log):
            logger.error("Log file not found: %s", args.log)
            sys.exit(1)
        with open(args.log, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    else:
        parser.error("Provide --log <file> or --stdin")

    sys.exit(_parse_and_upload(lines, args.so_base, args.server, args.output))


if __name__ == "__main__":
    main()
