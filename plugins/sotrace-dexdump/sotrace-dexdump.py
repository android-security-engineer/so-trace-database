#!/usr/bin/env python3
"""
sotrace-dexdump.py — Parse dexdump -d output and upload to sotrace-server.

Runs ``dexdump -d`` on a .dex, .apk, or .jar file, parses the Dalvik bytecode
disassembly, and uploads call/instruction events to sotrace-server.

Usage examples:

  # Upload to sotrace-server:
  python sotrace-dexdump.py classes.dex --server http://192.168.1.83:3000

  # Save to JSONL (no server):
  python sotrace-dexdump.py app.apk --output trace.jsonl

  # Upload and save:
  python sotrace-dexdump.py classes.dex \\
      --server http://192.168.1.83:3000 \\
      --output trace.jsonl

  # Filter to a specific package:
  python sotrace-dexdump.py classes.dex \\
      --server http://192.168.1.83:3000 \\
      --filter-class com/example

  # Only native methods (linked to a SO):
  python sotrace-dexdump.py classes.dex \\
      --so libnative \\
      --output native_trace.jsonl

  # Specify dexdump path explicitly:
  python sotrace-dexdump.py classes.dex \\
      --dexdump $ANDROID_HOME/build-tools/34.0.0/dexdump \\
      --output trace.jsonl

Requirements:
  - Python 3.8+, stdlib only (no third-party packages)
  - Android SDK build-tools (or dexdump on PATH / via --dexdump)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys

from sotrace_dexdump.finder import DexdumpFinder
from sotrace_dexdump.parser import DexdumpParser
from sotrace_dexdump.mapper import DexdumpMapper
from sotrace_dexdump.client import SoTraceClient

logger = logging.getLogger("sotrace-dexdump")


# ---------------------------------------------------------------------------
# dexdump runner
# ---------------------------------------------------------------------------


def run_dexdump(dex_file: str, dexdump_bin: str) -> str:
    """Invoke ``dexdump -d`` and return stdout as a string.

    A non-zero exit code from dexdump is treated as a warning rather than a
    hard error because some APK/DEX files trigger dexdump warnings while still
    producing usable disassembly output.
    """
    cmd = [dexdump_bin, "-d", dex_file]
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.error("dexdump binary not found: %s", dexdump_bin)
        sys.exit(1)

    if result.stderr:
        for line in result.stderr.decode(errors="replace").splitlines():
            lvl = logging.WARNING if "error" in line.lower() else logging.DEBUG
            logger.log(lvl, "[dexdump] %s", line)

    if result.returncode != 0:
        logger.warning(
            "dexdump exited with code %d — may still have usable output",
            result.returncode,
        )

    return result.stdout.decode(errors="replace")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(
        prog="sotrace-dexdump",
        description=(
            "Parse dexdump -d output and upload Dalvik call/instruction "
            "traces to sotrace-server."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "dex_file",
        metavar="DEX_FILE",
        help=".dex, .apk, or .jar file to disassemble",
    )
    p.add_argument(
        "--server",
        metavar="URL",
        default="",
        help="Upload to sotrace-server, e.g. http://192.168.1.83:3000",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        default="",
        help="Append trace import envelope as JSONL to this file",
    )
    p.add_argument(
        "--so",
        metavar="NAME",
        default="",
        help=(
            "Filter by SO name for native method linkage (e.g. libnative). "
            "When set, only native methods are included in the trace."
        ),
    )
    p.add_argument(
        "--dexdump",
        metavar="PATH",
        default="",
        help="Path to dexdump binary (auto-detect from ANDROID_HOME if omitted)",
    )
    p.add_argument(
        "--filter-class",
        metavar="PATTERN",
        default="",
        help='Only include classes whose name contains PATTERN, e.g. "com/example"',
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.server and not args.output:
        p.error("Provide --server and/or --output (nothing to do otherwise)")

    # Locate dexdump binary
    if args.dexdump:
        dexdump_bin = args.dexdump
        logger.info("Using dexdump: %s", dexdump_bin)
    else:
        finder = DexdumpFinder()
        try:
            dexdump_bin = finder.find_dexdump()
            logger.info("Using dexdump: %s", dexdump_bin)
        except FileNotFoundError as exc:
            logger.error("%s", exc)
            sys.exit(1)

    # Run dexdump -d
    raw = run_dexdump(args.dex_file, dexdump_bin)
    if not raw.strip():
        logger.error("dexdump produced no output for: %s", args.dex_file)
        sys.exit(1)

    # Parse output
    dex_parser = DexdumpParser()
    result = dex_parser.parse(raw, class_filter=args.filter_class)

    total_insns = sum(len(m.instructions) for m in result.methods)
    logger.info(
        "Parsed: methods=%d  native=%d  instructions=%d",
        len(result.methods),
        len(result.native_methods),
        total_insns,
    )

    if not result.methods:
        logger.warning("No methods found — nothing to upload")
        sys.exit(0)

    # Apply --so filter: keep only native methods when a SO name is given
    methods = result.methods
    if args.so:
        before = len(methods)
        methods = [m for m in methods if m.is_native]
        logger.info(
            "SO filter '%s': keeping native methods only (%d → %d)",
            args.so, before, len(methods),
        )
        if not methods:
            logger.warning("No native methods found for --so '%s'", args.so)
            sys.exit(0)
        result.methods = methods

    # Build import envelope
    trace_name = f"dexdump:{os.path.basename(args.dex_file)}"
    mapper = DexdumpMapper()
    envelope = mapper.build_envelope(result, trace_name=trace_name)

    insn_count = len(envelope["instructions"])
    call_count = len(envelope["calls"])

    # Save to JSONL
    if args.output:
        with open(args.output, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope) + "\n")
        logger.info(
            "Saved to %s (instructions=%d  calls=%d)",
            args.output, insn_count, call_count,
        )

    # Upload to server
    if args.server:
        client = SoTraceClient(args.server)
        try:
            trace_id = client.import_trace(envelope)
            logger.info("Uploaded — trace_id=%d", trace_id)
            print(f"trace_id={trace_id}  instructions={insn_count}  calls={call_count}")
            print(f"Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")
        except RuntimeError as exc:
            logger.error("Upload failed: %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
