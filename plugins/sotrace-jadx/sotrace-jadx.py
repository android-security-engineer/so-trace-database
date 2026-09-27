#!/usr/bin/env python3
"""
sotrace-jadx.py — JADX-based JNI boundary extractor for sotrace-database.

Runs JADX to decompile an APK/DEX/JAR, scans the resulting Java source for
``native`` method declarations and ``System.loadLibrary`` calls, then uploads
the extracted JNI crossing information to sotrace-server (or saves to JSONL).

Usage examples:

  # Decompile and upload to sotrace-server:
  python sotrace-jadx.py jadx --apk target.apk --server http://192.168.1.83:3000

  # Decompile, save to file, and upload:
  python sotrace-jadx.py jadx --apk target.apk \\
      --output jni_methods.jsonl --server http://192.168.1.83:3000

  # Filter by SO name:
  python sotrace-jadx.py jadx --apk target.apk --so libnative --server http://192.168.1.83:3000

  # Save only (no server):
  python sotrace-jadx.py jadx --apk target.apk --output jni_methods.jsonl

Requirements:
  - jadx CLI must be on $PATH (or set JADX_PATH env var)
  - Python 3.8+, stdlib only (no third-party packages)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

from sotrace_jadx.scanner import JadxScanner
from sotrace_jadx.mapper import JniMapper
from sotrace_jadx.client import SoTraceClient

logger = logging.getLogger("sotrace-jadx")


# ---------------------------------------------------------------------------
# JADX runner
# ---------------------------------------------------------------------------

def find_jadx() -> str:
    """Return the path to the jadx binary.

    Checks JADX_PATH env var first, then falls back to PATH lookup.
    """
    custom = os.environ.get("JADX_PATH", "")
    if custom and os.path.isfile(custom) and os.access(custom, os.X_OK):
        return custom
    found = shutil.which("jadx")
    if found:
        return found
    raise FileNotFoundError(
        "jadx not found. Install it or set JADX_PATH=/path/to/jadx"
    )


def run_jadx(apk_path: str, output_dir: str, jadx_bin: str) -> None:
    """Invoke jadx to decompile *apk_path* into *output_dir*.

    Raises subprocess.CalledProcessError on non-zero exit.
    """
    cmd = [jadx_bin, "--output-dir", output_dir, apk_path]
    logger.info("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    if result.stdout:
        for line in result.stdout.splitlines():
            logger.debug("[jadx] %s", line)
    if result.stderr:
        for line in result.stderr.splitlines():
            # jadx prints progress on stderr; log at debug unless it looks like an error
            level = logging.WARNING if "ERROR" in line.upper() else logging.DEBUG
            logger.log(level, "[jadx] %s", line)
    result.check_returncode()


# ---------------------------------------------------------------------------
# Main command handler
# ---------------------------------------------------------------------------

def cmd_jadx(args: argparse.Namespace) -> int:
    """Execute the 'jadx' subcommand: decompile APK and extract JNI info."""

    apk_path = args.apk
    if not os.path.isfile(apk_path):
        logger.error("APK/DEX file not found: %s", apk_path)
        return 1

    if not args.server and not args.output:
        logger.error("Specify --server <URL> or --output <file> (or both)")
        return 1

    # Locate jadx
    try:
        jadx_bin = find_jadx()
        logger.info("Using jadx: %s", jadx_bin)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    # Decompile into a temp directory
    tmp_dir = tempfile.mkdtemp(prefix="sotrace-jadx-")
    try:
        logger.info("Decompiling %s → %s", apk_path, tmp_dir)
        try:
            run_jadx(apk_path, tmp_dir, jadx_bin)
        except subprocess.CalledProcessError as exc:
            logger.error("jadx exited with code %d", exc.returncode)
            return 1

        # Scan decompiled sources
        scanner = JadxScanner()
        src_dir = os.path.join(tmp_dir, "sources")
        if not os.path.isdir(src_dir):
            # Some jadx versions put sources directly in output dir
            src_dir = tmp_dir
        logger.info("Scanning Java sources in %s", src_dir)
        methods = scanner.scan_sources(src_dir)

        if not methods:
            logger.warning("No native methods found — nothing to upload")
            return 0

        so_filter: Optional[str] = args.so if args.so else None
        if so_filter:
            before = len(methods)
            methods = [m for m in methods if m.so_name == so_filter]
            logger.info("SO filter '%s': %d → %d methods", so_filter, before, len(methods))

        logger.info("Found %d native method(s)", len(methods))
        for m in methods:
            logger.debug(
                "  %s.%s%s  [so=%s]",
                m.class_name, m.method_name, m.signature, m.so_name,
            )

        # Build import envelope
        mapper = JniMapper()
        envelope = mapper.build_envelope(
            methods,
            trace_id=0,       # 0 = let server auto-assign
            so_filter=None,   # already filtered above
            trace_name=f"jadx:{Path(apk_path).name}",
        )

        # Save to JSONL if requested
        if args.output:
            _save_jsonl(envelope, args.output)
            logger.info("Saved to %s", args.output)

        # Upload to server if requested
        if args.server:
            client = SoTraceClient(args.server)
            try:
                trace_id = client.import_trace(envelope)
                logger.info("Uploaded — trace_id=%d", trace_id)
                print(f"trace_id={trace_id}")
            except RuntimeError as exc:
                logger.error("Upload failed: %s", exc)
                return 1

    finally:
        # Clean up temp dir (suppress errors — don't mask real failures)
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

    return 0


# ---------------------------------------------------------------------------
# JSONL writer
# ---------------------------------------------------------------------------

def _save_jsonl(envelope: dict, path: str) -> None:
    """Append the envelope as one JSONL line to *path*."""
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(envelope) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sotrace-jadx",
        description=(
            "JADX-based JNI boundary extractor for sotrace-database.\n"
            "Decompiles an APK/DEX and uploads JNI crossing info to sotrace-server."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    subparsers = p.add_subparsers(dest="command", required=True)

    # ---- jadx subcommand ----
    jadx_p = subparsers.add_parser(
        "jadx",
        help="Run JADX to decompile and extract JNI boundaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Decompile an APK/DEX/JAR with JADX and extract JNI boundary info.\n\n"
            "Examples:\n"
            "  python sotrace-jadx.py jadx --apk target.apk --server http://HOST:3000\n"
            "  python sotrace-jadx.py jadx --apk target.apk --output jni.jsonl\n"
            "  python sotrace-jadx.py jadx --apk target.apk --so libnative --server http://HOST:3000\n"
        ),
    )
    jadx_p.add_argument("--apk", required=True, metavar="FILE",
                        help="APK, DEX, or JAR file to analyze")
    jadx_p.add_argument("--server", metavar="URL",
                        help="sotrace-server base URL (e.g. http://192.168.1.83:3000)")
    jadx_p.add_argument("--output", metavar="FILE",
                        help="Append import envelope as JSONL to this file")
    jadx_p.add_argument("--so", metavar="NAME",
                        help="Filter: only include methods loaded by System.loadLibrary('<NAME>')")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    handlers = {"jadx": cmd_jadx}
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
