#!/usr/bin/env python3
"""
sotrace-perf.py — Parse Linux perf / Android simpleperf call-graph output
and upload call-trace events to sotrace-server.

Data source options
-------------------
  --input FILE       Parse an existing `perf script` output text file.
  --perf-data FILE   Run `perf script -i <FILE>` and parse its output.
  --run CMD...       Run `perf record -g -o /tmp/sotrace-perf.data -- CMD`,
                     then run `perf script` on the result and parse.

Output options
--------------
  --server URL       Upload to sotrace-server (POST /api/v1/traces/import).
  --output FILE      Save the import envelope as JSONL.

Both --server and --output may be specified simultaneously.

Android / simpleperf note
-------------------------
Android does not ship Linux `perf`; use `simpleperf` from the NDK instead.
simpleperf can export a compatible text format:

    # On device:
    simpleperf record -g -o /data/local/tmp/perf.data ./harness

    # On host (after adb pull):
    simpleperf report --show-callchain -i perf.data > perf.script

Then pass perf.script to --input.  See examples/profile_android.sh for a
full end-to-end workflow.

Examples
--------
  # Parse saved file, upload to server:
  python sotrace-perf.py --input perf.script --server http://192.168.1.83:3000

  # Filter to a specific shared library:
  python sotrace-perf.py --input perf.script --server http://192.168.1.83:3000 \\
      --so libfoo.so

  # Record + parse in one shot (requires perf on PATH):
  python sotrace-perf.py --run ./my_binary arg1 arg2 \\
      --server http://192.168.1.83:3000

  # From existing perf.data:
  python sotrace-perf.py --perf-data ./perf.data --output trace.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from sotrace_perf.client import SoTraceClient
from sotrace_perf.mapper import PerfMapper
from sotrace_perf.parser import PerfScriptParser, Sample

logger = logging.getLogger("sotrace-perf")


# ---------------------------------------------------------------------------
# Perf invocation helpers
# ---------------------------------------------------------------------------

def _run_perf_record(cmd: List[str], perf: str, output: str) -> None:
    """Run `perf record -g -o OUTPUT -- CMD`."""
    full_cmd = [perf, "record", "-g", "-o", output, "--"] + cmd
    logger.info("Running: %s", " ".join(full_cmd))
    try:
        subprocess.run(full_cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"perf record failed with exit code {exc.returncode}") from exc
    except FileNotFoundError as exc:
        raise SystemExit(
            f"perf binary not found: '{perf}'. Install linux-perf or pass --perf <path>."
        ) from exc


def _run_perf_script(perf_data: str, perf: str) -> str:
    """Run `perf script -i PERF_DATA` and return the captured text."""
    cmd = [perf, "script", "-i", perf_data]
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"perf script failed (exit {exc.returncode}):\n{exc.stderr}"
        ) from exc
    except FileNotFoundError as exc:
        raise SystemExit(
            f"perf binary not found: '{perf}'. Install linux-perf or pass --perf <path>."
        ) from exc


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def _parse_samples(text: str, so_filter: str) -> List[Sample]:
    parser = PerfScriptParser()
    samples = parser.parse(text, so_filter=so_filter)
    logger.info(
        "Parsed %d sample(s)%s",
        len(samples),
        f" (filtered to '{so_filter}')" if so_filter else "",
    )
    return samples


def _build_envelope(samples: List[Sample], trace_id: int = 0) -> dict:
    mapper = PerfMapper()
    envelope = mapper.build(samples, trace_id=trace_id)
    n_calls = len(envelope["calls"])
    n_instr = len(envelope["instructions"])
    logger.info("Envelope: %d call event(s), %d instruction event(s)", n_calls, n_instr)
    return envelope


def _save_jsonl(envelope: dict, path: str) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(envelope) + "\n")
    logger.info("Saved envelope to %s", path)


def _upload(envelope: dict, server_url: str) -> int:
    client = SoTraceClient(server_url)
    trace_id = client.import_trace(envelope)
    logger.info("Uploaded to %s — trace_id=%d", server_url, trace_id)
    return trace_id


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sotrace-perf",
        description=(
            "Parse Linux perf / Android simpleperf call-graph output and "
            "upload to sotrace-server."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # --- Data source (mutually exclusive) ---
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--input", metavar="FILE",
        help="Parse an existing `perf script` output text file.",
    )
    src.add_argument(
        "--perf-data", metavar="FILE",
        help="Run `perf script -i <FILE>` and parse the result.",
    )
    src.add_argument(
        "--run", metavar="CMD", nargs=argparse.REMAINDER,
        help=(
            "Run `perf record -g -o /tmp/sotrace-perf.data -- CMD ...` then "
            "parse the result."
        ),
    )

    # --- Output ---
    p.add_argument(
        "--server", metavar="URL",
        help="sotrace-server base URL (e.g. http://192.168.1.83:3000).",
    )
    p.add_argument(
        "--output", metavar="FILE",
        help="Save import envelope as JSONL (can be combined with --server).",
    )

    # --- Filtering ---
    p.add_argument(
        "--so", metavar="NAME", default="",
        help=(
            "Only include frames whose library path basename contains NAME "
            "(e.g. 'libfoo.so')."
        ),
    )

    # --- Perf binary ---
    p.add_argument(
        "--perf", metavar="PATH", default="perf",
        help="Path to the perf binary (default: perf, searched on PATH).",
    )

    # --- Misc ---
    p.add_argument(
        "--trace-id", type=int, default=0, metavar="ID",
        help=(
            "Existing trace_id to append to (0 = server assigns a new one, "
            "default: 0)."
        ),
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")

    return p


def main(argv: Optional[List[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.server and not args.output:
        parser.error("Specify at least one of --server or --output.")

    # ---- Acquire perf script text ----
    if args.input:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
        logger.info("Read %d bytes from %s", len(text), args.input)

    elif args.perf_data:
        text = _run_perf_script(args.perf_data, args.perf)

    else:  # --run
        cmd = args.run
        if not cmd:
            parser.error("--run requires a command (e.g. --run ./my_binary arg1).")
        tmp_data = "/tmp/sotrace-perf.data"
        _run_perf_record(cmd, args.perf, tmp_data)
        text = _run_perf_script(tmp_data, args.perf)

    # ---- Parse → Map → Output ----
    samples = _parse_samples(text, so_filter=args.so)
    if not samples:
        logger.warning("No samples parsed — nothing to upload.")
        return

    envelope = _build_envelope(samples, trace_id=args.trace_id)

    if args.output:
        _save_jsonl(envelope, args.output)

    if args.server:
        trace_id = _upload(envelope, args.server)
        print(f"trace_id={trace_id}")


if __name__ == "__main__":
    main()
