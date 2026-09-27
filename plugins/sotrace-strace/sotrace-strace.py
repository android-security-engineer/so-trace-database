#!/usr/bin/env python3
"""
sotrace-strace.py — parse strace/ltrace output and upload to sotrace-server.

Modes (subcommands):
  run     — spawn target under strace/ltrace and upload on exit
  parse   — parse an existing strace/ltrace log file and upload
  attach  — attach strace to a running process by PID

Usage examples:

  # Trace a binary and upload (SO filter + skip futex):
  python sotrace-strace.py run \\
      --server http://192.168.1.83:3000 \\
      --so libfoo.so --no-futex \\
      -- ./harness arg1 arg2

  # Parse an existing strace log:
  python sotrace-strace.py parse \\
      --log strace.log \\
      --server http://192.168.1.83:3000 \\
      --so libfoo.so

  # Attach to a running process (strace only):
  python sotrace-strace.py attach \\
      --pid 1234 \\
      --server http://192.168.1.83:3000

  # Use ltrace for library-call tracing:
  python sotrace-strace.py run --tool ltrace \\
      --server http://192.168.1.83:3000 \\
      -- ./harness

  # Save to JSONL file instead of uploading:
  python sotrace-strace.py run \\
      --output trace.jsonl \\
      -- ./harness
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile

# Allow running directly from the plugin directory without installing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sotrace_strace.parser import StraceParser
from sotrace_strace.client import SoTraceClient

logger = logging.getLogger("sotrace-strace")

# Syscalls captured by strace in run/attach mode
_STRACE_SYSCALLS = "mmap,mmap2,futex,clone,openat,open"


# ---------------------------------------------------------------------------
# strace/ltrace invocation helpers
# ---------------------------------------------------------------------------

def _find_tool(name: str) -> str:
    import shutil
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"{name} not found in PATH")
    return path


def _build_strace_cmd(
    tool: str,
    log_file: str,
    pid: int = 0,
    target_args: list = None,
) -> list:
    cmd = [tool]
    if tool == "strace":
        cmd += [
            "-f",             # follow forks (multi-thread)
            "-tt",            # microsecond timestamps  (required for -f -tt format)
            "-T",             # append syscall duration
            "-e", f"trace={_STRACE_SYSCALLS}",
            "-o", log_file,
        ]
    else:  # ltrace
        cmd += [
            "-f",
            "-e", (
                "pthread_mutex_lock+pthread_mutex_unlock+pthread_mutex_trylock"
                "+pthread_rwlock_rdlock+pthread_rwlock_wrlock+pthread_rwlock_unlock"
                "+pthread_cond_wait+pthread_cond_signal+pthread_cond_broadcast"
                "+sem_wait+sem_post+pthread_barrier_wait"
            ),
            "-o", log_file,
        ]
    if pid:
        cmd += ["-p", str(pid)]
    elif target_args:
        cmd += target_args
    return cmd


# ---------------------------------------------------------------------------
# Shared parse + upload logic
# ---------------------------------------------------------------------------

def _parse_and_upload(
    log_file: str,
    so_name: str,
    no_futex: bool,
    no_mmap: bool,
    so_base: int,
    server_url: str,
    output_file: str,
    tool: str,
) -> int:
    parser = StraceParser(
        so_name=so_name,
        skip_futex=no_futex,
        skip_mmap=no_mmap,
        so_base=so_base,
    )
    events = parser.parse_file(log_file)

    n_sync   = sum(1 for e in events if e.kind == "sync")
    n_mem    = sum(1 for e in events if e.kind == "memory")
    n_thread = sum(1 for e in events if e.kind == "thread")
    logger.info(
        "Parsed: threads=%d  sync_events=%d  memory_ranges=%d  (source: %s)",
        n_thread, n_sync, n_mem, tool,
    )

    if not events:
        logger.warning("No relevant events found — check strace/ltrace filter flags")

    envelope = parser.events_to_envelope(events)

    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope) + "\n")
        logger.info("Saved to %s", output_file)

    if server_url:
        client = SoTraceClient(server_url)
        try:
            trace_id = client.import_trace(envelope)
        except Exception as exc:
            logger.error("Upload failed: %s", exc)
            return 1
        logger.info("Uploaded — trace_id=%d", trace_id)
        print(f"trace_id={trace_id}")
        print(f"Analysis: {server_url}/api/v1/traces/{trace_id}/analyze/threads")

    if not output_file and not server_url:
        print(json.dumps(envelope, indent=2))

    return 0


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    if not args.target:
        logger.error("Provide the target command after '--'")
        return 1

    tool = args.tool
    try:
        _find_tool(tool)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    with tempfile.NamedTemporaryFile(
        suffix=".log", prefix="sotrace-strace-", delete=False
    ) as tmp:
        log_file = tmp.name

    cmd = _build_strace_cmd(tool, log_file, target_args=args.target)
    logger.info("Running: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        logger.info("Interrupted (Ctrl-C)")

    ret = _parse_and_upload(
        log_file, args.so, args.no_futex, args.no_mmap,
        args.so_base, args.server, args.output, tool,
    )
    try:
        os.unlink(log_file)
    except OSError:
        pass
    return ret


def cmd_parse(args: argparse.Namespace) -> int:
    if not os.path.isfile(args.log):
        logger.error("Log file not found: %s", args.log)
        return 1
    return _parse_and_upload(
        args.log, args.so, args.no_futex, args.no_mmap,
        args.so_base, args.server, args.output, args.tool,
    )


def cmd_attach(args: argparse.Namespace) -> int:
    tool = args.tool
    try:
        _find_tool(tool)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    if tool == "ltrace":
        logger.warning("ltrace attach mode may not support --pid on all platforms")

    with tempfile.NamedTemporaryFile(
        suffix=".log", prefix="sotrace-strace-", delete=False
    ) as tmp:
        log_file = tmp.name

    cmd = _build_strace_cmd(tool, log_file, pid=args.pid)
    logger.info("Attaching to PID %d: %s", args.pid, " ".join(cmd))
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        logger.info("Detached (Ctrl-C)")

    ret = _parse_and_upload(
        log_file, args.so, args.no_futex, args.no_mmap,
        args.so_base, args.server, args.output, tool,
    )
    try:
        os.unlink(log_file)
    except OSError:
        pass
    return ret


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _add_common_args(p: argparse.ArgumentParser) -> None:
    """Add flags shared across all subcommands."""
    p.add_argument(
        "--server", default="", metavar="URL",
        help="Upload to sotrace-server (e.g. http://192.168.1.83:3000)",
    )
    p.add_argument(
        "--output", default="", metavar="FILE",
        help="Save import envelope as JSONL file",
    )
    p.add_argument(
        "--so", default="", metavar="NAME",
        help=(
            "Filter by SO filename (matched case-insensitively against openat paths). "
            "Flags mmap ranges whose fd belongs to this SO."
        ),
    )
    p.add_argument(
        "--no-futex", action="store_true",
        help="Skip futex() sync events",
    )
    p.add_argument(
        "--no-mmap", action="store_true",
        help="Skip mmap()/mmap2() memory-range records",
    )
    p.add_argument(
        "--so-base", type=lambda x: int(x, 0), default=0, metavar="HEX",
        help="SO load base for address normalisation (subtracted from mmap addresses)",
    )
    p.add_argument(
        "--tool", choices=["strace", "ltrace"], default="strace",
        help="Tracing tool to use (default: strace)",
    )


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="sotrace-strace",
        description=(
            "Parse strace/ltrace output (syscall/library trace) and upload "
            "relevant events to sotrace-server."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = root.add_subparsers(dest="command", required=True)

    # --- run ---
    run_p = sub.add_parser(
        "run",
        help="Spawn a process under strace/ltrace, then upload on exit",
    )
    _add_common_args(run_p)
    run_p.add_argument(
        "target", nargs="*",
        help="Command to trace (supply after '--')",
    )

    # --- parse ---
    parse_p = sub.add_parser(
        "parse",
        help="Parse an existing strace/ltrace log file",
    )
    _add_common_args(parse_p)
    parse_p.add_argument("--log", required=True, metavar="FILE",
                         help="Path to strace/ltrace log file")

    # --- attach ---
    attach_p = sub.add_parser(
        "attach",
        help="Attach strace/ltrace to a running process by PID",
    )
    _add_common_args(attach_p)
    attach_p.add_argument("--pid", required=True, type=int,
                          help="PID of the process to attach to")

    return root


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Strip leading '--' separator from positional remainder (run subcommand)
    if hasattr(args, "target") and args.target and args.target[0] == "--":
        args.target = args.target[1:]

    dispatch = {"run": cmd_run, "parse": cmd_parse, "attach": cmd_attach}
    sys.exit(dispatch[args.command](args))


if __name__ == "__main__":
    main()
