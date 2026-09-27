"""sotrace-ltrace: parse ltrace library-call output and upload to sotrace-server.

Usage examples
--------------
Parse an existing log file and print the envelope as JSON:
    python sotrace-ltrace.py --input trace.log

Run ltrace inline and upload to sotrace-server:
    python sotrace-ltrace.py --run --server http://localhost:3000 -- ./my_binary arg1

Run ltrace and save to JSONL (import later via sotrace-cli):
    python sotrace-ltrace.py --run --output trace.jsonl -- ./my_binary

Filter to events related to a specific SO (must appear in a dlopen call):
    python sotrace-ltrace.py --input trace.log --so libfoo.so

ltrace invocation (--run mode):
    ltrace -f -tt -T -e 'pthread_*+dlopen+dlsym+malloc+free' -o <tmp> <cmd>
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile

# Support running the script directly from the plugin directory without install
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sotrace_ltrace.parser import LtraceParser
from sotrace_ltrace.mapper import LtraceMapper


# ---------------------------------------------------------------------------
# ltrace runner
# ---------------------------------------------------------------------------

# Functions traced by default when --run is used.
# pthread_* covers the full pthread API (mutex, cond, rwlock, create, join …).
_LTRACE_FILTER = "pthread_*+dlopen+dlsym+malloc+free+realloc"


def _run_ltrace(cmd: list, log_path: str) -> None:
    """Invoke ltrace on *cmd*, writing output to *log_path*."""
    ltrace_cmd = [
        "ltrace",
        "-f",           # follow child processes / threads
        "-tt",          # print timestamps with microseconds
        "-T",           # print time spent in each call
        "-e", _LTRACE_FILTER,
        "-o", log_path,
    ] + cmd

    print(f"[sotrace-ltrace] running: {' '.join(ltrace_cmd)}", file=sys.stderr)
    result = subprocess.run(ltrace_cmd)
    if result.returncode not in (0, 1):
        # ltrace exits 1 when the traced process itself exits non-zero — ignore
        print(
            f"[sotrace-ltrace] ltrace exited with code {result.returncode}",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def _deliver(envelope: dict, server: str, output: str) -> None:
    n_sync  = len(envelope["sync_events"])
    n_calls = len(envelope["calls"])
    n_thrs  = len(envelope["threads"])

    if server:
        from sotrace_ltrace.client import SoTraceClient
        client = SoTraceClient(server)
        trace_id = client.import_trace(envelope)
        print(
            f"[sotrace-ltrace] uploaded"
            f"  trace_id={trace_id}"
            f"  threads={n_thrs}"
            f"  sync_events={n_sync}"
            f"  calls={n_calls}"
        )

    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write(json.dumps(envelope) + "\n")
        print(f"[sotrace-ltrace] saved → {output}")

    if not server and not output:
        print(json.dumps(envelope, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Parse ltrace library-call output and upload to sotrace-server.\n"
            "Use --input to parse an existing log, or --run to trace a command inline."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--input", metavar="FILE", default="",
        help="parse an existing ltrace log file",
    )
    parser.add_argument(
        "--run", action="store_true",
        help="run ltrace on the command provided after --",
    )
    parser.add_argument(
        "--server", metavar="URL", default="",
        help="upload trace to this sotrace-server base URL",
    )
    parser.add_argument(
        "--output", metavar="FILE", default="",
        help="append trace envelope to this JSONL file",
    )
    parser.add_argument(
        "--so", metavar="NAME", default="",
        help="filter events by SO name (matched against dlopen calls)",
    )
    parser.add_argument(
        "cmd", nargs=argparse.REMAINDER,
        help="-- <binary> [args ...]  (used with --run)",
    )

    args = parser.parse_args()

    # Strip leading '--' separator before the target command
    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not args.input and not args.run:
        parser.error("Provide --input FILE or --run -- <command>")

    if args.run and not cmd:
        parser.error("--run requires a command after --")

    # ------------------------------------------------------------------
    # Acquire log content
    # ------------------------------------------------------------------
    if args.input:
        with open(args.input, "r", errors="replace") as f:
            log_content = f.read()

    else:  # --run
        tmp = tempfile.NamedTemporaryFile(
            suffix=".ltrace.log", delete=False, mode="w"
        )
        tmp.close()
        log_path = tmp.name

        try:
            _run_ltrace(cmd, log_path)
            with open(log_path, "r", errors="replace") as f:
                log_content = f.read()
        finally:
            try:
                os.unlink(log_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Parse → map → deliver
    # ------------------------------------------------------------------
    events   = LtraceParser().parse(log_content)
    envelope = LtraceMapper(so_filter=args.so).map(events)

    _deliver(envelope, args.server, args.output)


if __name__ == "__main__":
    main()
