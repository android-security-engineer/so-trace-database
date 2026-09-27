#!/usr/bin/env python3
"""
sotrace-dynamorio.py — build and run the sotrace DynamoRIO client, then upload the trace.

Subcommands
-----------
build   Compile sotrace_client.so with CMake.
run     Execute the target under DynamoRIO and upload the collected trace.

Examples
--------
# Build (once)
python sotrace-dynamorio.py build --dynamorio-dir /opt/DynamoRIO

# Run + upload
python sotrace-dynamorio.py run \\
    --client ./build/libsotrace_client.so \\
    --server http://192.168.1.83:3000 \\
    --so libfoo.so \\
    -- ./target_binary arg1 arg2

# Run + save to file (no server)
python sotrace-dynamorio.py run \\
    --client ./build/libsotrace_client.so \\
    --output trace.jsonl \\
    --so libfoo.so \\
    -- ./target_binary
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from sotrace_dynamorio.client import SoTraceClient, parse_jsonl


# ---------------------------------------------------------------------------
# Build subcommand
# ---------------------------------------------------------------------------

def cmd_build(args):
    script_dir = Path(__file__).parent.resolve()
    build_dir  = script_dir / "build"
    build_dir.mkdir(exist_ok=True)

    dynamorio_cmake = Path(args.dynamorio_dir) / "cmake"
    if not dynamorio_cmake.exists():
        print(f"[sotrace] ERROR: DynamoRIO cmake dir not found: {dynamorio_cmake}")
        print("  Install DynamoRIO from https://dynamorio.org/page_releases.html")
        sys.exit(1)

    cmake_opts = [
        f"-DDynamoRIO_DIR={dynamorio_cmake}",
        f"-DCMAKE_BUILD_TYPE={args.build_type}",
    ]
    if args.enable_memory:
        cmake_opts.append("-DSOTRACE_ENABLE_MEMORY=ON")

    print(f"[sotrace] Configuring in {build_dir} ...")
    subprocess.run(
        ["cmake", str(script_dir)] + cmake_opts,
        cwd=build_dir, check=True
    )

    print("[sotrace] Building ...")
    subprocess.run(
        ["cmake", "--build", ".", "--parallel"],
        cwd=build_dir, check=True
    )

    client_so = next(build_dir.glob("*sotrace_client*.so"), None)
    if client_so:
        print(f"[sotrace] Built: {client_so}")
    else:
        print("[sotrace] WARNING: libsotrace_client.so not found in build dir")


# ---------------------------------------------------------------------------
# Run subcommand
# ---------------------------------------------------------------------------

def cmd_run(args):
    client_so = Path(args.client).resolve()
    if not client_so.exists():
        print(f"[sotrace] ERROR: client library not found: {client_so}")
        print("  Run: python sotrace-dynamorio.py build --dynamorio-dir /opt/DynamoRIO")
        sys.exit(1)

    drrun = _find_drrun(args.dynamorio_dir)

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        trace_path = tf.name

    try:
        # Build the drrun command
        client_opts = ["-outfile", trace_path]
        if args.so:
            client_opts += ["-so", args.so]
        if args.enable_memory:
            client_opts += ["-mem"]

        target_args = args.target_args
        if target_args and target_args[0] == "--":
            target_args = target_args[1:]

        drrun_cmd = [
            drrun,
            "-c", str(client_so),
        ] + client_opts + ["--"] + target_args

        print(f"[sotrace] Running: {' '.join(drrun_cmd)}")
        proc = subprocess.run(drrun_cmd, check=False)
        if proc.returncode not in (0, -6):  # -6 = SIGABRT sometimes from drrun
            print(f"[sotrace] drrun exited with code {proc.returncode}")

        # Parse JSONL output
        if not os.path.exists(trace_path) or os.path.getsize(trace_path) == 0:
            print("[sotrace] ERROR: no trace output generated")
            sys.exit(1)

        envelope = parse_jsonl(trace_path)
        n_insns = len(envelope["instructions"])
        print(f"[sotrace] Collected {n_insns} instructions, "
              f"{len(envelope['memory_reads'])} reads, "
              f"{len(envelope['memory_writes'])} writes")

        if args.output:
            with open(args.output, "w") as f:
                f.write(json.dumps(envelope) + "\n")
            print(f"[sotrace] Saved to {args.output}")

        if args.server:
            client = SoTraceClient(args.server)
            trace_id = client.import_trace(envelope)
            print(f"[sotrace] Uploaded  trace_id={trace_id}")
            print(f"[sotrace] Analyze:  {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")

        if not args.output and not args.server:
            print("[sotrace] WARNING: neither --output nor --server specified; trace discarded")

    finally:
        if not args.keep_log:
            try:
                os.unlink(trace_path)
            except OSError:
                pass
        else:
            print(f"[sotrace] Raw trace log kept at: {trace_path}")


def _find_drrun(dynamorio_dir: str) -> str:
    import shutil

    # 1. Explicit --dynamorio-dir
    if dynamorio_dir:
        for rel in ("bin64/drrun", "bin/drrun", "drrun"):
            candidate = os.path.join(dynamorio_dir, rel)
            if os.path.isfile(candidate):
                return candidate

    # 2. PATH
    found = shutil.which("drrun")
    if found:
        return found

    print("[sotrace] ERROR: drrun not found. Install DynamoRIO and either:")
    print("  - add its bin64/ to PATH, or")
    print("  - pass --dynamorio-dir /opt/DynamoRIO")
    sys.exit(1)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="sotrace-dynamorio",
        description="Build and run the sotrace DynamoRIO client",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    # build
    bp = sub.add_parser("build", help="Compile sotrace_client.so")
    bp.add_argument("--dynamorio-dir", default="/opt/DynamoRIO",
                    help="DynamoRIO install dir (default: /opt/DynamoRIO)")
    bp.add_argument("--build-type", default="Release",
                    choices=["Release", "Debug", "RelWithDebInfo"])
    bp.add_argument("--enable-memory", action="store_true",
                    help="Enable memory-access instrumentation (slower)")

    # run
    rp = sub.add_parser("run", help="Trace a binary and upload the result")
    rp.add_argument("--client", required=True,
                    help="Path to libsotrace_client.so")
    rp.add_argument("--server", default="",
                    help="sotrace-server URL (e.g. http://192.168.1.83:3000)")
    rp.add_argument("--output", default="",
                    help="Save JSONL trace to this file path")
    rp.add_argument("--so", default="",
                    help="Filter: only record instructions inside this SO")
    rp.add_argument("--dynamorio-dir", default="",
                    help="DynamoRIO install dir (to find drrun)")
    rp.add_argument("--enable-memory", action="store_true",
                    help="Pass -mem flag to client (record memory accesses)")
    rp.add_argument("--keep-log", action="store_true",
                    help="Keep the raw JSONL log file for debugging")
    rp.add_argument("target_args", nargs=argparse.REMAINDER,
                    help="-- <binary> [args...]")

    args = parser.parse_args()
    if args.subcmd == "build":
        cmd_build(args)
    elif args.subcmd == "run":
        cmd_run(args)


if __name__ == "__main__":
    main()
