#!/usr/bin/env python3
"""
sotrace-apktool.py — decompile an APK with apktool, scan smali bytecode,
and upload a synthetic call + instruction trace to sotrace-server.

How it works
------------
1. Runs ``apktool d <apk>`` to produce smali text-format bytecode.
2. Walks all *.smali files to extract:
   - ``System.loadLibrary`` calls          → loaded SO names
   - ``.method ... native`` declarations   → JNI boundary markers
   - ``invoke-*`` instructions             → synthetic call events
3. Maps every invoke instruction to a sequential address (0x0, 0x4, 0x8, …).
4. Uploads the envelope to sotrace-server and/or saves it as JSONL.

Usage examples
--------------
# Upload to server
python sotrace-apktool.py --apk app.apk --server http://192.168.1.83:3000

# Save to file (no server required)
python sotrace-apktool.py --apk app.apk --output trace.jsonl

# Both at once
python sotrace-apktool.py --apk app.apk \\
    --server http://192.168.1.83:3000 --output trace.jsonl

# Filter by SO name (warn if not found; trace still covers all smali)
python sotrace-apktool.py --apk app.apk --server http://host:3000 --so libtarget

# Keep the apktool output directory for inspection
python sotrace-apktool.py --apk app.apk --output trace.jsonl --keep-dir
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from sotrace_apktool.scanner import SmaliScanner
from sotrace_apktool.mapper  import SmaliMapper
from sotrace_apktool.client  import SoTraceClient


# ---------------------------------------------------------------------------
# apktool wrapper
# ---------------------------------------------------------------------------

def run_apktool(apk_path: str, output_dir: str) -> None:
    """Invoke ``apktool d <apk_path> -o <output_dir> -f`` as a subprocess."""
    cmd = ["apktool", "d", apk_path, "-o", output_dir, "-f"]
    print(f"[sotrace] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("[sotrace] ERROR: apktool not found in PATH")
        print("  Install: https://apktool.org/docs/install/")
        print("  Or on Debian/Ubuntu: sudo apt install apktool")
        sys.exit(1)

    if proc.stdout.strip():
        print(proc.stdout.strip())

    if proc.returncode != 0:
        print(f"[sotrace] ERROR: apktool exited with code {proc.returncode}")
        if proc.stderr.strip():
            print(proc.stderr.strip())
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sotrace-apktool",
        description=(
            "Decompile an APK with apktool, scan smali bytecode, "
            "and upload a synthetic trace to sotrace-server."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--apk", required=True, metavar="FILE",
        help="APK file to decompile",
    )
    parser.add_argument(
        "--server", default="", metavar="URL",
        help="sotrace-server base URL (e.g. http://192.168.1.83:3000)",
    )
    parser.add_argument(
        "--output", default="", metavar="FILE",
        help="Write the trace envelope as JSONL to this file (can combine with --server)",
    )
    parser.add_argument(
        "--so", default="", metavar="NAME",
        help=(
            "Filter: only retain SO names containing NAME in scan results; "
            "warn if the SO is not found in any loadLibrary call"
        ),
    )
    parser.add_argument(
        "--keep-dir", action="store_true",
        help=(
            "Keep the apktool output directory after run "
            "(moved to <apk-stem>_decompiled/ in the current directory)"
        ),
    )
    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("At least one of --server or --output is required")

    apk_path = os.path.abspath(args.apk)
    if not os.path.isfile(apk_path):
        print(f"[sotrace] ERROR: APK file not found: {apk_path}")
        sys.exit(1)

    # Decompile into a temp directory so we don't pollute the cwd
    tmp_root   = tempfile.mkdtemp(prefix="sotrace_apktool_")
    decode_dir = os.path.join(tmp_root, "decoded")

    try:
        # ----------------------------------------------------------------
        # Step 1: Decompile APK
        # ----------------------------------------------------------------
        run_apktool(apk_path, decode_dir)

        # ----------------------------------------------------------------
        # Step 2: Scan smali files
        # ----------------------------------------------------------------
        scanner = SmaliScanner()
        result  = scanner.scan_dir(decode_dir, so_filter=args.so)

        print(
            f"[sotrace] SO names found: "
            f"{result.so_names if result.so_names else '(none)'}"
        )
        print(f"[sotrace] Native methods : {len(result.native_methods)}")
        print(f"[sotrace] invoke-* calls : {len(result.invoke_calls)}")

        if args.so and not result.so_names:
            print(
                f"[sotrace] WARNING: '{args.so}' not found in any "
                f"System.loadLibrary() call — trace still includes all smali"
            )

        # ----------------------------------------------------------------
        # Step 3: Build import envelope
        # ----------------------------------------------------------------
        mapper   = SmaliMapper()
        envelope = mapper.build_envelope(result, so_name=args.so)
        n_insns  = len(envelope["instructions"])
        n_calls  = len(envelope["calls"])
        print(f"[sotrace] Envelope: {n_insns} instruction(s), {n_calls} call event(s)")

        # ----------------------------------------------------------------
        # Step 4a: Save to file
        # ----------------------------------------------------------------
        if args.output:
            out_path = os.path.abspath(args.output)
            with open(out_path, "w") as fh:
                fh.write(json.dumps(envelope) + "\n")
            print(f"[sotrace] Saved to {out_path}")

        # ----------------------------------------------------------------
        # Step 4b: Upload to server
        # ----------------------------------------------------------------
        if args.server:
            client   = SoTraceClient(args.server)
            trace_id = client.import_trace(envelope)
            print(f"[sotrace] Uploaded  trace_id={trace_id}")
            print(
                f"[sotrace] Analyze:  "
                f"{args.server}/api/v1/traces/{trace_id}/analyze/threads/races"
            )

        # ----------------------------------------------------------------
        # Step 5: Optionally keep the apktool output
        # ----------------------------------------------------------------
        if args.keep_dir:
            dest = os.path.join(
                os.getcwd(),
                Path(apk_path).stem + "_decompiled",
            )
            if os.path.exists(dest):
                shutil.rmtree(dest)
            shutil.move(decode_dir, dest)
            print(f"[sotrace] apktool output kept at: {dest}")

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    main()
