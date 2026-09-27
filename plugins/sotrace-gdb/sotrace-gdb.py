"""
sotrace-gdb.py — load this file inside a GDB session to enable sotrace tracing.

Usage (inside GDB):
    (gdb) source /path/to/sotrace-gdb.py
    (gdb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 5000
    (gdb) sotrace-trace --output /tmp/trace.jsonl --so libfoo.so --steps 2000
    (gdb) sotrace-trace --server http://192.168.1.83:3000 --so-base 0x71000000 --so-size 0x100000 --steps 1000

Options:
    --server URL       sotrace-server base URL (upload trace on finish)
    --output FILE      save trace as JSONL instead of (or in addition to) uploading
    --so NAME          SO file name substring for auto base-address lookup
    --so-base ADDR     hex SO load address (overrides --so lookup)
    --so-size SIZE     hex SO size in bytes (used with --so-base; default 0x10000000)
    --steps N          maximum stepi steps to collect (default 10000)
    --thread TID       restrict collection to a single thread LWP id
"""

import sys
import os
import json
import shlex
import logging

logging.basicConfig(level=logging.INFO, format="[sotrace] %(message)s")
logger = logging.getLogger("sotrace_gdb")

# ---------------------------------------------------------------------------
# Bootstrap: make sotrace_gdb importable even when not installed as a package.
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import gdb  # noqa: E402 — only available inside GDB
from sotrace_gdb.batcher import EventBatcher
from sotrace_gdb.client import SoTraceClient
from sotrace_gdb.collector import SoTraceCollector, find_so_base


class SoTraceCommand(gdb.Command):
    """GDB command: sotrace-trace [options]

    Trace instructions executed inside the target SO and upload to sotrace-server.
    """

    def __init__(self):
        super().__init__("sotrace-trace", gdb.COMMAND_USER)
        self._collector = None

    # ------------------------------------------------------------------
    # GDB entry point
    # ------------------------------------------------------------------

    def invoke(self, args_str: str, from_tty: bool):
        try:
            opts = self._parse(args_str)
        except SystemExit:
            return  # argparse printed help/error
        except Exception as e:
            gdb.write(f"[sotrace] Argument error: {e}\n")
            return

        # Resolve SO base address
        so_base, so_size = self._resolve_so(opts)
        if so_base == 0 and not opts.get("so_base_explicit"):
            gdb.write("[sotrace] WARNING: SO base not found — collecting all addresses\n")

        # Build components
        batcher = EventBatcher(batch_size=opts.get("batch_size", 5000))
        client = SoTraceClient(opts["server"]) if opts.get("server") else None

        collector = SoTraceCollector(
            gdb=gdb,
            batcher=batcher,
            so_base=so_base,
            so_size=so_size,
            max_steps=opts.get("steps", 10000),
            target_tid=opts.get("thread"),
        )
        self._collector = collector

        output_file = opts.get("output")

        def on_finish():
            self._on_finish(batcher, client, output_file, opts.get("trace_id", 0))

        gdb.write(
            f"[sotrace] Starting trace: so_base=0x{so_base:x}  so_size=0x{so_size:x}"
            f"  max_steps={opts.get('steps', 10000)}\n"
        )
        collector.start(on_finish=on_finish)

    # ------------------------------------------------------------------
    # Finish callback (called when stepi loop ends or process exits)
    # ------------------------------------------------------------------

    def _on_finish(self, batcher: EventBatcher, client, output_file, trace_id: int):
        if batcher.is_empty():
            gdb.write("[sotrace] No events collected.\n")
            return

        envelope = batcher.drain(trace_id)
        instr_count = len(envelope["instructions"])
        gdb.write(f"[sotrace] Collected {instr_count} instructions.\n")

        if output_file:
            try:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(envelope) + "\n")
                gdb.write(f"[sotrace] Saved to {output_file}\n")
            except Exception as e:
                gdb.write(f"[sotrace] Save failed: {e}\n")

        if client:
            try:
                assigned_id = client.import_trace(envelope)
                gdb.write(f"[sotrace] Uploaded trace_id={assigned_id}\n")
                gdb.write(f"[sotrace] Analyze: {client.server_url}"
                          f"/api/v1/traces/{assigned_id}/analyze/threads/races\n")
            except Exception as e:
                gdb.write(f"[sotrace] Upload failed: {e}\n")

    # ------------------------------------------------------------------
    # Argument parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse(args_str: str) -> dict:
        tokens = shlex.split(args_str)
        opts = {
            "steps": 10000,
            "batch_size": 5000,
            "trace_id": 0,
        }
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "--server" and i + 1 < len(tokens):
                opts["server"] = tokens[i + 1]; i += 2
            elif tok == "--output" and i + 1 < len(tokens):
                opts["output"] = tokens[i + 1]; i += 2
            elif tok == "--so" and i + 1 < len(tokens):
                opts["so"] = tokens[i + 1]; i += 2
            elif tok == "--so-base" and i + 1 < len(tokens):
                opts["so_base"] = int(tokens[i + 1], 16); opts["so_base_explicit"] = True; i += 2
            elif tok == "--so-size" and i + 1 < len(tokens):
                opts["so_size"] = int(tokens[i + 1], 16); i += 2
            elif tok == "--steps" and i + 1 < len(tokens):
                opts["steps"] = int(tokens[i + 1]); i += 2
            elif tok == "--thread" and i + 1 < len(tokens):
                opts["thread"] = int(tokens[i + 1]); i += 2
            elif tok == "--trace-id" and i + 1 < len(tokens):
                opts["trace_id"] = int(tokens[i + 1]); i += 2
            else:
                gdb.write(f"[sotrace] Unknown option: {tok}\n"); i += 1
        return opts

    @staticmethod
    def _resolve_so(opts: dict):
        if opts.get("so_base_explicit"):
            base = opts["so_base"]
            size = opts.get("so_size", 0x10000000)
            return base, size
        if opts.get("so"):
            base, size = find_so_base(gdb, opts["so"])
            if size == 0:
                size = 0x10000000  # 256 MiB fallback
            return base, size
        return 0, 0x10000000


# Register the command when this file is sourced
SoTraceCommand()
gdb.write("[sotrace] Loaded — use 'sotrace-trace --help' to see options.\n")
gdb.write("[sotrace] Example: sotrace-trace --server http://192.168.1.83:3000 "
          "--so libfoo.so --steps 5000\n")
