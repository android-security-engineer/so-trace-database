#!/usr/bin/env python3
"""
sotrace-frida.py — Frida host script for sotrace-database.

Injects sotrace-agent.js into a target process, collects batched trace events,
and ships them to sotrace-server in real time (or saves to a JSONL file).

Usage examples:

  # Spawn an app and send traces to sotrace-server:
  python sotrace-frida.py -U -f com.example.app \\
      --server http://192.168.1.83:3000 \\
      --so-base 0x71000000

  # Attach to a running process and save to file:
  python sotrace-frida.py -U com.example.app \\
      --output trace.jsonl

  # Spawn with a custom so name (auto-resolves base address):
  python sotrace-frida.py -U -f com.example.app \\
      --server http://192.168.1.83:3000 \\
      --so-name libtarget.so

  # Full trace (instruction-level, expensive):
  python sotrace-frida.py -U -f com.example.app \\
      --server http://192.168.1.83:3000 \\
      --enable-instructions
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import frida
import requests

logger = logging.getLogger("sotrace-frida")


# ---------------------------------------------------------------------------
# Trace event accumulator & uploader
# ---------------------------------------------------------------------------

class TraceUploader:
    """
    Accumulates batches received from the agent and posts them to sotrace-server.
    When --output is used, appends raw payloads to a JSONL file instead.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        output_path: Optional[str] = None,
        trace_name: str = "frida-trace",
    ):
        self._server_url = server_url.rstrip("/") if server_url else None
        self._output_path = output_path
        self._trace_name = trace_name
        self._trace_id: int = 0
        self._lock = threading.Lock()
        self._session: Optional[requests.Session] = None
        self._out_file = None

        if self._server_url:
            self._session = requests.Session()
            self._session.headers.update({"Content-Type": "application/json"})
        if self._output_path:
            self._out_file = open(self._output_path, "a", encoding="utf-8")  # noqa: SIM115

    # -------- public --------

    @property
    def trace_id(self) -> int:
        return self._trace_id

    def ingest(self, payload: dict) -> None:
        """Process one sotrace:batch payload from the agent."""
        with self._lock:
            if self._output_path:
                self._write_jsonl(payload)
            if self._server_url:
                self._upload(payload)

    def close(self) -> None:
        if self._out_file:
            self._out_file.close()
        if self._session:
            self._session.close()

    # -------- internal --------

    def _write_jsonl(self, payload: dict) -> None:
        try:
            self._out_file.write(json.dumps(payload) + "\n")
            self._out_file.flush()
        except Exception as exc:
            logger.warning("JSONL write error: %s", exc)

    def _upload(self, payload: dict) -> None:
        """Convert agent batch payload to sotrace import format and POST."""
        envelope = self._build_envelope(payload)
        url = f"{self._server_url}/api/v1/traces/import"
        try:
            resp = self._session.post(url, json=envelope, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            returned_id = data.get("trace_id", 0)
            if returned_id and self._trace_id == 0:
                self._trace_id = returned_id
                logger.info("sotrace-server assigned trace_id=%d", self._trace_id)
        except requests.RequestException as exc:
            logger.error("Upload failed: %s", exc)

    def _build_envelope(self, payload: dict) -> dict:
        """Convert agent batch format to sotrace import envelope format."""
        return {
            "trace_id": self._trace_id,  # 0 = server auto-assigns on first call
            "name": self._trace_name,
            "threads": [],              # threads auto-created from thread IDs below
            "instructions": [
                {
                    "step":         ev.get("seq", 0),
                    "tid":          ev.get("tid", 0),
                    "address":      ev.get("address", 0),
                    "is_branch":    ev.get("is_branch", False),
                    "branch_taken": ev.get("branch_taken", False),
                }
                for ev in payload.get("instructions", [])
            ],
            "memory_writes": [
                {
                    "step":    ev.get("step", 0),
                    "tid":     ev.get("tid", 0),
                    "address": ev.get("address", 0),
                    "data":    ev.get("data", []),
                }
                for ev in payload.get("memoryWrites", [])
            ],
            "memory_reads": [
                {
                    "step":    ev.get("step", 0),
                    "tid":     ev.get("tid", 0),
                    "address": ev.get("address", 0),
                    "size":    ev.get("size", 0),
                }
                for ev in payload.get("memoryReads", [])
            ],
            "sync_events": [
                {
                    "step":             ev.get("step", 0),
                    "tid":              ev.get("tid", 0),
                    "sync_type":        ev.get("sync_type", ""),
                    "sync_object_addr": ev.get("sync_object_addr", 0),
                    "result":           ev.get("result", "Success"),
                }
                for ev in payload.get("syncEvents", [])
            ],
            "context_switches":  [],
            "state_changes":     [],
            "jni_calls":         [],
            "calls": [
                {
                    "step":       ev.get("seq", 0),
                    "tid":        ev.get("tid", 0),
                    "caller":     ev.get("caller", 0),
                    "callee":     ev.get("callee", 0),
                    "depth":      ev.get("depth", 0),
                    "event_type": ev.get("event_type", "Call"),
                }
                for ev in payload.get("calls", [])
            ],
        }


# ---------------------------------------------------------------------------
# Frida session manager
# ---------------------------------------------------------------------------

AGENT_JS = Path(__file__).parent / "sotrace-agent.js"


class SoTraceSession:
    def __init__(
        self,
        args: argparse.Namespace,
        uploader: TraceUploader,
    ):
        self._args = args
        self._uploader = uploader
        self._frida_session: Optional[frida.core.Session] = None
        self._script: Optional[frida.core.Script] = None
        self._done = threading.Event()

    def run(self) -> None:
        device = self._get_device()

        if self._args.spawn:
            logger.info("Spawning %s …", self._args.spawn)
            pid = device.spawn([self._args.spawn] + (self._args.spawn_args or []))
            self._frida_session = device.attach(pid)
        elif self._args.target:
            logger.info("Attaching to %s …", self._args.target)
            self._frida_session = device.attach(self._args.target)
        else:
            raise RuntimeError("Specify -f/--spawn or a process name/PID")

        self._script = self._frida_session.create_script(AGENT_JS.read_text())
        self._script.on("message", self._on_message)
        self._script.load()

        # Configure the agent
        agent_cfg = self._build_agent_config(device)
        self._script.exports_sync.configure(agent_cfg)
        logger.info("Agent configured: %s", agent_cfg)

        if self._args.spawn:
            device.resume(self._frida_session.pid)
            logger.info("Process resumed (pid=%d)", self._frida_session.pid)

        logger.info("Collecting traces. Press Ctrl-C to stop.")
        try:
            self._done.wait()
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

    # -------- signal handling --------

    def stop(self) -> None:
        self._done.set()

    # -------- internal --------

    def _get_device(self) -> frida.core.Device:
        args = self._args
        if args.usb:
            return frida.get_usb_device(timeout=10)
        if args.remote:
            return frida.get_remote_device()
        if args.device:
            return frida.get_device(args.device, timeout=10)
        return frida.get_local_device()

    def _build_agent_config(self, device: frida.core.Device) -> dict:
        args = self._args
        cfg: dict = {
            "enableInstructions": args.enable_instructions,
            "enableMemory":       not args.no_memory,
            "enableSync":         not args.no_sync,
            "enableCalls":        not args.no_calls,
            "batchSize":          args.batch_size,
            "flushIntervalMs":    args.flush_interval,
        }

        # Resolve SO base address
        if args.so_base:
            # User-supplied hex or decimal address
            base = int(args.so_base, 16) if args.so_base.startswith("0x") else int(args.so_base)
            cfg["soBase"] = base
        elif args.so_name:
            # Auto-resolve from loaded modules
            base = self._resolve_so_base(args.so_name)
            if base:
                cfg["soBase"] = base
                logger.info("Resolved %s base: 0x%x", args.so_name, base)
            else:
                logger.warning("Could not find module '%s' — soBase not set", args.so_name)

        return cfg

    def _resolve_so_base(self, name: str) -> Optional[int]:
        """Ask the agent for loaded module list and find the SO by name."""
        try:
            modules = self._script.exports_sync.list_modules()
            for m in modules:
                if name in m.get("name", "") or name in m.get("path", ""):
                    base_str = m.get("base", "0x0")
                    return int(base_str, 16)
        except Exception as exc:
            logger.debug("list_modules failed: %s", exc)
        return None

    def _on_message(self, message: dict, data) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict) and payload.get("type") == "sotrace:batch":
                self._uploader.ingest(payload)
                # Update the agent's traceId so incremental uploads link batches
                tid = self._uploader.trace_id
                if tid and self._script:
                    try:
                        self._script.exports_sync.set_trace_id(tid)
                    except Exception:
                        pass
        elif message.get("type") == "error":
            desc = message.get("description", "unknown error")
            stack = message.get("stack", "")
            logger.error("[agent] %s\n%s", desc, stack)

    def _shutdown(self) -> None:
        if self._script:
            try:
                self._script.exports_sync.flush()
            except Exception:
                pass
            try:
                self._script.unload()
            except Exception:
                pass
        if self._frida_session:
            try:
                self._frida_session.detach()
            except Exception:
                pass
        self._uploader.close()
        logger.info("Session closed. trace_id=%d", self._uploader.trace_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sotrace-frida",
        description="Frida host script for sotrace-database — collects trace events and uploads to sotrace-server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Frida device selection (mirrors frida-tools conventions) ---
    dev = p.add_mutually_exclusive_group()
    dev.add_argument("-U", "--usb",    action="store_true", help="Use USB device")
    dev.add_argument("-R", "--remote", action="store_true", help="Use remote device")
    dev.add_argument("-D", "--device", metavar="ID",        help="Use device with the given ID")

    # --- Target ---
    p.add_argument("-f", "--spawn", metavar="APP",   help="Spawn this app / binary")
    p.add_argument("target",        nargs="?",        help="Process name or PID to attach to")
    p.add_argument("--spawn-args",  nargs="*", default=[], metavar="ARG", help="Extra args for spawned process")

    # --- sotrace output ---
    out = p.add_mutually_exclusive_group()
    out.add_argument("--server",  metavar="URL",  help="sotrace-server URL (e.g. http://192.168.1.83:3000)")
    out.add_argument("--output",  metavar="FILE", help="Save raw trace batches to JSONL file")

    p.add_argument("--trace-name", default="frida-trace", metavar="NAME",
                   help="Human-readable name for the trace (default: frida-trace)")

    # --- SO address ---
    so = p.add_mutually_exclusive_group()
    so.add_argument("--so-base", metavar="ADDR",
                    help="SO base address in hex (e.g. 0x71000000)")
    so.add_argument("--so-name", metavar="NAME",
                    help="SO name; base address is auto-resolved from the target's module list")

    # --- Agent tuning ---
    p.add_argument("--enable-instructions", action="store_true",
                   help="Enable exec-level instruction tracing (very verbose, high overhead)")
    p.add_argument("--no-memory", action="store_true",
                   help="Disable memory write hooks")
    p.add_argument("--no-sync", action="store_true",
                   help="Disable pthread sync event hooks")
    p.add_argument("--no-calls", action="store_true",
                   help="Disable call/return tracing via Stalker")
    p.add_argument("--batch-size", type=int, default=500, metavar="N",
                   help="Agent batch size (default: 500)")
    p.add_argument("--flush-interval", type=int, default=500, metavar="MS",
                   help="Agent flush interval ms (default: 500)")

    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    if not AGENT_JS.exists():
        logger.error("Agent script not found: %s", AGENT_JS)
        sys.exit(1)

    if not args.server and not args.output:
        logger.error("Specify --server <URL> or --output <file>")
        parser.print_help()
        sys.exit(1)

    if not args.spawn and not args.target:
        logger.error("Specify -f <app> to spawn or a process name/PID to attach")
        parser.print_help()
        sys.exit(1)

    uploader = TraceUploader(
        server_url=args.server,
        output_path=args.output,
        trace_name=args.trace_name,
    )
    session = SoTraceSession(args, uploader)

    def _sighandler(sig, frame):
        logger.info("Interrupted — flushing and exiting …")
        session.stop()

    signal.signal(signal.SIGINT,  _sighandler)
    signal.signal(signal.SIGTERM, _sighandler)

    session.run()


if __name__ == "__main__":
    main()
