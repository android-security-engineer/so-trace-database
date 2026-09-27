#!/usr/bin/env python3
"""
Headless Ghidra analysis via PyGhidra (Python 3 + Jpype).

Install:
    pip install pyghidra

Usage:
    python sotrace-ghidra.py --ghidra-home /opt/ghidra \
        --server http://192.168.1.83:3000 libfoo.so

    python sotrace-ghidra.py --ghidra-home /opt/ghidra \
        --output trace.jsonl libfoo.so
"""
import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "sotrace_ghidra"))
from client import SoTraceClient  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a binary with Ghidra (headless) and upload to sotrace-server"
    )
    parser.add_argument("binary", help="Path to the SO / binary to analyze")
    parser.add_argument("--ghidra-home", required=True, help="Ghidra installation directory")
    parser.add_argument("--server", default="", help="sotrace-server base URL")
    parser.add_argument("--output", default="", help="JSONL output file path")
    parser.add_argument(
        "--project-dir", default="/tmp/sotrace_ghidra_proj",
        help="Ghidra project directory (created if absent)"
    )
    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("Provide --server, --output, or both")

    try:
        import pyghidra  # type: ignore
    except ImportError:
        print("Error: PyGhidra not installed.  Run: pip install pyghidra")
        sys.exit(1)

    print(f"[sotrace] Starting Ghidra JVM from {args.ghidra_home} …")
    pyghidra.start(args.ghidra_home)

    os.makedirs(args.project_dir, exist_ok=True)

    print(f"[sotrace] Opening {args.binary} …")
    with pyghidra.open_program(
        args.binary,
        project_location=args.project_dir,
        project_name="sotrace_analysis",
        analyze=True,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        base = program.getImageBase().getOffset()

        instructions = []
        calls = []
        seq = 0

        func_iter = program.getListing().getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            try:
                insn_iter = program.getListing().getInstructions(func.getBody(), True)
                while insn_iter.hasNext():
                    insn = insn_iter.next()
                    addr   = insn.getAddress().getOffset()
                    offset = addr - base
                    ft     = insn.getFlowType()

                    is_br   = bool(ft.isBranch() or ft.isCall() or ft.isTerminal())
                    is_call = bool(ft.isCall())

                    seq += 1
                    instructions.append({
                        "seq": seq, "thread_id": 1,
                        "address": offset,
                        "is_branch": is_br, "branch_taken": False,
                    })

                    if is_call:
                        for flow in insn.getFlows():
                            seq += 1
                            calls.append({
                                "seq": seq, "thread_id": 1,
                                "caller_address": offset,
                                "callee_address": flow.getOffset() - base,
                                "depth": 0, "event_type": "Call",
                            })
            except Exception:
                pass  # skip broken functions

    print(f"[sotrace] Collected {len(instructions)} instructions, {len(calls)} calls")

    envelope = {
        "trace_id": 0,
        "threads": [{
            "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
            "stack_base": 0, "stack_size": 0, "tls_addr": 0,
            "is_jni_attached": False,
        }],
        "instructions": instructions,
        "calls": calls,
        "memory_writes": [],
        "memory_reads": [],
        "sync_events": [],
    }

    if args.server:
        client = SoTraceClient(args.server)
        trace_id = client.import_trace(envelope)
        print(f"[sotrace] trace_id={trace_id}")
        print(f"[sotrace] Races: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope) + "\n")
        print(f"[sotrace] Saved to {args.output}")


if __name__ == "__main__":
    main()
