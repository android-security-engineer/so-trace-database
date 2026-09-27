#!/usr/bin/env python3
"""
IDA Pro headless / batch analysis via idat64.

Usage:
    python headless_analysis.py --idat /opt/ida/idat64 \
        --server http://192.168.1.83:3000 \
        /path/to/libnative.so

The script writes a temporary IDAPython batch script, runs idat64 with -A -S,
and uploads the resulting JSONL to sotrace-server.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.request


BATCH_SCRIPT = """\
import idautils, idaapi, json, sys

base = idaapi.get_imagebase()
insn_obj = idaapi.insn_t()
instructions = []
calls = []
seq = 0
CF_CALL = idaapi.CF_CALL
CF_JUMP = idaapi.CF_JUMP
CF_STOP = idaapi.CF_STOP

for func_ea in idautils.Functions():
    for ea in idautils.FuncItems(func_ea):
        if idaapi.decode_insn(insn_obj, ea) == 0:
            continue
        feat = insn_obj.get_canon_feature()
        is_call = bool(feat & CF_CALL)
        is_br   = is_call or bool(feat & CF_JUMP) or bool(feat & CF_STOP)
        offset  = ea - base
        seq += 1
        instructions.append({"seq": seq, "thread_id": 1, "address": offset,
                              "is_branch": is_br, "branch_taken": False})
        if is_call:
            for tgt in idautils.CodeRefsFrom(ea, flow=False):
                seq += 1
                calls.append({"seq": seq, "thread_id": 1,
                               "caller_address": offset,
                               "callee_address": tgt - base,
                               "depth": 0, "event_type": "Call"})

envelope = {
    "trace_id": 0,
    "threads": [{"thread_id":1,"create_step":0,"parent_thread_id":0,
                  "stack_base":0,"stack_size":0,"tls_addr":0,"is_jni_attached":False}],
    "instructions": instructions,
    "calls": calls,
    "memory_writes": [], "memory_reads": [], "sync_events": [],
}

out_path = idc.ARGV[1] if len(idc.ARGV) > 1 else "/tmp/sotrace_ida.jsonl"
with open(out_path, "w") as fh:
    fh.write(json.dumps(envelope) + "\\n")
print(f"[sotrace] written {len(instructions)} insns, {len(calls)} calls → {out_path}")
idc.qexit(0)
"""


def upload(envelope: dict, server_url: str) -> int:
    data = json.dumps(envelope).encode()
    req = urllib.request.Request(
        server_url.rstrip("/") + "/api/v1/traces/import",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read())
    return int(body.get("trace_id", 0))


def main() -> None:
    parser = argparse.ArgumentParser(description="IDA headless → sotrace upload")
    parser.add_argument("binary", help="SO / binary to analyze")
    parser.add_argument("--idat", default="idat64", help="Path to idat64 executable")
    parser.add_argument("--server", default="", help="sotrace-server URL")
    parser.add_argument("--output", default="", help="JSONL output path")
    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("Provide --server, --output, or both")

    with tempfile.TemporaryDirectory() as tmpdir:
        script_path = os.path.join(tmpdir, "sotrace_batch.py")
        out_jsonl   = os.path.join(tmpdir, "trace.jsonl")

        with open(script_path, "w") as fh:
            fh.write(BATCH_SCRIPT)

        cmd = [args.idat, "-A", f'-S"{script_path}" "{out_jsonl}"', args.binary]
        print(f"[sotrace] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            sys.exit(result.returncode)

        with open(out_jsonl, "r") as fh:
            envelope = json.loads(fh.readline())

    n_insn = len(envelope.get("instructions", []))
    n_call = len(envelope.get("calls", []))
    print(f"[sotrace] Collected {n_insn} instructions, {n_call} calls")

    if args.server:
        trace_id = upload(envelope, args.server)
        print(f"[sotrace] trace_id={trace_id}")
        print(f"[sotrace] Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(json.dumps(envelope) + "\n")
        print(f"[sotrace] Saved to {args.output}")


if __name__ == "__main__":
    main()
