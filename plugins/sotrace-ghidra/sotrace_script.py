# Ghidra Python Script (Jython 2.7 compatible)
# Place in ~/ghidra_scripts/ and run from Script Manager
#@author sotrace-database
#@category Analysis
#@menupath Analysis.sotrace.Upload (Python)
#@toolbar

import json
import urllib2  # Jython / Python 2

SO_BASE = currentProgram.getImageBase().getOffset()


def get_offset(addr):
    return addr.getOffset() - SO_BASE


def is_branch_insn(insn):
    ft = insn.getFlowType()
    return ft.isBranch() or ft.isCall() or ft.isTerminal()


def run():
    server_url = askString(
        "sotrace-server URL",
        "URL (empty = save to file):",
        "http://localhost:3000",
    )

    out_file = None
    if not server_url or not server_url.strip():
        f = askFile("Save trace as JSONL", "Save")
        if f is None:
            return
        out_file = f.getAbsolutePath()
        server_url = None

    instructions = []
    calls = []
    seq = [0]

    monitor.setMessage("Collecting instructions...")
    func_iter = currentProgram.getListing().getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        insn_iter = currentProgram.getListing().getInstructions(func.getBody(), True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            offset = get_offset(insn.getAddress())
            branch = is_branch_insn(insn)
            call = insn.getFlowType().isCall()

            seq[0] += 1
            instructions.append({
                "seq": seq[0],
                "thread_id": 1,
                "address": offset,
                "is_branch": bool(branch),
                "branch_taken": False,
            })

            if call:
                for flow in insn.getFlows():
                    seq[0] += 1
                    calls.append({
                        "seq": seq[0],
                        "thread_id": 1,
                        "caller_address": offset,
                        "callee_address": get_offset(flow),
                        "depth": 0,
                        "event_type": "Call",
                    })

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

    body = json.dumps(envelope)

    if server_url:
        req = urllib2.Request(
            server_url.rstrip("/") + "/api/v1/traces/import",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        resp_body = urllib2.urlopen(req, timeout=30).read()
        resp = json.loads(resp_body)
        trace_id = resp.get("trace_id", 0)
        popup("sotrace upload done!\ntrace_id=" + str(trace_id)
              + "\ninstructions=" + str(len(instructions))
              + "\ncalls=" + str(len(calls)))

    if out_file:
        with open(out_file, "w") as fh:
            fh.write(body + "\n")
        popup("Saved to " + out_file)


run()
