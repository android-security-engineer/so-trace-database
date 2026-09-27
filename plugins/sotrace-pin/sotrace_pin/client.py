"""HTTP client and JSONL parser for sotrace-pin."""

import json
import urllib.request


# ---------------------------------------------------------------------------
# JSONL parser
# ---------------------------------------------------------------------------

def parse_jsonl(path: str) -> dict:
    """
    Parse the JSONL file written by SoTracePintool and return an import envelope.

    Each line is a JSON object with a "type" field:
      instruction  → seq, thread_id, address, is_branch, branch_taken
      mem_read     → step, thread_id, address, size
      mem_write    → step, thread_id, address, size, data
      thread       → thread_id, create_step
    """
    threads:       list = []
    instructions:  list = []
    memory_reads:  list = []
    memory_writes: list = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue

            kind = obj.get("type", "")

            if kind == "thread":
                threads.append({
                    "thread_id":        int(obj.get("thread_id", 1)),
                    "create_step":      int(obj.get("create_step", 0)),
                    "parent_thread_id": 0,
                    "stack_base":       0,
                    "stack_size":       0,
                    "tls_addr":         0,
                    "is_jni_attached":  False,
                })

            elif kind == "instruction":
                instructions.append({
                    "seq":          int(obj["seq"]),
                    "thread_id":    int(obj.get("thread_id", 1)),
                    "address":      int(obj["address"]),
                    "is_branch":    bool(obj.get("is_branch", False)),
                    "branch_taken": bool(obj.get("branch_taken", False)),
                })

            elif kind == "mem_read":
                memory_reads.append({
                    "step":      int(obj["step"]),
                    "thread_id": int(obj.get("thread_id", 1)),
                    "address":   int(obj["address"]),
                    "size":      int(obj.get("size", 4)),
                })

            elif kind == "mem_write":
                memory_writes.append({
                    "step":      int(obj["step"]),
                    "thread_id": int(obj.get("thread_id", 1)),
                    "address":   int(obj["address"]),
                    "data":      list(obj.get("data", [])),
                })

    if not threads:
        threads = [{
            "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
            "stack_base": 0, "stack_size": 0, "tls_addr": 0,
            "is_jni_attached": False,
        }]

    return {
        "trace_id":      0,
        "threads":       threads,
        "instructions":  instructions,
        "memory_reads":  memory_reads,
        "memory_writes": memory_writes,
        "sync_events":   [],
        "calls":         [],
    }


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class SoTraceClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: dict) -> int:
        data = json.dumps(envelope).encode()
        req  = urllib.request.Request(
            self.server_url + "/api/v1/traces/import",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
            assigned = body.get("trace_id", envelope.get("trace_id", 0))
            return assigned if assigned else envelope.get("trace_id", 0)

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        with urllib.request.urlopen(url, timeout=60) as resp:
            return json.loads(resp.read())
