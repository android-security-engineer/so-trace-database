"""Parse JSONL output from sotrace_client.c and upload to sotrace-server."""

import json
import urllib.request
import urllib.error


def parse_jsonl(path: str) -> dict:
    """
    Parse the JSONL file written by sotrace_client.c into a sotrace import envelope.

    Each line is one of:
      {"type":"instruction", "seq":N, "thread_id":1, "address":OFFSET, "is_branch":bool, "branch_taken":bool}
      {"type":"mem_read",    "step":N, "thread_id":1, "address":ADDR, "size":N}
      {"type":"mem_write",   "step":N, "thread_id":1, "address":ADDR, "data":[u8,...]}
    """
    instructions   = []
    memory_reads   = []
    memory_writes  = []

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            t = obj.get("type", "")
            tid = obj.get("thread_id", 1)

            if t == "instruction":
                instructions.append({
                    "seq":          obj["seq"],
                    "thread_id":    tid,
                    "address":      obj["address"],
                    "is_branch":    bool(obj.get("is_branch", False)),
                    "branch_taken": bool(obj.get("branch_taken", False)),
                })
            elif t == "mem_read":
                memory_reads.append({
                    "step":      obj["step"],
                    "thread_id": tid,
                    "address":   obj["address"],
                    "size":      int(obj.get("size", 4)),
                })
            elif t == "mem_write":
                memory_writes.append({
                    "step":      obj["step"],
                    "thread_id": tid,
                    "address":   obj["address"],
                    "data":      list(obj.get("data", [])),
                })

    return {
        "trace_id": 0,
        "threads": [
            {
                "thread_id": 1, "create_step": 0, "parent_thread_id": 0,
                "stack_base": 0, "stack_size": 0, "tls_addr": 0,
                "is_jni_attached": False,
            }
        ],
        "instructions":  instructions,
        "memory_reads":  memory_reads,
        "memory_writes": memory_writes,
        "sync_events":   [],
        "calls":         [],
    }


class SoTraceClient:
    """Minimal urllib-based HTTP client for sotrace-server (no extra deps)."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: dict) -> int:
        data = json.dumps(envelope).encode()
        req  = urllib.request.Request(
            self.server_url + "/api/v1/traces/import",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = json.loads(resp.read())
                return body.get("trace_id", envelope["trace_id"])
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"sotrace import failed: HTTP {e.code} — {e.read().decode()}") from e

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"sotrace analysis failed: HTTP {e.code}") from e
