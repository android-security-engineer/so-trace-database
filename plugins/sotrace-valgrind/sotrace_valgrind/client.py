"""HTTP client for sotrace-server — stdlib only (urllib.request)."""

import json
import urllib.request
import urllib.error


class SoTraceClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: dict) -> int:
        """POST /api/v1/traces/import — returns assigned trace_id."""
        data = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            self.server_url + "/api/v1/traces/import",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        return body.get("trace_id", envelope.get("trace_id", 0))

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        """GET /api/v1/traces/:id/analyze/threads/:endpoint"""
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        with urllib.request.urlopen(url, timeout=60) as resp:
            return json.loads(resp.read())
