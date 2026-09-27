"""HTTP client for sotrace-server — stdlib urllib only, no extra deps."""

import json
import urllib.request
import urllib.error


class SoTraceClient:
    """Thin wrapper around the sotrace-server HTTP API."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')

    def import_trace(self, envelope: dict) -> int:
        """POST envelope to /api/v1/traces/import and return the assigned trace_id."""
        url = self.server_url + "/api/v1/traces/import"
        body = json.dumps(envelope).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                assigned = data.get("trace_id", envelope["trace_id"])
                return assigned if assigned else envelope["trace_id"]
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"sotrace import failed: HTTP {e.code} — {e.read().decode()}"
            ) from e

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        """GET /api/v1/traces/<trace_id>/analyze/threads/<endpoint>."""
        url = self.server_url + f"/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"sotrace analysis failed: HTTP {e.code}") from e
