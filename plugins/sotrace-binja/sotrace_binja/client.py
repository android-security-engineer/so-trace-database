"""HTTP client — uploads trace data to sotrace-server using stdlib urllib."""

import json
import urllib.request
import urllib.error


class SoTraceClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: dict) -> int:
        """POST envelope to /api/v1/traces/import; return assigned trace_id."""
        data = json.dumps(envelope).encode()
        req = urllib.request.Request(
            self.server_url + "/api/v1/traces/import",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read())
                assigned = body.get("trace_id", envelope.get("trace_id", 0))
                return assigned if assigned else envelope.get("trace_id", 0)
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"sotrace import failed: HTTP {e.code} — {e.read().decode()}"
            ) from e

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        """GET /api/v1/traces/{id}/analyze/threads/{endpoint}."""
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"sotrace analysis failed: HTTP {e.code} — {e.read().decode()}"
            ) from e
