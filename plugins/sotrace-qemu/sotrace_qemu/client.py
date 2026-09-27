"""HTTP client for sotrace-server."""

import requests


class SoTraceClient:
    def __init__(self, server_url: str):
        self.base = server_url.rstrip('/')
        self._session = requests.Session()

    def import_trace(self, envelope: dict) -> int:
        resp = self._session.post(
            f"{self.base}/api/v1/traces/import",
            json=envelope,
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        assigned = data.get("trace_id", envelope.get("trace_id", 0))
        return assigned if assigned else envelope.get("trace_id", 0)

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        resp = self._session.get(
            f"{self.base}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}",
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()
