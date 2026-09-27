"""HTTP client for sotrace-server import and analysis endpoints."""

import requests


class SoTraceClient:
    def __init__(self, server_url: str):
        self.base = server_url.rstrip('/')
        self.session = requests.Session()

    def import_trace(self, envelope: dict) -> int:
        resp = self.session.post(
            f"{self.base}/api/v1/traces/import",
            json=envelope,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        assigned = data.get('trace_id', envelope['trace_id'])
        return assigned if assigned else envelope['trace_id']

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        resp = self.session.get(
            f"{self.base}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}",
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()
