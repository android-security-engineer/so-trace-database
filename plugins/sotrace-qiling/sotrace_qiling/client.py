import requests


class SoTraceClient:
    """HTTP client for sotrace-server."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})

    def import_trace(self, envelope: dict) -> int:
        """POST envelope to /api/v1/traces/import. Returns trace_id."""
        resp = self.session.post(
            f"{self.server_url}/api/v1/traces/import",
            json=envelope,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        returned_id = data.get('trace_id', envelope.get('trace_id', 0))
        return returned_id if returned_id else envelope.get('trace_id', 0)

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        """GET /api/v1/traces/{id}/analyze/threads/{endpoint}."""
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        resp = self.session.get(url, timeout=60)
        resp.raise_for_status()
        return resp.json()
