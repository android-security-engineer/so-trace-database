"""HTTP client for sotrace-server."""

import json
import urllib.request
import urllib.error


class SoTraceClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')

    def import_trace(self, envelope: dict) -> int:
        data = json.dumps(envelope).encode('utf-8')
        req = urllib.request.Request(
            f"{self.server_url}/api/v1/traces/import",
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        assigned = body.get('trace_id', envelope.get('trace_id', 0))
        return assigned if assigned else envelope.get('trace_id', 0)

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
