"""HTTP client using only Python stdlib — safe in LLDB's embedded Python."""

import json
import urllib.request
import urllib.error


class SoTraceClient:
    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip('/')

    def import_trace(self, envelope: dict) -> int:
        data = json.dumps(envelope).encode('utf-8')
        req = urllib.request.Request(
            self.server_url + '/api/v1/traces/import',
            data=data,
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode('utf-8'))
                returned = body.get('trace_id', envelope.get('trace_id', 0))
                return returned if returned else envelope.get('trace_id', 0)
        except urllib.error.HTTPError as e:
            raise IOError(f"sotrace import failed: HTTP {e.code} — {e.read().decode()}")

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        url = f"{self.server_url}/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            raise IOError(f"sotrace analysis failed: HTTP {e.code}")
