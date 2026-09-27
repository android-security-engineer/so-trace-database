"""
client.py — minimal urllib-based HTTP client for sotrace-server.

No third-party dependencies; uses only stdlib urllib.request.
"""

import json
import urllib.error
import urllib.request


class SoTraceClient:
    """Upload traces and retrieve analysis results from a sotrace-server instance."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: dict) -> int:
        """
        POST the import envelope to /api/v1/traces/import.

        Returns the trace_id assigned by the server.
        Raises RuntimeError on HTTP error.
        """
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
                return int(body.get("trace_id", envelope.get("trace_id", 0)))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode(errors="replace")
            except Exception:
                pass
            raise RuntimeError(
                f"sotrace import failed: HTTP {exc.code} — {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"sotrace import failed: connection error — {exc.reason}"
            ) from exc

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        """
        GET /api/v1/traces/<trace_id>/analyze/threads/<endpoint>.

        Common endpoint values: "races", "deadlocks", "contention", "summary".
        Returns the parsed JSON response dict.
        Raises RuntimeError on HTTP error.
        """
        url = (
            f"{self.server_url}/api/v1/traces/{trace_id}"
            f"/analyze/threads/{endpoint}"
        )
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"sotrace analysis failed: HTTP {exc.code} ({endpoint})"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"sotrace analysis failed: connection error — {exc.reason}"
            ) from exc
