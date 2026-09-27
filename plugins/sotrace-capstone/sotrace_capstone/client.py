"""HTTP client for sotrace-server using stdlib urllib only (no extra deps)."""

from __future__ import annotations

import json
import urllib.request
import urllib.error


class SoTraceClient:
    """Minimal HTTP client for the sotrace-server import API."""

    def __init__(self, server_url: str):
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: dict) -> int:
        """POST /api/v1/traces/import and return the assigned trace_id."""
        url = self.server_url + "/api/v1/traces/import"
        body = json.dumps(envelope).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                assigned = data.get("trace_id", envelope["trace_id"])
                return int(assigned) if assigned else int(envelope["trace_id"])
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            raise RuntimeError(
                f"sotrace import failed: HTTP {e.code} — {body_text}"
            ) from e

    def get_analysis(self, trace_id: int, endpoint: str) -> dict:
        """GET /api/v1/traces/<id>/analyze/threads/<endpoint>."""
        url = self.server_url + f"/api/v1/traces/{trace_id}/analyze/threads/{endpoint}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"sotrace analysis failed: HTTP {e.code}"
            ) from e
