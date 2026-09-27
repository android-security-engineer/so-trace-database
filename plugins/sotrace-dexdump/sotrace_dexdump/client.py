"""HTTP client for uploading traces to sotrace-server (stdlib only — no requests)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict


class SoTraceClient:
    """Thin HTTP client that speaks to the sotrace-server REST API."""

    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")

    def import_trace(self, envelope: Dict[str, Any]) -> int:
        """POST /api/v1/traces/import and return the assigned trace_id.

        Args:
            envelope: Import payload built by :class:`DexdumpMapper`.

        Returns:
            The ``trace_id`` reported by the server, or 0 on ambiguity.

        Raises:
            RuntimeError: on HTTP error, with status code and body included.
        """
        data = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            self.server_url + "/api/v1/traces/import",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read())
            return int(body.get("trace_id", envelope.get("trace_id", 0)))
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"import_trace HTTP {exc.code}: {raw}") from exc

    def get_analysis(self, trace_id: int, endpoint: str) -> Dict[str, Any]:
        """GET /api/v1/traces/:trace_id/analyze/threads/:endpoint.

        Args:
            trace_id: Trace to analyze.
            endpoint: Analysis type, e.g. ``"races"``, ``"deadlock"``,
                      ``"jni_boundary"``, ``"scheduling"``.

        Returns:
            Parsed JSON response body.

        Raises:
            RuntimeError: on HTTP error.
        """
        url = (
            f"{self.server_url}/api/v1/traces/{trace_id}"
            f"/analyze/threads/{endpoint}"
        )
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"get_analysis HTTP {exc.code}: {raw}") from exc
