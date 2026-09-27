"""
client.py — Minimal HTTP client for sotrace-server.

Uses only the Python standard library (urllib.request); no third-party
dependencies are required.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class SoTraceClient:
    """
    Thin wrapper around the sotrace-server HTTP API.

    Parameters
    ----------
    server_url:
        Base URL of sotrace-server, e.g. ``http://192.168.1.83:3000``.
    """

    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")

    # ------------------------------------------------------------------
    # Trace import
    # ------------------------------------------------------------------

    def import_trace(self, envelope: dict) -> int:
        """
        POST *envelope* to ``/api/v1/traces/import``.

        Returns the trace_id assigned by the server (or the one in the
        envelope if the server echoes it back without change).

        Raises
        ------
        IOError
            On any HTTP error or connection failure.
        """
        url = f"{self.server_url}/api/v1/traces/import"
        body = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                assigned = data.get("trace_id", envelope.get("trace_id", 0))
                return int(assigned) if assigned else 0
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_text = exc.read().decode(errors="replace")
            except Exception:
                pass
            raise IOError(
                f"sotrace import failed: HTTP {exc.code} — {body_text}"
            ) from exc
        except urllib.error.URLError as exc:
            raise IOError(f"sotrace import failed: {exc.reason}") from exc

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def get_thread_analysis(self, trace_id: int) -> dict:
        """Fetch the full thread analysis for *trace_id*."""
        return self._get(f"/api/v1/traces/{trace_id}/analyze/threads")

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            self.server_url + path,
            headers={"Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise IOError(
                f"sotrace GET {path} failed: HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise IOError(f"sotrace GET {path} failed: {exc.reason}") from exc
