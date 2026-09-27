"""
Headless Binary Ninja analysis — runs without the UI.

Requirements:
  - Binary Ninja commercial license (headless API)
  - `pip install binaryninja` or set PYTHONPATH to your Binja installation

Usage:
  python headless_analysis.py libcrackme.so http://192.168.1.83:3000
"""

import sys
import os

# Allow running from the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import binaryninja as bn
from sotrace_binja.analyzer import SoTraceAnalyzer
from sotrace_binja.client import SoTraceClient


def main():
    so_path = sys.argv[1] if len(sys.argv) > 1 else "libfoo.so"
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:3000"

    print(f"[sotrace] Opening {so_path} ...")
    bv = bn.load(so_path)
    if bv is None:
        print(f"[sotrace] ERROR: could not open {so_path}")
        sys.exit(1)

    bv.update_analysis_and_wait()
    print(f"[sotrace] Analysis complete — {len(list(bv.functions))} functions found")

    analyzer = SoTraceAnalyzer(bv)
    envelope = analyzer.analyze_static()

    print(
        f"[sotrace] Collected {len(envelope['instructions'])} instructions, "
        f"{len(envelope['calls'])} calls"
    )

    client = SoTraceClient(server_url)
    trace_id = client.import_trace(envelope)
    print(f"[sotrace] trace_id = {trace_id}")
    print(f"[sotrace] Races: {server_url}/traces/{trace_id}/analyze/threads/races")

    # Fetch race analysis
    try:
        races = client.get_analysis(trace_id, "races")
        print(f"[sotrace] Race conditions found: {len(races.get('races', []))}")
    except Exception as e:
        print(f"[sotrace] Could not fetch race analysis: {e}")


if __name__ == "__main__":
    main()
