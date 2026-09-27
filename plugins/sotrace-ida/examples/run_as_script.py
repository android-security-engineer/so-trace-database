"""
sotrace IDA script — run via File -> Script File -> run_as_script.py
OR copy sotrace_ida.py + sotrace_ida/ to <IDA>/plugins/ for persistent plugin.

Three usage patterns shown below.
"""

# ── Pattern 1: upload all functions ─────────────────────────────────────────
# Open libfoo.so in IDA, wait for auto-analysis, then:
#   File -> Script File -> run_as_script.py
# A dialog asks for the sotrace-server URL.  On success an info box shows
# trace_id and a link to the race-condition analysis.

# ── Pattern 2: analyse only the current function ────────────────────────────
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import idaapi
import idc
from sotrace_ida.analyzer import IDAAnalyzer
from sotrace_ida.client import SoTraceClient

SOTRACE_URL = "http://192.168.1.83:3000"

analyzer = IDAAnalyzer()

# Analyse only the function containing the cursor
func_ea = idc.here()
envelope = analyzer.analyze_function(func_ea)

client = SoTraceClient(SOTRACE_URL)
trace_id = client.import_trace(envelope)
print("[sotrace] trace_id={} instructions={} calls={}".format(
    trace_id,
    len(envelope["instructions"]),
    len(envelope["calls"]),
))

# Fetch race-condition analysis
result = client.get_analysis(trace_id, "races")
print("[sotrace] races:", result)

# ── Pattern 3: save to file (no server) ─────────────────────────────────────
import json

envelope_all = analyzer.analyze_all()
with open("/tmp/sotrace_ida_trace.jsonl", "w") as fh:
    fh.write(json.dumps(envelope_all) + "\n")
print("[sotrace] saved {} instructions to /tmp/sotrace_ida_trace.jsonl".format(
    len(envelope_all["instructions"])))
# Import later with: sotrace-cli trace-import --file /tmp/sotrace_ida_trace.jsonl
