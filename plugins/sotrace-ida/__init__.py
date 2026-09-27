"""
IDA Pro plugin entry point.

Install:
  Copy this entire directory (sotrace-ida/) to:
    $IDA_HOME/plugins/sotrace_ida/
  or:
    $HOME/.idapro/plugins/sotrace_ida/

  Then restart IDA Pro.

Usage (GUI):
  Press Ctrl+Shift+T   — or use Edit → Plugins → Upload to sotrace-server
"""
import sys
import os

# Ensure our package is importable when loaded from IDA's plugin dir.
sys.path.insert(0, os.path.dirname(__file__))

try:
    from sotrace_ida.plugin import PLUGIN_ENTRY, SoTracePlugin  # noqa: F401
except ImportError:
    pass


def PLUGIN_ENTRY():  # noqa: N802 — IDA requires this exact name
    from sotrace_ida.plugin import SoTracePlugin
    return SoTracePlugin()
