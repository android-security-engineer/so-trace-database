"""Binary Ninja plugin for sotrace-database.

Install by symlinking or copying this directory to:
  Linux/macOS: ~/.binaryninja/plugins/sotrace-binja/
  Windows:     %APPDATA%\\Binary Ninja\\plugins\\sotrace-binja\\

Usage:
  Tools menu → sotrace → Upload All Functions
  Right-click a function → sotrace → Upload This Function
  Tools menu → sotrace → Save Trace to File

Headless (no UI):
  from sotrace_binja.analyzer import SoTraceAnalyzer
  from sotrace_binja.client import SoTraceClient
"""

try:
    import binaryninja as bn
    from sotrace_binja.commands import register_commands
    register_commands()
except ImportError:
    # Running outside Binary Ninja (e.g. import check) — skip silently
    pass
