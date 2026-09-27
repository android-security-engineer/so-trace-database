"""sotrace_strace — parse strace/ltrace output and upload to sotrace-server."""

from .parser import StraceParser, ParsedEvent
from .client import SoTraceClient

__all__ = ["StraceParser", "ParsedEvent", "SoTraceClient"]
