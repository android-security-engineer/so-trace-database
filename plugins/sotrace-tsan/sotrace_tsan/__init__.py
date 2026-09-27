"""sotrace_tsan package — TSan report parser for sotrace-database."""
from .parser import TsanParser
from .client import SoTraceClient

__all__ = ["TsanParser", "SoTraceClient"]
