"""sotrace-gdb: GDB Python plugin for sotrace-database trace collection."""

from .batcher import EventBatcher
from .client import SoTraceClient

__all__ = ["EventBatcher", "SoTraceClient"]
__version__ = "0.1.0"
