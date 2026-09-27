"""
parser.py — Parse `perf script` (or compatible simpleperf) text output into Sample objects.

perf script format (one "sample" block per call-graph snapshot):

    target_binary  1234  12345.678901:   1000000 cycles:ppp:
            7f1234001234 foo+0x10 (/path/to/libfoo.so)
            7f1234001100 bar+0x5 (/path/to/libfoo.so)
                  400abc main+0x20 (/path/to/target_binary)

    target_binary  1234  12345.680000:   1000000 cycles:ppp:
            ...

The top frame is the most-recently-executing function (innermost callee).
Frames below are callers, deepest last.

Android simpleperf can produce a compatible text output via:
    simpleperf report --show-callchain -i perf.data

Both formats are parsed by the same regex.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Frame:
    """One call-graph frame inside a sample."""
    address: int          # virtual address at the time of capture
    symbol: str           # symbol name (may include +offset component, stripped)
    lib_path: str         # absolute path to the shared library / binary
    offset: int           # byte offset within the SO (= address - so_base)


@dataclass
class Sample:
    """One call-graph snapshot emitted by perf/simpleperf."""
    comm: str             # process command name
    pid: int
    timestamp: float      # seconds since boot (from perf clock)
    frames: List[Frame] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

# Sample header line:
#   COMM   PID   TIMESTAMP:   COUNT   EVENT:
# Examples:
#   target_binary 1234 12345.678901:      1000000 cycles:ppp:
#   perf  7890 10000.123456:          1 task-clock:ppp:
_HEADER = re.compile(
    r'^(\S+)\s+'          # COMM
    r'(\d+)\s+'           # PID
    r'[\d.]+:\s+'         # TIMESTAMP:
    r'\d+\s+'             # COUNT
    r'\S+:'               # EVENT:
)

# Frame line (leading whitespace is required):
#   ADDR   SYMBOL+OFFSET   (LIB_PATH)
# Examples:
#   	7f1234001234 foo+0x10 (/path/to/libfoo.so)
#   	     400abc main+0x20 (/path/to/target)
#   	           0 [unknown] ([unknown])
_FRAME = re.compile(
    r'^\s+'                       # leading whitespace (tab or spaces)
    r'([0-9a-fA-F]+)\s+'          # hex address
    r'(\S+)\s+'                   # symbol+offset (or [unknown])
    r'\(([^)]+)\)'                # (lib_path)
)

# Symbol+offset split: "foo+0x10" → ("foo", 0x10)
_SYM_OFFSET = re.compile(r'^(.+?)\+0x([0-9a-fA-F]+)$')


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _parse_symbol(raw: str) -> tuple[str, int]:
    """Split 'symbol+0xOFFSET' into (symbol, offset). Returns (raw, 0) if no match."""
    m = _SYM_OFFSET.match(raw)
    if m:
        return m.group(1), int(m.group(2), 16)
    return raw, 0


def _so_base_map(samples: List[Sample]) -> Dict[str, int]:
    """
    For each unique lib_path, determine the SO base address as the minimum
    virtual address seen across all samples.  This is a heuristic that works
    well for position-independent shared libraries.
    """
    minimums: Dict[str, int] = {}
    for sample in samples:
        for frame in sample.frames:
            lib = frame.lib_path
            if lib in minimums:
                if frame.address < minimums[lib]:
                    minimums[lib] = frame.address
            else:
                minimums[lib] = frame.address
    return minimums


class PerfScriptParser:
    """
    Parse the text output of `perf script` or `simpleperf report --show-callchain`.

    Usage::

        parser = PerfScriptParser()
        samples = parser.parse(text, so_filter="libfoo.so")
    """

    def parse(self, text: str, so_filter: str = "") -> List[Sample]:
        """
        Parse *text* (full content of a perf script output file) and return
        a list of Sample objects in chronological order.

        Parameters
        ----------
        text:
            Raw text from `perf script` / `simpleperf report --show-callchain`.
        so_filter:
            If non-empty, only include frames whose lib_path basename contains
            this string.  Samples that end up with no frames after filtering are
            dropped.
        """
        samples = self._split_samples(text)
        if so_filter:
            samples = self._apply_so_filter(samples, so_filter)
        # Compute per-SO base addresses and fill in offset field
        base_map = _so_base_map(samples)
        for sample in samples:
            for frame in sample.frames:
                base = base_map.get(frame.lib_path, 0)
                frame.offset = frame.address - base if frame.address >= base else 0
        return samples

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _split_samples(self, text: str) -> List[Sample]:
        """Walk lines and group them into Sample objects."""
        samples: List[Sample] = []
        current: Sample | None = None

        for raw_line in text.splitlines():
            # Blank line = end of current sample block
            if not raw_line.strip():
                current = None
                continue

            header_m = _HEADER.match(raw_line)
            if header_m:
                # Start a new sample
                comm = header_m.group(1)
                pid = int(header_m.group(2))
                # Extract timestamp from the raw line (third field before the colon)
                ts_part = raw_line.split()[2]  # e.g. "12345.678901:"
                try:
                    ts = float(ts_part.rstrip(":"))
                except ValueError:
                    ts = 0.0
                current = Sample(comm=comm, pid=pid, timestamp=ts)
                samples.append(current)
                continue

            frame_m = _FRAME.match(raw_line)
            if frame_m and current is not None:
                addr = int(frame_m.group(1), 16)
                sym_raw = frame_m.group(2)
                lib_path = frame_m.group(3)
                symbol, _ = _parse_symbol(sym_raw)
                # Ignore [unknown] frames (no useful address information)
                if lib_path == "[unknown]" or symbol == "[unknown]":
                    continue
                frame = Frame(
                    address=addr,
                    symbol=symbol,
                    lib_path=lib_path,
                    offset=0,  # filled in later by _so_base_map
                )
                current.frames.append(frame)

        return samples

    def _apply_so_filter(self, samples: List[Sample], so_filter: str) -> List[Sample]:
        """Keep only frames whose lib_path basename contains *so_filter*."""
        result: List[Sample] = []
        for sample in samples:
            filtered_frames = [
                f for f in sample.frames
                if so_filter in os.path.basename(f.lib_path)
            ]
            if filtered_frames:
                sample.frames = filtered_frames
                result.append(sample)
        return result
