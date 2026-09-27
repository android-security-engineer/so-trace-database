"""
mapper.py — Convert parsed perf Sample objects to a sotrace-server import envelope.

Mapping rules
-------------
- Each unique PID becomes one thread entry.
- Samples are processed in timestamp order (they are already sorted because
  perf script outputs events chronologically).
- Each sample contributes:
    * call events  — one per consecutive (caller, callee) frame pair, from
                     the bottom of the call stack (outermost caller) toward
                     the top (innermost callee).  This reconstructs the call
                     chain at the moment of the sample.
    * instruction events — one per unique (pid, address) pair across all
                     samples (de-duplicated because a call-graph sample does
                     not represent individual instruction executions, only the
                     call chain state at that moment).
- Steps are assigned sequentially (one per call event) in timestamp order.
  Instruction events share the same step as the call event that introduced them.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from .parser import Frame, Sample


# ---------------------------------------------------------------------------
# Envelope builder
# ---------------------------------------------------------------------------

class PerfMapper:
    """
    Convert a list of Sample objects (output of PerfScriptParser.parse) into
    a sotrace-server import envelope dict.

    Usage::

        mapper = PerfMapper()
        envelope = mapper.build(samples, trace_id=0)
    """

    def build(self, samples: List[Sample], trace_id: int = 0) -> dict:
        """
        Build a complete import envelope from *samples*.

        Parameters
        ----------
        samples:
            Parsed samples in chronological order.
        trace_id:
            Pass 0 so the server auto-assigns an ID on the first import.
        """
        # Collect unique PIDs to build the threads list
        pids: Dict[int, int] = {}  # pid -> create_step (first appearance)

        # First pass: discover threads
        for s in samples:
            if s.pid not in pids:
                pids[s.pid] = 0  # step assigned later in second pass

        # Second pass: generate events
        call_events: List[dict] = []
        instruction_events: List[dict] = []
        seen_instructions: Set[Tuple[int, int]] = set()  # (pid, address)
        step = 1

        for s in sorted(samples, key=lambda x: x.timestamp):
            # Record thread create_step at first appearance
            if pids[s.pid] == 0 and step > 1:
                pids[s.pid] = step

            frames = s.frames
            # perf outputs frames top→bottom (innermost first); reverse for
            # caller→callee reconstruction
            # frames[0] = current IP (innermost callee)
            # frames[-1] = outermost caller (e.g. main or _start)
            # We walk from outermost to innermost: frames[-1] → frames[0]
            ordered = list(reversed(frames))  # ordered[0]=caller, ordered[-1]=callee

            # Emit instruction events for unique addresses in this sample
            for frame in frames:
                key = (s.pid, frame.address)
                if key not in seen_instructions:
                    seen_instructions.add(key)
                    instruction_events.append({
                        "seq":          step,
                        "thread_id":    s.pid,
                        "address":      frame.address,
                        "is_branch":    True,   # call-graph entries are call sites
                        "branch_taken": True,
                    })

            # Emit call events for each consecutive frame pair
            depth = 0
            for i in range(len(ordered) - 1):
                caller: Frame = ordered[i]
                callee: Frame = ordered[i + 1]
                call_events.append({
                    "seq":            step,
                    "thread_id":      s.pid,
                    "caller_address": caller.address,
                    "callee_address": callee.address,
                    "depth":          depth,
                    "event_type":     "Call",
                })
                depth += 1
                step += 1

            # Advance step even for samples with a single frame (no pairs)
            if len(ordered) <= 1:
                step += 1

        threads = [
            {
                "thread_id":        pid,
                "create_step":      create_step,
                "parent_thread_id": 0,
                "stack_base":       0,
                "stack_size":       0,
                "tls_addr":         0,
                "is_jni_attached":  False,
            }
            for pid, create_step in sorted(pids.items())
        ]

        return {
            "trace_id":       trace_id,
            "threads":        threads,
            "instructions":   instruction_events,
            "calls":          call_events,
            "memory_reads":   [],
            "memory_writes":  [],
            "sync_events":    [],
        }
