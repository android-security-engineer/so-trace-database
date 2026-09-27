#!/usr/bin/env python3
"""Parse a pre-existing strace log file and upload to sotrace-server."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sotrace_strace.parser import StraceParser
from sotrace_strace.client import SoTraceClient


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "strace.log"
    server   = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:3000"
    so_base  = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0

    parser = StraceParser(so_base=so_base)
    events = parser.parse_file(log_path)

    n_sync = sum(1 for e in events if e.kind == "sync")
    n_mem  = sum(1 for e in events if e.kind == "memory")
    print(f"Parsed {n_sync} sync events, {n_mem} memory events")

    envelope = parser.events_to_envelope(events)

    client = SoTraceClient(server)
    trace_id = client.import_trace(envelope)
    print(f"trace_id={trace_id}")
    print(f"Deadlocks: {server}/api/v1/traces/{trace_id}/analyze/threads/deadlocks")
    print(f"Contentions: {server}/api/v1/traces/{trace_id}/analyze/threads/contentions")


if __name__ == "__main__":
    main()
