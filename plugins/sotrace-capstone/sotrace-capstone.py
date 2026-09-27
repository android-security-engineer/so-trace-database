#!/usr/bin/env python3
"""sotrace-capstone: statically disassemble a SO/ELF file with Capstone and upload to sotrace-server.

Usage examples:
  # Auto-detect arch from ELF, upload to server
  python sotrace-capstone.py libfoo.so --server http://192.168.1.83:3000

  # Save to JSONL file instead
  python sotrace-capstone.py libfoo.so --output trace.jsonl

  # Force ARM Thumb mode (e.g. mixed ARM32 binary)
  python sotrace-capstone.py libfoo.so --arch arm_thumb --server http://192.168.1.83:3000

  # Raw binary with explicit arch, offset and size
  python sotrace-capstone.py payload.bin --arch aarch64 --offset 0x200 --size 0x1000

  # Adjust base address for SO-relative offset calculation
  python sotrace-capstone.py libfoo.so --base 0x71000000 --server http://192.168.1.83:3000
"""

import argparse
import json
import logging
import sys


logging.basicConfig(level=logging.INFO, format="%(message)s")


def _is_elf(path: str) -> bool:
    """Return True if the file starts with the ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Statically disassemble a SO/ELF file with Capstone and upload to sotrace-server"
    )
    parser.add_argument("binary", help="Path to SO/ELF or raw binary")
    parser.add_argument(
        "--server", default="",
        help="sotrace-server base URL, e.g. http://192.168.1.83:3000",
    )
    parser.add_argument(
        "--output", default="",
        help="Save trace envelope to this JSONL file",
    )
    parser.add_argument(
        "--arch",
        choices=["aarch64", "arm", "arm_thumb", "x86_64", "x86"],
        default=None,
        help="Target arch (default: auto-detect from ELF header)",
    )
    parser.add_argument(
        "--offset", type=lambda x: int(x, 0), default=None,
        metavar="HEX",
        help="Start offset in file for raw mode (default: 0). Ignored for ELF (uses .text).",
    )
    parser.add_argument(
        "--size", type=lambda x: int(x, 0), default=None,
        metavar="N",
        help="Bytes to disassemble in raw mode (default: all). Ignored for ELF.",
    )
    parser.add_argument(
        "--base", type=lambda x: int(x, 0), default=0,
        metavar="HEX",
        help="SO load base address; subtracted from every VA to produce SO-relative offset (default: 0)",
    )
    parser.add_argument(
        "--trace-id", type=int, default=0, dest="trace_id",
        help="Hint trace_id to server (default: 0; server assigns final id)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("Provide --server and/or --output")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Lazy-import check for capstone
    try:
        import capstone  # noqa: F401
    except ImportError:
        sys.exit("capstone not installed — run: pip install capstone")

    from sotrace_capstone import CapstoneDisassembler, CapstoneMapper, SoTraceClient

    disasm = CapstoneDisassembler(arch=args.arch)
    use_elf = _is_elf(args.binary)

    if use_elf and args.arch is None:
        # ELF path: auto-detect + section-based disassembly
        result = disasm.disassemble_elf(args.binary)
    elif use_elf:
        # ELF + forced arch: still use pyelftools for section discovery if available
        try:
            result = disasm.disassemble_elf(args.binary)
        except ImportError:
            # pyelftools absent — fall back to raw
            logging.warning("[capstone] pyelftools not available; falling back to raw mode")
            use_elf = False

    if not use_elf:
        # Raw binary path
        with open(args.binary, "rb") as f:
            data = f.read()
        offset = args.offset or 0
        size = args.size if args.size is not None else len(data) - offset
        data = data[offset: offset + size]
        base_va = args.base + offset
        result = disasm.disassemble_raw(data, base_addr=base_va)

    mapper = CapstoneMapper(base_addr=args.base, trace_id=args.trace_id)
    envelope = mapper.to_envelope(result)

    n_insns = len(envelope["instructions"])
    n_calls = len(envelope["calls"])

    if args.server:
        client = SoTraceClient(args.server)
        trace_id = client.import_trace(envelope)
        print(f"[sotrace] trace_id={trace_id}  instructions={n_insns}  calls={n_calls}")
        print(f"[sotrace] Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")

    if args.output:
        with open(args.output, "w") as f:
            f.write(json.dumps(envelope) + "\n")
        print(f"[sotrace] Saved to {args.output}  instructions={n_insns}  calls={n_calls}")


if __name__ == "__main__":
    main()
