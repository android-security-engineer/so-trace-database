#!/usr/bin/env python3
"""sotrace-objdump: parse GNU objdump -d output and upload to sotrace-server.

Usage examples
--------------
# Auto-detect arch from ELF header, upload to server:
  python sotrace-objdump.py libfoo.so --server http://192.168.1.83:3000

# Cross-compiled objdump for ARM64, save output to file:
  python sotrace-objdump.py libfoo.so \\
      --objdump aarch64-linux-gnu-objdump \\
      --output trace.jsonl

# Only disassemble .text section:
  python sotrace-objdump.py libfoo.so --section .text --server http://192.168.1.83:3000

# Force architecture (skip ELF auto-detect):
  python sotrace-objdump.py libfoo.so --arch arm --server http://192.168.1.83:3000
"""

import argparse
import json
import logging
import os
import shutil
import struct
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("sotrace-objdump")

# ELF e_machine values at bytes 18-19 (little-endian u16)
_ELF_MACHINES = {
    3:   'x86',      # EM_386
    40:  'arm',      # EM_ARM
    62:  'x86_64',   # EM_X86_64
    183: 'aarch64',  # EM_AARCH64
}

# Candidate objdump binaries tried in order when --objdump is not set
_DEFAULT_OBJDUMP_CANDIDATES = [
    'aarch64-linux-gnu-objdump',
    'arm-linux-gnueabihf-objdump',
    'objdump',
]


def detect_arch(binary_path: str) -> str:
    """Read the ELF e_machine field and return an arch string.

    Returns 'aarch64', 'arm', 'x86_64', or 'x86'.
    Falls back to 'aarch64' if the header is unreadable or unknown.
    """
    try:
        with open(binary_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF':
                log.warning("Not an ELF file; defaulting arch to aarch64")
                return 'aarch64'
            f.seek(18)
            e_machine = struct.unpack('<H', f.read(2))[0]
        arch = _ELF_MACHINES.get(e_machine)
        if arch:
            log.info(f"[arch] ELF e_machine=0x{e_machine:04x} → {arch}")
            return arch
        log.warning(f"Unknown ELF e_machine 0x{e_machine:04x}; defaulting to aarch64")
        return 'aarch64'
    except OSError as exc:
        log.warning(f"Cannot read ELF header: {exc}; defaulting to aarch64")
        return 'aarch64'


def find_objdump(hint: str, arch: str) -> str:
    """Resolve the objdump binary path.

    Uses *hint* directly if supplied.  Otherwise tries arch-prefixed candidates
    first (matching detected arch), then falls back through the default list.
    """
    if hint:
        if not shutil.which(hint) and not os.path.isfile(hint):
            log.warning(f"--objdump '{hint}' not found in PATH; trying anyway")
        return hint

    # Build a prioritised candidate list: arch-specific binary first
    arch_prefix_map = {
        'aarch64': 'aarch64-linux-gnu-objdump',
        'arm':     'arm-linux-gnueabihf-objdump',
        'x86_64':  'x86_64-linux-gnu-objdump',
        'x86':     'i686-linux-gnu-objdump',
    }
    candidates = []
    pref = arch_prefix_map.get(arch)
    if pref:
        candidates.append(pref)
    for c in _DEFAULT_OBJDUMP_CANDIDATES:
        if c not in candidates:
            candidates.append(c)

    for candidate in candidates:
        if shutil.which(candidate):
            log.info(f"[objdump] Using: {candidate}")
            return candidate

    # Last resort: plain 'objdump' — let the OS error surface naturally
    log.warning("No objdump binary found; will try 'objdump' and hope for the best")
    return 'objdump'


def run_objdump(binary: str, objdump_bin: str, arch: str, section: str) -> str:
    """Run objdump -d and return stdout as a string.

    Args:
        binary:      Path to the SO/ELF file.
        objdump_bin: objdump binary (path or name).
        arch:        Detected or user-supplied arch string.
        section:     If non-empty, pass ``-j <section>`` to limit disassembly.

    Returns:
        The combined stdout text from objdump.
    """
    cmd = [objdump_bin, '-d', '--no-show-raw-insn']

    # -M no-aliases: show canonical ARM64 instruction names (e.g. mov vs orr)
    if arch in ('aarch64', 'arm'):
        cmd += ['-M', 'no-aliases']

    if section:
        cmd += ['-j', section]

    cmd.append(binary)

    log.info(f"[objdump] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except FileNotFoundError:
        sys.exit(f"[error] objdump binary not found: {objdump_bin}\n"
                 "Install with: sudo apt-get install binutils-aarch64-linux-gnu")
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode(errors='replace')
        sys.exit(f"[error] objdump failed (exit {exc.returncode}):\n{stderr}")

    return result.stdout.decode(errors='replace')


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='sotrace-objdump',
        description='Disassemble an ELF/SO with objdump and upload to sotrace-server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'binary',
        help='Path to the SO/ELF file to disassemble',
    )
    parser.add_argument(
        '--server', default='',
        metavar='URL',
        help='Upload to sotrace-server, e.g. http://192.168.1.83:3000',
    )
    parser.add_argument(
        '--output', default='',
        metavar='FILE',
        help='Save trace envelope to a JSONL file',
    )
    parser.add_argument(
        '--arch', default='',
        choices=['aarch64', 'arm', 'x86_64', 'x86'],
        help='Target architecture (default: auto-detect from ELF header)',
    )
    parser.add_argument(
        '--objdump', default='',
        metavar='PATH',
        help='Path to objdump binary (default: tries aarch64-linux-gnu-objdump, objdump)',
    )
    parser.add_argument(
        '--section', default='',
        metavar='TEXT',
        help='Only disassemble the named section, e.g. .text',
    )
    args = parser.parse_args()

    if not args.server and not args.output:
        parser.error("Provide --server and/or --output (nothing to do otherwise)")

    # Resolve architecture
    arch = args.arch if args.arch else detect_arch(args.binary)

    # Resolve objdump binary
    objdump_bin = find_objdump(args.objdump, arch)

    # Run disassembler
    objdump_text = run_objdump(args.binary, objdump_bin, arch, args.section)

    # Parse output
    from sotrace_objdump import ObjdumpParser, ObjdumpMapper, SoTraceClient

    parser_obj = ObjdumpParser(arch=arch)
    result = parser_obj.parse(objdump_text)
    log.info(
        f"[parse] functions={len(result.functions)}  "
        f"instructions={len(result.instructions)}  "
        f"calls={len(result.calls)}"
    )

    # Map to envelope
    mapper = ObjdumpMapper()
    envelope = mapper.build_envelope(result)

    # Upload to server
    if args.server:
        client = SoTraceClient(args.server)
        trace_id = client.import_trace(envelope)
        print(
            f"[sotrace] trace_id={trace_id}  "
            f"instructions={len(result.instructions)}  "
            f"calls={len(result.calls)}"
        )
        print(f"[sotrace] Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races")

    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            f.write(json.dumps(envelope) + '\n')
        print(f"[sotrace] Saved to {args.output}")


if __name__ == '__main__':
    main()
