"""Parse `objdump -d` disassembly output into structured records."""

import re
from dataclasses import dataclass, field

# objdump output patterns
_FUNC_HEADER = re.compile(r'^([0-9a-fA-F]+) <([^>]+)>:')
_INSN = re.compile(r'^\s+([0-9a-fA-F]+):\s+(?:[0-9a-fA-F ]+\t)?(\S+)\s*(.*)')

# ARM64 unconditional branch mnemonics
_ARM64_BRANCHES = frozenset({
    'b', 'bl', 'blr', 'br', 'ret',
    'cbz', 'cbnz', 'tbz', 'tbnz',
})

# ARM64 conditional branch suffixes (used with b.<cond>)
_ARM64_COND_SUFFIXES = frozenset({
    'eq', 'ne', 'lt', 'le', 'gt', 'ge',
    'lo', 'ls', 'hi', 'hs', 'mi', 'pl',
    'vs', 'vc', 'al', 'nv',
})

# ARM (32-bit) branch mnemonics
_ARM32_BRANCHES = frozenset({
    'b', 'bl', 'blx', 'bx', 'bxj',
    'cbz', 'cbnz',
})

# ARM32 two-letter condition codes (same set as ARM64 suffixes)
_ARM32_COND_CODES = _ARM64_COND_SUFFIXES

# x86 / x86_64 branch and jump mnemonics
_X86_BRANCHES = frozenset({
    'jmp', 'jmpq', 'call', 'callq',
    'ret', 'retq', 'retn', 'retf',
    'je', 'jne', 'jz', 'jnz',
    'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae',
    'js', 'jns', 'jp', 'jnp',
    'jcxz', 'jecxz', 'jrcxz',
    'loop', 'loope', 'loopne',
})

# Mnemonics that represent function calls (produce CallRecord)
_CALL_MNEMONICS = frozenset({'bl', 'blx', 'call', 'callq'})


@dataclass
class InsnRecord:
    """A single disassembled instruction."""
    seq: int
    address: int
    mnemonic: str
    operands: str
    is_branch: bool
    branch_taken: bool  # always False for static analysis
    func_name: str


@dataclass
class CallRecord:
    """A call edge derived from a bl/blx/call instruction."""
    seq: int            # same seq as the triggering InsnRecord
    caller_address: int
    callee_address: int
    callee_name: str    # symbol name if available, else ""
    depth: int          # estimated call depth at this point


@dataclass
class FuncRecord:
    """A function entry point from a function header line."""
    address: int
    name: str


@dataclass
class ParseResult:
    """All records extracted from one objdump run."""
    instructions: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    functions: list = field(default_factory=list)


def _is_branch(mnemonic: str, arch: str) -> bool:
    """Return True if the mnemonic is a branch / jump / call / return."""
    m = mnemonic.lower()
    if arch in ('aarch64', 'arm64'):
        if m in _ARM64_BRANCHES:
            return True
        # b.eq, b.ne, b.lt, ... (GNU objdump format)
        if m.startswith('b.') and m[2:] in _ARM64_COND_SUFFIXES:
            return True
        return False
    elif arch == 'arm':
        if m in _ARM32_BRANCHES:
            return True
        # beq, bne, bleq, blne, blxeq, ... (condition code suffix)
        for prefix in ('blx', 'bl', 'bx', 'b'):
            if m.startswith(prefix) and m[len(prefix):] in _ARM32_COND_CODES:
                return True
        return False
    else:  # x86 / x86_64
        return m in _X86_BRANCHES


def _is_call(mnemonic: str, arch: str) -> bool:
    """Return True if the instruction is a call (emits a CallRecord)."""
    m = mnemonic.lower()
    if arch in ('aarch64', 'arm64', 'arm'):
        # bl, blx and their conditional variants (bleq, blne, blxeq, ...)
        if m in ('bl', 'blx'):
            return True
        for prefix in ('blx', 'bl'):
            if m.startswith(prefix) and m[len(prefix):] in _ARM32_COND_CODES:
                return True
        return False
    else:
        return m in ('call', 'callq')


def _parse_callee(operands: str) -> tuple:
    """Parse callee address and optional symbol from an operand string.

    Handles these GNU objdump formats:
      "11fc <bar>"          -> (0x11fc, "bar")
      "0x11fc <bar>"        -> (0x11fc, "bar")
      "#0x11fc <bar>"       -> (0x11fc, "bar")
      "0x11fc"              -> (0x11fc, "")
      "#11fc"               -> (0x11fc, "")

    Returns (callee_address, callee_name).  callee_address==0 means unparseable.
    """
    ops = operands.strip().lstrip('#')
    # Pattern: optional "0x" + hex digits + optional " <symbol[+offset]>"
    m = re.match(r'(?:0x)?([0-9a-fA-F]+)\s+<([^>+]+)(?:\+[^>]*)?>?', ops)
    if m:
        return int(m.group(1), 16), m.group(2)
    # Plain hex address (with or without 0x prefix)
    m = re.match(r'(?:0x)?([0-9a-fA-F]+)', ops)
    if m:
        return int(m.group(1), 16), ""
    return 0, ""


class ObjdumpParser:
    """Parse the text output of ``objdump -d`` into structured records.

    Usage::

        parser = ObjdumpParser(arch='aarch64')
        result = parser.parse(open('objdump.txt').read())
    """

    def __init__(self, arch: str = 'aarch64'):
        # Normalise arch string
        self.arch = arch.lower().replace('-', '_')
        if self.arch in ('aarch64', 'arm64', 'armv8'):
            self.arch = 'aarch64'
        elif self.arch in ('arm', 'armv7', 'armv7l', 'armhf'):
            self.arch = 'arm'
        elif self.arch in ('x86_64', 'amd64', 'x86-64'):
            self.arch = 'x86_64'
        elif self.arch in ('x86', 'i386', 'i686'):
            self.arch = 'x86'

    def parse(self, text: str) -> ParseResult:
        """Parse objdump -d text output and return a ParseResult."""
        result = ParseResult()
        current_func = ""
        seq = 0
        # Crude call-depth tracker: increment on calls, decrement on rets
        depth_stack: list = []

        for line in text.splitlines():
            # Function header: "0000000000001234 <foo>:"
            fh = _FUNC_HEADER.match(line)
            if fh:
                current_func = fh.group(2)
                func_addr = int(fh.group(1), 16)
                result.functions.append(FuncRecord(func_addr, current_func))
                depth_stack = []  # new function resets depth estimation
                continue

            # Instruction line: "    1234:   <bytes>   mnemonic  operands"
            im = _INSN.match(line)
            if not im:
                continue

            addr = int(im.group(1), 16)
            mnemonic = im.group(2)
            operands = im.group(3).strip()
            seq += 1

            branch = _is_branch(mnemonic, self.arch)
            insn = InsnRecord(
                seq=seq,
                address=addr,
                mnemonic=mnemonic,
                operands=operands,
                is_branch=branch,
                branch_taken=False,
                func_name=current_func,
            )
            result.instructions.append(insn)

            # Emit a CallRecord for call-like instructions
            if _is_call(mnemonic, self.arch):
                callee_addr, callee_name = _parse_callee(operands)
                if callee_addr:
                    current_depth = len(depth_stack)
                    result.calls.append(CallRecord(
                        seq=seq,
                        caller_address=addr,
                        callee_address=callee_addr,
                        callee_name=callee_name,
                        depth=current_depth,
                    ))
                    depth_stack.append(addr)

            # Track return instructions to maintain depth estimate
            if mnemonic.lower() in ('ret', 'retq', 'bx', 'bx lr') and depth_stack:
                depth_stack.pop()

        return result
