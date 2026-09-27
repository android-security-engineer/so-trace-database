"""Parse ``dexdump -d`` output into structured records.

Supports two instruction formats produced by different dexdump versions:

  Standard (with hex dump):
    000130: 1200           |0000: const/4 v0, #int 0

  Simplified (inside "insns :" block, newer SDKs):
        0000: const/4 v0, #int 0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Instruction classification
# --------------------------------------------------------------------------

# All invoke-* variants (base opcode names; /range suffixes included)
_INVOKE_OPCODES: frozenset[str] = frozenset({
    "invoke-virtual",      "invoke-virtual/range",
    "invoke-static",       "invoke-static/range",
    "invoke-interface",    "invoke-interface/range",
    "invoke-direct",       "invoke-direct/range",
    "invoke-super",        "invoke-super/range",
    "invoke-polymorphic",  "invoke-polymorphic/range",
    "invoke-custom",       "invoke-custom/range",
})

# Branch opcodes: conditional, unconditional, switches, returns, throw
_BRANCH_OPCODES: frozenset[str] = frozenset({
    "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
    "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
    "goto", "goto/16", "goto/32",
    "packed-switch", "sparse-switch",
    "return", "return-void", "return-wide", "return-object",
    "throw",
})

# --------------------------------------------------------------------------
# Regex patterns for dexdump -d output
# --------------------------------------------------------------------------

# Class descriptor: "  Class descriptor  : 'Lcom/example/Foo;'"
_RE_CLASS_DESC = re.compile(r"Class descriptor\s*:\s*'(L[^;]+;)'")

# Method boundary: "    #0              : (in Lcom/example/Foo;)"
_RE_METHOD_NUM = re.compile(r"^\s{4}#\d+\s+:")

# Method name: "      name          : 'bar'"
_RE_METHOD_NAME = re.compile(r"^\s+name\s*:\s*'([^']+)'")

# Method type/descriptor: "      type          : '(I)V'"
_RE_METHOD_TYPE = re.compile(r"^\s+type\s*:\s*'([^']+)'")

# Access flags: "      access        : 0x0101 (PUBLIC NATIVE)"
_RE_METHOD_ACCESS = re.compile(r"^\s+access\s*:\s*0x[0-9a-fA-F]+\s+\(([^)]+)\)")

# "      code          -"  (code section starts here)
_RE_CODE_START = re.compile(r"^\s+code\s+-\s*$")

# "      code          : (none)"  (native or abstract — no bytecode)
_RE_CODE_NONE = re.compile(r"^\s+code\s*:\s*\(none\)")

# "      catches       :"  (signals end of code section)
_RE_CATCHES = re.compile(r"^\s+catches\s*:")

# "      insns         :"  (simplified format: instructions follow as indented lines)
_RE_INSNS_HEADER = re.compile(r"^\s+insns\s*:")

# Standard format instruction line: "XXXXXX: bytes... |YYYY: opcode operands"
_RE_INSN_STD = re.compile(r"\|([0-9a-f]+):\s+(\S+)(.*)", re.IGNORECASE)

# Simplified format instruction line inside "insns :" block:
# "        0000: const/4 v0, #int 0"
# Requires >=6 leading spaces so it does not match section headers.
_RE_INSN_SIMPLE = re.compile(r"^\s{6,}([0-9a-f]{4,}): (\S+)(.*)", re.IGNORECASE)

# Strip trailing assembler comments ("// method@0001", "// #int 0", etc.)
_RE_COMMENT = re.compile(r"\s*//.*$")

# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------


@dataclass
class DalvikInsn:
    """A single Dalvik instruction."""

    offset: int       # method-relative PC (Dalvik unit index)
    opcode: str       # lower-cased opcode, e.g. "invoke-virtual"
    operands: str     # remainder of the instruction line (stripped)
    is_invoke: bool   # True for any invoke-* opcode
    is_branch: bool   # True for goto/if-*/return/switch/throw


@dataclass
class MethodRecord:
    """All information extracted for one Dalvik method."""

    class_name: str          # e.g. "com/example/Foo"
    method_name: str         # e.g. "bar"
    descriptor: str          # e.g. "(I)V"
    is_native: bool
    instructions: list[DalvikInsn] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        """Canonical key used for call-target resolution."""
        return f"{self.class_name}->{self.method_name}{self.descriptor}"


@dataclass
class ParseResult:
    """Top-level result of one dexdump parse run."""

    methods: list[MethodRecord] = field(default_factory=list)
    # full_name strings for every native method encountered
    native_methods: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------


class DexdumpParser:
    """State-machine parser for ``dexdump -d`` text output.

    Usage::

        parser = DexdumpParser()
        result = parser.parse(open("out.txt").read(), class_filter="com/example")
    """

    def parse(self, text: str, class_filter: str = "") -> ParseResult:
        """Parse the full stdout of ``dexdump -d <file>``.

        Args:
            text:         Raw output text from dexdump.
            class_filter: Substring filter on class name (e.g. ``"com/example"``).
                          Empty string means include all classes.

        Returns:
            A :class:`ParseResult` with all parsed methods and native method names.
        """
        result = ParseResult()

        # Current state
        current_class: str = ""
        method_name: str = ""
        method_type: str = ""
        is_native: bool = False
        insns: list[DalvikInsn] = []
        in_code: bool = False
        in_insns_simple: bool = False  # inside indented "insns :" block

        def flush() -> None:
            nonlocal method_name, method_type, is_native, insns
            nonlocal in_code, in_insns_simple
            if current_class and method_name:
                if not class_filter or class_filter in current_class:
                    rec = MethodRecord(
                        class_name=current_class,
                        method_name=method_name,
                        descriptor=method_type,
                        is_native=is_native,
                        instructions=list(insns),
                    )
                    result.methods.append(rec)
                    if is_native:
                        result.native_methods.append(rec.full_name)
            method_name = ""
            method_type = ""
            is_native = False
            insns = []
            in_code = False
            in_insns_simple = False

        for line in text.splitlines():
            # ------------------------------------------------------------------
            # Class descriptor
            # ------------------------------------------------------------------
            m = _RE_CLASS_DESC.search(line)
            if m:
                flush()
                raw = m.group(1)               # "Lcom/example/Foo;"
                current_class = raw[1:-1]      # strip L...;  → "com/example/Foo"
                continue

            # ------------------------------------------------------------------
            # Method boundary marker — start of a new method block
            # ------------------------------------------------------------------
            if _RE_METHOD_NUM.match(line):
                flush()
                continue

            # ------------------------------------------------------------------
            # Method metadata (only meaningful inside a method block)
            # ------------------------------------------------------------------
            m = _RE_METHOD_NAME.match(line)
            if m:
                method_name = m.group(1)
                continue

            m = _RE_METHOD_TYPE.match(line)
            if m:
                method_type = m.group(1)
                continue

            m = _RE_METHOD_ACCESS.match(line)
            if m:
                is_native = "NATIVE" in m.group(1).upper()
                continue

            # "code -" → entering code/bytecode section
            if _RE_CODE_START.match(line):
                in_code = True
                in_insns_simple = False
                continue

            # "code : (none)" → no bytecode (native or abstract)
            if _RE_CODE_NONE.match(line):
                in_code = False
                continue

            # ------------------------------------------------------------------
            # Inside code section
            # ------------------------------------------------------------------
            if not in_code:
                continue

            # "catches :" → end of code section
            if _RE_CATCHES.match(line):
                in_code = False
                in_insns_simple = False
                continue

            # "insns :" → switch to simplified instruction format
            if _RE_INSNS_HEADER.match(line):
                in_insns_simple = True
                continue

            # Standard format: "XXXXXX: bytes... |YYYY: opcode operands"
            m_std = _RE_INSN_STD.search(line)
            if m_std:
                offset = int(m_std.group(1), 16)
                opcode = m_std.group(2).lower()
                operands = _RE_COMMENT.sub("", m_std.group(3)).strip()
                insns.append(DalvikInsn(
                    offset=offset,
                    opcode=opcode,
                    operands=operands,
                    is_invoke=opcode in _INVOKE_OPCODES,
                    is_branch=opcode in _BRANCH_OPCODES,
                ))
                continue

            # Simplified format (inside "insns :" block):
            # "        0000: const/4 v0, #int 0"
            if in_insns_simple:
                m_s = _RE_INSN_SIMPLE.match(line)
                if m_s:
                    offset = int(m_s.group(1), 16)
                    opcode = m_s.group(2).lower()
                    operands = _RE_COMMENT.sub("", m_s.group(3)).strip()
                    insns.append(DalvikInsn(
                        offset=offset,
                        opcode=opcode,
                        operands=operands,
                        is_invoke=opcode in _INVOKE_OPCODES,
                        is_branch=opcode in _BRANCH_OPCODES,
                    ))

        # Flush the last method
        flush()

        return result
