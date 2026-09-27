"""
scanner.py — scan apktool smali output for invoke instructions,
native method declarations, and System.loadLibrary calls.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# .class public final Lcom/example/Foo;
_RE_CLASS = re.compile(r'^\.class\s+.*?\s+(L[\w/$]+;)\s*$')

# .method public static native nativeMethod(Ljava/lang/String;)V
_RE_METHOD_HDR = re.compile(r'^\.method\s+(.*)')
_RE_END_METHOD = re.compile(r'^\.end method')

# const-string v0, "libfoo"   or   const-string/jumbo v0, "libfoo"
_RE_CONST_STR = re.compile(r'^\s*const-string(?:/jumbo)?\s+(\w+),\s+"([^"]*)"')

# invoke-virtual {v0}, Lsome/Class;->method(...)retType
# Captures: (opcode, registers, class_descriptor_with_semicolon, method_name)
_RE_INVOKE = re.compile(
    r'^\s*(invoke-\S+)\s+\{([^}]*)\},\s*([^;]+;)->([\w<>$]+)\('
)

_LOAD_LIB_CLASS  = "java/lang/System"
_LOAD_LIB_METHOD = "loadLibrary"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class NativeMethod:
    """A smali method declared with the 'native' modifier."""
    class_name:  str   # e.g. "com/example/Foo"
    method_name: str   # e.g. "nativeMethod"
    descriptor:  str   # e.g. "(Ljava/lang/String;)V"


@dataclass
class InvokeCall:
    """A single invoke-* instruction found in smali bytecode."""
    caller_class:  str   # class containing the invoke (e.g. "com/example/Bar")
    caller_method: str   # method containing the invoke (e.g. "onCreate")
    callee_class:  str   # target class (e.g. "com/example/Foo")
    callee_method: str   # target method name (e.g. "nativeMethod")
    smali_opcode:  str   # e.g. "invoke-virtual", "invoke-interface"


@dataclass
class ScanResult:
    """Aggregated output of a SmaliScanner run."""
    so_names:       List[str]          = field(default_factory=list)
    native_methods: List[NativeMethod] = field(default_factory=list)
    invoke_calls:   List[InvokeCall]   = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _descriptor_to_class(descriptor: str) -> str:
    """Strip smali class descriptor framing: 'Lcom/example/Foo;' -> 'com/example/Foo'."""
    s = descriptor
    if s.startswith("L"):
        s = s[1:]
    if s.endswith(";"):
        s = s[:-1]
    return s


class SmaliScanner:
    """Walk a directory tree produced by apktool and extract smali call information."""

    def scan_dir(self, smali_dir: str, so_filter: str = "") -> ScanResult:
        """
        Recursively scan all .smali files under *smali_dir*.

        Parameters
        ----------
        smali_dir:
            Root directory to scan (may be the apktool output root or a
            specific smali/ subdirectory — both work).
        so_filter:
            When non-empty, only retain SO names that contain this substring.

        Returns
        -------
        ScanResult with deduplicated so_names and all collected methods/calls.
        """
        result = ScanResult()
        for dirpath, _dirs, filenames in os.walk(smali_dir):
            for fname in filenames:
                if fname.endswith(".smali"):
                    self._scan_file(os.path.join(dirpath, fname), result)

        # Apply SO name filter
        if so_filter:
            result.so_names = [n for n in result.so_names if so_filter in n]

        # Deduplicate SO names while preserving order
        seen: set = set()
        deduped: List[str] = []
        for name in result.so_names:
            if name not in seen:
                seen.add(name)
                deduped.append(name)
        result.so_names = deduped

        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_file(self, path: str, result: ScanResult) -> None:
        """Parse one .smali file and append findings to *result*."""
        current_class  = ""
        current_method = ""
        in_method      = False
        # Register-to-string-literal map for the current method body
        string_regs: Dict[str, str] = {}

        try:
            with open(path, "r", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return

        for line in lines:
            stripped = line.strip()

            # ---- .class declaration ----------------------------------------
            m = _RE_CLASS.match(stripped)
            if m:
                current_class = _descriptor_to_class(m.group(1))
                continue

            # ---- .method declaration ----------------------------------------
            m = _RE_METHOD_HDR.match(stripped)
            if m:
                in_method   = True
                modifiers   = m.group(1)
                is_native   = "native" in modifiers.split()
                string_regs = {}

                # Last token is "methodName(signature)retType"
                tokens  = modifiers.split()
                sig_tok = tokens[-1] if tokens else ""
                paren   = sig_tok.find("(")
                if paren != -1:
                    current_method = sig_tok[:paren]
                    descriptor     = sig_tok[paren:]
                else:
                    current_method = sig_tok
                    descriptor     = ""

                if is_native:
                    result.native_methods.append(NativeMethod(
                        class_name  = current_class,
                        method_name = current_method,
                        descriptor  = descriptor,
                    ))
                continue

            # ---- .end method ------------------------------------------------
            if _RE_END_METHOD.match(stripped):
                in_method      = False
                current_method = ""
                string_regs    = {}
                continue

            if not in_method:
                continue

            # ---- const-string (track register -> literal) -------------------
            m = _RE_CONST_STR.match(line)
            if m:
                string_regs[m.group(1)] = m.group(2)
                continue

            # ---- invoke-* ---------------------------------------------------
            m = _RE_INVOKE.match(line)
            if not m:
                continue

            opcode       = m.group(1)
            regs_str     = m.group(2).strip()
            callee_class = _descriptor_to_class(m.group(3))
            callee_meth  = m.group(4)

            # Detect System.loadLibrary — read library name from string register
            if callee_class == _LOAD_LIB_CLASS and callee_meth == _LOAD_LIB_METHOD:
                reg_list = [r.strip() for r in regs_str.split(",") if r.strip()]
                if reg_list:
                    so_name = string_regs.get(reg_list[0], "")
                    if so_name:
                        result.so_names.append(so_name)

            result.invoke_calls.append(InvokeCall(
                caller_class  = current_class,
                caller_method = current_method,
                callee_class  = callee_class,
                callee_method = callee_meth,
                smali_opcode  = opcode,
            ))
