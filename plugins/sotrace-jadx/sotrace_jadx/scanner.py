"""
scanner.py — Walk JADX-decompiled Java sources and extract JNI boundary info.

Key outputs:
  - native method declarations (class, method, signature)
  - System.loadLibrary("xxx") calls that bind a SO name to a class
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class JniMethod:
    """A single JNI boundary crossing point extracted from decompiled Java."""

    class_name: str           # fully-qualified class name, e.g. "com.example.Foo"
    method_name: str          # Java method name, e.g. "nativeInit"
    signature: str            # JNI-style descriptor, e.g. "(ILjava/lang/String;)V"
    is_native: bool           # True for 'native' keyword declarations
    so_name: Optional[str]    # SO name from System.loadLibrary, if resolved
    # Raw parameter list string (pre-parse), kept for diagnostics
    raw_params: str = field(default="", repr=False)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Match any `native` method declaration across multiple access-modifier orderings.
# Group 1: return type, Group 2: method name, Group 3: parameter list (raw)
_NATIVE_METHOD_RE = re.compile(
    r"""
    (?:(?:public|private|protected|static|final|synchronized|abstract|strictfp)\s+)*
    native\s+
    (?:(?:public|private|protected|static|final|synchronized|abstract|strictfp)\s+)*
    ([\w.\[\]<>,\s]+?)\s+   # return type (greedy reluctant)
    (\w+)\s*                 # method name
    \(([^)]*)\)              # parameter list
    \s*;                     # semicolon (abstract / interface)
    """,
    re.VERBOSE | re.MULTILINE,
)

# System.loadLibrary("soname") — single or double quotes
_LOADLIB_RE = re.compile(r'System\.loadLibrary\(\s*["\']([^"\']+)["\']\s*\)')

# Class/interface declaration to extract the current class name
_CLASS_DECL_RE = re.compile(
    r'(?:public|private|protected|abstract|final|\s)*\s+'
    r'(?:class|interface|enum)\s+(\w+)'
)

# Package declaration
_PACKAGE_RE = re.compile(r'^\s*package\s+([\w.]+)\s*;', re.MULTILINE)


# ---------------------------------------------------------------------------
# JNI type mapping helpers
# ---------------------------------------------------------------------------

# Map from Java simple types to JNI descriptors
_JAVA_TO_JNI: dict[str, str] = {
    "void":    "V",
    "boolean": "Z",
    "byte":    "B",
    "char":    "C",
    "short":   "S",
    "int":     "I",
    "long":    "J",
    "float":   "F",
    "double":  "D",
    "String":  "Ljava/lang/String;",
    "Object":  "Ljava/lang/Object;",
}


def _java_type_to_jni(java_type: str) -> str:
    """Convert a Java type string to its JNI descriptor character(s).

    Handles primitives, arrays (trailing []), and fully-qualified class names.
    Falls back to Ljava/lang/Object; for unknown types.
    """
    java_type = java_type.strip()
    # Array suffix
    if java_type.endswith("[]"):
        return "[" + _java_type_to_jni(java_type[:-2])
    # Known primitives / common classes
    if java_type in _JAVA_TO_JNI:
        return _JAVA_TO_JNI[java_type]
    # Fully qualified name like com.example.Foo → Lcom/example/Foo;
    if "." in java_type:
        return "L" + java_type.replace(".", "/") + ";"
    # Short class name (import not resolved) → treat as Object
    if java_type[0].isupper():
        return "Ljava/lang/Object;"
    return "Ljava/lang/Object;"


def _build_jni_signature(raw_params: str, return_type: str) -> str:
    """Build a JNI method descriptor from raw Java parameter list and return type.

    E.g. ("int a, String b", "void") → "(ILjava/lang/String;)V"
    """
    params_desc = ""
    raw_params = raw_params.strip()
    if raw_params:
        for param in raw_params.split(","):
            param = param.strip()
            if not param:
                continue
            # "int a" → take the type part (everything before the last word)
            parts = param.split()
            if len(parts) >= 2:
                type_str = " ".join(parts[:-1])
            else:
                type_str = parts[0]
            params_desc += _java_type_to_jni(type_str)
    return_desc = _java_type_to_jni(return_type.strip())
    return f"({params_desc}){return_desc}"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class JadxScanner:
    """Walk a JADX-decompiled source directory and extract JNI boundary info."""

    def scan_sources(self, src_dir: str) -> list[JniMethod]:
        """Return a list of JniMethod found under *src_dir* (recursive .java walk).

        Each file is scanned for:
          1. Package declaration → determines fully-qualified class name prefix.
          2. Class/interface declarations → tracks the active class.
          3. ``native`` method declarations → yields JniMethod with is_native=True.
          4. ``System.loadLibrary`` calls → associates a SO name with all native
             methods in the same class (last-wins if multiple loadLibrary calls).
        """
        methods: list[JniMethod] = []

        for root, _dirs, files in os.walk(src_dir):
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        source = fh.read()
                except OSError:
                    continue

                file_methods = self._scan_file(source)
                methods.extend(file_methods)

        return methods

    # ------------------------------------------------------------------

    def _scan_file(self, source: str) -> list[JniMethod]:
        """Parse a single Java source string and return found JniMethod objects."""

        # Derive package prefix
        pkg_match = _PACKAGE_RE.search(source)
        package = pkg_match.group(1) if pkg_match else ""

        # Extract all SO names loaded in this file
        so_names = _LOADLIB_RE.findall(source)

        # Primary SO name: use first occurrence; later code may refine per-class
        primary_so: Optional[str] = so_names[0] if so_names else None

        # Extract class names from file (simple heuristic: first class decl)
        class_names = _CLASS_DECL_RE.findall(source)

        # Build class->so_name map by scanning class blocks naively.
        # For most Android code a single file has one public class, so we
        # assign the file-level SO to all classes found.  A more precise
        # per-class scan would require a proper Java parser.
        class_so_map: dict[str, Optional[str]] = {
            cn: primary_so for cn in class_names
        }

        # Resolve a loadLibrary per class by checking which class block
        # contains each loadLibrary call (rough line-proximity heuristic).
        if so_names and class_names:
            class_so_map = self._refine_class_so_map(
                source, class_names, so_names, package
            )

        methods: list[JniMethod] = []

        for match in _NATIVE_METHOD_RE.finditer(source):
            return_type = match.group(1).strip()
            method_name = match.group(2).strip()
            raw_params = match.group(3).strip()

            # Find the enclosing class by scanning backwards from the match
            enclosing = self._find_enclosing_class(source, match.start(), class_names)
            if enclosing:
                fq_class = f"{package}.{enclosing}" if package else enclosing
            else:
                # Fallback: derive from file if class list is empty
                fq_class = package or "Unknown"

            so_name = class_so_map.get(enclosing or "", primary_so)
            signature = _build_jni_signature(raw_params, return_type)

            methods.append(JniMethod(
                class_name=fq_class,
                method_name=method_name,
                signature=signature,
                is_native=True,
                so_name=so_name,
                raw_params=raw_params,
            ))

        return methods

    # ------------------------------------------------------------------

    @staticmethod
    def _find_enclosing_class(source: str, pos: int, class_names: list[str]) -> Optional[str]:
        """Return the class name whose opening brace most recently precedes *pos*."""
        best_name: Optional[str] = None
        best_pos = -1
        for cn in class_names:
            # Find the last occurrence of the class declaration before pos
            pattern = re.compile(
                r'(?:class|interface|enum)\s+' + re.escape(cn) + r'[\s\w<>,]*\{'
            )
            for m in pattern.finditer(source[:pos]):
                if m.start() > best_pos:
                    best_pos = m.start()
                    best_name = cn
        return best_name

    @staticmethod
    def _refine_class_so_map(
        source: str,
        class_names: list[str],
        so_names: list[str],
        package: str,
    ) -> dict[str, Optional[str]]:
        """Associate each class name with its nearest preceding loadLibrary call."""
        # Build list of (pos, so_name) for each loadLibrary call
        lib_positions: list[tuple[int, str]] = []
        for m in _LOADLIB_RE.finditer(source):
            lib_positions.append((m.start(), m.group(1)))

        result: dict[str, Optional[str]] = {cn: None for cn in class_names}
        if not lib_positions:
            return result

        for cn in class_names:
            # Find class declaration position
            decl_re = re.compile(
                r'(?:class|interface|enum)\s+' + re.escape(cn) + r'[\s\w<>,]*\{'
            )
            m = decl_re.search(source)
            if not m:
                result[cn] = lib_positions[-1][1]
                continue
            class_start = m.start()
            # Find the last loadLibrary before or inside this class
            candidate: Optional[str] = None
            for lib_pos, lib_name in lib_positions:
                if lib_pos >= class_start:
                    candidate = lib_name
                    break
            if candidate is None:
                # Use the very last one if all appear after class declaration
                candidate = lib_positions[-1][1]
            result[cn] = candidate

        return result
