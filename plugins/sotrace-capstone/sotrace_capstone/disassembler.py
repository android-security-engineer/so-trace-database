"""CapstoneDisassembler — static disassembly of ELF/SO or raw binary using Capstone."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class InsnRecord:
    address: int          # virtual address as returned by Capstone
    mnemonic: str
    is_branch: bool
    is_call: bool
    branch_target: Optional[int]  # immediate target if known, else None


@dataclass
class CallRecord:
    caller_address: int
    callee_address: int   # 0 if indirect (blr/call reg)


@dataclass
class DisasmResult:
    instructions: list[InsnRecord] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Arch / mode helpers
# ---------------------------------------------------------------------------

# Mapping from arch name string to (capstone.CS_ARCH_*, capstone.CS_MODE_*)
_ARCH_MAP = {
    "aarch64":   ("CS_ARCH_ARM64", "CS_MODE_ARM"),
    "arm":       ("CS_ARCH_ARM",   "CS_MODE_ARM"),
    "arm_thumb": ("CS_ARCH_ARM",   "CS_MODE_THUMB"),
    "x86_64":    ("CS_ARCH_X86",   "CS_MODE_64"),
    "x86":       ("CS_ARCH_X86",   "CS_MODE_32"),
}

# ELF e_machine values → default arch string
# EM_386=3, EM_ARM=40, EM_X86_64=62, EM_AARCH64=183
_EM_TO_ARCH = {
    3:   "x86",
    40:  "arm",
    62:  "x86_64",
    183: "aarch64",
}

# ELF section flag: SHF_EXECINSTR
_SHF_EXECINSTR = 0x4
# ELF segment permission: PF_X
_PF_X = 0x1


def _resolve_arch_mode(arch_name: str):
    """Return (CS_ARCH, CS_MODE) capstone constants for the given arch string."""
    try:
        import capstone
    except ImportError:
        raise ImportError("capstone not installed — run: pip install capstone")

    entry = _ARCH_MAP.get(arch_name)
    if entry is None:
        raise ValueError(f"Unknown arch '{arch_name}'. Choices: {list(_ARCH_MAP)}")

    cs_arch = getattr(capstone, entry[0])
    cs_mode = getattr(capstone, entry[1])
    return cs_arch, cs_mode


# ---------------------------------------------------------------------------
# Main disassembler class
# ---------------------------------------------------------------------------

class CapstoneDisassembler:
    """Thin wrapper around capstone.Cs that also handles ELF parsing via pyelftools."""

    def __init__(self, arch: Optional[str] = None, mode_override: Optional[str] = None):
        """
        arch: one of 'aarch64', 'arm', 'arm_thumb', 'x86_64', 'x86', or None (auto from ELF).
        mode_override: reserved for future use; currently unused.
        """
        self._arch_name = arch  # may be None until ELF is parsed
        self._mode_override = mode_override
        self._cs = None  # created lazily after arch is known

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def disassemble_elf(self, path: str) -> DisasmResult:
        """Parse an ELF file, auto-detect arch, disassemble all executable sections."""
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.constants import SH_FLAGS
        except ImportError:
            raise ImportError(
                "pyelftools not installed — run: pip install pyelftools\n"
                "Alternatively, use --arch to force an arch and pass a raw binary."
            )

        result = DisasmResult()

        with open(path, "rb") as f:
            elf = ELFFile(f)

            # Auto-detect arch from ELF header if not forced by user
            if self._arch_name is None:
                e_machine = elf.header.e_machine
                # elftools returns a string like 'EM_AARCH64'; also check numeric
                if isinstance(e_machine, int):
                    arch = _EM_TO_ARCH.get(e_machine)
                else:
                    arch = _elf_machine_str_to_arch(e_machine)
                if arch is None:
                    raise ValueError(
                        f"Cannot auto-detect arch for e_machine={e_machine!r}. "
                        "Use --arch to specify explicitly."
                    )
                self._arch_name = arch
                logger.info(f"[capstone] ELF e_machine={e_machine!r} → arch={arch}")

            self._ensure_cs()

            # Try sections first (more precise)
            exec_sections = [
                sec for sec in elf.iter_sections()
                if sec.header.sh_flags & _SHF_EXECINSTR
                and sec.header.sh_size > 0
            ]

            if exec_sections:
                for sec in exec_sections:
                    data = sec.data()
                    base_va = sec.header.sh_addr
                    logger.info(
                        f"[capstone] Disassembling section '{sec.name}' "
                        f"VA=0x{base_va:x} size={len(data)}"
                    )
                    sub = self.disassemble_raw(data, base_addr=base_va)
                    result.instructions.extend(sub.instructions)
                    result.calls.extend(sub.calls)
            else:
                # Fall back to PT_LOAD segments with PF_X
                logger.warning("[capstone] No SHF_EXECINSTR sections found; using PT_LOAD+PF_X segments")
                for seg in elf.iter_segments():
                    if seg.header.p_type != "PT_LOAD":
                        continue
                    if not (seg.header.p_flags & _PF_X):
                        continue
                    data = seg.data()
                    base_va = seg.header.p_vaddr
                    logger.info(
                        f"[capstone] Disassembling PT_LOAD segment "
                        f"VA=0x{base_va:x} size={len(data)}"
                    )
                    sub = self.disassemble_raw(data, base_addr=base_va)
                    result.instructions.extend(sub.instructions)
                    result.calls.extend(sub.calls)

        logger.info(
            f"[capstone] Total: {len(result.instructions)} instructions, "
            f"{len(result.calls)} calls"
        )
        return result

    def disassemble_raw(self, data: bytes, base_addr: int = 0) -> DisasmResult:
        """Disassemble a raw byte buffer starting at base_addr."""
        self._ensure_cs()
        result = DisasmResult()

        try:
            import capstone
        except ImportError:
            raise ImportError("capstone not installed — run: pip install capstone")

        for insn in self._cs.disasm(data, base_addr):
            is_branch = (
                insn.group(capstone.CS_GRP_BRANCH)
                or insn.group(capstone.CS_GRP_JUMP)
            )
            is_call = insn.group(capstone.CS_GRP_CALL)
            branch_target: Optional[int] = None

            if (is_branch or is_call) and insn.operands:
                # For immediate operands extract the target address
                try:
                    op = insn.operands[0]
                    # capstone operand types: IMM=2
                    if op.type == capstone.arm64.ARM64_OP_IMM if hasattr(capstone, 'arm64') else False:
                        branch_target = op.imm
                    elif op.type == capstone.x86.X86_OP_IMM if hasattr(capstone, 'x86') else False:
                        branch_target = op.imm
                    elif op.type == capstone.arm.ARM_OP_IMM if hasattr(capstone, 'arm') else False:
                        branch_target = op.imm
                    else:
                        # Generic fallback: check common IMM type constant (2)
                        if op.type == 2:
                            branch_target = op.imm
                except Exception:
                    pass

            rec = InsnRecord(
                address=insn.address,
                mnemonic=insn.mnemonic,
                is_branch=bool(is_branch),
                is_call=bool(is_call),
                branch_target=branch_target,
            )
            result.instructions.append(rec)

            if is_call:
                callee = branch_target if branch_target is not None else 0
                result.calls.append(CallRecord(
                    caller_address=insn.address,
                    callee_address=callee,
                ))

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_cs(self):
        """Lazily create the capstone.Cs instance once arch is known."""
        if self._cs is not None:
            return
        if self._arch_name is None:
            raise RuntimeError("Arch not set — call disassemble_elf() or set --arch explicitly")
        try:
            import capstone
        except ImportError:
            raise ImportError("capstone not installed — run: pip install capstone")

        cs_arch, cs_mode = _resolve_arch_mode(self._arch_name)
        cs = capstone.Cs(cs_arch, cs_mode)
        cs.detail = True  # required for group/operand inspection
        self._cs = cs
        logger.info(f"[capstone] Cs created arch={self._arch_name}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _elf_machine_str_to_arch(machine_str: str) -> Optional[str]:
    """Map elftools e_machine string to our arch name."""
    s = machine_str.upper()
    if "AARCH64" in s:
        return "aarch64"
    if "ARM" in s:
        return "arm"
    if "X86_64" in s or "AMD64" in s:
        return "x86_64"
    if "386" in s or "X86" in s:
        return "x86"
    return None
