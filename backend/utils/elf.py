import hashlib
import io
from typing import Optional
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def compute_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_arch(elf: ELFFile) -> str:
    machine = elf.get_machine_arch()
    arch_map = {
        "AArch64": "arm64",
        "ARM": "arm32",
        "x64": "x86_64",
        "x86": "x86",
        "MIPS": "mips",
    }
    return arch_map.get(machine, machine)


def parse_elf(data: bytes) -> dict:
    """Parse ELF binary and return functions, symbols, segments."""
    f = io.BytesIO(data)
    elf = ELFFile(f)

    arch = parse_arch(elf)

    # Parse segments
    segments = []
    for seg in elf.iter_segments():
        if seg.header.p_type in ("PT_LOAD", "PT_DYNAMIC"):
            segments.append({
                "name": seg.header.p_type,
                "vaddr": seg.header.p_vaddr,
                "filesz": seg.header.p_filesz,
                "memsz": seg.header.p_memsz,
                "flags": seg.header.p_flags,
            })

    # Parse symbols and functions from symbol table
    functions = []
    symbols = []
    seen_funcs = set()

    dynsym = elf.get_section_by_name(".dynsym")
    symtab = elf.get_section_by_name(".symtab")

    for section in [dynsym, symtab]:
        if section is None or not isinstance(section, SymbolTableSection):
            continue
        is_imported = (section.name == ".dynsym")
        for sym in section.iter_symbols():
            name = sym.name
            if not name:
                continue
            addr = sym["st_value"]
            sym_type = sym["st_info"]["type"]
            size = sym["st_size"]

            symbols.append({
                "name": name,
                "address": addr,
                "symbol_type": sym_type,
            })

            if sym_type == "STT_FUNC" and name not in seen_funcs:
                seen_funcs.add(name)
                functions.append({
                    "name": name,
                    "offset": addr,
                    "size": size,
                    "is_jni": name.startswith("Java_") or name.startswith("JNI_"),
                    "is_imported": is_imported and addr == 0,
                    "is_exported": not (is_imported and addr == 0),
                })

    return {
        "arch": arch,
        "functions": functions,
        "symbols": symbols,
        "segments": segments,
    }
