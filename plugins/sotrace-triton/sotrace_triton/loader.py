"""ELF segment loader for Triton contexts.

Tries lief → pyelftools → raw file mapping, in that order.
"""


def load_elf_segments(ctx, elf_path: str, base: int) -> int:
    """
    Map PT_LOAD segments of an ELF/SO file into the Triton memory context.

    Returns the total loaded size (max_vaddr - min_vaddr), or len(raw_bytes)
    when falling back to raw mapping.
    """
    # --- lief (preferred) ---------------------------------------------------
    try:
        import lief  # type: ignore
        binary = lief.parse(elf_path)
        load_segs = [s for s in binary.segments
                     if s.type == lief.ELF.SEGMENT_TYPES.LOAD]
        if not load_segs:
            raise ValueError("no PT_LOAD segments found via lief")
        min_va = min(s.virtual_address for s in load_segs)
        max_va = 0
        for seg in load_segs:
            va = seg.virtual_address
            content = bytes(seg.content)
            ctx.setConcreteMemoryAreaValue(base + va - min_va, content)
            max_va = max(max_va, va + seg.virtual_size)
        return max_va - min_va
    except ImportError:
        pass
    except Exception:
        pass

    # --- pyelftools ----------------------------------------------------------
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            loads = [s for s in elf.iter_segments()
                     if s.header.p_type == 'PT_LOAD']
            if not loads:
                raise ValueError("no PT_LOAD segments via pyelftools")
            min_va = min(s.header.p_vaddr for s in loads)
            max_va = 0
            for seg in loads:
                va = seg.header.p_vaddr
                data = seg.data()
                ctx.setConcreteMemoryAreaValue(base + va - min_va, data)
                max_va = max(max_va, va + seg.header.p_memsz)
        return max_va - min_va
    except ImportError:
        pass
    except Exception:
        pass

    # --- Raw fallback --------------------------------------------------------
    with open(elf_path, 'rb') as f:
        data = f.read()
    ctx.setConcreteMemoryAreaValue(base, data)
    return len(data)
