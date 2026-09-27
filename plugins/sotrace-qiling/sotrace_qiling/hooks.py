"""Qiling hook callbacks for instruction, memory, and sync event collection."""

import struct

# AArch64 branch opcode masks (top 6 bits)
# B/BL:     op[31:26] = 0b000101 (B) or 0b100101 (BL)
# CBZ/CBNZ: op[31:24] = 0b0011010x / 0b1011010x  -> [31:25] = 0b0011010 / 0b1011010
# TBZ/TBNZ: op[31:25] = 0b0110110 / 0b1110110 for 32-bit, or 0b0110111 / 0b1110111
_AARCH64_BRANCH_MASKS = [
    (0xFC000000, 0x14000000),  # B
    (0xFC000000, 0x94000000),  # BL
    (0x7E000000, 0x34000000),  # CBZ  (W/X)
    (0x7E000000, 0x35000000),  # CBNZ (W/X)
    (0x7F000000, 0x36000000),  # TBZ  (32-bit)
    (0x7F000000, 0x37000000),  # TBNZ (32-bit)
    (0xFF000000, 0xD6000000),  # BR / BLR / RET family
]


def _is_branch_opcode(ql, address: int) -> bool:
    """Quick branch detection by reading the raw 4-byte opcode."""
    try:
        raw = bytes(ql.mem.read(address, 4))
        insn = struct.unpack_from('<I', raw)[0]
        for mask, expected in _AARCH64_BRANCH_MASKS:
            if (insn & mask) == expected:
                return True
    except Exception:
        pass
    return False


def make_code_hook(plugin):
    """Return a code hook callback bound to the given plugin."""
    def _on_instruction(ql, address, size):
        try:
            seq = plugin.batcher.next_seq()
            is_branch = size == 4 and _is_branch_opcode(ql, address)
            plugin.batcher.add_instruction({
                "seq": seq,
                "thread_id": 1,
                "address": address - plugin.so_base if plugin.so_base else address,
                "is_branch": is_branch,
                "branch_taken": False,
            })
            if plugin.batcher.size() >= plugin.batch_size and plugin.server_url:
                plugin._auto_flush()
        except Exception:
            pass
    return _on_instruction


def make_mem_write_hook(plugin):
    """Return a memory-write hook callback bound to the given plugin."""
    def _on_mem_write(ql, access, address, size, value):
        try:
            step = plugin.batcher.next_seq()
            # value is an integer; convert to little-endian bytes
            data = list(value.to_bytes(max(size, 1), 'little')[:size])
            plugin.batcher.add_memory_write({
                "step": step,
                "thread_id": 1,
                "address": address - plugin.so_base if plugin.so_base else address,
                "data": data,
            })
        except Exception:
            pass
    return _on_mem_write


def make_mem_read_hook(plugin):
    """Return a memory-read hook callback bound to the given plugin."""
    def _on_mem_read(ql, access, address, size, value):
        try:
            step = plugin.batcher.next_seq()
            plugin.batcher.add_memory_read({
                "step": step,
                "thread_id": 1,
                "address": address - plugin.so_base if plugin.so_base else address,
                "size": size,
            })
        except Exception:
            pass
    return _on_mem_read


# Sync event type mapping (futex op codes)
_FUTEX_WAIT = 0
_FUTEX_WAKE = 1
_FUTEX_LOCK_PI = 6
_FUTEX_UNLOCK_PI = 7

_FUTEX_OP_MAP = {
    _FUTEX_WAIT:      "CondvarWait",
    _FUTEX_WAKE:      "CondvarSignal",
    _FUTEX_LOCK_PI:   "MutexLock",
    _FUTEX_UNLOCK_PI: "MutexUnlock",
}


def make_futex_hook(plugin):
    """Return a futex syscall hook that records sync events."""
    def _on_futex(ql, *args):
        try:
            # futex(uaddr, futex_op, val, ...)
            # On AArch64: x0=uaddr, x1=futex_op, x2=val
            # On ARM32:   r0=uaddr, r1=futex_op, r2=val
            try:
                arch = ql.arch.type.name.lower()  # 'arm', 'arm64', 'x86', 'x8664'
            except Exception:
                arch = ''

            if 'arm64' in arch or 'aarch64' in arch:
                uaddr = ql.arch.regs.x0
                futex_op = ql.arch.regs.x1 & 0x7F  # strip FUTEX_PRIVATE_FLAG
            else:
                uaddr = ql.arch.regs.r0
                futex_op = ql.arch.regs.r1 & 0x7F

            sync_type = _FUTEX_OP_MAP.get(futex_op)
            if sync_type:
                step = plugin.batcher.next_seq()
                plugin.batcher.add_sync({
                    "step": step,
                    "thread_id": 1,
                    "sync_type": sync_type,
                    "sync_object_addr": uaddr,
                    "result": "Success",
                })
        except Exception:
            pass
    return _on_futex


def _make_named_mutex_hook(plugin, sync_type: str):
    """Return a code hook for a named pthread_mutex_* symbol entry."""
    def _hook(ql, address, size):
        try:
            arch = ''
            try:
                arch = ql.arch.type.name.lower()
            except Exception:
                pass
            if 'arm64' in arch or 'aarch64' in arch:
                mutex_addr = ql.arch.regs.x0
            else:
                mutex_addr = ql.arch.regs.r0
            step = plugin.batcher.next_seq()
            plugin.batcher.add_sync({
                "step": step,
                "thread_id": 1,
                "sync_type": sync_type,
                "sync_object_addr": mutex_addr,
                "result": "Success",
            })
        except Exception:
            pass
    return _hook


PTHREAD_SYNC_SYMBOLS = {
    "pthread_mutex_lock":      "MutexLock",
    "pthread_mutex_unlock":    "MutexUnlock",
    "pthread_mutex_trylock":   "MutexTryLock",
    "pthread_mutex_timedlock": "MutexLock",
    "pthread_rwlock_rdlock":   "RwLockRead",
    "pthread_rwlock_wrlock":   "RwLockWrite",
    "pthread_rwlock_unlock":   "RwLockUnlock",
    "pthread_cond_wait":       "CondvarWait",
    "pthread_cond_signal":     "CondvarSignal",
    "pthread_cond_broadcast":  "CondvarBroadcast",
}


def try_hook_pthread_symbols(ql, plugin):
    """Attempt to hook pthread_mutex_* via symbol lookup (best-effort)."""
    try:
        for sym_name, sync_type in PTHREAD_SYNC_SYMBOLS.items():
            try:
                addr = ql.os.find_symbol(sym_name)
                if addr and addr != 0:
                    cb = _make_named_mutex_hook(plugin, sync_type)
                    ql.hook_address(cb, addr)
            except Exception:
                pass
    except Exception:
        pass
