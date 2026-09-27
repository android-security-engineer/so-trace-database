"""Parse QEMU user-mode -d in_asm,exec debug log output."""

import re
from typing import List, Tuple

# Matches instruction lines: "0x0000000000401000:  d10083ff  sub  sp, sp, #0x20"
INSN_LINE = re.compile(r'^\s*(0x[0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+(.+)')

# Matches exec trace lines: "Trace 0x5596e22dd010 [0000000000401000] main"
EXEC_TRACE = re.compile(r'^Trace\s+\S+\s+\[([0-9a-fA-F]+)\]')

# AArch64/ARM branch mnemonics (first word of disassembly)
_BRANCH_MNEMONICS = frozenset({
    'b', 'bl', 'br', 'blr', 'ret', 'eret',
    'cbz', 'cbnz', 'tbz', 'tbnz',
    'beq', 'bne', 'blt', 'bgt', 'ble', 'bge',
    'bhi', 'blo', 'bpl', 'bmi', 'bvs', 'bvc',
    'bcs', 'bcc', 'bhs', 'bls', 'bal', 'bnv',
    # x86
    'jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'ja', 'jae', 'jb', 'jbe', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp',
    'jcxz', 'jecxz', 'jrcxz', 'call', 'ret', 'retn', 'retf', 'loop', 'loope', 'loopne',
})


def _is_branch_mnemonic(mnemonic: str) -> bool:
    first = mnemonic.strip().lower().split()[0].rstrip('.')
    return first in _BRANCH_MNEMONICS


class QemuLogParser:
    """
    Parses QEMU user-mode -d in_asm[,exec] log into sotrace instruction records.

    Two modes:
    - static (in_asm only): each basic block's instructions appear once,
      reflecting disassembly order, not runtime execution order.
    - dynamic (in_asm + exec): exec lines drive a replay that reconstructs
      the actual execution sequence by replaying BBs in exec order.
    """

    def __init__(self, so_base: int = 0, so_size: int = 0, so_name: str = ""):
        """
        Args:
            so_base: VA of the SO's first executable segment (0 = no filtering)
            so_size: byte length of that segment (0 = no upper bound filter)
            so_name: informational only
        """
        self.so_base = so_base
        self.so_size = so_size
        self.so_name = so_name

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, log_path: str) -> List[dict]:
        """
        Parse a QEMU log file and return a list of instruction records.

        If the log contains Trace/exec lines the method produces a dynamic
        sequence; otherwise it falls back to the static in_asm order.
        """
        bbs, exec_seq = self._load_log(log_path)

        if exec_seq:
            return self._build_dynamic(bbs, exec_seq)
        else:
            return self._build_static(bbs)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_log(self, log_path: str):
        """
        First pass: collect basic blocks (addr → [insn, ...]) and exec sequence.
        Returns (bbs: dict[int, list[dict]], exec_seq: list[int]).
        """
        bbs: dict = {}       # bb_start_addr → list of raw instruction dicts
        exec_seq: list = []  # ordered list of bb start addresses (exec trace)
        current_bb_start = None
        current_bb_insns: list = []

        with open(log_path, 'r', errors='replace') as f:
            for line in f:
                # Exec trace line
                m_exec = EXEC_TRACE.match(line)
                if m_exec:
                    exec_seq.append(int(m_exec.group(1), 16))
                    continue

                # Instruction line
                m_insn = INSN_LINE.match(line)
                if m_insn:
                    addr = int(m_insn.group(1), 16)
                    mnemonic = m_insn.group(2).strip()
                    insn = {"addr": addr, "mnemonic": mnemonic}

                    if current_bb_start is None or addr < current_bb_start or (
                        current_bb_insns and addr > current_bb_insns[-1]["addr"] + 16
                        and addr < current_bb_start
                    ):
                        # New basic block
                        if current_bb_start is not None and current_bb_insns:
                            bbs[current_bb_start] = current_bb_insns
                        current_bb_start = addr
                        current_bb_insns = [insn]
                    else:
                        current_bb_insns.append(insn)
                    continue

                # Separator / IN: header → flush current bb
                if line.startswith('IN:') or line.startswith('----'):
                    if current_bb_start is not None and current_bb_insns:
                        bbs[current_bb_start] = current_bb_insns
                    current_bb_start = None
                    current_bb_insns = []

        if current_bb_start is not None and current_bb_insns:
            bbs[current_bb_start] = current_bb_insns

        return bbs, exec_seq

    def _build_dynamic(self, bbs: dict, exec_seq: list) -> List[dict]:
        """Replay exec sequence, expanding each BB into its instructions."""
        records = []
        seq = 0
        for bb_start in exec_seq:
            insns = bbs.get(bb_start)
            if insns is None:
                # BB not in log (filtered out by QEMU or outside capture range)
                continue
            for insn in insns:
                if not self._in_so_range(insn["addr"]):
                    continue
                seq += 1
                records.append(self._make_record(seq, insn["addr"], insn["mnemonic"]))
        return records

    def _build_static(self, bbs: dict) -> List[dict]:
        """Emit all instructions in address order (static disassembly view)."""
        records = []
        seq = 0
        for bb_start in sorted(bbs):
            for insn in bbs[bb_start]:
                if not self._in_so_range(insn["addr"]):
                    continue
                seq += 1
                records.append(self._make_record(seq, insn["addr"], insn["mnemonic"]))
        return records

    def _in_so_range(self, addr: int) -> bool:
        if not self.so_base:
            return True
        if not self.so_size:
            return addr >= self.so_base
        return self.so_base <= addr < self.so_base + self.so_size

    def _make_record(self, seq: int, addr: int, mnemonic: str) -> dict:
        offset = addr - self.so_base if self.so_base else addr
        return {
            "seq": seq,
            "thread_id": 1,
            "address": offset,
            "is_branch": _is_branch_mnemonic(mnemonic),
            "branch_taken": False,
        }


# ------------------------------------------------------------------
# SO range estimation helpers
# ------------------------------------------------------------------

def estimate_so_range_from_log(log_path: str, so_name: str = "") -> Tuple[int, int]:
    """
    Scan all instruction addresses in the log and return (base, size).

    Heuristic: addresses within 64 MiB of each other are considered part of
    the same segment.  The segment containing the most addresses is returned.
    Returns (0, 0) if the log is empty or unreadable.
    """
    addrs = []
    try:
        with open(log_path, 'r', errors='replace') as f:
            for line in f:
                m = INSN_LINE.match(line)
                if m:
                    addrs.append(int(m.group(1), 16))
    except OSError:
        return 0, 0

    if not addrs:
        return 0, 0

    addrs.sort()

    # Split into contiguous segments (gap > 64 MiB → new segment)
    GAP = 64 << 20
    segments: list = []
    seg_start = addrs[0]
    seg_end = addrs[0]
    count = 1

    for a in addrs[1:]:
        if a - seg_end > GAP:
            segments.append((seg_start, seg_end + 4, count))
            seg_start = a
            count = 1
        else:
            count += 1
        seg_end = a

    segments.append((seg_start, seg_end + 4, count))

    # Return the largest segment by instruction count
    best = max(segments, key=lambda s: s[2])
    return best[0], best[1] - best[0]


def find_so_base_from_maps(pid: int, so_name: str) -> Tuple[int, int]:
    """
    Read /proc/<pid>/maps and return (base, size) for the first r-xp mapping
    whose path contains so_name.  Returns (0, 0) on failure.
    """
    try:
        with open(f'/proc/{pid}/maps') as f:
            for line in f:
                if so_name in line and 'r-xp' in line:
                    parts = line.split()
                    start_s, end_s = parts[0].split('-')
                    start = int(start_s, 16)
                    end = int(end_s, 16)
                    return start, end - start
    except OSError:
        pass
    return 0, 0
