#!/usr/bin/env bash
# Examples for sotrace-capstone — static ELF/SO disassembly via Capstone

set -euo pipefail

# Install dependencies (pure Python, no Rust/native build required)
pip install capstone pyelftools

# -----------------------------------------------------------------------
# Basic usage: auto-detect arch from ELF, upload to sotrace-server
# -----------------------------------------------------------------------
python sotrace-capstone.py libfoo.so \
    --server http://192.168.1.83:3000

# -----------------------------------------------------------------------
# Save to JSONL file for later inspection or offline import
# -----------------------------------------------------------------------
python sotrace-capstone.py libfoo.so --output trace.jsonl

# -----------------------------------------------------------------------
# Force ARM32 Thumb mode (e.g. mixed ARM32 library)
# -----------------------------------------------------------------------
python sotrace-capstone.py libfoo.so \
    --arch arm_thumb \
    --server http://192.168.1.83:3000

# -----------------------------------------------------------------------
# x86-64 library with explicit load base for SO-relative offsets
# -----------------------------------------------------------------------
python sotrace-capstone.py libfoo.so \
    --arch x86_64 \
    --base 0x7f0000000000 \
    --server http://192.168.1.83:3000

# -----------------------------------------------------------------------
# Raw binary snippet (no ELF header): specify arch, offset and size
# -----------------------------------------------------------------------
python sotrace-capstone.py payload.bin \
    --arch aarch64 \
    --offset 0x200 \
    --size 0x1000 \
    --server http://192.168.1.83:3000

# -----------------------------------------------------------------------
# Verbose output for debugging
# -----------------------------------------------------------------------
python sotrace-capstone.py libfoo.so \
    --server http://192.168.1.83:3000 \
    --verbose
