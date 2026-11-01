# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/analyze_fifo.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
"""Find stores and loads to a hardware address window in extracted assembly.

Usage: analyze_fifo.py LO HI GLOB...   e.g. analyze_fifo.py 0xLOW 0xHIGH 'libglcore/asm/*/*.s'

Tracks lui/ori/addiu constants within a basic block and reports every
memory access whose effective address falls in [LO, HI]. The window comes
from your own findings: nothing board-specific is built in.
"""
import glob
import re
import sys

if len(sys.argv) < 4:
    sys.exit(__doc__)
LO, HI = int(sys.argv[1], 0), int(sys.argv[2], 0)
files = sorted(f for pat in sys.argv[3:] for f in glob.glob(pat))

# Matches lui $reg, 0xNN
lui_re = re.compile(r'^\s*lui\s+(\$[a-z0-9]+)\s*,\s*0x([0-9a-fA-F]+)')
# Matches ori $reg, $reg, 0xNN
ori_re = re.compile(r'^\s*ori\s+(\$[a-z0-9]+)\s*,\s*(\$[a-z0-9]+)\s*,\s*0x([0-9a-fA-F]+)')
# Matches addiu $reg, $reg, NN
addiu_re = re.compile(r'^\s*addiu\s+(\$[a-z0-9]+)\s*,\s*(\$[a-z0-9]+)\s*,\s*(-?[0-9]+)')
# Matches sw/swc1/sd/sh/sb/lw/lwc1 $src, off($base)
mem_re = re.compile(r'^\s*(swc1|sw|sdc1|sd|sh|sb|lwc1|lw|ldc1|ld|lh|lhu|lb|lbu)\s+(\$[a-z0-9]+)\s*,\s*(-?[0-9]+)\((\$[a-z0-9]+)\)')

fifo_accesses = {}

for f in files:
    fname = f.split('/')[-1]
    with open(f) as fp:
        lines = fp.readlines()
    
    regs = {}
    for idx, line in enumerate(lines):
        line_clean = line.split('#')[0].strip()
        if not line_clean:
            continue
        
        # Check if line defines a label or function end - clear regs across basic blocks
        if line_clean.endswith(':') or line_clean.startswith('.end') or line_clean.startswith('b ') or line_clean.startswith('jr '):
            regs = {}
            continue

        m = lui_re.match(line_clean)
        if m:
            r = m.group(1)
            v = int(m.group(2), 16) << 16
            regs[r] = v
            continue

        m = ori_re.match(line_clean)
        if m:
            dst = m.group(1)
            src = m.group(2)
            imm = int(m.group(3), 16)
            if src in regs:
                regs[dst] = regs[src] | imm
            continue

        m = addiu_re.match(line_clean)
        if m:
            dst = m.group(1)
            src = m.group(2)
            imm = int(m.group(3))
            if src in regs:
                regs[dst] = regs[src] + imm
            continue

        m = mem_re.match(line_clean)
        if m:
            op = m.group(1)
            src = m.group(2)
            offset = int(m.group(3))
            base = m.group(4)
            if base in regs:
                addr = regs[base] + offset
                if LO <= addr <= HI:
                    # capture next 5 instructions to see payload sequence
                    context = [lines[idx+i].strip() for i in range(1, min(8, len(lines)-idx))]
                    fifo_accesses.setdefault(addr, []).append({
                        'file': fname,
                        'line': idx+1,
                        'op': op,
                        'src': src,
                        'full': line.strip(),
                        'next': context
                    })

print(f"Discovered {len(fifo_accesses)} distinct hardware addresses in the window:")
for addr in sorted(fifo_accesses.keys()):
    accs = fifo_accesses[addr]
    ops = sorted(list(set([a['op'] for a in accs])))
    files = sorted(list(set([a['file'] for a in accs])))
    print(f"0x{addr:06x}: {len(accs):3d} refs, ops={ops}, files={files[:3]}")
