"""List the command tokens the kernel driver itself writes to the pipe.

Usage: kernel_commands.py [DISASM_DIR] > kona_kernel/commands.tsv
       default DISASM_DIR: kona_kernel/disasm

The driver sends a packet by writing a token word and then payload words to
the pipe's command port (the address held in the per-pipe state at offset
2304, 0x900). The token is a constant loaded just before the write. This
scans every function for a write through that port whose value is a constant
in the token range of GE.h (0x160 and up; smaller constants are payload
values) and prints (member, function, token, name, number of sites). Tokens
the driver builds from a variable, and the user-supplied command groups of
the DMA ioctls, do not appear. Payload lengths are not counted here: the
code is full of retry branches, so they are read by hand (docs/kernel.md).
"""

import collections
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else 'kona_kernel/disasm'
names = {}
for line in open('GE.h'):
    m = re.match(r'\s*(KONA_HP_\w+)\s*=\s*(0x[0-9a-f]+)', line)
    if m:
        names[int(m.group(2), 16)] = m.group(1)

glabel = re.compile(r'glabel (\w+)')
li = re.compile(r'\s*(?:li|addiu)\s+\$a1,(?:\$zero,)?(0x[0-9a-f]+|-?\d+)')
call = re.compile(r'\s*jal\s+gfx_pio_write_32')
port = re.compile(r'\s*ld\s+\$a0,2304\(')

rows = collections.Counter()
for member in sorted(os.listdir(root)):
    p = os.path.join(root, member, member + '.text.s')
    if not os.path.exists(p):
        continue
    func = '?'
    lines = open(p).read().split('\n')
    for i, ln in enumerate(lines):
        g = glabel.match(ln)
        if g:
            func = g.group(1)
        if not call.match(ln):
            continue
        near = lines[max(0, i - 4):i + 2]
        if not any(port.match(x) for x in near):
            continue
        for x in near:
            m = li.match(x)
            if m and int(m.group(1), 0) in names and int(m.group(1), 0) >= 0x160:
                rows[(member, func, int(m.group(1), 0))] += 1   # smaller values are payload constants
print('member\tfunction\ttoken\tname\tsites')
for (member, func, v), n in sorted(rows.items()):
    print('\t'.join([member, func, '0x%x' % v, names[v], str(n)]))
