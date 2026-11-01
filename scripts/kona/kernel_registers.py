"""List every register the kernel driver reads or writes through gfx_pio_*_32.

Usage: kernel_registers.py [DISASM_DIR] > kona_kernel/registers.tsv
       default DISASM_DIR: kona_kernel/disasm

The driver reaches the pipe's registers with one pair of helpers,
gfx_pio_read_32(addr) and gfx_pio_write_32(addr, value), where addr is the
pipe's register base (a per-pipe state word) plus a constant built with
lui/ori. This scans each function for those calls, recovers the constant
from the instructions just before the call and prints one row per
(member, function, offset, direction, count). A call whose offset cannot be
recovered from the preceding instructions prints offset "?" (these are the
command-word writes and the writes whose address comes from a data
structure). Offsets of 0x800000 and above get the HH_ name HIP.h gives
(the name is looked up by the low 12 bits; HIP1 and HIP2 may name the same
offset differently, and both are listed). Small offsets are registers of the
pipe's Xtalk widget (docs/xg.md); window labels are the names HIP.h and
docs/xg.md use.
"""
import collections
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else 'kona_kernel/disasm'
names = {}
for line in open('HIP.h'):
    m = re.match(r'#define KONA_(?:HIP[12]_)?(HH_\w+)\s+(0x[0-9a-f]+)', line)
    if m:
        names.setdefault(int(m.group(2), 16), []).append(m.group(1))

lui = re.compile(r'\s*lui\s+(\$\w+),(0x[0-9a-f]+|\d+)')
ori = re.compile(r'\s*(?:ori|addiu|daddiu)\s+(\$\w+),(\$\w+),(0x[0-9a-f]+|-?\d+)')
li = re.compile(r'\s*li\s+(\$\w+),(0x[0-9a-f]+|-?\d+)')
call = re.compile(r'\s*jal\s+gfx_pio_(read|write)_32')
base = re.compile(r'\s*ld\s+(\$\w+),2376\(')
add = re.compile(r'\s*d?addu\s+(\$\w+),(\$\w+),(\$\w+)')
mov = re.compile(r'\s*move\s+(\$\w+),(\$\w+)')
glabel = re.compile(r'glabel (\w+)')

CMD = 'cmd'   # the command-port pointer, pipe state +2304 (0x900)
cmdport = re.compile(r'\s*ld\s+(\$\w+),2304\(')
jal = re.compile(r'\s*jal\s+(\w+)')
kept = re.compile(r'\$(s\d|s8|sp|gp|fp)$')


def step(regs, s):
    """Replay one instruction on the map of registers holding known values."""
    for pat, kind in ((lui, 'lui'), (cmdport, 'cmd'), (base, 'base'), (ori, 'ori'),
                      (li, 'li'), (add, 'add'), (mov, 'mov')):
        m = pat.match(s)
        if not m:
            continue
        if kind == 'lui':
            regs[m.group(1)] = int(m.group(2), 0) << 16
        elif kind == 'cmd':
            regs[m.group(1)] = CMD
        elif kind == 'base':
            regs[m.group(1)] = 0   # the pipe's register base, state offset 2376 (0x948)
        elif kind == 'ori':
            src = regs.get(m.group(2))
            if isinstance(src, int):
                v = int(m.group(3), 0)
                regs[m.group(1)] = src | v if 'ori' in s else src + v
            else:
                regs.pop(m.group(1), None)
        elif kind == 'li':
            regs[m.group(1)] = int(m.group(2), 0)
        elif kind == 'add':
            a, b = regs.get(m.group(2)), regs.get(m.group(3))
            if isinstance(a, int) and isinstance(b, int):
                regs[m.group(1)] = a + b
            else:
                regs.pop(m.group(1), None)
        elif kind == 'mov':
            if m.group(2) in regs:
                regs[m.group(1)] = regs[m.group(2)]
            else:
                regs.pop(m.group(1), None)
        return
    # any other instruction that writes a register forgets it
    m = re.match(r'\s*[a-z.0-9]+\s+(\$\w+),', s)
    if m and not re.match(r'\s*(s[bhwd]|sw[lr]|sd[lr]|b\w*|teq|tne|mt\w*|div\w*|mult\w*)\s', s):
        regs.pop(m.group(1), None)


rows = collections.Counter()
for member in sorted(os.listdir(root)):
    p = os.path.join(root, member, member + '.text.s')
    if not os.path.exists(p):
        continue
    func = '?'
    lines = open(p).read().split('\n')
    regs = {}
    skip = False
    for i, ln in enumerate(lines):
        if skip:
            skip = False
            continue
        g = glabel.match(ln)
        if g:
            func = g.group(1)
            regs = {}
            continue
        j = jal.match(ln)
        if not j:
            step(regs, ln)
            if re.match(r'\s*(b|j|jr)\s', ln):
                # an unconditional transfer: what follows its delay slot is
                # reached only by a branch, so only the saved registers,
                # which this compiler keeps fixed across a function's
                # loops, are carried over
                if i + 1 < len(lines):
                    step(regs, lines[i + 1])
                regs = {r: v for r, v in regs.items() if kept.match(r)}
                skip = True
            continue
        # the delay slot runs before the call
        if i + 1 < len(lines):
            step(regs, lines[i + 1])
        skip = True
        c = call.match(ln)
        if c:
            # the address argument is $a0 at the call. Values are followed in
            # text order through labels, so a value reached only by a branch
            # from elsewhere stays unknown rather than taking a wrong one.
            off = regs.get('$a0')
            if off == CMD:
                key = (member, func, 'cmd', c.group(1))
            else:
                if off is not None and off % 4:
                    off = None   # a 32-bit register offset is a multiple of 4
                key = (member, func, '?' if off is None else '0x%x' % off, c.group(1))
            rows[key] += 1
        regs = {r: v for r, v in regs.items() if kept.match(r)}

print('member\tfunction\toffset\tdirection\tcalls\twindow\tname')
for (member, func, off, d), n in sorted(rows.items()):
    nm = ''
    if off == 'cmd':
        win = 'command port (pointer at pipe state +2304)'
    elif off != '?':
        v = int(off, 16)
        nm = ','.join(sorted(set(names.get(v & 0xfff, []))) if v >= 0x800000 else [])
        win = ('host-interface window' if v >= 0x800000 and v < 0xc00000 else
               'host-interface alias 0xc00000' if v >= 0xc00000 else 'pipe base offset (XG widget registers, docs/xg.md)')
    else:
        win = 'address from a data structure or reached by a branch (see docs/kernel.md)'
    print('\t'.join([member, func, off, d, str(n), win, nm]))
