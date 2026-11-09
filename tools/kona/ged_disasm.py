"""Disassemble the distributor program (ged1b.u) with the field layout the
IR diagnostic uses to build distributor instructions.

Usage: ged_disasm.py [GED1B_U] [OUT]
       defaults: ucode/KONA/ged1b.u ucode/ged_listing.txt

Field layout: irsaudit (usr/diags/IR/bin/irsaudit, IRIX 6.5.30m) packs a
13-field structure into one 32-bit distributor word in Compact_GED_Ucode
(0x1013fc60); ucode/ged.md gives the layout and the evidence. Bits 31-30
pick one of four word types:

  0  control:  29-27 sub, 26 fetch, 25-24 x, 23 y, 22-17 r, 16 a, 15 b,
               13 c, 12 release, 11-10 z, 9-0 n
  1  transfer: 29-27 op, 26 fetch, 25 p, 24 q, 23-16 register (one-hot
               for ops 5 and 7), 15-10 value (ops 1-3), 9-0 target
  2  load:     29-27 op, 26 fetch, 25-24 x, 23 y, 22-16 register,
               15-0 immediate (ops 0 and 2)
  3  (only bits 31-30 are set by the packer)

The mnemonics are labels for the word types, not hardware names. The
listing also shows the source file and line from the file's line table,
the indexes of the 512-entry table B that start at each word and, for loads of
registers 62 and 69-72, the geometry-engine slot the ARM relocates
(ucode/ged_relocs.tsv).
"""
import csv
import struct
import sys

ged = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/ged1b.u'
out = sys.argv[2] if len(sys.argv) > 2 else 'ucode/ged_listing.txt'

b = open(ged, 'rb').read()
hdr = struct.unpack('>11I', b[:44])
code = b[hdr[3]:hdr[3] + hdr[4]]
_, blen = struct.unpack('>II', code[:8])
prog = [struct.unpack('>I', code[8 + 4 * i:12 + 4 * i])[0] for i in range(blen // 4)]
toff = 16 + blen
tables = [struct.unpack('>I', code[toff + 4 * i:toff + 4 * i + 4])[0] for i in range(528)]
table_a, table_b = tables[:16], tables[16:]
files = [x.decode().split('/')[-1] for x in b[hdr[9]:hdr[9] + hdr[10]].split(b'\0')][:18]
lt = b[hdr[5]:hdr[5] + hdr[6]]
line = {}
for i in range(0, len(lt), 8):
    a, ln, f = struct.unpack('>IHH', lt[i:i + 8])
    line[a] = (files[f], ln)

handler = {}
try:
    for r in csv.reader((x for x in open('ucode/ged_relocs.tsv') if not x.startswith('#')), delimiter='\t'):
        if r[0] != 'ged_word':
            handler[int(r[0], 16)] = r[5]
except OSError:
    pass

ONEHOT = {1 << i: 53 + i for i in range(8)}


def f(w, lo, n):
    return (w >> lo) & ((1 << n) - 1)


def dis(i, w):
    t = w >> 30
    fe = ' +fetch' if f(w, 26, 1) else ''
    if t == 0:
        parts = []
        for name, lo, n in (('x', 24, 2), ('y', 23, 1), ('r', 17, 6), ('a', 16, 1),
                            ('b', 15, 1), ('c', 13, 1), ('z', 10, 2), ('n', 0, 10)):
            if f(w, lo, n):
                parts.append(f'{name}={f(w, lo, n):#x}')
        if f(w, 12, 1):
            parts.append('release')
        if f(w, 27, 3):
            parts.append(f'sub={f(w, 27, 3)}')
        if not parts and not fe:
            return 'nop'
        return ('ctl' + fe + ' ' + ' '.join(parts)).rstrip()
    if t == 1:
        op = f(w, 27, 3)
        r = f(w, 16, 8)
        reg = f'r{ONEHOT[r]}' if op in (5, 7) and r in ONEHOT else f'r{r}'
        extra = f' p={f(w, 25, 1)}' if f(w, 25, 1) else ''
        extra += f' q={f(w, 24, 1)}' if f(w, 24, 1) else ''
        val = f' v={f(w, 10, 6)}' if op in (1, 2, 3) else ''
        return f'xfer{op}{fe}{extra} {reg}{val} -> {f(w, 0, 10):03x}'
    if t == 2:
        op = f(w, 27, 3)
        extra = f' x={f(w, 24, 2)}' if f(w, 24, 2) else ''
        extra += ' y' if f(w, 23, 1) else ''
        reg = f(w, 16, 7)
        imm = f(w, 0, 16)
        if op == 2:
            return f'move{fe}{extra} r{reg} <- r{imm}'
        s = f'load{op}{fe}{extra} r{reg}, {imm:#x}'
        if reg == 49:
            s += f'  (state {imm >> 10}, word {imm & 0x3ff:03x})'
        if i in handler:
            s += f'  (slot {imm}: {handler[i]})'
        return s
    return f'type3 {w:#010x}'


starts = {}
for n, a in enumerate(table_b):
    starts.setdefault(a, []).append(n)


def ranges(ns):
    out, i = [], 0
    while i < len(ns):
        j = i
        while j + 1 < len(ns) and ns[j + 1] == ns[j] + 1:
            j += 1
        out.append(f'{ns[i]:03x}' if i == j else f'{ns[i]:03x}-{ns[j]:03x}')
        i = j + 1
    return ','.join(out)


with open(out, 'w') as o:
    o.write('# Distributor program ged1b.u (IRIX 6.5.30m), disassembled by scripts/ged_disasm.py.\n')
    o.write('# Field layout from irsaudit Compact_GED_Ucode; see ucode/ged.md. Mnemonics are labels.\n')
    o.write('# table A (16 words, x8 = base in table B): ' + ' '.join(f'{v:#x}' for v in table_a) + '\n')
    o.write('# word  value     source:line        instruction    <= table B indexes that start here\n')
    for i, w in enumerate(prog):
        src = '%s:%d' % line.get(i, ('?', 0))
        e = '  <= B[' + ranges(starts[i]) + ']' if i in starts else ''
        o.write(f'{i:03x}  {w:08x}  {src:<17}  {dis(i, w)}{e}\n')
