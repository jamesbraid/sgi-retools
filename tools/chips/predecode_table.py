#!/usr/bin/env python3
"""Decode the table of 36-bit primary instruction-cache words in the IP35 PROM and check the layout.

Usage: predecode_table.py PROM.bin

PROM.bin is the flat `ip35prom` segment from tools/promgen64.py (physical 0x1fc00000). The routine at
0x1fc028cc loads, for eight 64-byte primary instruction-cache lines, a tag (TagHi/TagLo from the table, then
`cache 8`) and sixteen words, each a TagHi, TagLo and ECC triple fed to Index Store Data (I) at 0x1fc02934. The
table runs from 0x1fc89a20 (the two address constants at 0x1fc028d8..0x1fc028e0 in the image) to 0x1fc8a0a0;
each line is 16 bytes (the line's xkphys address, TagHi, TagLo) then sixteen 12-byte triples.

The words belong to the code at 0x1fc027c0..0x1fc02bff, so each can be set beside the flash instruction at the
same address. The check below states the layout the 49 distinct instruction words follow (see the page
docs/questions/ip35-prom-cache-staging.md) and lists every word that does not follow it.
"""
import struct
import sys

TABLE, END, BASE = 0x1fc89a20, 0x1fc8a0a0, 0x1fc00000
RT_DEST = {0x08, 0x09, 0x0d, 0x0f, 0x19, 0x37}  # addi addiu ori lui daddiu ld: write rt


def fields(f):
    """The 26 non-opcode instruction bits as the table lays them out in bits 25:0."""
    func, sa, rs = f & 63, f >> 6 & 31, f >> 21 & 31
    rt, rd = f >> 16 & 31, f >> 11 & 31
    lo, hi = (rt, rd) if f >> 26 in RT_DEST else (rd, rt)  # bits 4:0 hold the destination register
    return func << 20 | sa << 15 | rs << 10 | hi << 5 | lo


def inverse(p):
    """Instruction bits 25:0 from a table word (opcode not included)."""
    lo, hi, rs, sa, func = p & 31, p >> 5 & 31, p >> 10 & 31, p >> 15 & 31, p >> 20 & 63
    return rs << 21 | func | sa << 6 | hi << 16 | lo << 11, rs, lo, hi, sa, func


def main():
    d = open(sys.argv[1], 'rb').read()
    words, slots = {}, []
    o = TABLE - BASE
    print('line  address               tag(TagHi:TagLo)   state')
    for n in range((END - TABLE) // 0xd0):
        va, th, tl = struct.unpack('>QII', d[o:o + 16])
        o += 16
        print('%d     %#018x  %#x:%#010x  %s' % (n, va, th, tl, 'Valid' if tl >> 6 & 1 else 'Invalid'))
        for i in range(16):
            h, l, e = struct.unpack('>III', d[o:o + 12])
            o += 12
            pa = (va & 0x1fffffff) + 4 * i
            fl = struct.unpack('>I', d[pa - BASE:pa - BASE + 4])[0]
            p = h << 32 | l
            if tl >> 6 & 1:  # lines whose tag is Invalid carry zero words and stage nothing
                words.setdefault(fl, set()).add((p, e))
                slots.append((fl, p))
            if '-v' in sys.argv:
                print('   %#x  flash %08x  table %#x:%08x ecc %d' % (pa, fl, h, l, e))
    nz = {f: v for f, v in words.items() if f}
    print('\n%d distinct nonzero flash words in the Valid lines; table words per flash word: %s' % (len(nz), sorted({len(v) for v in nz.values()})))
    bad = 0
    par = 0
    for f, v in sorted(nz.items()):
        for p, e in v:
            if (p & 0x3ffffff) != fields(f):
                bad += 1
                print('  does not follow the layout: flash %08x table %09x (table decodes to instruction bits 25:0 = %07x)'
                      % (f, p, inverse(p)[0]))
            if e != bin(p).count('1') & 1:
                par += 1
            if (p >> 26 & 7) != f >> 26 & 7:
                print('  opcode[2:0] differs: %08x' % f)
    print('bits 25:0 follow the layout for %d of %d words; parity bit equals the XOR of the 36 data bits for %d of %d'
          % (len(nz) - bad, len(nz), len(nz) - par, len(nz)))
    # class table: p[35:29] against the instruction it stands for
    rows = {}
    for fl, p in slots:
        c = p >> 29
        r = rows.setdefault(c, dict(n=0, ops=set(), f3=set(), pos=set(), c3=set()))
        r['n'] += 1
        r['f3'].add(fl >> 29)
        r['c3'].add(p >> 26 & 7)
        if fl:
            r['ops'].add((fl >> 26, fl & 63 if fl >> 26 == 0 else None))
            r['pos'].add('rt' if fl >> 26 in RT_DEST else 'rd')
        else:
            r['ops'].add((0, 0))
    print('\nclass p[35:29] (hex), opcode/funct it stands for, f[31:29], bits 4:0 hold, p[28:26], words in the Valid lines:')
    for c, r in sorted(rows.items()):
        ops = ', '.join('op %02x' % o if f is None else 'SPECIAL funct %02x' % f for o, f in sorted(r['ops'], key=lambda x: (x[0], x[1] or 0)))
        print('  %#04x  %-34s f[31:29]=%s  %s  p[28:26]=%s  %d' % (
            c, ops, ','.join(format(x, '03b') for x in sorted(r['f3'])), '/'.join(sorted(r['pos'])) or '-',
            ','.join(format(x, '03b') for x in sorted(r['c3'])), r['n']))
    zero_invalid = 0
    o = TABLE - BASE
    for n in range((END - TABLE) // 0xd0):
        va, th, tl = struct.unpack('>QII', d[o:o + 16])
        o += 16
        for i in range(16):
            h, l, e = struct.unpack('>III', d[o:o + 12])
            o += 12
            if not tl >> 6 & 1:
                zero_invalid += (h | l | e) == 0
    print('zero words (all of TagHi, TagLo, ECC) in the Invalid lines 5 to 7: %d of 48' % zero_invalid)
    print('\npattern test table at 0x1fc8a130 (data, stored and compared, never an instruction):')
    for k in range(4):
        q0, q1, q2 = struct.unpack('>QQQ', d[0x8a130 + 24 * k:0x8a130 + 24 * k + 24])
        v = (q2 >> 32) << 32 | (q2 & 0xffffffff)
        print('  TagHi:TagLo %#x:%08x  p[35:29] = %#04x  ECC %d' % (v >> 32, v & 0xffffffff, v >> 29, q1 >> 32))
    known = {k for r in rows.values() for k in r['ops']}
    print('\nopcodes in the code ranges the 0x1fc04980 routine stages through Index Load/Store Data (I), and whether the table gives their class:')
    for name, lo, hi in (('routine itself', 0x1fc04980, 0x1fc04f40), ('0x1fc027e8', 0x1fc027c0, 0x1fc02900), ('0x1fc03490', 0x1fc03480, 0x1fc03640),
                         ('0x1fc036dc', 0x1fc036c0, 0x1fc038c0), ('0x1fc0394c', 0x1fc03940, 0x1fc039c0),
                         ('copy 0x1fc05950', 0x1fc05940, 0x1fc05a00), ('verify 0x1fc05a14', 0x1fc05a00, 0x1fc05b40)):
        ops = set()
        for a in range(lo, hi, 4):
            f = struct.unpack('>I', d[a - BASE:a - BASE + 4])[0]
            ops.add((f >> 26, f & 63 if f >> 26 == 0 else None))
        miss = sorted(ops - known, key=lambda x: (x[0], x[1] or 0))
        print('  %-18s %2d distinct opcode/funct, %2d without a class in the table: %s' % (
            name, len(ops), len(miss), ' '.join('%02x' % o if f is None else '00/%02x' % f for o, f in miss) or '-'))
    same = sum(1 for f, p in slots if p == f)
    print('\nof %d slots in Valid lines, %d hold the flash word unchanged in TagLo (zero words and no others); %d are nops'
          % (len(slots), same, sum(1 for f, p in slots if f == 0)))


if __name__ == '__main__':
    main()
