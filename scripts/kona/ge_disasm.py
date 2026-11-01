"""Decode the geometry-engine microcode into fields and write listings.

Usage: ge_disasm.py [UCODE_DIR] [OUT_DIR]
       defaults: ucode/KONA ucode

Reads ge.hex (72-bit words), ge.u (the same program as 256-bit decoded
records, with the line and file tables) and ge_symbols (IRIX 6.5.30m).

The method, described in ucode/ge_isa.md: each ge.u record is the decoded
control word of the ge.hex word at the same address. For every form
(W bits 67-70) and every record bit, find the W bit that equals it, or its
inverse, in at least 99.5% of the form's words. That gives the wiring
table; record bits that follow no single W bit are decoded from several.
Padding words (all-zero W with record bits 8-62 also zero, which real
no-ops never have) are left out.

Writes:
  OUT_DIR/ge_wiring.tsv          form, record bit, source, agreement
  OUT_DIR/ge_listing/<src>.lst   one listing per source file named by the
                                 line table, in address order, each
                                 instruction with its labels, the record
                                 fields that differ from a real no-op, a
                                 decoded transfer where there is one, and
                                 the source line
"""
import collections
import os
import struct
import sys

src = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA'
out = sys.argv[2] if len(sys.argv) > 2 else 'ucode'

# Display groups over the 256-bit record, high bit first. The boundaries
# follow the wiring table (runs of record bits fed by consecutive W bits in
# some form); the names are labels, not meanings, except where ge_isa.md
# gives one.
GROUPS = [
    ('imm', 255, 224), ('w71', 223, 223), ('r222', 222, 222), ('r221', 221, 221),
    ('r220', 220, 220), ('r219', 219, 218), ('r217', 217, 216), ('r215', 215, 214),
    ('r213', 213, 212), ('r211', 211, 210), ('cc', 209, 199), ('r198', 198, 192),
    ('A', 191, 187), ('B', 186, 182), ('C', 181, 177), ('r176', 176, 175),
    ('D', 174, 169), ('E', 168, 163), ('r162', 162, 160), ('F', 159, 154),
    ('G', 153, 149), ('r148', 148, 139), ('P', 138, 134), ('Q', 133, 129),
    ('r128', 128, 122), ('M', 121, 111), ('r110', 110, 100), ('r99', 99, 96),
    ('r95', 95, 89), ('seq', 88, 72), ('r71', 71, 63), ('r62', 62, 26), ('r25', 25, 0),
]
SEQ_LO = 72


def load_hex(path):
    words = {}
    for line in open(path):
        a, w = line.split()
        words[int(a, 16)] = int(w, 16)
    return words


def load_u(path):
    b = open(path, 'rb').read()
    hdr = struct.unpack('>11I', b[:44])
    recs = {}
    o, end = hdr[3], hdr[3] + hdr[4]
    while o < end:
        ba, bl = struct.unpack('>II', b[o:o + 8])
        o += 8
        for i in range(bl // 32):
            recs[ba // 32 + i] = int.from_bytes(b[o + 32 * i:o + 32 * i + 32], 'big')
        o += bl
    lo, ll, fo, fl, no = hdr[5], hdr[6], hdr[7], hdr[8], hdr[9]
    offs = struct.unpack('>%dH' % (fl // 2), b[fo:fo + fl])
    files = [b[no + x:b.index(b'\0', no + x)].decode() for x in offs]
    lines = {}
    for i in range(ll // 8):
        ia, ln, fi = struct.unpack('>IHH', b[lo + 8 * i:lo + 8 * i + 8])
        lines.setdefault(ia, (files[fi].split('/')[-1], ln))
    return recs, lines


def form(w):
    return (w >> 67) & 15


def is_padding(w, r):
    return w == 0 and (r >> 8) & ((1 << 55) - 1) == 0


def wiring(words, recs):
    byform = collections.defaultdict(list)
    for a, w in words.items():
        r = recs[a]
        if not is_padding(w, r):
            byform[form(w)].append((w, r))
    table = {}
    for f, ws in sorted(byform.items()):
        n = len(ws)
        full = (1 << n) - 1
        wcol = [sum(((w >> b) & 1) << i for i, (w, r) in enumerate(ws)) for b in range(72)]
        for k in range(256):
            col = sum(((r >> k) & 1) << i for i, (w, r) in enumerate(ws))
            if col == 0:
                table[(f, k)] = ('0', n, n)
                continue
            if col == full:
                table[(f, k)] = ('1', n, n)
                continue
            best = (0, None)
            for b in range(72):
                for inv in (0, 1):
                    agree = n - bin(col ^ wcol[b] ^ (full if inv else 0)).count('1')
                    if agree > best[0]:
                        best = (agree, ('~W%d' if inv else 'W%d') % b)
            if best[0] >= n * 0.995:
                table[(f, k)] = (best[1], best[0], n)
            else:
                table[(f, k)] = ('decoded', best[0], n)
    return table, {f: len(v) for f, v in byform.items()}


def field(r, hi, lo):
    return (r >> lo) & ((1 << (hi - lo + 1)) - 1)


def transfer(a, r, nop_seq):
    """Inferred reading of the sequencer group; see ge_isa.md."""
    s = field(r, 88, 72)
    if s == nop_seq:
        return None
    op = (s >> 12) & 7
    if op == 6:
        return None
    rel = (s >> 15) & 1
    imm = field(r, 255, 224)
    simm = imm - (1 << 32) if imm >> 31 else imm
    target = (a + simm) & 0xffff if rel else imm & 0xffff
    return op, rel, s & 0x1f, field(r, 209, 199), target


def main():
    words = load_hex(os.path.join(src, 'ge.hex'))
    recs, lines = load_u(os.path.join(src, 'ge.u'))
    syms = collections.defaultdict(list)
    for line in open(os.path.join(src, 'ge_symbols')):
        n, a = line.split()
        syms[int(a, 16)].append(n)
    nop = recs[0]
    nop_seq = field(nop, 88, 72)

    table, counts = wiring(words, recs)
    with open(os.path.join(out, 'ge_wiring.tsv'), 'w') as fh:
        fh.write('# Geometry-engine record bit sources per form (ge.hex vs ge.u, IRIX 6.5.30m).\n')
        fh.write('# source: Wn = equals W bit n, ~Wn = its inverse, 0/1 = constant in the form,\n')
        fh.write('# decoded = no single W bit agrees in 99.5% of the form\'s words.\n')
        fh.write('# agree/words: words where the source matched / non-padding words in the form.\n')
        fh.write('form\trecord_bit\tnop_value\tsource\tagree\twords\n')
        for f in sorted(counts):
            for k in range(255, -1, -1):
                s, ag, n = table[(f, k)]
                fh.write('%d\t%d\t%d\t%s\t%d\t%d\n' % (f, k, (nop >> k) & 1, s, ag, n))

    ldir = os.path.join(out, 'ge_listing')
    os.makedirs(ldir, exist_ok=True)
    per_file = collections.defaultdict(list)
    current = 'unattributed'
    for a in sorted(words):
        w, r = words[a], recs[a]
        if is_padding(w, r):
            continue
        if a in lines:
            current = lines[a][0]
        per_file[current].append(a)
    for fname, addrs in per_file.items():
        with open(os.path.join(ldir, fname + '.lst'), 'w') as fh:
            fh.write('# %s: geometry-engine instructions attributed to this source by the ge.u line table\n' % fname)
            fh.write('# (unlisted words follow the previous attributed one). Fields per ucode/ge_isa.md.\n')
            for a in addrs:
                w, r = words[a], recs[a]
                for n in syms.get(a, []):
                    fh.write('%s:\n' % n)
                parts = []
                t = transfer(a, r, nop_seq)
                if t:
                    op, rel, cond, cc, target = t
                    tl = syms.get(target, [''])[0]
                    parts.append('xfer%d%s c%d cc=%x -> %04x%s' % (op, '.rel' if rel else '', cond, cc, target,
                                                                   ' <%s>' % tl if tl else ''))
                x = r ^ nop
                for name, hi, lo in GROUPS:
                    if field(x, hi, lo):
                        parts.append('%s=%x' % (name, field(r, hi, lo)))
                text = ' '.join(parts) if parts else 'nop'
                ln = lines.get(a)
                fh.write('%04x: %018x f%-2d %s%s\n' % (a, w, form(w), text,
                                                       ('  ; %s:%d' % ln) if ln else ''))


if __name__ == '__main__':
    main()
