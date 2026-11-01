"""Count the operation-code tuples and control idioms in the geometry-engine program.

Usage: ge_ops.py [UCODE_DIR] [OUT_DIR]
       defaults: ucode/KONA ucode

Reads ge.hex (72-bit words), ge.u (256-bit decoded records and the line and
file tables) and ge_symbols, as ge_disasm.py does, and writes:

  OUT_DIR/ge_optuples.tsv  the decoded record groups that look like operation
                           selectors (M R121-111, r110 R110-100, r99 R99-96,
                           r148 R148-139, r128 R128-122), as tuples per form with
                           their counts, the most common operand fields and the
                           handlers that use them most
  OUT_DIR/ge_idioms.tsv    named counts behind ucode/ge_ops.md: handler
                           prologue and epilogue words, how handlers end, the
                           relative-transfer base test and the compare idiom

Source order comes from the line table: the packed address order is
software-pipelined, the source line order is the programmer's.
"""
import bisect
import collections
import os
import struct
import sys

src = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA'
out = sys.argv[2] if len(sys.argv) > 2 else 'ucode'


def bits(v, hi, lo):
    return (v >> lo) & ((1 << (hi - lo + 1)) - 1)


W = {}
for line in open(os.path.join(src, 'ge.hex')):
    a, w = line.split()
    W[int(a, 16)] = int(w, 16)
b = open(os.path.join(src, 'ge.u'), 'rb').read()
hdr = struct.unpack('>11I', b[:44])
R = {}
o, end = hdr[3], hdr[3] + hdr[4]
while o < end:
    ba, bl = struct.unpack('>II', b[o:o + 8])
    o += 8
    for i in range(bl // 32):
        R[ba // 32 + i] = int.from_bytes(b[o + 32 * i:o + 32 * i + 32], 'big')
    o += bl
lo, ll, fo, fl, no = hdr[5], hdr[6], hdr[7], hdr[8], hdr[9]
offs = struct.unpack('>%dH' % (fl // 2), b[fo:fo + fl])
files = [b[no + x:b.index(b'\0', no + x)].decode().split('/')[-1] for x in offs]
lines = {}
for i in range(ll // 8):
    ia, ln, fi = struct.unpack('>IHH', b[lo + 8 * i:lo + 8 * i + 8])
    lines.setdefault(ia, (files[fi], ln))
syms = {}
for line in open(os.path.join(src, 'ge_symbols')):
    n, a = line.split()
    syms[int(a, 16)] = n
sa = sorted(syms)

# padding is an all-zero word whose record bits 8-62 are zero (ge_isa.md)
words = [a for a in W if a in R and not (W[a] == 0 and bits(R[a], 62, 8) == 0)]
wset = set(words)


def form(w):
    return (w >> 67) & 15


def owner(a):
    return syms[sa[bisect.bisect_right(sa, a) - 1]]


def tcode(a):
    return (R[a] >> 84) & 7


def imm(a):
    return (R[a] >> 224) & 0xffffffff


def cc(a):
    return bits(R[a], 209, 199)


# ---- operation-selector tuples
cnt = collections.Counter()
ex = {}
opnd = collections.defaultdict(collections.Counter)
who = collections.defaultdict(collections.Counter)
for a in words:
    f = form(W[a])
    r = R[a]
    key = (f, bits(r, 121, 111), bits(r, 110, 100), bits(r, 99, 96), bits(r, 148, 139), bits(r, 128, 122))
    cnt[key] += 1
    ex.setdefault(key, a)
    opnd[key][bits(W[a], 66, 62)] += 1
    who[key][owner(a)] += 1
with open(os.path.join(out, 'ge_optuples.tsv'), 'w') as fh:
    fh.write('# Operation-selector tuples of the geometry-engine program (ge.u records, IRIX 6.5.30m),\n')
    fh.write('# the 400 most common. M = R121-111, r110 = R110-100, r99 = R99-96, r148 = R148-139,\n')
    fh.write('# r128 = R128-122: the decoded record groups no single W bit feeds (ucode/ge_isa.md).\n')
    fh.write('# Meanings are unknown except where ucode/ge_ops.md says; A = W66-62 is the most common first operand.\n')
    fh.write('form\tM\tr110\tr99\tr148\tr128\tcount\ttop_A\texample_addr\tfile:line\tusers\n')
    for key, n in cnt.most_common(400):
        a = ex[key]
        fh.write('%d\t0x%03x\t0x%03x\t0x%x\t0x%03x\t0x%02x\t%d\t0x%02x\t0x%04x\t%s:%d\t%s\n' % (
            key[0], key[1], key[2], key[3], key[4], key[5], n, opnd[key].most_common(1)[0][0], a,
            lines.get(a, ('', 0))[0], lines.get(a, ('', 0))[1],
            ','.join(h for h, _ in who[key].most_common(3))))

# ---- idioms
rows = []


def put(name, value, note=''):
    rows.append((name, value, note))


handlers = [a for a in sa if syms[a].startswith(('mgeb', 'mges', 'mgebi', 'mgesi'))]
rng = {a: (a, sa[sa.index(a) + 1] if sa.index(a) + 1 < len(sa) else a + 1) for a in handlers}
put('handlers', len(rng), 'ge_symbols labels starting mgeb, mges, mgebi, mgesi')
first = collections.Counter()
for a in rng:
    if a in W:
        w = W[a]
        first[(w & ~0xffffffff) if form(w) == 15 else (w & ~0x3ffff) if form(w) == 14 else w] += 1
for w, n in first.most_common(4):
    put('first_word_%018x' % w, n, 'handlers whose first instruction is this word with its immediate masked')

# how handlers end
jump0 = idiom = both = neither = 0
last = 0
for a, (s, e) in rng.items():
    ws = [x for x in range(s, e) if x in wset]
    j0 = any(tcode(x) == 4 and not (R[x] >> 87) & 1 and imm(x) == 0 for x in ws)
    ids = [x for x in ws if tcode(x) == 4 and (R[x] >> 87) & 1 and imm(x) == 0 and cc(x) == 0x11]
    if j0 and ids:
        both += 1
    elif j0:
        jump0 += 1
    elif ids:
        idiom += 1
    else:
        neither += 1
    if ids and ids[0] in lines:
        fl_ = [lines[x][1] for x in ws if x in lines and lines[x][0] == lines[ids[0]][0]]
        if fl_ and lines[ids[0]][1] >= max(fl_) - 1:
            last += 1
put('end_transfer_cc11_imm0', idiom + both, 'handlers holding a relative jump with imm 0 and cc 0x11')
put('end_jump_to_address_0', jump0 + both, 'handlers holding an absolute jump to address 0')
put('end_other', neither, 'handlers with neither (they jump into shared code)')
put('end_idiom_on_last_source_line', last, 'of the end_transfer_cc11_imm0 handlers, idiom on the last or next-to-last source line')

# relative transfer base test
res = collections.defaultdict(int)
tot = collections.Counter()
for a in words:
    if tcode(a) in (3, 4, 5) and (R[a] >> 87) & 1:
        i = imm(a)
        s = i if i < 0x80000000 else i - (1 << 32)
        k = (tcode(a), 'imm0' if s == 0 else 'imm_nonzero')
        tot[k] += 1
        for base in (0, 5):
            if a + base + s in wset:
                res[(k, base)] += 1
for k in sorted(tot):
    for base in (0, 5):
        put('rel_transfer_code%d_%s_base%d_lands_on_instruction' % (k[0], k[1], base), res[(k, base)],
            'of %d relative transfers' % tot[k])

# compare idiom
cmpw = [a for a in words if form(W[a]) == 13 and bits(R[a], 121, 111) == 0x6c2 and bits(R[a], 110, 100) == 0x7bd]
put('compare_idiom_instances', len(cmpw), 'form 13 with M=0x6c2 and r110=0x7bd')
put('compare_idiom_A_0x18', sum(1 for a in cmpw if bits(W[a], 66, 62) == 24), '')
consts = collections.Counter()
for a in cmpw:
    # the assembler hoists constant loads, so look at execution (address) order
    prev = [x for x in range(a - 3, a) if x in wset and form(W[x]) == 15 and bits(W[x], 48, 44) == 0x1e]
    if prev:
        consts[W[prev[-1]] & 0xffffffff] += 1
put('compare_idiom_with_constant_loaded_to_C1e', sum(consts.values()), 'a form-15 load into C=0x1e within the three words before')
for v, n in sorted(consts.items()):
    put('compare_constant_0x%x' % v, n, '')
with open(os.path.join(out, 'ge_idioms.tsv'), 'w') as fh:
    fh.write('# Counts behind ucode/ge_ops.md (ge.hex, ge.u and ge_symbols of IRIX 6.5.30m). Produced by scripts/ge_ops.py.\n')
    fh.write('name\tvalue\tnote\n')
    for r in rows:
        fh.write('%s\t%s\t%s\n' % r)


# ---- which W bits determine each decoded record group
def greedy(rows, tgt, cands, maxk=24):
    """Forward-select W bits until the group is a function of them over the form."""
    chosen = []

    def conflicts(sel):
        d = {}
        c = 0
        for w, r in rows:
            k = tuple((w >> x) & 1 for x in sel)
            v = tgt(r)
            if k in d and d[k] != v:
                c += 1
            d.setdefault(k, v)
        return c
    cur = conflicts([])
    while cur > 0 and len(chosen) < maxk:
        best = None
        for x in cands:
            if x in chosen:
                continue
            c = conflicts(chosen + [x])
            if best is None or c < best[0]:
                best = (c, x)
        chosen.append(best[1])
        cur = best[0]
    return sorted(chosen), cur


with open(os.path.join(out, 'ge_opdeps.tsv'), 'w') as fh:
    fh.write('# W bits that, taken together, determine a decoded record group over every word of a form\n')
    fh.write('# (forward selection: a sufficient set, not proved minimal; conflicts = words that still disagree).\n')
    fh.write('# Candidates are W bits 0-66, including those wired straight into a field. Produced by scripts/ge_ops.py.\n')
    fh.write('form\twords\tgroup\trecord_bits\tw_bits\tconflicts\n')
    for f in (5, 12, 13, 14, 15):
        rows_ = [(W[a], R[a]) for a in words if form(W[a]) == f]
        for name, hi, lo in (('M', 121, 111), ('r110', 110, 100), ('r99', 99, 96), ('r148', 148, 139), ('r128', 128, 122)):
            sel, c = greedy(rows_, lambda r, hi=hi, lo=lo: bits(r, hi, lo), range(0, 67))
            fh.write('%d\t%d\t%s\tR%d-%d\t%s\t%d\n' % (f, len(rows_), name, hi, lo, ' '.join('W%d' % x for x in reversed(sel)) or '-', c))
