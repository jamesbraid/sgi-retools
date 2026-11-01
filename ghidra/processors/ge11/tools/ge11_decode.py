#!/usr/bin/env python3
"""Build and check data/ge11_decode.tsv, the GE11 word-to-record table.

Usage: ge11_decode.py build [UCODE_DIR]   write ../data/ge11_decode.tsv
       ge11_decode.py check [UCODE_DIR]   the table must give every
                                          record of every program exactly
       ge11_decode.py compare HEX U       agreement, per record group, on
                                          the words of another program that
                                          the table was not learnt from
       ge11_decode.py decode HEX          print address, W and the record
       UCODE_DIR defaults to root/usr/gfx/ucode/MG (IRIX 6.5.0).

Why a table. The GE11 fetches a 72-bit word W. The assembler also wrote
each program out as 256-bit decoded control records (mgras_ge*.u), and the
Ghidra module needs those records. A program that ships only as W (the
6.5.7 diagnostic's mgras_ge.hex, ge11*.bin) has no records, and the decode
from W to record is not known as logic. IRIX 6.5.0 ships six GE11 programs
in both forms (mgras_ge, _DB, _revB, _revB_DB, _revB_HQ4, _revB_HQ4_DB),
23969 distinct non-padding words, and no W maps to two records.

What the table is. For every form (W bits 70-67) and every record bit, a
binary decision tree over W bits whose leaves are a constant, a W bit or its
inverse. Each tree is grown greedily on those 23969 pairs until every leaf
agrees with all of its words, so the table reproduces every record of the
six programs exactly (check). For a word none of them holds the table is a
prediction: the trees split on W bits, so a new combination of known fields
decodes, but a field value never seen in its form may not. compare gives
the measured rate on the KONA programs, whose assembler produced the same
record for the same W in 9132 of the 9133 words the two chips share.

Table format, one line per leaf: form, record bit, the W-bit conditions on
the path (bit=value, comma-separated, "-" for none), and the leaf (0, 1, Wn
or ~Wn). The leaves of one (form, bit) partition all words, so exactly one
leaf matches.
"""
import collections
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, '..', 'data', 'ge11_decode.tsv')
VARIANTS = ['', '_DB', '_revB', '_revB_DB', '_revB_HQ4', '_revB_HQ4_DB']

# Record groups (high bit, low bit), the names the KONA listings use.
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


def load_hex(path):
    """Address -> W from a text program: hex address and 18 hex digits a line."""
    words = {}
    for line in open(path):
        f = line.split()
        if len(f) == 2:
            words[int(f[0], 16)] = int(f[1], 16)
    return words


def load_bin(path):
    """Address -> W from a raw image of 12-byte words (bits 31-0, 63-32, 71-64)."""
    b = open(path, 'rb').read()
    words = {}
    for i in range(len(b) // 12):
        lo, mid, top = struct.unpack('>III', b[12 * i:12 * i + 12])
        words[i] = lo | mid << 32 | (top & 0xff) << 64
    return words


def load_u(path):
    """Address -> 256-bit record from a .u container (magic 0x45900003)."""
    b = open(path, 'rb').read()
    hdr = struct.unpack('>11I', b[:44])
    if hdr[0] != 0x45900003:
        sys.exit('%s: magic 0x%08x is not a decoded-record program' % (path, hdr[0]))
    recs = {}
    o, end = hdr[3], hdr[3] + hdr[4]
    while o < end:
        ba, bl = struct.unpack('>II', b[o:o + 8])
        o += 8
        for i in range(bl // 32):
            recs[ba // 32 + i] = int.from_bytes(b[o + 32 * i:o + 32 * i + 32], 'big')
        o += bl
    return recs


def form(w):
    return (w >> 67) & 15


def is_padding(w, r):
    """Zero words the assembler left between modules: W = 0 and record bits
    62-8 clear, which a real no-op never has."""
    return w == 0 and (r >> 8) & ((1 << 55) - 1) == 0


def field(r, hi, lo):
    return (r >> lo) & ((1 << (hi - lo + 1)) - 1)


def pairs_from(ucode):
    pairs = {}
    for v in VARIANTS:
        h, u = os.path.join(ucode, 'mgras_ge%s.hex' % v), os.path.join(ucode, 'mgras_ge%s.u' % v)
        if not (os.path.exists(h) and os.path.exists(u)):
            sys.exit('missing %s or %s (see IRIX_FILES.md)' % (h, u))
        words, recs = load_hex(h), load_u(u)
        for a, w in words.items():
            r = recs[a]
            if is_padding(w, r):
                continue
            if pairs.setdefault(w, r) != r:
                sys.exit('word %018x has two records' % w)
    return pairs


# ---- learning: columns are bit sets over the training words (int bitsets)

def _leaf(y, P, cols, full):
    """Best leaf for the words in P: (mismatches, leaf)."""
    best = ((y & P).bit_count(), '0')
    m = (~y & P).bit_count()
    if m < best[0]:
        best = (m, '1')
    if best[0] == 0:
        return best
    for b, c in enumerate(cols):
        m = ((y ^ c) & P).bit_count()
        if m < best[0]:
            best = (m, 'W%d' % b)
            if m == 0:
                return best
        m = ((y ^ c ^ full) & P).bit_count()
        if m < best[0]:
            best = (m, '~W%d' % b)
            if m == 0:
                return best
    return best


def _grow(y, P, cols, full, path, out):
    m, leaf = _leaf(y, P, cols, full)
    if m == 0:
        out.append((path, leaf))
        return
    used = {b for b, _ in path}
    best = None
    for b, c in enumerate(cols):
        if b in used or not P & c or not P & ~c:
            continue
        s = _leaf(y, P & c, cols, full)[0] + _leaf(y, P & ~c, cols, full)[0]
        if best is None or s < best[0]:
            best = (s, b)
    if best is None:
        sys.exit('no split separates the words at %r' % (path,))
    b = best[1]
    _grow(y, P & ~cols[b], cols, full, path + ((b, 0),), out)
    _grow(y, P & cols[b], cols, full, path + ((b, 1),), out)


def learn(pairs):
    byform = collections.defaultdict(list)
    for w in sorted(pairs):
        byform[form(w)].append((w, pairs[w]))
    rules = []
    for f, ws in sorted(byform.items()):
        full = (1 << len(ws)) - 1
        cols = [sum(((w >> b) & 1) << i for i, (w, _) in enumerate(ws)) for b in range(72)]
        for k in range(255, -1, -1):
            y = sum(((r >> k) & 1) << i for i, (_, r) in enumerate(ws))
            out = []
            _grow(y, full, cols, full, (), out)
            for path, leaf in out:
                rules.append((f, k, path, leaf))
    return rules, {f: len(v) for f, v in byform.items()}


def write_table(rules, counts, path):
    with open(path, 'w') as fh:
        fh.write('# GE11 word-to-record decode, written by tools/ge11_decode.py build from the\n')
        fh.write('# six IRIX 6.5.0 programs that ship as both mgras_ge*.hex and mgras_ge*.u.\n')
        fh.write('# Training words per form: %s.\n' % ', '.join('%d: %d' % kv for kv in sorted(counts.items())))
        fh.write('# form, record bit, W-bit conditions (bit=value), leaf (0, 1, Wn, ~Wn).\n')
        fh.write('form\tbit\twhen\tvalue\n')
        for f, k, p, leaf in rules:
            fh.write('%d\t%d\t%s\t%s\n' % (f, k, ','.join('%d=%d' % c for c in p) or '-', leaf))


def read_table(path=TABLE):
    trees = collections.defaultdict(list)
    for line in open(path):
        if line.startswith(('#', 'form')):
            continue
        f, k, when, leaf = line.rstrip('\n').split('\t')
        conds = [] if when == '-' else [tuple(map(int, c.split('='))) for c in when.split(',')]
        trees[(int(f), int(k))].append((conds, leaf))
    return trees


def decode(trees, w):
    """Record for W, or None when the form has no table (form 4 never occurs)."""
    f = form(w)
    if (f, 0) not in trees:
        return None
    r = 0
    for k in range(256):
        for conds, leaf in trees[(f, k)]:
            if all((w >> b) & 1 == v for b, v in conds):
                break
        else:
            raise AssertionError('no leaf for form %d bit %d' % (f, k))
        if leaf == '1':
            v = 1
        elif leaf == '0':
            v = 0
        elif leaf[0] == '~':
            v = 1 - ((w >> int(leaf[2:])) & 1)
        else:
            v = (w >> int(leaf[1:])) & 1
        r |= v << k
    return r


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    ucode = sys.argv[2] if len(sys.argv) > 2 else 'root/usr/gfx/ucode/MG'
    if cmd == 'build':
        rules, counts = learn(pairs_from(ucode))
        write_table(rules, counts, TABLE)
        print('%d leaves for %d forms written to %s' % (len(rules), len(counts), os.path.relpath(TABLE)))
    elif cmd == 'check':
        trees, pairs = read_table(), pairs_from(ucode)
        bad = [w for w, r in pairs.items() if decode(trees, w) != r]
        print('%s: %d of %d distinct words decode to their record' % (
            'PASS' if not bad else 'FAIL', len(pairs) - len(bad), len(pairs)))
        sys.exit(1 if bad else 0)
    elif cmd == 'compare':
        trees = read_table()
        words, recs = load_hex(sys.argv[2]), load_u(sys.argv[3])
        known = pairs_from(sys.argv[4]) if len(sys.argv) > 4 else {}
        ok, n, exact = collections.Counter(), 0, 0
        for a, w in words.items():
            if is_padding(w, recs[a]) or w in known:
                continue
            r = decode(trees, w)
            n += 1
            exact += r == recs[a]
            for g, hi, lo in GROUPS:
                ok[g] += r is not None and field(r, hi, lo) == field(recs[a], hi, lo)
        print('%d words, %d records exact (%.1f%%)' % (n, exact, 100.0 * exact / max(n, 1)))
        print(' '.join('%s %.3f' % (g, ok[g] / max(n, 1)) for g, _, _ in GROUPS))
    elif cmd == 'decode':
        trees = read_table()
        src = sys.argv[2]
        words = load_bin(src) if src.endswith('.bin') else load_hex(src)
        for a in sorted(words):
            r = decode(trees, words[a])
            print('%04x %018x %s' % (a, words[a], '-' if r is None else '%064x' % r))
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
