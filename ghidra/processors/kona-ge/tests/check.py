#!/usr/bin/env python3
"""Compare the KONA-GE Ghidra module's output with the documents.

Usage: check.py [OUTDIR]   (default .cache/kona-ge; run-ghidra.sh writes it)

  (a) every listed word of ucode/KONA/ge.u: Ghidra's fields equal those of
      scripts/ge_disasm.py (ucode/ge_listing/), field for field;
  (b) irsaudit's 172-word instruction test (ucode/ge_inst_results.tsv):
      each output word decodes as the output store, and each operation the
      operation table of ucode/ge_ops.md fixes decodes as that operation;
  (c) every routine ucode/ge_compute.md gives an entry to is a function
      entry Ghidra found;
  (d) the decompiled mmo_Clamp, uMatrixMultCCC and mMatrixMultCCW show the
      arithmetic ucode/ge_compute.md documents.

Prints one line per test and the failures; exits non-zero if any test fails.
"""
import collections
import glob
import os
import re
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.cache/kona-ge'
LST = re.compile(r'^([0-9a-f]{4}): ([0-9a-f]{18}) f\d+\s+(.*?)(?:  ; .*)?$')
XF_PY = re.compile(r'xfer(\d)(\.rel)? c(\d+) cc=([0-9a-f]+) -> ([0-9a-f]+)(?: <[^>]*>)?')
XF_GH = re.compile(r'xfer0x([0-9a-f]+)(\.rel)?\s+c0x([0-9a-f]+)\s+cc=0x([0-9a-f]+)\s+->\s+0x([0-9a-f]+)')
KV = re.compile(r'\b([A-Za-z][A-Za-z0-9]*)=(0x[0-9a-f]+(?::0x[0-9a-f]+)?|[0-9a-f]+)')


def fields(text, ghidra):
    """Transfer tuple and {group: value} from one listing's instruction text."""
    xf = (XF_GH if ghidra else XF_PY).search(text)
    t = None
    if xf:
        op, rel, grp, cc, tgt = xf.groups()
        t = (int(op, 16 if ghidra else 10), bool(rel), int(grp, 16 if ghidra else 10),
             int(cc, 16), int(tgt, 16))
        text = text[:xf.start()] + text[xf.end():]
    kv = {}
    for k, v in KV.findall(text):
        if ':' in v:
            hi, lo = v.split(':')
            kv[k] = (int(hi, 16) << 32) | int(lo, 16)
        else:
            kv[k] = int(v, 16)
    return t, kv


def ghidra_listing(path):
    res = {}
    for line in open(path):
        a, w, text = line.rstrip('\n').split('\t')
        res[int(a, 16)] = (w, text)
    return res


def test_a():
    gh = ghidra_listing(os.path.join(OUT, 'prod.listing'))
    n = bad = 0
    shown = []
    for f in sorted(glob.glob('ucode/ge_listing/*.lst')):
        for line in open(f):
            m = LST.match(line.rstrip('\n'))
            if not m:
                continue
            a, w, text = int(m.group(1), 16), m.group(2), m.group(3)
            n += 1
            gw, gtext = gh.get(a, ('', '<missing>'))
            mn, _, rest = gtext.partition(' ')
            ok = gw == w and gtext != '<none>'
            if ok:
                if text == 'nop':
                    ok = fields(rest, True) == (None, {}) and mn.lstrip('_') == 'nop'
                else:
                    ok = fields(text, False) == fields(rest, True)
            if not ok:
                bad += 1
                if len(shown) < 5:
                    shown.append('  %04x py: %s\n       gh: %s %s' % (a, text, gw, gtext))
    print('(a) %s: %d of %d listed words match field for field' % ('PASS' if not bad and n else 'FAIL',
                                                                    n - bad, n))
    for s in shown:
        print(s)
    return not bad and n > 0


# Documented operation per expected index (ucode/ge_ops.md, operation table).
OPS = {48: 'iadd', 49: 'iadd', 50: 'iadd', 136: 'iadd', 137: 'and', 138: 'not', 139: 'or',
       140: 'isub', 141: 'xor', 142: 'mov', 143: 'movb', 144: 'fadd', 145: 'fmin', 146: 'fmax',
       147: 'fsub', 148: 'itof', 149: 'dadd', 151: 'dsub', 153: 'clamp', 154: 'clamp',
       155: 'clamp', 156: 'fmul', 157: 'fmov', 158: 'u2_0x5', 159: 'rcpstep', 160: 'rsqstep',
       161: 'dmul', 163: 'dmov', 165: 'u2_0x7', 167: 'rcpseed', 168: 'rsqseed',
       169: 'rcpseed', 170: 'rsqseed'}
OPS.update({i: 'fmul.iadd' for i in range(128, 136)})


def producer(gh, addr, reg):
    """Nearest earlier word whose unit result is written to register reg."""
    for a in range(addr - 1, max(addr - 400, -1), -1):
        if a not in gh:
            continue
        mn, _, rest = gh[a][1].lstrip('_').partition(' ')
        _, kv = fields(rest, True)
        m = kv.get('M', 0x6ff)
        u1, u2 = (m & 0x7f) != 0x7f, (m >> 7) != 0xd
        if (u1 and kv.get('Q', 0x1f) == reg) or (u2 and kv.get('P', 0x1f) == reg):
            return a, mn, kv
    return None, None, None


def test_b():
    gh = ghidra_listing(os.path.join(OUT, 'diag.listing'))
    rows = [l.rstrip('\n').split('\t') for l in open('ucode/ge_inst_results.tsv') if l[0].isdigit()]
    bad = []
    nops = 0
    for row in rows:
        i, a = int(row[0]), int(row[1], 16)
        mn, _, rest = gh[a][1].lstrip('_').partition(' ')
        _, kv = fields(rest, True)
        if not (mn in ('st', 'mov', 'movb', 'fmov') and kv.get('r213') == 3 and kv.get('B') in (9, 10, 11)
                and kv.get('M') in (0x6ca, 0x6cb, 0x27f)):
            bad.append('  out %d @%04x: %s' % (i, a, gh[a][1]))
            continue
        if i not in OPS:
            continue
        nops += 1
        reg = kv.get('r148', 0) >> 5
        pa, pmn, pkv = producer(gh, a, reg)
        want = OPS[i]
        if want in ('rcpseed', 'rsqseed'):
            # The seed reaches a register through the unit-2 move r110 = 0x68d.
            if pkv is None or pkv.get('r110') != 0x68d:
                bad.append('  op %d: no seed move before %04x' % (i, a))
                continue
            for b in range(pa - 1, pa - 40, -1):
                bmn = gh.get(b, ('', ''))[1].lstrip('_').split(' ')[0]
                if bmn in ('rcpseed', 'rsqseed'):
                    pa, pmn = b, bmn
                    break
        if pmn != want:
            bad.append('  op %d (out @%04x, R%d): want %s, got %s @%s' % (
                i, a, reg, want, pmn, '%04x' % pa if pa is not None else '-'))
    ok = not bad and len(rows) == 172
    print('(b) %s: %d output words, %d documented operations; %d mismatches' % (
        'PASS' if ok else 'FAIL', len(rows), nops, len(bad)))
    for s in bad[:12]:
        print(s)
    return ok


def compute_routines():
    """Routine entries among the bullet subjects of ge_compute.md.

    A subject is a routine entry when ucode/ge_xref.tsv says something
    outside its own code reaches it (a geif.u slot, an ARM load, the
    distributor table, its address stored as a constant) or a call word
    (group-0 transfer in ucode/ge_listing/) names it, or when it shares its
    address with such a label. Loop heads and branch targets inside a
    routine (lXF1, mainloop_clamp, ...) are not routine entries.
    """
    syms = {}
    for line in open('ucode/KONA/ge_symbols'):
        n, a = line.split()
        syms[n] = int(a, 16)
    reached = set()
    for line in open('ucode/ge_xref.tsv'):
        f = line.rstrip('\n').split('\t')
        if line.startswith(('#', 'address')) or len(f) < 11:
            continue
        slots, arm, _, ged, _, consts = f[5:11]
        if slots or arm or ged or consts:
            reached.add(int(f[0], 16))
    for p in glob.glob('ucode/ge_listing/*.lst'):
        for line in open(p):
            m = re.search(r' xfer[45] c0 cc=[0-9a-f]+ -> ([0-9a-f]{4})', line)
            if m:
                reached.add(int(m.group(1), 16))
    names, other = [], []
    for line in open('ucode/ge_compute.md'):
        m = re.match(r'^- `([A-Za-z_][A-Za-z0-9_]*)`', line)
        if m and m.group(1) in syms:
            (names if syms[m.group(1)] in reached else other).append((m.group(1), syms[m.group(1)], line))
    return names, other


def test_c():
    funcs = {}
    for line in open(os.path.join(OUT, 'prod.functions')):
        a, n = line.split('\t')
        funcs[int(a, 16)] = n.strip()
    routines, other = compute_routines()
    miss = [(n, a) for n, a, _ in routines if a not in funcs]
    ok = not miss
    print('(c) %s: %d of %d routine entries in ge_compute.md are functions (%d functions found; '
          '%d other subjects are loop heads or branch targets, %d of them function entries)' % (
              'PASS' if ok else 'FAIL', len(routines) - len(miss), len(routines), len(funcs),
              len(other), sum(1 for _, a, _ in other if a in funcs)))
    for n, a in miss[:40]:
        print('  missing %04x %s' % (a, n))
    return ok


def test_d():
    ok = True
    checks = {
        # mmo_Clamp: the loop clamps 24 inputs per pass with 0x7c, multiplies
        # each by a scale, stores the products (ge_compute.md, clamp.s).
        '1633': [('clamp of each loop input', r'clamp01\(', 24),
                 ('float multiply', r'\*\s*\w+', 24),
                 ('clamped value multiplied by its scale', r'clamp01\([^()]*\)\s*\*', 24),
                 ('counted loop', r'\bwhile\b', 1)],
        # uMatrixMultCCC: reads the projection 0x3f-0x4e, the 0.5 constant,
        # four subtracts of the fourth and third elements, multiplies by the
        # modelview, stores 0x4f-0x5e.
        '0e62': [('projection words read', r'DAT_cram_00(3f|4[0-9a-e])\b', 12),
                 ('the 0.5 constant', r'\b0\.5\b', 1),
                 ('third elements 0x41/45/49/4d read', r'DAT_cram_00(41|45|49|4d)\b', 4),
                 ('float subtracts', r'\s-\s', 4),
                 ('results stored to 0x4f-0x5e', r'DAT_cram_00(4f|5[0-9a-e])\s*=', 16)],
        # mMatrixMultCCW: 32 multiply words (0xeb5-0xed7) run in lanes 0 and
        # 1. Lane 0 reads W's words 0-7 through AR11, lane 1 words 8-0xf
        # through its own AR11 (0xeb1 adds 8), so the words give 64 products
        # in 16 sums of four; r95 = 4 stores lane 0's sum to C + k and r95 = 5
        # lane 1's to C + 8 + k (ge_isa.md, "Lanes"), all 16 words of C.
        '0eb0': [('float multiplies', r'[\w\]\)]\s\*\s[\w\(*]', 64),
                 ('float adds', r'\s\+\s', 24),
                 ('stores to C + 0 to 0xf', r'(?:\*in_AR10|in_AR10\[(?:0x[0-9a-f]+|\d+)\])\s=\s', 16)],
        # mClipTriFlush: 0xf1e4 loads the transfer-target register from
        # control word 0xe (r95 = 2) and 0xf1e6 pushes it on the link stack,
        # the word above register 0x17 (r95 = 7; ge_isa.md, "Calls, returns
        # and the end of a command").
        'f1dc': [('successor word pushed at register 0x17 plus 1',
                  r'\(in_AR23 \+ 1\) = DAT_cram_000e;', 1)],
    }
    for k, cs in checks.items():
        p = os.path.join(OUT, 'decomp', k + '.c')
        src = open(p).read() if os.path.exists(p) else ''
        lines = src.count('\n')
        res = []
        # The decompiler may hold a clamped value in a variable before the
        # multiply; count a multiply whose operand is such a variable too.
        clamped = set(re.findall(r'(\w+) = (?:\(float\))?clamp01\(', src))
        for what, rx, need in cs:
            got = len(re.findall(rx, src))
            if rx.startswith(r'clamp01\([^()]*\)\s*\*') and clamped:
                got += len(re.findall(r'\b(?:%s)\s\*\s' % '|'.join(map(re.escape, clamped)), src))
            res.append((what, got, need, got >= need))
        good = all(r[3] for r in res) and 'decompile failed' not in src and lines > 5
        ok &= good
        print('(d) %s %s (%d lines): %s' % ('PASS' if good else 'FAIL', k, lines, '; '.join(
            '%s %d/%d%s' % (w, g, n, '' if f else ' MISSING') for w, g, n, f in res)))
    return ok


def test_imports():
    """ge11.u and ge.hex import to the same words as ge.u; ge_diag_init too."""
    ok = True
    base = ghidra_listing(os.path.join(OUT, 'prod.listing'))
    for name, ref in (('ge11.u', base), ('ge.hex', base), ('ge_diag_init.hex', None)):
        p = os.path.join(OUT, name + '.listing')
        got = ghidra_listing(p) if os.path.exists(p) else {}
        if ref is None:
            good = len(got) == 283 and all(t != '<none>' for _, t in got.values())
        else:
            good = got == ref
        ok &= good
        print('(import) %s %s: %d words' % ('PASS' if good else 'FAIL', name, len(got)))
    return ok


def main():
    results = [test_a(), test_b(), test_c(), test_d(), test_imports()]
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
