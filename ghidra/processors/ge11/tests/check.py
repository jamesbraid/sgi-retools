#!/usr/bin/env python3
"""Compare the GE11 Ghidra module's output with the sources and GE11.h.

Usage: check.py [OUTDIR]   (default .cache/ge11; run-ghidra.sh writes it)

  (a) mgras_ge.hex alone, decoded through data/ge11_decode.tsv, lists every
      word exactly as mgras_ge.u with its own records does;
  (b) ucode/ge11.bin, also through the table, lists the same at every
      address mgras_ge.hex holds, and nothing else (the image fills the
      addresses the program leaves unused);
  (c) the 6.5.7 diagnostic: its output stores are the 172 words of
      ge_inst.h in order, plus the four of vol_aalu3_cond_B that ge_inst.h
      keeps in a comment; those four carry W71; and each operation the
      GE11.h operation table fixes is the word that computes the stored
      register;
  (d) routine discovery: every command handler of mgras_geif.u, every call
      target and every pixel module GE11.h lists is a function entry
      (the pixel modules by their source-file name: GE11.h gives their 6.5.22
      addresses, and this is the 6.5.0 program); in the diagnostic,
      every call target is a function;
  (e) the decompiled umatrix.s, uxform.s and trigeom.s modules carry float
      arithmetic;
  (f) tools/kona_gen_slaspec.py is the KONA generator, when a kona checkout
      sits beside this repository.

Prints one line per test and the failures; exits non-zero if any fails.
"""
import os
import re
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.cache/ge11'
DIAG = 'root/irix-6.5.7-src/stand/arcs/ide/isddevices/graphics/MGRAS'
HERE = os.path.dirname(os.path.abspath(__file__))
KV = re.compile(r'\b([A-Za-z][A-Za-z0-9]*)=(0x[0-9a-f]+)')
XFER = re.compile(r'^(call|callc|jmp|bc|loop)\b.*->\s+0x([0-9a-f]+)')


def listing(name):
    res = {}
    for line in open(os.path.join(OUT, name)):
        a, w, text = line.rstrip('\n').split('\t')
        res[int(a, 16)] = (w, text.strip())
    return res


def functions(name):
    res = {}
    for line in open(os.path.join(OUT, name)):
        a, n = line.rstrip('\n').split('\t')
        res[int(a, 16)] = n
    return res


def fields(text):
    mn, _, rest = text.lstrip('_').partition(' ')
    return mn, {k: int(v, 16) for k, v in KV.findall(rest)}


def report(name, ok, msg, shown=()):
    print('%s %s: %s' % (name, 'PASS' if ok else 'FAIL', msg))
    for s in list(shown)[:8]:
        print('  ' + s)
    return ok


def test_a():
    prod, hexl = listing('prod.listing'), listing('hex.listing')
    bad = [a for a in prod if hexl.get(a) != prod[a]]
    return report('(a)', not bad and len(prod) == len(hexl),
                  '%d of %d words of mgras_ge.hex decode as mgras_ge.u lists them' % (len(prod) - len(bad), len(prod)),
                  ['%04x u: %s\n       hex: %s' % (a, prod[a], hexl.get(a)) for a in bad])


def test_b():
    prod, binl = listing('prod.listing'), listing('bin.listing')
    bad = ['%04x u: %s\n       bin: %s' % (a, prod[a], binl.get(a)) for a in prod if binl.get(a) != prod[a]]
    extra = [a for a in binl if a not in prod]
    if extra:
        bad.append('ge11.bin lists %d words mgras_ge.u does not hold' % len(extra))
    return report('(b)', not bad, '%d of %d words of ge11.bin list as mgras_ge.u does; '
                  'its other words are fill' % (len(prod) - len(bad), len(prod)), bad)


# Operation that computes each expected word of ge_inst.h, by index (GE11.h,
# "MICROCODE INSTRUCTION WORD", operation table). The same 172 words come
# back from the KONA engine's copy of this test.
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
        mn, kv = fields(gh[a][1])
        m = kv.get('M', 0x6ff)
        u1, u2 = (m & 0x7f) != 0x7f, (m >> 7) != 0xd
        if (u1 and kv.get('Q', 0x1f) == reg) or (u2 and kv.get('P', 0x1f) == reg):
            return a, mn, kv
    return None, None, None


def diag_symbols():
    syms = {}
    for line in open(os.path.join(DIAG, 'ge11symtab.h')):
        m = re.match(r'#define\s+(\S+)\s+\((0x[0-9a-f]+)\)', line)
        if m:
            syms[m.group(1)] = int(m.group(2), 16)
    return syms


def expected_count():
    text = re.sub(r'/\*.*?\*/', '', open(os.path.join(DIAG, 'ge_inst.h')).read(), flags=re.S)
    body = text[text.index('{'):text.index('}')]
    return len(re.findall(r'0x[0-9a-fA-F]+', body))


def test_c():
    gh = listing('diag.listing')
    syms = diag_symbols()
    b_lo = syms['vol_aalu3_cond_B']
    b_hi = min(a for a in syms.values() if a > b_lo)
    outs, bad = [], []
    for a in sorted(gh):
        mn, kv = fields(gh[a][1])
        if mn in ('st', 'mov', 'movb', 'fmov') and kv.get('r213') == 3 and kv.get('B') in (9, 10, 11) \
                and kv.get('M') in (0x6ca, 0x6cb, 0x27f):
            outs.append(a)
    thread_b = [a for a in outs if b_lo <= a < b_hi]
    rows = [a for a in outs if not b_lo <= a < b_hi]
    for a in thread_b:
        if fields(gh[a][1])[1].get('w71') != 1:
            bad.append('thread-B output %04x lacks W71' % a)
    nops = 0
    if len(rows) == expected_count():
        for i, a in enumerate(rows):
            if i not in OPS:
                continue
            nops += 1
            reg = fields(gh[a][1])[1].get('r148', 0) >> 5
            pa, pmn, pkv = producer(gh, a, reg)
            want = OPS[i]
            if want in ('rcpseed', 'rsqseed'):
                if pkv is None or pkv.get('r110') != 0x68d:
                    bad.append('op %d: no seed move before %04x' % (i, a))
                    continue
                for b in range(pa - 1, pa - 40, -1):
                    bmn = fields(gh.get(b, ('', ''))[1])[0]
                    if bmn in ('rcpseed', 'rsqseed'):
                        pa, pmn = b, bmn
                        break
            if pmn != want:
                bad.append('op %d (out @%04x, R%d): want %s, got %s @%s' % (
                    i, a, reg, want, pmn, '%04x' % pa if pa is not None else '-'))
    ok = not bad and len(rows) == expected_count() and len(thread_b) == 4
    return report('(c)', ok, '%d output stores for %d expected words, %d in the thread-B block; '
                  '%d documented operations, %d mismatches' % (
                      len(rows), expected_count(), len(thread_b), nops, len(bad)), bad)


GE11H = os.path.join(HERE, '..', '..', '..', '..', 'GE11.h')


def pixel_modules():
    """Names of the pixel modules GE11.h lists ("0x156A clamp ...")."""
    text = open(GE11H).read()
    i = text.index('Entries are the routines')
    block = text[i:text.index('States live', i)]
    names = re.findall(r'0x[0-9A-F]{4} (?:/ 0x[0-9A-F]{4} )*([A-Za-z]+)', block)
    return names + (['bitmaptoint'] if 'bitmaptoint 0x' in text else [])


def test_d():
    prod, funcs = listing('prod.listing'), functions('prod.functions')
    bad = []
    targets = set()
    for a, (w, t) in prod.items():
        m = XFER.match(t)
        if m and t.startswith(('call', 'callc')):
            targets.add(int(m.group(2), 16))
    for a in sorted(targets):
        if a not in funcs:
            bad.append('call target %04x is not a function' % a)
    cmds = [a for a, n in funcs.items() if n.startswith('cmd_')]
    names = {n for n in funcs.values()}
    mods = pixel_modules()
    for m in mods:
        if m + '_s' not in names:
            bad.append('GE11.h pixel module %s is not a source-file function' % m)
    dg, dfn = listing('diag.listing'), functions('diag.functions')
    dt = {int(XFER.match(t).group(2), 16) for _, (w, t) in dg.items() if t.startswith('call') and XFER.match(t)}
    for a in sorted(dt):
        if a not in dfn:
            bad.append('diagnostic call target %04x is not a function' % a)
    ok = not bad and len(cmds) > 0 and len(mods) >= 15
    return report('(d)', ok, '%d functions, %d command handlers, %d call targets, %d GE11.h module '
                  'entries; diagnostic: %d functions, %d call targets' % (
                      len(funcs), len(cmds), len(targets), len(mods), len(dfn), len(dt)), bad)


def test_e():
    ok, msgs = True, []
    for a in ('0e58', '114e', '298f'):
        p = os.path.join(OUT, 'decomp', a + '.c')
        src = open(p).read() if os.path.exists(p) else ''
        n = len(re.findall(r'[\w\]\)] [*+-] [\w\(]', src))
        good = 'decompile failed' not in src and src.count('\n') > 20 and n >= 8
        ok &= good
        msgs.append('%s %d lines, %d arithmetic operators%s' % (a, src.count('\n'), n, '' if good else ' FAIL'))
    return report('(e)', ok, '; '.join(msgs))


def test_f():
    mine = os.path.join(HERE, '..', 'tools', 'kona_gen_slaspec.py')
    root = os.path.join(HERE, '..', '..', '..', '..', '..', 'kona')
    for rel in ('ghidra/processors/kona-ge/tools/gen_slaspec.py', 'sleigh/kona-ge/tools/gen_slaspec.py'):
        theirs = os.path.join(root, rel)
        if os.path.exists(theirs):
            same = open(mine).read() == open(theirs).read()
            return report('(f)', same, 'kona_gen_slaspec.py %s ../kona/%s' % (
                'equals' if same else 'differs from', rel))
    print('(f) SKIP: no ../kona checkout beside this repository')
    return True


def main():
    results = [test_a(), test_b(), test_c(), test_d(), test_e(), test_f()]
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
