#!/usr/bin/env python3
"""A big-endian MIPS test image built from hand-encoded words, and the records the walks must give for it.

  mips_synthetic.py                      check the generator against itself
  mips_synthetic.py write DIR            write DIR/mips.bin, mips-functions.tsv and mips-expected-*.tsv
  mips_synthetic.py check-walks DIR [P]  compare DIR/Pcalls.tsv and DIR/Paccesses.tsv (WalkDump.java's
                                         output) with DIR/Pexpected-calls.tsv and DIR/Pexpected-accesses.tsv
  mips_synthetic.py check-golden DIR GOLDEN P   compare the default output of DumpCallEdges and FindWindowStores
                                         (DIR/P-edges.tsv, -stores.tsv, -helper.tsv) with the golden ones taken
                                         before the walks were added: edges and helper rows equal, access rows
                                         equal in their first ten columns and four columns longer
  mips_synthetic.py check-hand DIR       check DIR/hand.tsv, what HandProbe.java saw around ReHandFunctions.java
  mips_synthetic.py check-twice A B      two runs' result files are identical, but for the export's timings
  mips_synthetic.py check-names FILE...  every identifier in the export's C is known or on the decompiler list
  mips_synthetic.py check-xref DIR P     compare DIR/xref-P/xref-*.jsonl (ReXrefExport's records) with the walks'
                                         expected ones, the hardware flags and the one string reference
  mips_synthetic.py check-sites DIR P    compare DumpCallEdges' sites rows (DIR/P-sites.tsv) with DIR/P-expected-calls.tsv

No byte comes from an SGI image. The image is flat, loaded at BASE as MIPS:BE:64:64-32addr, and read-only
once imported. Code is at the bottom; the read-only tables are above it.
"""
import os
import sys

BASE = 0xbfc00000
DEVICE = 0xbf000000      # a kseg1 device window, outside the image
PTR_TARGET = 0xbf100000  # what the pointer table holds: another window
STRING = BASE + 0x1500   # a string in the image
SIZE = 0x1700

# Register numbers.
ZERO, V0, A0, A1, T0, T1, T2, T3, T4, T5, T6, T7, T9, RA = 0, 2, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 25, 31


def r_type(rs, rt, rd, sa, funct):
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct


def i_type(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)


class Image:
    """Words placed at addresses, with the records they should produce."""

    def __init__(self):
        self.words = {}
        self.calls = []       # (site, function, target or None, kind, source or None, tail)
        self.accesses = []    # (site, function, address, width, op, addressing, base, load_site, value, uses)
        self.entries = []     # function entries in address order
        self.strings = []     # (string address, text, function, site of the instruction that makes the address)
        self.pc = BASE
        self.func = None

    def at(self, address):
        self.pc = address

    def word(self, value):
        self.words[self.pc] = value & 0xffffffff
        self.pc += 4
        return self.pc - 4

    def function(self, address):
        self.at(address)
        self.func = address
        self.entries.append(address)

    # instructions
    def nop(self):
        self.word(0)

    def lui(self, rt, imm):
        self.word(i_type(0xf, 0, rt, imm))

    def ori(self, rt, rs, imm):
        self.word(i_type(0xd, rs, rt, imm))

    def addiu(self, rt, rs, imm):
        self.word(i_type(9, rs, rt, imm))

    def addu(self, rd, rs, rt):
        self.word(r_type(rs, rt, rd, 0, 0x21))

    def sll(self, rd, rt, sa):
        self.word(r_type(0, rt, rd, sa, 0))

    def sltiu(self, rt, rs, imm):
        self.word(i_type(0xb, rs, rt, imm))

    def sltu(self, rd, rs, rt):
        self.word(r_type(rs, rt, rd, 0, 0x2b))

    def andi(self, rt, rs, imm):
        self.word(i_type(0xc, rs, rt, imm))

    def beq(self, rs, rt, target):
        self.word(i_type(4, rs, rt, (target - (self.pc + 4)) >> 2))
        self.nop()

    def ret(self):
        self.word(r_type(RA, 0, 0, 0, 8))
        self.nop()

    def load_const(self, rt, value):
        self.lui(rt, (value >> 16) & 0xffff)
        self.ori(rt, rt, value & 0xffff)

    # calls: each records what the call walk must say
    def jal(self, target):
        site = self.word((3 << 26) | ((target >> 2) & 0x3ffffff))
        self.nop()
        self.calls.append((site, self.func, target, 'direct', None, False))

    def tail(self, target):
        site = self.word((2 << 26) | ((target >> 2) & 0x3ffffff))
        self.nop()
        self.calls.append((site, self.func, target, 'direct', None, True))

    def jalr(self, rs, target, kind, source=None):
        site = self.word(r_type(rs, 0, RA, 0, 9))
        self.nop()
        self.calls.append((site, self.func, target, kind, source, False))

    # memory: each records the access the walk must say, for a device address built here
    def mem(self, op, rt, base, disp, address, width, op_name, addressing='absolute', base_word=None, rec=True,
            delay=False, value='', uses=()):
        site = self.word(i_type(op, base, rt, disp))
        if rec:
            # Ghidra gives a delay slot's p-code to the branch, so that is the site the walk reports.
            self.accesses.append((site - 4 if delay else site, self.func, address, width, op_name, addressing,
                                  base_word, None, value, tuple(uses)))
        return site

    def lw(self, rt, base, disp, address=None, **kw):
        return self.mem(0x23, rt, base, disp, address, 4, 'load', rec=address is not None, **kw)

    def sw(self, rt, base, disp, address, **kw):
        return self.mem(0x2b, rt, base, disp, address, 4, 'store', **kw)

    def sb(self, rt, base, disp, address, **kw):
        return self.mem(0x28, rt, base, disp, address, 1, 'store', **kw)

    def sd(self, rt, base, disp, address, **kw):
        return self.mem(0x3f, rt, base, disp, address, 8, 'store', **kw)


def build():
    im = Image()
    tab, ptrs, jt = BASE + 0x800, BASE + 0x810, BASE + 0x900
    f_a, f_b, f_c, f_d = BASE + 0x100, BASE + 0x200, BASE + 0x220, BASE + 0x240

    # Calls of every resolution kind.
    im.function(BASE)
    im.jal(f_a)
    im.lui(T9, f_b >> 16)
    im.addiu(T9, T9, f_b & 0xffff)
    im.jalr(T9, f_b, 'constant')
    im.lui(T0, tab >> 16)
    im.lw(T0, T0, tab & 0xffff)   # a read of the image itself is not a device access
    im.jalr(T0, f_b, 'constant', tab)
    im.sll(T1, A0, 2)
    im.lui(T0, tab >> 16)
    im.addu(T0, T0, T1)
    im.lw(T0, T0, tab & 0xffff)
    im.jalr(T0, None, 'table', tab)
    im.jalr(A1, None, 'unresolved')
    im.tail(f_c)

    # Device accesses.
    im.function(f_a)
    d = DEVICE
    im.lui(T0, d >> 16)
    im.lw(T1, T0, 0x10, d + 0x10)
    im.sw(T2, T0, 0x20, d + 0x20, value='?')    # T2 was never set: no value
    im.sb(T2, T0, 0x30, d + 0x30, value='?')
    im.sd(T2, T0, 0x38, d + 0x38, value='?')
    load = im.lw(T1, T0, 0x40)                 # read, change, write: one rmw
    im.ori(T1, T1, 1)
    store = im.sw(T1, T0, 0x40, d + 0x40, rec=False)
    im.accesses.append((store, f_a, d + 0x40, 4, 'rmw', 'absolute', None, load, 'load@0x%x' % load, ('or 0x1',)))
    im.lw(T1, T0, 0x44, d + 0x44, uses=('eq 0x0',))   # the same, split by a branch: a load and a store
    im.beq(T1, ZERO, im.pc + 8)
    im.lui(T0, d >> 16)
    im.sw(T1, T0, 0x44, d + 0x44, value='?')   # the branch target starts a block: the value is not known here
    im.lui(T0, ptrs >> 16)                      # a base loaded from a pointer table in the image
    im.lw(T0, T0, ptrs & 0xffff)
    im.lw(T1, T0, 8, PTR_TARGET + 8, addressing='base+offset', base_word=ptrs)
    im.word(r_type(RA, 0, 0, 0, 8))             # a store in a delay slot is still an access
    im.sw(T2, T0, 0x70, PTR_TARGET + 0x70, addressing='base+offset', base_word=ptrs, delay=True, value='?')

    for entry in (f_b, f_c, f_d):
        im.function(entry)
        im.ret()

    # A switch through a table of three cases.
    sw = BASE + 0x300
    im.function(sw)
    im.sltiu(T0, A0, 3)
    im.beq(T0, ZERO, sw + 0x40)
    im.sll(T0, A0, 2)
    im.lui(T1, jt >> 16)
    im.addu(T1, T1, T0)
    im.lw(T1, T1, jt & 0xffff)
    im.word(r_type(T1, 0, 0, 0, 8))
    im.nop()
    cases = [sw + 0x30, sw + 0x38, sw + 0x40]
    im.at(sw + 0x30)
    for _ in range(3):
        im.ret()
    im.at(sw + 0x40)
    im.ret()
    im.at(jt)
    for target in cases:
        im.word(target)

    # A routine that never returns and runs on into the next.
    im.function(BASE + 0x400)
    im.lui(T0, d >> 16)
    im.sw(ZERO, T0, 0x60, d + 0x60, value='0x0')
    im.function(BASE + 0x410)
    im.lui(T0, d >> 16)
    im.sw(ZERO, T0, 0x64, d + 0x64, value='0x0')
    im.ret()

    # A branch-likely whose delay slot (run only when taken) changes the base: the store after it has no
    # known address, so no record.
    im.function(BASE + 0x600)
    im.lui(T0, d >> 16)
    im.word(i_type(0x14, T1, ZERO, 2))
    im.lui(T0, (d + 0x10000) >> 16)
    im.sw(T2, T0, 0x80, None, rec=False)
    im.ret()

    # A store helper and a caller that passes it a device address and a value.
    helper = BASE + 0x500
    im.function(helper)
    im.word(i_type(0x2b, A0, A1, 0))
    im.ret()
    im.function(BASE + 0x520)
    im.load_const(A0, d + 0x100)
    im.addiu(A1, ZERO, 5)
    im.jal(helper)
    im.ret()

    # Pairing: a store takes the nearest load its changed value came from, a copy is not a change, a paired
    # load is used up, and a table index needs a read-only base (the device window is not one).
    im.function(BASE + 0x700)
    im.lui(T0, d >> 16)
    first = im.lw(T1, T0, 0xa0, d + 0xa0)       # two loads of one address, summed: the store pairs with the second
    second = im.lw(T2, T0, 0xa0)
    im.addu(T1, T1, T2)
    store = im.sw(T1, T0, 0xa0, d + 0xa0, rec=False)
    im.accesses.append((store, im.func, d + 0xa0, 4, 'rmw', 'absolute', None, second,
                        'load@0x%x,load@0x%x' % (first, second), ()))
    copied = im.lw(T1, T0, 0xa8, d + 0xa8)      # a copy is not a change (and not a use): a load and a store
    im.addu(T3, T1, ZERO)
    im.sw(T3, T0, 0xa8, d + 0xa8, value='load@0x%x' % copied)
    load = im.lw(T1, T0, 0xb0)                  # one rmw, then the same value stored again: a plain store
    im.ori(T1, T1, 1)
    store = im.sw(T1, T0, 0xb0, d + 0xb0, rec=False)
    im.accesses.append((store, im.func, d + 0xb0, 4, 'rmw', 'absolute', None, load, 'load@0x%x' % load, ('or 0x1',)))
    im.sw(T1, T0, 0xb0, d + 0xb0, value='load@0x%x' % load)
    im.sll(T2, A0, 2)                           # a load indexed from the window is no table
    im.addu(T2, T0, T2)
    im.lw(T2, T2, 0xc0)
    im.jalr(T2, None, 'unresolved')
    im.ret()

    # A long straight-line function, above any small test budget.
    im.function(BASE + 0xa00)
    for _ in range(600):
        im.addiu(T1, T1, 1)
    im.ret()

    # What a loaded value meets: a mask, a bound, both signs of an addend, a constant on the left, a compare of
    # the masked value, and the values stored afterwards (a derived one, a constant, a built constant). Then a loaded
    # pointer, whose field is no use of it and no source of the value stored after it.
    im.function(BASE + 0x1400)
    im.lui(T0, d >> 16)
    load = im.lw(T1, T0, 0xd0, d + 0xd0, uses=('and 0xff', 'ltu 0x10', 'add 0x7b2', 'sub 0x7b2', 'gtu 0x3', 'eq 0x3'))
    im.andi(T2, T1, 0xff)
    im.sltiu(T4, T1, 0x10)
    im.addiu(T5, T1, 0x7b2)
    im.addiu(T6, T1, -0x7b2)
    im.addiu(T3, ZERO, 3)
    im.sltu(T4, T3, T1)
    im.sw(T2, T0, 0xd4, d + 0xd4, value='load@0x%x' % load)
    im.sw(T3, T0, 0xd8, d + 0xd8, value='0x3')
    im.load_const(T7, 0x1234abcd)
    im.sw(T7, T0, 0xdc, d + 0xdc, value='0x1234abcd')
    im.lw(T5, T0, 0xe0, d + 0xe0)
    word = im.lw(T6, T5, 8)
    im.andi(T4, T6, 0xf)
    im.sw(T4, T0, 0xe4, d + 0xe4, value='load@0x%x' % word)
    im.beq(T2, T3, im.pc + 8)
    im.ret()

    # A reference to a string: its address built by a lui and an ori.
    im.function(BASE + 0x1480)
    im.lui(T0, STRING >> 16)
    site = im.word(i_type(0xd, T0, T0, STRING & 0xffff))
    im.strings.append((STRING, 'hello!', im.func, site))
    im.ret()
    im.at(STRING)
    im.word(0x68656c6c)
    im.word(0x6f210000)

    im.at(tab)
    for target in (f_b, f_c, f_d):
        im.word(target)
    im.at(ptrs)
    im.word(PTR_TARGET)
    return im


def image_bytes(im):
    data = bytearray(SIZE)
    for address, word in im.words.items():
        off = address - BASE
        data[off:off + 4] = word.to_bytes(4, 'big')
    return bytes(data)


def hexa(value):
    return '-' if value is None else '0x%x' % value


def call_rows(im):
    return sorted('\t'.join((hexa(s), hexa(f), hexa(t), k, hexa(src), '1' if tail else '0'))
                  for s, f, t, k, src, tail in im.calls)


def access_rows(im):
    return sorted('\t'.join((hexa(s), hexa(f), hexa(a), hexa(a & 0x1fffffff), str(w), o, ad, hexa(b), hexa(ls),
                             v or '-', ';'.join(u) or '-'))
                  for s, f, a, w, o, ad, b, ls, v, u in im.accesses)


# The no-return pair at BASE+0x400: Ghidra merges it into one function; a curator's list splits it.
PAIR = [{'entry': '0x%x' % (BASE + 0x400), 'end': '0x%x' % (BASE + 0x410), 'name': 'hand_a'},
        {'entry': '0x%x' % (BASE + 0x410), 'end': '0x%x' % (BASE + 0x420), 'name': 'hand_b'}]
DROP = PAIR[1:]


def write_hand(out):
    import json
    for name, data in (('hand-pair.json', PAIR), ('hand-drop.json', DROP)):
        with open(os.path.join(out, name), 'w') as f:
            json.dump(data, f)


def check_hand(out):
    def rows(name):
        return [tuple(l.split('\t')[1:]) for l in open(os.path.join(out, 'hand.tsv')).read().splitlines()
                if l.split('\t')[0] == name]
    pair = [('0x%x' % (BASE + 0x400), '0x%x' % (BASE + 0x410), 'hand_a'), ('0x%x' % (BASE + 0x410), '0x%x' % (BASE + 0x420), 'hand_b')]
    want = {'pre': pair, 'restored': pair,
            'merged': [('0x%x' % (BASE + 0x400), '0x%x' % (BASE + 0x420), 'FUN_bfc00400')],
            'drop': [pair[1]]}
    bad = 0
    for name, w in want.items():
        if rows(name) != w:
            bad = 1
            print('FAIL hand %s: got %s, want %s' % (name, rows(name), w))
    log = open(os.path.join(out, 'headless-hand-drop.txt')).read()
    if 'ReHandFunctions: dropped FUN_bfc00400' not in log or '1 functions, 1 restored, 1 dropped' not in log:
        bad = 1
        print('FAIL hand-drop did not report the overlapping automatic function')
    if not bad:
        print('PASS hand functions: set before analysis, restored after, an overlapping automatic one dropped')
    return bad


def write(out):
    write_hand(out)
    im = build()
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'mips.bin'), 'wb') as f:
        f.write(image_bytes(im))
    with open(os.path.join(out, 'mips-functions.tsv'), 'w') as f:
        f.write(''.join('%s\n' % hexa(e) for e in im.entries) + ''.join('string %s\n' % hexa(a) for a, _, _, _ in im.strings))
    with open(os.path.join(out, 'mips-expected-calls.tsv'), 'w') as f:
        f.write(''.join(r + '\n' for r in call_rows(im)))
    with open(os.path.join(out, 'mips-expected-accesses.tsv'), 'w') as f:
        f.write(''.join(r + '\n' for r in access_rows(im)))


def read_sorted(path):
    with open(path) as f:
        return sorted(line.rstrip('\n') for line in f if line.strip())


def check_walks(out, prefix=''):
    bad = 0
    for kind in ('calls', 'accesses'):
        got, want = '%s%s.tsv' % (prefix, kind), '%sexpected-%s.tsv' % (prefix, kind)
        g, w = read_sorted(os.path.join(out, got)), read_sorted(os.path.join(out, want))
        if g != w:
            bad = 1
            print('FAIL %s' % got)
            for line in sorted(set(w) - set(g)):
                print('  missing  ' + line)
            for line in sorted(set(g) - set(w)):
                print('  extra    ' + line)
        else:
            print('PASS %s: %d records' % (got, len(g)))
    return bad


def check_golden(out, golden, prefix):
    bad = 0
    for kind, keep in (('edges', None), ('helper', None), ('stores', 10)):
        got = open(os.path.join(out, '%s-%s.tsv' % (prefix, kind))).read().splitlines()
        want = open(os.path.join(golden, '%s-%s.tsv' % (prefix, kind))).read().splitlines()
        if keep:
            rows = [r.split('\t') for r in got]
            if any(len(r) != keep + 4 for r in rows):
                print('FAIL %s-%s: a row is not %d columns' % (prefix, kind, keep + 4))
                bad = 1
            got = ['\t'.join(r[:keep]) for r in rows]
        if got != want:
            bad = 1
            print('FAIL %s-%s differs from the golden' % (prefix, kind))
            for line in sorted(set(want) - set(got)):
                print('  missing  ' + line)
            for line in sorted(set(got) - set(want)):
                print('  extra    ' + line)
        else:
            print('PASS %s-%s: %d rows as before' % (prefix, kind, len(got)))
    return bad


def check_sites(out, prefix):
    rows = [r.split('\t') for r in open(os.path.join(out, '%s-sites.tsv' % prefix)).read().splitlines()]
    want = sorted(r.split('\t') for r in open(os.path.join(out, '%s-expected-calls.tsv' % prefix)).read().splitlines())
    want = [(r[0], r[2].replace('-', ''), r[3]) for r in want if r[5] == '0']
    got = sorted((r[4], r[5], r[6]) for r in rows)
    bad = 0 if got == want else 1
    for r in rows:
        if len(r) != 7 or (r[2] == '?') != (r[5] == '') or r[3] != ('indirect' if r[5] == '' else 'direct'):
            bad = 1
            print('FAIL sites row: %s' % r)
    print('%s %s-sites: %d rows' % ('FAIL' if bad else 'PASS', prefix, len(rows)))
    if bad:
        print('  got  %s\n  want %s' % (got, want))
    return bad


def check_xref(out, prefix):
    """ReXrefExport's records for the fixture: every walked access, the calls of the routines that call one, the
    hardware flags, the callers of the accessing routine, and the string reference."""
    import json
    def rows(name):
        return [json.loads(l) for l in open(os.path.join(out, 'xref-%s%s.jsonl' % (prefix, name))).read().splitlines()]
    im = build()
    sites, funcs, strings = rows('sites'), {r['entry']: r for r in rows('functions')}, rows('strings')
    got = sorted((r['site'], r['function'], r['kind'], r['address'], r['physical'], r['width'], r['value'], ';'.join(r['uses']))
                 for r in sites if r['kind'] != 'call')
    want = sorted((hexa(s), hexa(f), o, hexa(a), hexa(a & 0x1fffffff), w, v, ';'.join(u))
                  for s, f, a, w, o, ad, b, ls, v, u in im.accesses)
    f_a, first = hexa(BASE + 0x100), hexa(BASE)
    accessing = {a[1] for a in im.accesses}
    hardware = accessing | {BASE}    # BASE calls f_a
    calls = sorted((r['site'], r['target']) for r in sites if r['kind'] == 'call')
    wantc = sorted((hexa(s), '%s %s%s%s' % (hexa(t) if t is not None else '?', k, '@' + hexa(src) if src else '', ' tail' if tail else ''))
                   for s, f, t, k, src, tail in im.calls if f in hardware)
    flags = {a: r['hardware'] for a, r in funcs.items() if r['hardware']}
    wantf = {hexa(f): 'access' for f in accessing}
    wantf[first] = 'calls-access'
    bad = 0
    for what, g, w in (('accesses', got, want), ('calls', calls, wantc), ('hardware flags', flags, wantf),
                       ('callers of the accessing routine', funcs[f_a]['callers'], [first]),
                       ('strings', [(r['string'], r['text'], r['function'], r['site']) for r in strings],
                        [(hexa(a), t, hexa(f), hexa(s)) for a, t, f, s in im.strings])):
        if g != w:
            bad = 1
            print('FAIL %sxref %s\n  got  %s\n  want %s' % (prefix, what, g, w))
    if not bad:
        print('PASS %sxref: %d accesses, %d calls, %d hardware routines, %d string reference' % (prefix, len(got), len(calls), len(flags), len(strings)))
    return bad


def check_budget(out):
    rows = [r.split('\t') for r in open(os.path.join(out, 'budget1.tsv')).read().splitlines()]
    same = open(os.path.join(out, 'budget1.tsv')).read() == open(os.path.join(out, 'budget2.tsv')).read()
    status = {r[0]: r[1:3] for r in rows}
    long_fn = 'FUN_bfc00a00'
    bad = 0
    if status.get(long_fn) != ['failed', 'budget']:
        bad = 1
        print('FAIL %s under a 200-instruction limit: %s' % (long_fn, status.get(long_fn)))
    odd = [n for n, s in status.items() if n != long_fn and s[0] == 'failed']
    if odd:
        bad = 1
        print('FAIL functions failed that should not have: %s' % odd)
    if status.get('FUN_bfc00300', [''])[0] != 'partial':
        bad = 1
        print('FAIL the switch function should be partial (jump table not recovered): %s' % status.get('FUN_bfc00300'))
    if not same:
        bad = 1
        print('FAIL two runs gave different statuses')
    if not bad:
        print('PASS budget: the long function fails on budget, the switch is partial, two runs agree')
    return bad


# What Ghidra's C holds besides the program's own names: types, keywords and the invented names the list covers.
GHIDRA_WORDS = {'void', 'int', 'uint', 'long', 'ulong', 'char', 'uchar', 'short', 'ushort', 'byte', 'undefined', 'undefined1',
                'undefined2', 'undefined4', 'undefined8', 'longlong', 'ulonglong', 'code', 'bool', 'if', 'else', 'return',
                'while', 'do', 'for', 'switch', 'case', 'default', 'break', 'goto', 'struct', 'union', 'unsigned', 'WARNING',
                'NULL', 'sizeof', 'halt_baddata'}


def check_names(*paths):
    """Every identifier in Ghidra's C for the fixture is a function of the fixture, a keyword or type, or on the
    decompiler identifier list. A Ghidra release that invents another kind of name fails here."""
    import json
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'tools'))
    import leakcheck
    rows = [json.loads(l) for path in paths for l in open(path) if l.strip()]
    known = GHIDRA_WORDS | {r['name'] for r in rows}
    bad = 0
    for r in rows:
        extra = leakcheck.unmatched_identifiers(r.get('c', ''), known)
        if extra:
            bad = 1
            print('FAIL %s: identifiers neither known nor on the decompiler list: %s' % (r['name'], extra))
    if not bad:
        print('PASS ghidra names: %d functions, every identifier known or on the list' % len(rows))
    return bad


TIMINGS = ('decompile_ms', 'timeout_retried_s')


def check_twice(first, second):
    """The two runs wrote the same files, byte for byte, but for the export's timings. The headless logs and the
    scratch listings are not results. Any other difference fails; the comparison is never widened."""
    import json
    bad = 0
    names = sorted(os.path.relpath(os.path.join(d, f), first) for d, _, fs in os.walk(first) for f in fs
                   if not f.startswith('headless'))
    for name in names:
        a, b = open(os.path.join(first, name), 'rb').read(), open(os.path.join(second, name), 'rb').read()
        if name.endswith('.jsonl'):
            def strip(data):
                rows = [json.loads(l) for l in data.decode().splitlines() if l.strip()]
                return [{k: v for k, v in r.items() if k not in TIMINGS} for r in rows]
            same = strip(a) == strip(b)
        else:
            same = a == b
        if not same:
            bad = 1
            print('FAIL two runs differ in %s' % name)
    if not bad:
        print('PASS run twice: %d result files identical (export timings aside)' % len(names))
    return bad


def selfcheck():
    im = build()
    assert len(im.words) * 4 < SIZE and max(im.words) - BASE < SIZE
    assert len(set(im.entries)) == len(im.entries)
    assert len(call_rows(im)) == 8 and len(access_rows(im)) == 23 and len(im.strings) == 1, (len(call_rows(im)), len(access_rows(im)))
    print('mips_synthetic: %d words, %d functions' % (len(im.words), len(im.entries)))
    return 0


def main(argv):
    if len(argv) == 1:
        return selfcheck()
    if argv[1] == 'write':
        write(argv[2])
        return 0
    if argv[1] == 'check-twice':
        return check_twice(argv[2], argv[3])
    if argv[1] == 'check-names':
        return check_names(*argv[2:])
    if argv[1] == 'check-hand':
        return check_hand(argv[2])
    if argv[1] == 'check-budget':
        return check_budget(argv[2])
    if argv[1] == 'check-golden':
        return check_golden(argv[2], argv[3], argv[4])
    if argv[1] == 'check-xref':
        return check_xref(argv[2], argv[3])
    if argv[1] == 'check-sites':
        return check_sites(argv[2], argv[3])
    if argv[1] == 'check-walks':
        return check_walks(argv[2], argv[3] if len(argv) > 3 else '')
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
