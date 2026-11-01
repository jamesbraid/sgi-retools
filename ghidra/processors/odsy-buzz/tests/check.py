#!/usr/bin/env python3
"""Compare the ODSY-BUZZ Ghidra module's output with the script and the documents.

Usage: check.py [OUTDIR]   (default .cache/odsy-buzz; run-ghidra.sh writes it)

  (a) every record of buzz_xform.bin, of the kernel copy and of diagxform.bin:
      Ghidra's fields and end mark equal those scripts/buzz_ucode_disasm.py
      prints, field for field, and the idle record is idle in both;
  (b) every routine entry of ucode/buzz_routines.md's routine table (and its
      kernel record, in the kernel copy) is a function entry or a decoded
      record inside a function's flow;
  (c) the decompiled clip-plane routine 0, unlit transform program 214 and
      normalize program 1520 show the arithmetic ucode/buzz_routines.md and
      ucode/buzz_isa.md give them.

Prints one line per test and the failures; exits non-zero if any test fails.
"""
import itertools
import os
import re
import subprocess
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.cache/odsy-buzz'
IMAGES = [('xform', 'ucode/ODSY/buzz_xform.bin', []),
          ('kernel', 'ucode/buzz_ucode_ip30.bin', ['--kernel']),
          ('diag', 'root/builds/odydiags-6.5.15/usr/diags/ody/ucode/diagxform.bin', [])]
GROUPS = [('r1', 'r2', 'r3'), ('a', 'b'), ('ln', 'rb', 'bx'), ('mc', 'ma'),
          ('d0', 'd1', 'd2'), ('e0', 'e1', 'e2', 'e3'), ('s0', 's1')]
SEQ = {'': 0, 'end': 1, 'end2': 2, 'seq3': 3}
MNEMONIC = {'rec': 0, 'end': 1, 'end2': 2, 'seq3': 3}
PY_LINE = re.compile(r'^(\d{4})  (?:[0-9a-f]{4} ){6} (.*)$')
KV = re.compile(r'\b([a-z][a-z0-9]*)=0x([0-9a-f]+)')


def script_listing(image, opts):
    """{record: (fields or 'idle', mark)} from scripts/buzz_ucode_disasm.py."""
    text = subprocess.run([sys.executable, 'scripts/buzz_ucode_disasm.py', image] + opts,
                          check=True, capture_output=True, text=True).stdout
    res = {}
    for line in text.splitlines():
        m = PY_LINE.match(line)
        if not m:
            continue
        rec, rest = int(m.group(1)), m.group(2).strip()
        if rest == 'idle':
            res[rec] = ('idle', 0)
            continue
        parts = rest.split()
        mark = parts[7] if len(parts) > 7 else ''
        fields = {}
        for names, vals in zip(GROUPS, parts[:7]):
            for name, v in zip(names, vals.split('.')):
                fields[name] = int(v, 16)
        res[rec] = (fields, SEQ[mark])
    return res


def ghidra_listing(path):
    """{record: (fields or 'idle', mark)} from DumpListing.java's output."""
    res = {}
    for line in open(path):
        rec, text = line.rstrip('\n').split('\t')
        mn, _, rest = text.strip().partition(' ')
        mn = mn.lstrip('_')     # Ghidra marks delay-slot records with '_'
        if mn == 'idle':
            res[int(rec)] = ('idle', 0)
        elif mn in MNEMONIC:
            fields = {k: int(v, 16) for k, v in KV.findall(rest)}
            res[int(rec)] = (fields, MNEMONIC[mn])
        else:
            res[int(rec)] = (text, -1)
    return res


def test_a():
    ok = True
    for tag, image, opts in IMAGES:
        if not os.path.exists(image):
            print(f'(a) {tag}: {image} missing; skipped')
            continue
        py = script_listing(image, opts)
        gh = ghidra_listing(os.path.join(OUT, f'{tag}.listing'))
        bad = []
        for rec, (pf, pm) in py.items():
            gf, gm = gh.get(rec, ('<missing>', -1))
            if pf == 'idle' or gf == 'idle':
                same = pf == gf
            else:
                names = set(pf) | set(gf)
                same = gm == pm and all(pf.get(k, 0) == gf.get(k, 0) for k in names)
            if not same:
                bad.append(f'  {rec:04d} script: {pf} {pm}\n       ghidra: {gf} {gm}')
        extra = sorted(set(gh) - set(py))
        print(f'(a) {tag}: {len(py) - len(bad)} of {len(py)} records match field for field'
              + (f'; Ghidra has {len(extra)} records the script does not' if extra else ''))
        if bad or extra or not py:
            ok = False
            print('\n'.join(bad[:5]))
    return ok


def routine_table():
    """(entry, kernel record or None) rows of buzz_routines.md's routine table."""
    rows, on = [], False
    for line in open('ucode/buzz_routines.md'):
        if line.startswith('## Routines'):
            on = True
            continue
        if on and line.startswith('#'):
            break
        m = re.match(r'^\| (\d+) \| \d+ \| \d+ \| (\d+|none) \|', line)
        if on and m:
            rows.append((int(m.group(1)), None if m.group(2) == 'none' else int(m.group(2))))
    return rows


def functions(path):
    entries, bodies = set(), []
    for line in open(path):
        rec, _, ranges = line.rstrip('\n').split('\t')
        entries.add(int(rec))
        for r in ranges.split():
            lo, hi = r.split('-')
            bodies.append((int(lo), int(hi)))
    return entries, bodies


def found(rec, entries, bodies, listing):
    if rec in entries:
        return 'function'
    if any(lo <= rec <= hi for lo, hi in bodies) and listing.get(rec, ('', -1))[1] >= 0:
        return 'inside'
    return None


def test_b():
    rows = routine_table()
    ok = bool(rows)
    for tag, col in (('xform', 0), ('kernel', 1)):
        entries, bodies = functions(os.path.join(OUT, f'{tag}.functions'))
        listing = ghidra_listing(os.path.join(OUT, f'{tag}.listing'))
        # The table's kernel numbers past the copy's last record name routines
        # that only buzz_xform.bin has.
        want = [r[col] for r in rows if r[col] is not None and r[col] < len(listing)]
        res = {e: found(e, entries, bodies, listing) for e in want}
        miss = [e for e, v in res.items() if v is None]
        nfun = sum(1 for v in res.values() if v == 'function')
        print(f'(b) {tag}: {len(want) - len(miss)} of {len(want)} routine-table entries found '
              f'({nfun} as function entries, the rest inside a table program\'s flow)')
        if miss:
            ok = False
            print('  missing:', ' '.join(map(str, miss)))
    return ok


def decomp(rec):
    path = os.path.join(OUT, 'decomp', f'{rec}.c')
    return open(path).read() if os.path.exists(path) else ''


class Defs:
    """The assignments of one decompiled function, so a check can look
    through the decompiler's temporaries: forms(x) is every way of writing x
    with temporaries replaced by what they were assigned (to depth 3)."""
    VAR = re.compile(r'\b(?:[a-z]Var\d+|in_[A-Z0-9]+)\b')

    def __init__(self, text):
        text = re.sub(r'\((?:float|char|bool)\)', '', text)
        self.text = re.sub(r'\s+', ' ', text)
        self.defs = {}
        for name, rhs in re.findall(r'\b(\w+) = ([^;,=]+?)(?=[;,])', self.text):
            self.defs.setdefault(name, set()).add(rhs.strip())

    def forms(self, expr, depth=4):
        vars_ = sorted(set(self.VAR.findall(expr)) & set(self.defs))
        out = {expr}
        if depth == 0 or not vars_:
            return out
        for choice in itertools.islice(itertools.product(*(sorted(self.defs[v]) for v in vars_)), 64):
            sub = dict(zip(vars_, choice))

            def put(m):
                rhs = sub[m.group(0)]
                bare = (m.start() > 0 and m.string[m.start() - 1] == '('
                        and m.string[m.end():m.end() + 1] == ')')
                simple = re.fullmatch(r'[\w.]+(?:\([^()]*\))?', rhs)
                return rhs if bare or simple or m.group(0) == m.string else f'({rhs})'
            new = re.sub(r'\b(?:' + '|'.join(vars_) + r')\b', put, expr)
            out |= self.forms(new, depth - 1)
            if len(out) > 2000:
                break
        return out

    def assigned(self, name, pattern):
        """Some assignment to NAME has a form matching PATTERN."""
        return any(re.fullmatch(pattern, f) for rhs in self.defs.get(name, ())
                   for f in self.forms(rhs))

    def anywhere(self, pattern):
        """Some assignment's right-hand side has a form containing PATTERN."""
        return any(re.search(pattern, f) for rhss in self.defs.values()
                   for rhs in rhss for f in self.forms(rhs))


def dot_of(a, b):
    """The four-lane product of register A with input slot or register B, in
    Ghidra's order: x, y, z then w, each lane a product."""
    return r' \+ '.join(rf'{a}_{l} \* {b}_{l}' for l in 'xyzw')


def test_c():
    failures = []

    def check(name, cond, why):
        if not cond:
            failures.append(f'  {name}: {why}')

    # Routine 0: eye coordinates R27 = modelview rows R9 to R12 times the
    # position (records 0 to 3, written at 7 to 10); plane B into R26 from
    # parameter words 0x124 to 0x127, plane C's first two words into R25.x and
    # R25.y over plane A's last two (ucode/buzz_routines.md, routine 0; plane
    # A's own four words go only into the product the routine fires at 9).
    d = Defs(decomp(0))
    for lane, row in zip('xyzw', (9, 10, 11, 12)):
        check('0', d.assigned(f'R27_{lane}', dot_of(f'R{row}', 'P')), f'R27.{lane} is not R{row} . P')
    for reg, lane, word in [(26, 'x', 0x124), (26, 'y', 0x125), (26, 'z', 0x126), (26, 'w', 0x127),
                            (25, 'x', 0x128), (25, 'y', 0x129), (25, 'z', 0x122), (25, 'w', 0x123)]:
        check('0', d.assigned(f'R{reg}_{lane}', f'pm_{word:03x}'),
              f'R{reg}.{lane} does not take parameter word {word:#x}')
    # Program 214: 1/w from the R3 product (d2 0x2b) as word 3, x/w and y/w
    # from the R0 and R1 products (0x46, 0x26) as words 5 and 6, z/w from R2
    # as word 4 (ucode/buzz_routines.md, routine 214; buzz_isa.md pass 18).
    d = Defs(decomp(214))
    invw = rf'1\.0 / \({dot_of("R3", "P")}\)'
    check('214', d.assigned('word3', invw), 'word 3 is not 1/(R3 . P)')
    for word, row in ((5, 0), (6, 1), (4, 2)):
        check('214', d.assigned(f'word{word}', rf'\({dot_of(f"R{row}", "P")}\) \* \({invw}\)'),
              f'word {word} is not (R{row} . P)/w')
    # Program 1520 (GL_NORMALIZE on): the eye normal n is R13 to R15 against
    # the normal slot; code 1 takes the reciprocal square root of |n|^2 (R17.w
    # adds the w term, 0 after set-up 515); code 6 scales the specular dot
    # n . R18 by it; code 3 takes that through (1, 0, 0, 1) against
    # (code-6 result, 0, 0, R18.w = 8 + s) (ucode/buzz_routines.md, routine
    # 1520; buzz_isa.md pass 17).
    d = Defs(decomp(1520))
    n = [rf'\({dot_of(f"R{r}", "N")}\)' for r in (13, 14, 15)]
    sq = rf'{n[0]} \* {n[0]} \+ {n[1]} \* {n[1]} \+ {n[2]} \* {n[2]} \+ R17_w \* R17_w'
    rs = rf'1\.0 / SQRT\({sq}\)'
    spec = rf'{n[0]} \* R18_x \+ {n[1]} \* R18_y \+ {n[2]} \* R18_z \+ R17_w \* R18_w'
    check('1520', d.anywhere(rs), 'no reciprocal square root of |n|^2')
    check('1520', d.anywhere(rf'\({rs}\) \* \({spec}\)'), 'code 6 does not scale n . R18 by it')
    check('1520', d.anywhere(rf'scalar_table\(k_1 \* \({rs}\) \* \({spec}\) \+ '
                             r'R26_y \* k_0 \+ R26_z \* k_0 \+ R16_w \* R18_w\)'),
          'code 3 does not take (code-6 result) + 8 + s')
    for name in ('0', '214', '1520'):
        if not decomp(int(name)):
            failures.append(f'  {name}: no decompiled output')
    print(f'(c) decompiled routines 0, 214 and 1520: {"match" if not failures else "differ"}'
          ' the documented arithmetic')
    if failures:
        print('\n'.join(failures))
    return not failures


def main():
    results = [test_a(), test_b(), test_c()]
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
