"""Compare the KONA-GED import of ged1b.u with scripts/ged_disasm.py.

Usage: python3 ghidra/processors/kona-ged/tests/check.py [DUMPDIR]   (default .cache/kona-ged)

Runs scripts/ged_disasm.py into DUMPDIR/ged_listing.txt, then checks every
program word of DUMPDIR/ged1b.listing (tests/run-ghidra.sh) against it:
the same mnemonic and the same operands. Ghidra prints numbers in hex and a
transfer target as a byte address; the comparison reads every number as a
value and a target as its word (address / 4). The script's annotations in
parentheses and its table B column are not instruction text and are
dropped. Also checks that every table B start word is a function entry.
Exits 1 on any mismatch.
"""
import os
import re
import subprocess
import sys

D = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.cache/kona-ged')
os.chdir(os.path.dirname(os.path.abspath(__file__)) + '/../../../..')
ref = os.path.join(D, 'ged_listing.txt')
subprocess.run([sys.executable, 'scripts/ged_disasm.py', 'ucode/KONA/ged1b.u', ref], check=True)


def norm_tok(t):
    if re.fullmatch(r'0x[0-9a-f]+|\d+', t):
        return str(int(t, 0))
    m = re.fullmatch(r'([a-z]+)=(0x[0-9a-f]+|\d+)', t)
    if m:
        return f'{m.group(1)}={int(m.group(2), 0)}'
    return t


def norm(text, target_scale):
    text = text.replace(',', ' ')
    m = re.search(r'->\s*(\S+)', text)
    if m:
        v = int(m.group(1), 16) // target_scale
        text = text[:m.start()] + f'-> {v}'
    return [norm_tok(t) for t in text.split()]


want, starts = {}, set()
for line in open(ref):
    if line.startswith('#'):
        continue
    m = re.match(r'^([0-9a-f]{3})  ([0-9a-f]{8})  \S+\s+(.*)$', line.rstrip('\n'))
    i, w, rest = int(m.group(1), 16), m.group(2), m.group(3)
    if '  <= B[' in rest:
        starts.add(i)
        rest = rest.split('  <= B[')[0]
    rest = rest.split('  (')[0]
    # The script prints a transfer target as three hex digits without 0x.
    want[i] = (w, norm(rest, 1))

got, funcs = {}, set()
for line in open(os.path.join(D, 'ged1b.listing')):
    r = line.rstrip('\n').split('\t')
    if r[0] == 'F':
        funcs.add(int(r[1], 16))
        continue
    text = r[2].lstrip('_')          # Ghidra marks delay-slot words with _
    got[int(r[0], 16)] = (r[1], norm(text, 4))

bad = 0
for i, (w, toks) in sorted(want.items()):
    g = got.get(i)
    if g is None or g[0] != w or g[1] != toks:
        bad += 1
        if bad <= 20:
            print(f'FAIL word {i:03x} {w}: ged_disasm.py {toks}, Ghidra {g}')
print(f'{len(want) - bad} of {len(want)} words match scripts/ged_disasm.py')
missing = sorted(starts - funcs)
for i in missing:
    bad += 1
    print(f'FAIL table B start {i:03x} is not a function entry')
print(f'{len(starts) - len(missing)} of {len(starts)} table B start words are function entries')
print('FAILURES:', bad)
sys.exit(1 if bad else 0)
