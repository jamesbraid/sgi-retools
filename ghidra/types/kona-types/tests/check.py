"""Check what KonaTypes.java applied.

Usage: python3 ghidra/types/kona-types/tests/check.py [DUMPDIR]   (default .cache/kona-types)

Reads the dumps and logs of tests/run-ghidra.sh and checks:

arm1.u
  - kona_arm_state is laid at SRAM 0;
  - each routed entry of the token list carries the type of its form, and
    the counts per form are those of ucode/ged.md (121 geometry, 71 pass,
    14 register/pixel), counted independently from ucode/icu_map.tsv.
kernel objects
  - every host-interface register access the inventory lists
    (docs/inventory/mmio.tsv, window hip, from the objdump-based scan) is
    named by KonaTypes in the same function at the same window offset.
    Functions the inventory elides as "+N more" are not checked.
Exits 1 on any mismatch.
"""
import collections
import os
import re
import sys

D = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.cache/kona-types')
os.chdir(os.path.dirname(os.path.abspath(__file__)) + '/../../../..')
bad = 0


def fail(m):
    global bad
    bad += 1
    print('FAIL', m)


def tsv(p):
    for line in open(p):
        if line.startswith('#') or not line.strip():
            continue
        yield line.rstrip('\n').split('\t')


# ---- arm1.u
S, T = None, {}
for r in tsv(os.path.join(D, 'arm1.u.dump')):
    if r[0] == 'S':
        S = r[1]
    elif r[0] == 'T':
        T[int(r[1].split('_')[2], 16)] = r[2]
if S != '/KONA/types/kona_arm_state':
    fail(f'arm1.u: SRAM 0 holds {S}, not kona_arm_state')
want = collections.Counter()
for r in tsv('ucode/icu_map.tsv'):
    if not r[0].startswith('0x') or r[3] != 'hw':
        continue
    e = int(r[2], 16)
    form = 'kona_entry_geom' if e >> 31 else 'kona_entry_regpix' if e & 0x20 else 'kona_entry_pass'
    want[form] += 1
    got = T.get(int(r[0], 16))
    if got != form:
        fail(f'arm1.u: token {r[0]} {r[1]} typed {got}, form {form}')
print('arm1.u: state block', S, '; routed entries by form:', dict(want))
if (want['kona_entry_geom'], want['kona_entry_pass'], want['kona_entry_regpix']) != (121, 71, 14):
    fail('arm1.u: form counts differ from ucode/ged.md (121, 71, 14)')

# ---- kernel
named = set()
for line in open(os.path.join(D, 'kernel.log')):
    m = re.search(r'KonaTypes\.java> hh\t(\S+)\t(\S+)\t(0x[0-9a-f]+)\t([rw])\t(\S+)', line)
    if m:
        named.add((m.group(2), int(m.group(3), 16)))
funcs = set()
for r in tsv(os.path.join(D, 'kernel.dump')):
    if r[0] == 'F':
        funcs.add(r[2])
checked = 0
for r in tsv('docs/inventory/mmio.tsv'):
    if r[0] != 'hip':
        continue
    off = int(r[1], 16)
    for f in r[6].split(';'):
        if f.startswith('+'):
            continue
        if f not in funcs:
            print(f'note: {f} (0x{off:x}) is not in the kernel objects imported')
            continue
        checked += 1
        if (f, off) not in named:
            fail(f'kernel: {f} reaches 0x{off:x} ({r[2]}) in mmio.tsv, not named by KonaTypes')
print(f'kernel: {len(named)} (function, register) pairs named; {checked} inventory pairs checked')
print('FAILURES:', bad)
sys.exit(1 if bad else 0)
