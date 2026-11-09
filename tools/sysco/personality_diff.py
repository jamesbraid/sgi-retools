#!/usr/bin/env python3
"""Compare the ColdFire packages of one L1 container routine by routine against the Origin 300 package.

Usage: tools/re-run python3 scripts/personality_diff.py [--release 6.5.30] [--out docs/personality-diffs]

For the Base 1MB, MIPS 2MB, Legacy 2MB and 2MB packages of a container, pair every routine of the
first flash bank with the routines of the Fuel/PE/O300 package using the matcher of version_diff.py
(same bytes, same code moved, changed in RAM address only, changed, added, removed), and write

  routines.tsv   one row per routine of the compared package
  summary.tsv    the counts per package and class

Run in the toolchain container (capstone is not on the host).
"""
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sysco_tables as st  # noqa: E402
import version_diff as vd  # noqa: E402

REL = '6.5.30'
OUT = os.path.join(st.REPO, 'docs', 'personality-diffs')
if '--release' in sys.argv:
    REL = sys.argv[sys.argv.index('--release') + 1]
if '--out' in sys.argv:
    OUT = os.path.abspath(sys.argv[sys.argv.index('--out') + 1])

BANK = {'Base 1MB image': 0x80000, 'Fuel/PE/O300 1MB image': 0x80000}
DEFAULT_BANK = 0x100000


def first_bank(p):
    n = BANK.get(p['label'], DEFAULT_BANK)
    q = dict(p)
    q['body'] = p['body'][:n]
    return q


def main():
    data = open(os.path.join(st.ROOT, REL, st.FW, 'l1.bin'), 'rb').read()
    pk = [p for p in st.l1_packages(data) if not p['linux']]
    ref = [p for p in pk if 'Fuel/PE' in p['label']][0]
    A = vd.routines(first_bank(ref))
    rows = [['package', 'label', 'routine', 'length', 'class', 'o300_routine', 'o300_length', 'similarity']]
    summ = [['package', 'label', 'routines', 'same-bytes', 'same-code-moved', 'changed-ram-address-only',
             'changed', 'added', 'o300-routines-without-a-pair']]
    for p in pk:
        if p is ref:
            continue
        B = vd.routines(first_bank(p))
        pairs, removed, added = vd.pair_routines(A, B)
        cnt = collections.Counter()
        out = []
        for ra, rb, _, s in pairs:
            k = vd.classify(ra, rb)
            cnt[k] += 1
            out.append((rb['addr'], ['%d' % p['index'], p['label'], '%x' % rb['addr'], rb['len'], k,
                                     '%x' % ra['addr'], ra['len'], '%.3f' % s]))
        for r in added:
            cnt['added'] += 1
            out.append((r['addr'], ['%d' % p['index'], p['label'], '%x' % r['addr'], r['len'], 'added', '', '', '']))
        rows += [r for _, r in sorted(out, key=lambda t: t[0])]
        summ.append(['%d' % p['index'], p['label'], len(B), cnt['same-bytes'], cnt['same-code-moved'],
                     cnt['changed-ram-address-only'], cnt['changed'], cnt['added'], len(removed)])
    os.makedirs(OUT, exist_ok=True)
    for name, r in (('routines.tsv', rows), ('summary.tsv', summ)):
        with open(os.path.join(OUT, name), 'w') as f:
            for line in r:
                f.write('\t'.join(str(x) for x in line) + '\n')
    for line in summ:
        print('\t'.join(str(x) for x in line))


if __name__ == '__main__':
    main()
