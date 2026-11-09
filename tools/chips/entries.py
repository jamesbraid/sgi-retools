#!/usr/bin/env python3
"""Stage 6 (no-spec mode): a register table with call-site context, from a census run.

Usage: entries.py CONFIG.json --dir work/CHIP --fields chips/*/census/CHIP/fields.tsv --variant V [--variant V2 ...]
                  [--window-base 0x1000000] --out FILE

One row per register slot: offset, widths, access, site and function counts, the accessor or caller names
(the function names the shipped binary carries), the bit-field evidence from retools/tools/chips/fields.py, and the
label of each claim. Everything here is machine-made evidence: the label column is `inferred` for
role and field meaning (taken from names and masks) and the rows say what was observed; nothing is
`established` until a person has read the function in full and written an entry in the chip page.
"""
import argparse
import collections
import csv
import json

ap = argparse.ArgumentParser()
ap.add_argument('config')
ap.add_argument('--dir', required=True)
ap.add_argument('--fields')
ap.add_argument('--variant', action='append', default=[])
ap.add_argument('--window-base', default='0')
ap.add_argument('--max-rows', type=int, default=400)
ap.add_argument('--out', required=True)
a = ap.parse_args()
base = int(a.window_base, 0)
want = set(a.variant)
sites = collections.defaultdict(lambda: {'rw': set(), 'w': set(), 'f': collections.Counter(), 'n': 0, 'img': set(), 'idx': False})
for r in csv.DictReader(open(a.dir + '/sites.tsv'), delimiter='\t'):
    vs = set(r['variant'].split('|'))
    off = int(r['offset'], 16)
    if want and not (vs & want) and r['variant'] != 'bedrock' and not (r['variant'] == '?' and off < 8):
        continue
    slot = off & ~7
    e = sites[slot]
    e['rw'].add(r['rw'])
    e['w'].add(r['width'])
    e['f'][r['function'].replace('pcireg_', '')] += 1
    e['n'] += 1
    e['img'].add(r['image'])
    e['idx'] = e['idx'] or r['idx'] == '1'
flds = collections.defaultdict(list)
if a.fields:
    for r in csv.DictReader(open(a.fields), delimiter='\t'):
        if not want or r['variant'] in want or r['variant'] in ('?', 'bedrock'):
            flds[int(r['register'], 16)].append('%s %s %s (%s sites)' % (r['source'], r['kind'], r['bits_or_value'], r['sites']))
# collapse runs of consecutive 8-byte slots reached by the same functions in the same way: one row
rows, cur = [], None
for slot in sorted(sites):
    e = sites[slot]
    key = (tuple(sorted(e['f'])), tuple(sorted(e['rw'])), tuple(sorted(e['w'])), e['idx'])
    if cur and cur['key'] == key and (slot - cur['hi'] == 8 or (slot >= 0x10000 and 0 < slot - cur['hi'] <= 0x40)):
        cur['hi'] = slot
        cur['n'] += e['n']
        cur['cnt'] += 1
        continue
    cur = {'key': key, 'lo': slot, 'hi': slot, 'e': e, 'n': e['n'], 'cnt': 1}
    rows.append(cur)
out = ['| register | widths | access | sites | accessors and callers (names from the binary) | field evidence | role (inferred from the names) |',
       '|---|---|---|---:|---|---|---|']
for r in rows[:a.max_rows]:
    e, slot = r['e'], r['lo']
    acc = ''.join(sorted(x for x in e['rw'] if x in 'rwa'))
    names = ', '.join('`%s`' % k for k, _ in e['f'].most_common(6))
    more = len(e['f']) - 6
    if more > 0:
        names += ' (+%d)' % more
    fl = '; '.join(sorted(flds.get(slot, []))[:5])
    reg = ('`+0x%x`' % (base + slot) + (' + unseen index' if e['idx'] else '')) if r['cnt'] == 1 else '`+0x%x` to `+0x%x` (%d slots)' % (base + slot, base + r['hi'], r['cnt'])
    out.append('| %s | %s | %s | %d | %s | %s | unknown unless the names say: see the entry |' % (
        reg, ','.join(sorted(e['w'], key=lambda x: int(x))), acc, r['n'], names, fl))
open(a.out, 'w').write('\n'.join(out) + '\n')
print(len(out) - 2, 'rows')
