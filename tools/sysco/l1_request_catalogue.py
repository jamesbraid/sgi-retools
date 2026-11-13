#!/usr/bin/env python3
"""General request codes of the Origin 300 L1 package in every set that carries it.

Usage: retools/tools/re-run python3 retools/tools/sysco/l1_request_catalogue.py [--out evidence/version-diffs]
       retools/tools/re-run python3 retools/tools/sysco/l1_request_catalogue.py --series early

--series early covers the early series (1.0.2 to 1.18.3, version_diff.EARLY_SETS) and writes
l1-early-request-catalogue.tsv and l1-early-request-changes.tsv; its reference column is 1.18.3.

Writes two TSV files under evidence/version-diffs/:

  l1-request-catalogue.tsv  one row per set and accepted general request code: the
                            handler address, a hash of the handler's normalised text
                            (addresses masked), its length in bytes, and how it compares
                            with the same code in 1.44.0
  l1-request-changes.tsv    one row per code that is added, removed, moved to another
                            handler, or whose handler text changes, between consecutive sets

The dispatch is the same run of the compare chain that retools/tools/sysco/version_diff.py uses
(every code from 0x0000 to 0x7fff, interpreted concretely). Only the general request
chain is read here; the command loop (task 3), the flash and power-bay tasks and the
peer forwarding paths are not in this catalogue.

The sets are the ones with a Fuel/PE package (the Origin 300 L1 image, package 1).
Sets 6.5.20 and 6.5.21 carry a different first package and are not included.
"""
import bisect
import collections
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import version_diff as vd  # noqa: E402
import sysco_tables as st  # noqa: E402

OUT = os.path.join(st.REPO, st.VERSION_DIFFS_DIR)
if '--out' in sys.argv:
    OUT = os.path.abspath(sys.argv[sys.argv.index('--out') + 1])

# Chronological by build stamp. The 1.32.15 patch (build 2004-12-22) falls between
# 6.5.26 (2004-09-27) and 6.5.27 (2005-01-04).
SETS = [
    ('1.24.8', '6.5.22'), ('1.26.5', '6.5.23'), ('1.28.3', '6.5.24'), ('1.30.6', '6.5.25'),
    ('1.32.6', '6.5.26'), ('1.32.15', 'patches/SG0005762'), ('1.34.2', '6.5.27'),
    ('1.38.4', '6.5.28'), ('1.40.5', '6.5.29'), ('1.44.0', '6.5.30'), ('1.48.1', 'patches/SG0007149'),
]
REF = '1.44.0'


def handler_norm(p, routine_list, target, valid_targets):
    """The handler's text as vd.handler_text reads it, returned as a list of lines."""
    body, base = p['body'], p['load']
    starts = [r['addr'] for r in routine_list]
    i = bisect.bisect_right(starts, target) - 1
    e = routine_list[i]['end']
    nxt = [x for x in valid_targets if x > target]
    if nxt:
        e = min(e, nxt[0])
    text, pos = [], target
    while pos < e:
        ins = next(iter(vd.MD.disasm(body[pos - base:pos - base + 16], pos, count=1)), None)
        if ins:
            text.append((ins.mnemonic + ' ' + vd.ADDR_RE.sub('ADDR', ins.op_str)).strip())
            pos += ins.size
        else:
            text.append('dc.w $%04x' % int.from_bytes(body[pos - base:pos - base + 2], 'big'))
            pos += 2
    return text


def catalogue(sets=SETS, package=vd.fuel_package):
    out = collections.OrderedDict()
    for ver, rel in sets:
        p = package(rel)
        routine_list = vd.routines(p)
        unknown, valid = vd.dispatch_catalogue(p)
        vt = sorted(set(valid.values()))
        texts = {}
        for code, target in valid.items():
            lines = handler_norm(p, routine_list, target, vt)
            # RAM operands (0x30xxxxxx) are masked in the second key, so a handler that
            # differs only in where its state lives shows up as such.
            texts[code] = (target, vd.sha('\n'.join(lines).encode()),
                           vd.sha('\n'.join(vd.RAM_RE.sub('RAM', x) for x in lines).encode()),
                           len(lines))
        out[ver] = {'release': rel, 'unknown': unknown, 'codes': texts}
        print('%s %s: %d codes, unknown-code handler %x' % (ver, rel, len(texts), unknown), file=sys.stderr)
    return out


def relation(x, y):
    """How handler y compares with handler x; None when the text is the same."""
    if x[1] == y[1]:
        return None
    if x[2] == y[2]:
        return 'RAM operands only'
    return 'text changed'


def compare(cat, ver, code, ref=REF):
    """Relation of a code's handler in ver to the same code in ref."""
    here = cat[ver]['codes'].get(code)
    there = cat[ref]['codes'].get(code)
    if here is None:
        return 'absent'
    if there is None:
        return 'absent in ' + ref
    return relation(there, here) or 'same text'


def catalogue_rows(cat, sets=SETS, ref=REF):
    rows = [['set', 'release', 'code', 'handler', 'handler_text_sha', 'handler_ram_masked_sha',
             'handler_lines', 'vs_' + ref]]
    for ver, _ in sets:
        for code in sorted(cat[ver]['codes']):
            target, sha, ram_sha, length = cat[ver]['codes'][code]
            rows.append([ver, cat[ver]['release'], '%04x' % code, '%x' % target, sha[:16], ram_sha[:16],
                         length, compare(cat, ver, code, ref)])
    return rows


def change_rows(cat, sets=SETS):
    """Codes added, removed or whose handler text changes between consecutive sets.

    A handler that only moved (same text at a new address) is not a change.
    """
    rows = [['from', 'to', 'code', 'change', 'from_handler', 'to_handler']]
    for (a, _), (b, _) in zip(sets, sets[1:]):
        ca, cb = cat[a]['codes'], cat[b]['codes']
        for code in sorted(set(ca) | set(cb)):
            x, y = ca.get(code), cb.get(code)
            if x is None:
                rows.append([a, b, '%04x' % code, 'added', '', '%x' % y[0]])
            elif y is None:
                rows.append([a, b, '%04x' % code, 'removed', '%x' % x[0], ''])
            elif relation(x, y):
                rows.append([a, b, '%04x' % code, relation(x, y), '%x' % x[0], '%x' % y[0]])
    return rows


def write_tsv(name, rows):
    with open(os.path.join(OUT, name), 'w') as f:
        for r in rows:
            f.write('\t'.join(str(c) for c in r) + '\n')


def early_main():
    """The early series (vd.EARLY_SETS, 1.0.2 to 1.18.3). The last set is the reference column."""
    os.makedirs(OUT, exist_ok=True)
    sets, ref = vd.EARLY_SETS, vd.EARLY_SETS[-1][0]
    cat = catalogue(sets, vd.series_package)
    write_tsv('l1-early-request-catalogue.tsv', catalogue_rows(cat, sets, ref))
    write_tsv('l1-early-request-changes.tsv', change_rows(cat, sets))
    counts = collections.Counter(r[3] for r in change_rows(cat, sets)[1:])
    print(dict(counts))


def main():
    if '--series' in sys.argv and sys.argv[sys.argv.index('--series') + 1:][:1] == ['early']:
        return early_main()
    os.makedirs(OUT, exist_ok=True)
    cat = catalogue()
    write_tsv('l1-request-catalogue.tsv', catalogue_rows(cat))
    write_tsv('l1-request-changes.tsv', change_rows(cat))
    counts = collections.Counter()
    for r in change_rows(cat)[1:]:
        counts[r[3]] += 1
    print(dict(counts))


if __name__ == '__main__':
    main()
