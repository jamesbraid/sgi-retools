#!/usr/bin/env python3
"""Write the routine table of ucode/buzz_routines.md from buzz_xform.bin.

Usage: scripts/buzz_routine_table.py > TABLE

A routine runs from a start record to the next record whose bits 1:0 are 1 or
2 (an end mark); a start is record 0, a libGLcore list entry, or the record
five after an end mark (ucode/buzz_isa.md). Every column is read from the
records; no column names an operation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import buzz_ucode_disasm as d  # noqa: E402

IMG = 'root/usr/gfx/ucode/ODSY/buzz_xform.bin'


def fld(w, name):
    for n, hi, lo in d.FIELDS:
        if n == name:
            return d.field(w, hi, lo)
    raise KeyError(name)


def main():
    recs, _ = d.records(IMG)
    ents = set(d.ENTRIES)
    ends = [i for i, w in enumerate(recs) if d.field(w, 1, 0) in (1, 2)]
    starts = sorted({0} | {e + 5 for e in ends if e + 5 < len(recs)} | {e for e in ents if e < len(recs)})
    rows = []
    for s in starts:
        e = next((x for x in ends if x >= s), None)
        if e is None:
            continue
        body = recs[s:e + 1]
        idle = sum(1 for w in body if w == d.IDLE)
        mas = [fld(w, 'ma') for w in body if w != d.IDLE and fld(w, 'ma')]
        lanes = sorted({fld(w, 'ln') for w in body if w != d.IDLE and fld(w, 'ln')})
        seq3 = sum(1 for w in body if d.field(w, 1, 0) == 3)
        rows.append((s, e, len(body), idle, (min(mas), max(mas)) if mas else None, lanes, seq3, body))
    # a twin differs only in the data-memory address and the three register fields
    mask = ~(((1 << 10) - 1) << 48) & ((1 << 96) - 1)
    for k in ('r1', 'r2', 'r3'):
        for n, hi, lo in d.FIELDS:
            if n == k:
                mask &= ~(((1 << (hi - lo + 1)) - 1) << lo)
    sig = {}
    for r in rows:
        sig.setdefault((len(r[7]), tuple(w & mask for w in r[7])), []).append(r[0])
    print('| Entry | End mark | Records | Kernel record | In list | Idle | Data addresses | Lanes | Value-3 marks | Same shape as |')
    print('|---|---:|---:|---:|---|---:|---|---|---:|---|')
    for s, e, n, idle, ma, lanes, seq3, body in rows:
        if s >= d.INSERT_AT and s < d.INSERT_AT + d.INSERT_LEN:
            kern = 'none'
        elif s >= d.INSERT_AT:
            kern = str(s - d.INSERT_LEN)
        else:
            kern = str(s)
        twins = [t for t in sig[(n, tuple(w & mask for w in body))] if t != s]
        print('| %d | %d | %d | %s | %s | %d | %s | %s | %d | %s |' % (
            s, e, n, kern, 'yes' if s in ents else 'no', idle,
            ('0x%x-0x%x' % ma) if ma else '-', ','.join(map(str, lanes)) or '-', seq3,
            ', '.join(map(str, twins[:6])) + (' ...' if len(twins) > 6 else '') if twins else '-'))
    print('', file=sys.stderr)


if __name__ == '__main__':
    main()
