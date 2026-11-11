#!/usr/bin/env python3
"""Stage 4b (no-spec mode): bit-field evidence for each register, from how the code uses it.

Usage: fields.py CONFIG.json --sites sites.tsv --out PREFIX

For every access site the scan found, this reads the instructions around it:

  load   the register the load wrote is followed forward (up to WINDOW instructions in the same
         straight-line run) through and/andi masks, shifts, and compares with constants. Each
         mask is a field the code isolates; each constant it compares with is a value it expects.
  store  the register being stored is followed backward for the constants it was built from
         (ori/andi/li/addiu/lui+ori), so a write of a literal shows the field value written.

Output is PREFIX-fields.tsv: one row per (variant, register slot, kind, bit range) with how
many sites use it, in how many functions, and an example site. It is evidence for a human or a
worker to read, not a field table: a mask says "the code isolates these bits", not what they mean.
The meaning comes from the call-site context in PREFIX-context.tsv (the instructions around each
site and the name of the function it sits in).
"""
import argparse
import collections
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
import scan  # noqa: E402
import slots  # noqa: E402

WINDOW = 14
MASKERS = {'andi', 'ori', 'xori'}


def ranges(mask):
    out, i = [], 0
    while i < 64:
        if mask >> i & 1:
            j = i
            while j < 63 and mask >> (j + 1) & 1:
                j += 1
            out.append('%d' % i if i == j else '%d:%d' % (j, i))
            i = j + 1
        else:
            i += 1
    return ','.join(reversed(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('config')
    ap.add_argument('--sites', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--base', default=os.getcwd())
    ap.add_argument('--calls', help='accessor-calls.tsv from the scan: constants passed to register accessors')
    a = ap.parse_args()
    cfg = json.load(open(a.config))
    slot_of, _part_of = slots.make(cfg)
    space_of = slots.space_of(cfg)
    sites = list(csv.DictReader(open(a.sites), delimiter='\t'))
    want = collections.defaultdict(set)
    for s in sites:
        want[s['image']].add(s['function'])
    agg = collections.defaultdict(lambda: {'sites': 0, 'funcs': set(), 'example': ''})
    ctx_rows = []
    bysite = {}
    for s in sites:
        bysite.setdefault((s['image'], s['function']), []).append(s)
    for img in cfg['images']:
        label = img['label']
        if label not in want:
            continue
        funcs = scan.read_functions(os.path.join(a.base, img['dis']), img.get('split'))
        for name, start, insns in funcs:
            if (label, name) not in bysite:
                continue
            index = {i.addr: k for k, i in enumerate(insns)}
            for s in bysite[(label, name)]:
                k = index.get(int(s['addr'], 16))
                if k is None or s['insn'] == 'ret-addr':
                    continue
                ins = insns[k]
                off = int(s['offset'], 16)
                space = space_of(s['window'])
                slot = slot_of(off, space)
                key0 = (s['variant'], space, slot)
                call = ins.mn in scan.CALLS
                rt = 2 if call and s['rw'] == 'r' else 4 if call else scan.reg(ins.ops[0])
                if s['rw'] == 'r' and rt == 0:
                    # a load into $0 discards its value; the code after it (a nop is sll $0,$0,0) is not a field
                    continue
                found = []
                if s['rw'] == 'r':
                    live = {rt}
                    # an access made through an accessor routine returns its value in $2 after the call
                    # and its delay slot
                    for j in range(k + (2 if call else 1), min(k + 1 + WINDOW, len(insns))):
                        n = insns[j]
                        if n.mn in scan.COND or n.mn in scan.UNCOND:
                            # a compare against a constant right at the branch
                            pass
                        ops = n.ops
                        srcs = [scan.reg(o) for o in ops[1:3]] if len(ops) >= 3 else [scan.reg(o) for o in ops[1:2]]
                        if n.mn in ('andi',) and scan.reg(ops[1]) in live:
                            found.append(('mask', scan.to_int(ops[2])))
                            live.add(scan.reg(ops[0]))
                        elif n.mn in ('srl', 'dsrl', 'sra', 'dsra', 'dsrl32', 'dsra32', 'sll', 'dsll', 'dsll32') and scan.reg(ops[1]) in live:
                            sh = scan.to_int(ops[2]) + (32 if n.mn.endswith('32') else 0)
                            if sh != 32:        # dsll32/dsrl32 by 0 is the zero-extension of a word load
                                found.append(('shift', sh))
                            live.add(scan.reg(ops[0]))
                        elif n.mn in ('beq', 'bne') and len(ops) >= 3 and (scan.reg(ops[0]) in live or scan.reg(ops[1]) in live):
                            pass
                        elif n.mn in ('addiu', 'daddiu') and scan.reg(ops[1]) == 0 and len(ops) == 3:
                            pass
                        d = scan.Analyser.dest_of(None, n) if False else None
                        if n.mn in scan.LOADS or (n.mn in scan.RD_WRITERS and scan.reg(ops[0]) in live and n.mn not in ('sll', 'srl', 'sra', 'dsll', 'dsrl', 'dsra', 'dsll32', 'dsrl32', 'dsra32')):
                            if scan.reg(ops[0]) in live and n.mn in scan.LOADS:
                                live.discard(scan.reg(ops[0]))
                        if not live:
                            break
                else:
                    live = {rt}
                    # the value of an accessor's write is argument 0; the delay slot of the call can set it
                    order = ([k + 1] if call and k + 1 < len(insns) else []) + list(range(k - 1, max(k - 1 - WINDOW, -1), -1))
                    for j in order:
                        n = insns[j]
                        if n.mn in scan.COND or n.mn in scan.UNCOND or n.mn in scan.CALLS:
                            break
                        ops = n.ops
                        if len(ops) >= 2 and scan.reg(ops[0]) in live:
                            if n.mn in ('ori', 'andi', 'xori') and len(ops) == 3:
                                found.append(('const' if n.mn == 'ori' else 'mask', scan.to_int(ops[2])))
                            elif n.mn in ('addiu', 'daddiu', 'li', 'dli', 'lui'):
                                v = scan.to_int(ops[-1])
                                found.append(('const', v << 16 if n.mn == 'lui' else v))
                            elif n.mn in ('or', 'addu', 'daddu'):
                                live.add(scan.reg(ops[1]))
                                live.add(scan.reg(ops[2]))
                                continue
                            live.discard(scan.reg(ops[0]))
                            if n.mn in ('ori', 'andi', 'xori'):
                                live.add(scan.reg(ops[1]))
                        if not live:
                            break
                lo = max(0, k - 4)
                ctx = ' / '.join('%s %s' % (i.mn, ','.join(i.ops)) for i in insns[lo:k + 5])
                ctx_rows.append((label, name, s['addr'][-6:], s['variant'], space, hex(off), s['rw'], s['width'], ctx))
                for kind, val in found:
                    if kind == 'mask' and val:
                        rng = ranges(val)
                    elif kind == 'shift':
                        rng = 'shift %d' % val
                    elif kind == 'const':
                        rng = hex(val)
                    else:
                        continue
                    ak = key0 + (s['rw'], kind, rng)
                    e = agg[ak]
                    e['sites'] += 1
                    e['funcs'].add(name)
                    e['example'] = e['example'] or '%s@%s' % (name, s['addr'][-6:])
    # constants callers pass to an accessor are the field values the code writes to that accessor's
    # register: carry them to every (variant, slot) the accessor's own store sites hit
    if a.calls and os.path.exists(a.calls):
        reg_of = collections.defaultdict(set)
        for s in sites:
            if s['rw'] == 'w' and s['image'] == 'ip27-unix':
                reg_of[s['function']].add((s['variant'], int(s['offset'], 16) & ~7))
        seen = set()
        for c in csv.DictReader(open(a.calls), delimiter='\t'):
            if c['image'] != 'ip27-unix':
                continue            # the kernels carry identical accessor callers
            for arg in ('a1', 'a2', 'a3'):
                if c[arg] == '-':
                    continue
                val = int(c[arg], 16)
                kind = 'clear-mask' if c['callee'].endswith('_clr') else 'const'
                if val == 0:
                    continue
                for (v, slot) in reg_of.get(c['callee'], ()):
                    space = ''

                    if v in ('probe?',) or v.endswith('-face'):
                        continue
                    rng = ranges(val) if 'bit' in c['callee'] else hex(val)
                    ak = (v, space, slot, 'w', kind + ' via ' + c['callee'], rng)
                    e = agg[ak]
                    key = (v, slot, c['addr'], arg)
                    if key in seen:
                        continue
                    seen.add(key)
                    e['sites'] += 1
                    e['funcs'].add(c['caller'])
                    e['example'] = e['example'] or '%s@%s' % (c['caller'], c['addr'][-6:])
    with open(a.out + '-fields.tsv', 'w') as f:
        f.write('variant\tspace\tregister\tsource\tkind\tbits_or_value\tsites\tfunctions\texample\n')
        for (v, space, slot, rw, kind, rng), e in sorted(agg.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2], kv[0][4], -kv[1]['sites'])):
            f.write('%s\t%s\t%#x\t%s\t%s\t%s\t%d\t%d\t%s\n' % (v, space, slot, 'load' if rw == 'r' else 'store', kind, rng,
                                                          e['sites'], len(e['funcs']), e['example']))
    with open(a.out + '-context.tsv', 'w') as f:
        f.write('image\tfunction\taddr\tvariant\tspace\toffset\trw\twidth\tinstructions_around_site\n')
        for r in ctx_rows:
            f.write('\t'.join(str(x) for x in r) + '\n')
    print('fields rows', len(agg), 'context rows', len(ctx_rows))


if __name__ == '__main__':
    main()
