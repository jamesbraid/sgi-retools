#!/usr/bin/env python3
"""Call-argument census: the constants a driver passes to a register-access routine.

Usage: callargs.py CONFIG.json [--base DIR] [--out DIR]

Some chips have no memory window. A router is reached through a vector packet, and the kernel
names the register by a number it passes to an accessor routine (`router_reg_read(router, reg, out)`).
The window scan of scan.py has nothing to follow there, so this tool reads the call sites instead.

The config's `call_census` section lists the routines and the argument register that carries the
register number:

  "call_census": {
    "targets": [{"callee": "router_reg_read", "arg": 5, "rw": "r", "path": "router_reg"}, ...],
    "stride": 8,
    "families": [{"name": "RR_PORT_PARMS", "base": "0x0", ...}]   (optional, used by the report)
  }

Each call is resolved by straight-line constant propagation inside one routine. The state is dropped
at every branch target and after every call (caller-saved registers), so a value is reported only
when the instructions that build it sit on one path with the call. A register number built by
arithmetic on an index, or loaded from memory, is written to `unresolved` with its site. Nothing is
guessed.

Outputs (in --out): `call-sites.tsv` (one row per call), `values.tsv` (one row per constant and access
path), `census-symbolic.tsv` and `unresolved.tsv`, and `census.tsv` / `census-sites.tsv` in the shape the
other chip census directories use.
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan  # noqa: E402

M64 = (1 << 64) - 1
CALLER_SAVED = scan.CALLER_SAVED + [2, 3]


def regnum(o):
    return scan.reg(o)


def sx16(v):
    v &= 0xffff
    return v - 0x10000 if v & 0x8000 else v


class Sym:
    """An unknown base built at one instruction, plus the constant bits or-ed or added since."""
    __slots__ = ('ident', 'off')

    def __init__(self, ident, off=0):
        self.ident, self.off = ident, off

    def __repr__(self):
        return 'S%x+0x%x' % (self.ident, self.off)


def val(regs, r):
    if r == 0:
        return 0
    return regs.get(r)


def isint(v):
    return isinstance(v, int)


def step(regs, ins):
    """Apply one instruction to the constant state."""
    mn, ops = ins.mn, ins.ops
    if mn in ('addiu', 'daddiu', 'addi', 'daddi') and len(ops) == 3:
        rt, rs = regnum(ops[0]), regnum(ops[1])
        v = val(regs, rs)
        try:
            imm = scan.to_int(ops[2])
        except ValueError:
            imm = None
        if isinstance(v, Sym) and imm is not None and not ins.reloc:
            regs[rt] = Sym(v.ident, v.off + imm)
        elif v is None or imm is None or ins.reloc:
            regs.pop(rt, None)
        else:
            regs[rt] = (v + imm) & M64
        return
    if mn == 'ori' and len(ops) == 3:
        rt, rs = regnum(ops[0]), regnum(ops[1])
        v = val(regs, rs)
        if isinstance(v, Sym) and not ins.reloc:
            regs[rt] = Sym(v.ident, v.off | scan.to_int(ops[2]))
        elif v is None or ins.reloc:
            regs.pop(rt, None)
        else:
            regs[rt] = v | scan.to_int(ops[2])
        return
    if mn == 'andi' and len(ops) == 3:
        rt, rs = regnum(ops[0]), regnum(ops[1])
        v = val(regs, rs)
        if v is None or isinstance(v, Sym):
            regs.pop(rt, None)
        else:
            regs[rt] = v & scan.to_int(ops[2])
        return
    if mn == 'lui' and len(ops) == 2:
        rt = regnum(ops[0])
        if ins.reloc:
            regs.pop(rt, None)
        else:
            regs[rt] = (scan.sx32(scan.to_int(ops[1]) << 16)) & M64
        return
    if mn in ('dli', 'li') and len(ops) == 2:
        regs[regnum(ops[0])] = scan.to_int(ops[1]) & M64
        return
    if mn in ('or', 'addu', 'daddu') and len(ops) == 3:
        rd, rs, rt = regnum(ops[0]), regnum(ops[1]), regnum(ops[2])
        a, b = val(regs, rs), val(regs, rt)
        if mn == 'or' and isinstance(a, Sym) and b == 0:
            regs[rd] = a
        elif mn == 'or' and isinstance(b, Sym) and a == 0:
            regs[rd] = b
        elif mn == 'or' and isinstance(a, Sym) and isint(b):
            regs[rd] = Sym(a.ident, a.off | b)
        elif mn == 'or' and ((isinstance(a, Sym) and isinstance(b, Sym)) or
                             (a is None and b is None and rs != 0 and rt != 0)):
            regs[rd] = Sym(ins.addr)
        elif a is None or b is None or isinstance(a, Sym) or isinstance(b, Sym):
            regs.pop(rd, None)
        else:
            regs[rd] = (a | b if mn == 'or' else a + b) & M64
        return
    if mn in ('sll', 'dsll', 'dsll32', 'srl', 'dsrl', 'dsrl32', 'sra', 'dsra') and len(ops) == 3:
        rd, rt = regnum(ops[0]), regnum(ops[1])
        v = val(regs, rt)
        sh = scan.to_int(ops[2])
        if v is None and sh and mn in ('sll', 'dsll'):
            regs[rd] = Sym(ins.addr)  # an unknown index scaled by a constant
        elif v is None or isinstance(v, Sym):
            regs.pop(rd, None)
        elif mn == 'sll':
            regs[rd] = scan.sx32(v << sh) & M64 if sh else v
        elif mn == 'dsll':
            regs[rd] = (v << sh) & M64
        elif mn == 'dsll32':
            regs[rd] = (v << (sh + 32)) & M64
        elif mn in ('srl', 'dsrl'):
            regs[rd] = v >> sh
        elif mn == 'dsrl32':
            regs[rd] = v >> (sh + 32)
        else:
            regs.pop(rd, None)
        return
    # any other writer: forget the destination
    if mn in scan.RT_WRITERS and ops:
        regs.pop(regnum(ops[0]), None)
    elif mn in scan.RD_WRITERS and ops:
        regs.pop(regnum(ops[0]), None)


def fmt(v):
    if v is None:
        return '?'
    if isinstance(v, Sym):
        return 'base@%x+0x%x' % (v.ident, v.off)
    return '0x%x' % v


def census(cfg, base, out):
    cc = cfg['call_census']
    targets = {t['callee']: t for t in cc['targets']}
    sites = []
    for img in cfg['images']:
        path = os.path.join(base, img['dis'])
        if not os.path.exists(path):
            sys.exit('missing %s: run tools/disasm.sh first' % path)
        funcs = scan.read_functions(path, img.get('split'))
        for name, _start, insns in funcs:
            labels = set()
            for i in insns:
                if i.mn in scan.COND or i.mn in ('b', 'j'):
                    t = i.target()
                    if t is not None:
                        labels.add(t)
            regs = {}
            n = 0
            while n < len(insns):
                ins = insns[n]
                if ins.addr in labels:
                    regs = {}
                if ins.mn in ('jal', 'jalr', 'bal'):
                    callee = ins.sym if ins.mn != 'jalr' else None
                    delay = insns[n + 1] if n + 1 < len(insns) else None
                    snap = dict(regs)
                    if delay is not None:
                        step(snap, delay)
                    if callee in targets:
                        t = targets[callee]
                        v = val(snap, t['arg'])
                        sites.append({'image': img['label'], 'function': name, 'addr': ins.addr, 'callee': callee,
                                      'path': t['path'], 'rw': t['rw'], 'value': v})
                    for r in CALLER_SAVED:
                        regs.pop(r, None)
                    n += 2
                    continue
                step(regs, ins)
                n += 1
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'call-sites.tsv'), 'w') as f:
        f.write('image\tfunction\taddr\tcallee\tpath\trw\tregister\n')
        for s in sites:
            f.write('%s\t%s\t%x\t%s\t%s\t%s\t%s\n' % (
                s['image'], s['function'], s['addr'], s['callee'], s['path'], s['rw'], fmt(s['value'])))
    agg = collections.OrderedDict()
    unresolved = collections.Counter()
    symbolic = collections.OrderedDict()
    for s in sites:
        if isinstance(s['value'], Sym):
            k = (s['image'], s['function'], s['value'].ident, s['value'].off)
            e = symbolic.setdefault(k, {'rw': set(), 'sites': 0})
            e['rw'].add(s['rw'])
            e['sites'] += 1
            continue
        if s['value'] is None:
            unresolved[(s['image'], s['function'])] += 1
            continue
        e = agg.setdefault(s['value'], {'rw': set(), 'sites': 0, 'funcs': set(), 'images': set(), 'paths': set()})
        e['rw'].add(s['rw'])
        e['sites'] += 1
        e['funcs'].add(s['function'])
        e['images'].add(s['image'])
        e['paths'].add(s['path'])
    vname = cfg['call_census'].get('value_name', 'register')
    with open(os.path.join(out, 'values.tsv'), 'w') as f:
        f.write('%s\trw\tsites\tfunctions\timages\tpaths\n' % vname)
        for v in sorted(agg):
            e = agg[v]
            f.write('0x%x\t%s\t%d\t%s\t%s\t%s\n' % (
                v, ','.join(sorted(e['rw'])), e['sites'], ';'.join(sorted(e['funcs'])),
                ';'.join(sorted(e['images'])), ';'.join(sorted(e['paths']))))
    with open(os.path.join(out, 'census-symbolic.tsv'), 'w') as f:
        f.write('image\tfunction\tbase_built_at\toffset_or_added\trw\tsites\n')
        for (im, fn, ident, off), e in sorted(symbolic.items()):
            f.write('%s\t%s\t%x\t0x%x\t%s\t%d\n' % (im, fn, ident, off, ','.join(sorted(e['rw'])), e['sites']))
    with open(os.path.join(out, 'unresolved.tsv'), 'w') as f:
        f.write('image\tfunction\tsites\n')
        for (im, fn), c in sorted(unresolved.items()):
            f.write('%s\t%s\t%d\n' % (im, fn, c))
    emit_standard(cfg, out, sites)
    print('%d call sites, %d constant registers, %d base-relative rows, %d sites unresolved' % (
        len(sites), len(agg), len(symbolic), sum(unresolved.values())))


HDR = ['variant', 'offset', 'idx', 'name', 'access_seen', 'widths', 'halves', 'sites', 'functions', 'images', 'example',
       'datasheet', 'datasheet_ref', 'spec', 'spec_ref', 'model', 'model_detail', 'flags', 'tasks']


def emit_standard(cfg, out, sites):
    """census.tsv and census-sites.tsv in the shape tools/gen_headers.py and the inventory read.

    A register reached by a constant is one row at that number; a register reached as a constant added to a
    per-port base the code builds from a port number is one row at the constant, flagged as an indexed family
    (idx 1). Sites whose register number the straight-line pass could not resolve are not rows: they stay in
    unresolved.tsv. `by_hand` rows (see the config) carry the routines read by hand where the pass loses the
    value across a stack spill; their flag column says so."""
    cc = cfg['call_census']
    variants = cc.get('variants', {})
    names = cc.get('names', {})
    rows = collections.OrderedDict()
    srows = []
    for s in sites:
        v = s['value']
        var = variants.get(s['image'], s['image'])
        if isinstance(v, Sym):
            off, idx = v.off, 1
        elif v is not None:
            off, idx = v, 0
        else:
            continue
        k = (var, off, idx)
        e = rows.setdefault(k, {'rw': set(), 'sites': 0, 'funcs': [], 'imgs': set(), 'ex': None, 'flag': ''})
        e['rw'].add(s['rw'])
        e['sites'] += 1
        if s['function'] not in e['funcs']:
            e['funcs'].append(s['function'])
        e['imgs'].add(s['image'])
        e['ex'] = e['ex'] or '%s@%x' % (s['function'], s['addr'])
        srows.append((s['image'], s['function'], '%x' % s['addr'], 'call', s['rw'], 8, '0x%x' % off, idx, var, 'call-argument'))
    for h in cc.get('by_hand', []):
        k = (h['variant'], int(h['offset'], 16), h.get('idx', 0))
        e = rows.setdefault(k, {'rw': set(), 'sites': 0, 'funcs': [], 'imgs': set(), 'ex': None, 'flag': ''})
        e['rw'] |= set(h['rw'])
        e['sites'] += h['sites']
        for f in h['functions']:
            if f not in e['funcs']:
                e['funcs'].append(f)
        e['imgs'].add(h['image'])
        e['ex'] = e['ex'] or '%s@%s' % (h['functions'][0], h['example'])
        e['flag'] = 'read by hand: ' + h['note']
        for f in h['functions']:
            srows.append((h['image'], f, h['example'], 'call', ''.join(sorted(h['rw'])), 8, h['offset'], h.get('idx', 0), h['variant'], 'by-hand'))
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'census.tsv'), 'w') as f:
        f.write('\t'.join(HDR) + '\n')
        for (var, off, idx), e in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][2], kv[0][1])):
            nm = names.get(var, {}).get('0x%x' % off + ('@idx' if idx else ''), '')
            acc = ''.join(c for c in 'rw' if c in e['rw'])
            f.write('\t'.join([var, '0x%x' % off, str(idx), nm, acc if len(acc) == 1 else 'rw', '8', '0', str(e['sites']),
                              str(len(e['funcs'])), ','.join(sorted(e['imgs'])), e['ex'], 'n/a', '', 'n/a', '', 'n/a',
                              'no-spec mode: no datasheet or model compared', e['flag'],
                              'no-spec: inventory from the binaries']) + '\n')
    with open(os.path.join(out, 'census-sites.tsv'), 'w') as f:
        f.write('image\tfunction\taddr\tinsn\trw\twidth\toffset\tidx\tvariant\tbasis\n')
        for r in srows:
            f.write('\t'.join(str(x) for x in r) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('config')
    ap.add_argument('--base', default='.')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    census(json.load(open(a.config)), a.base, a.out)


if __name__ == '__main__':
    main()
