#!/usr/bin/env python3
"""scripts/build_equivalence.py - compare a routine of the O32 or 64-bit
libGLcore with the N32 routine of the same name.

The "same as N32" rows of docs/libglcore-driver-builds.md come from this
comparison, so a run lists them again. For each routine name that is unique
(and not rejected as multi-unit) in both builds it computes, from the
disassembly of the routine's address range:

  callees   the ordered list of called routines. A jal, bal or bgezal(l) with the zero register (the assembler's pc-relative call) is named from its
            target address. A jalr through a register is named from the
            global-offset-table slot that the same basic block loaded into the
            register (plus the addiu that follows a local slot); a register
            loaded before a branch target of the routine is `indirect`. A
            routine with no calls is `none`.
  stores    the number of stores to the command FIFO page (displacement 16384
            from the zero register, process address 0x4000).
  constants the immediates of 16 or more (not 4096 to 4200, the process-page
            words), taken from li, ori, andi, xori, slti and sltiu with the
            zero or another register, and lui-free addiu from the zero
            register.

A routine matches when all three agree. The result is an inference from the
instruction streams, not a reading of the routine.

Usage (inside the toolchain container, from the workspace root):

  python3 scripts/build_equivalence.py --build o32 [--out FILE] [--check-doc]

--check-doc compares the matches with the routines named in the tables of
docs/libglcore-driver-builds.md and reports names on only one side.
"""
import argparse
import csv
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import toolchain  # noqa: E402
from resolve_got import build_got_map  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
BUILDS = {
    'o32': 'usr/gfx/arch/IP27KONA/libGLcore.so',
    'n32': 'usr/gfx/arch/IP27KONA32/libGLcore.so',
    'n64': 'usr/gfx/arch/IP27KONA64/libGLcore.so',
}
INSN = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
FIFO = re.compile(r'^(?:.*,)?16384\(zero\)$')
IMM_OPS = {'li', 'ori', 'andi', 'xori', 'slti', 'sltiu', 'addiu', 'daddiu'}


DRIVER_DOCS = ('docs/libglcore-driver-functions.md', 'docs/libglcore-functions.md',
               'docs/libglcore-get-functions.md')


def n32_scope():
    """Names of the N32 routines that the driver chapters already explain."""
    out = set()
    with open(os.path.join(ROOT, 'docs/inventory/functions.tsv'), newline='') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            if r['binary'] == BUILDS['n32'] and r['status'] == 'understood' and \
                    r['doc'].split('#')[0] in DRIVER_DOCS:
                out.add(r['name'])
    return out


def load_functions(path):
    """name -> (address, size) for names unique in the binary and not rejected."""
    rows = []
    with open(os.path.join(ROOT, 'docs/inventory/functions.tsv'), newline='') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            if r['binary'] == path:
                rows.append(r)
    counts = {}
    for r in rows:
        counts[r['name']] = counts.get(r['name'], 0) + 1
    # An mdebug size can run past a function that starts inside it, so a
    # routine ends where the next listed routine starts if that is sooner.
    starts = sorted({int(r['address'], 16) for r in rows})
    nxt = dict(zip(starts, starts[1:]))
    out = {}
    byaddr = {}
    for r in rows:
        a = int(r['address'], 16)
        byaddr[a] = r['name']
        if counts[r['name']] == 1 and not r['rejected']:
            size = int(r['size'])
            if a in nxt:
                size = min(size, nxt[a] - a)
            out[r['name']] = (a, size)
    return out, byaddr


def disassemble(path):
    cmd = [toolchain.objdump(), '-d', '--no-show-raw-insn',
           os.path.join(ROOT, 'root', path)]
    text = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    insns = {}
    for line in text.splitlines():
        m = INSN.match(line)
        if m:
            insns[int(m.group(1), 16)] = (m.group(2), m.group(3).split('#')[0].strip())
    return insns


def target_of(ops):
    m = re.match(r'^([0-9a-f]+)\b', ops)
    return int(m.group(1), 16) if m else None


def parse_imm(tok):
    try:
        return int(tok, 0)
    except ValueError:
        return None


def fingerprint(insns, got, byaddr, addr, size, step):
    end = addr + size
    pcs = [pc for pc in range(addr, end, 4) if pc in insns]
    # branch targets split basic blocks: a register load before one is stale
    targets = set()
    for pc in pcs:
        op, ops = insns[pc]
        if op in ('b', 'beq', 'bne', 'beqz', 'bnez', 'bgez', 'bgtz', 'blez', 'bltz',
                  'beql', 'bnel', 'beqzl', 'bnezl', 'bgezl', 'bgtzl', 'blezl', 'bltzl',
                  'bc1t', 'bc1f', 'bc1tl', 'bc1fl'):
            t = target_of(ops.split(',')[-1])
            if t is not None:
                targets.add(t)
    callees = []
    stores = 0
    consts = set()
    regs = {}          # register -> (kind, value) loaded in the current block
    for pc in pcs:
        if pc in targets:
            regs = {}
        op, ops = insns[pc]
        parts = [p.strip() for p in ops.split(',')]
        if op.startswith(('sw', 'sd', 'sb', 'sh')) and parts and FIFO.match(ops):
            stores += 1
        elif op in ('swc1', 'sdc1') and FIFO.match(ops):
            stores += 1
        if op in IMM_OPS and len(parts) >= 2:
            v = parse_imm(parts[-1])
            src = parts[1] if len(parts) == 3 else 'zero'
            if v is not None and v >= 16 and not 4096 <= v <= 4200 and \
                    (op != 'addiu' and op != 'daddiu' or src == 'zero'):
                consts.add(v)
        m = re.match(r'^(-?\d+)\(gp\)$', parts[-1]) if parts else None
        if op in ('lw', 'ld') and m:
            slot = int(m.group(1))
            regs[parts[0]] = ('got', slot)
        elif op in ('addiu', 'daddiu') and len(parts) == 3 and parts[0] == parts[1] \
                and parts[0] in regs and regs[parts[0]][0] == 'got':
            regs[parts[0]] = ('gotlo', regs[parts[0]][1], parse_imm(parts[2]))
        elif parts and op not in ('jal', 'jalr', 'j', 'jr', 'bal', 'bgezal', 'bgezall') and parts[0] in regs \
                and not op.startswith(('s', 'b')):
            regs.pop(parts[0], None)
        if op in ('jal', 'bal', 'bgezal', 'bgezall'):
            t = target_of(parts[-1])
            callees.append(byaddr.get(t) or ('sub_%x' % t))
        elif op == 'jalr':
            reg = parts[-1]
            kind = regs.get(reg)
            if kind and kind[0] == 'got':
                callees.append(got.get(kind[1], 'indirect'))
            elif kind and kind[0] == 'gotlo':
                # a local routine: the slot holds a page address, the addiu adds the rest
                page = got.get(kind[1], '')
                m = re.match(r'^sub_([0-9a-f]+)$', page)
                t = int(m.group(1), 16) + kind[2] if m else None
                callees.append(byaddr.get(t) or ('sub_%x' % t if t else 'indirect'))
            else:
                callees.append('indirect')
    return callees, stores, sorted(consts)


def fmt_callees(callees):
    if not callees:
        return 'none'
    out = []
    for c in callees:
        if out and out[-1][0] == c:
            out[-1][1] += 1
        else:
            out.append([c, 1])
    return ', '.join(c if n == 1 else '%s x%d' % (c, n) for c, n in out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument('--build', choices=('o32', 'n64'), required=True)
    ap.add_argument('--out')
    ap.add_argument('--check-doc', action='store_true')
    args = ap.parse_args()
    data = {}
    for b in (args.build, 'n32'):
        funcs, byaddr = load_functions(BUILDS[b])
        got = build_got_map(os.path.join(ROOT, 'root', BUILDS[b]))
        data[b] = (funcs, byaddr, got, disassemble(BUILDS[b]))
    rows = []
    scope = n32_scope()
    for name, (a, s) in sorted(data[args.build][0].items()):
        if name not in data['n32'][0] or name not in scope:
            continue
        fps = []
        for b in (args.build, 'n32'):
            funcs, byaddr, got, insns = data[b]
            addr, size = funcs[name]
            fps.append(fingerprint(insns, got, byaddr, addr, size, 4))
        a2, s2 = data['n32'][0][name]
        rows.append((name, a, s, a2, s2, fps[0] == fps[1], fps[0]))
    out = open(args.out, 'w') if args.out else sys.stdout
    w = csv.writer(out, delimiter='\t', lineterminator='\n')
    w.writerow(['name', 'address', 'size', 'n32_address', 'n32_size', 'same',
                'callees', 'fifo_stores', 'constants'])
    for name, a, s, a2, s2, same, fp in rows:
        w.writerow([name, '0x%x' % a, s, '0x%x' % a2, s2, 'yes' if same else 'no',
                    fmt_callees(fp[0]), fp[1], ' '.join('0x%x' % c for c in fp[2][:6])])
    if args.check_doc:
        doc = open(os.path.join(ROOT, 'docs/libglcore-driver-builds.md')).read()
        sect = 'O32 build' if args.build == 'o32' else '64-bit build'
        i = doc.index('### ' + sect)
        j = doc.find('\n### ', i + 5)
        j = len(doc) if j < 0 else j
        docnames = set(re.findall(r'^\| `([^`]+)` \| `usr/gfx', doc[i:j], re.M))
        mine = {r[0] for r in rows if r[5]}
        print('doc rows %d, script matches %d (over %d common names)' %
              (len(docnames), len(mine), len(rows)), file=sys.stderr)
        print('only in doc:', sorted(docnames - mine)[:40], file=sys.stderr)
        print('only in script:', sorted(mine - docnames)[:40], file=sys.stderr)


if __name__ == '__main__':
    main()
