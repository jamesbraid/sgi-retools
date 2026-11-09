"""Cross-reference every geometry-engine label: where it sits, what reaches it.

Usage: ge_catalogue.py [UCODE_DIR] [LISTING_DIR] [OUT_TSV]
       defaults: ucode/KONA ucode/ge_listing ucode/ge_xref.tsv

Also rewrites the per-module tables of ucode/ge_handlers.md, below the
marker line, from the cross-reference and the hand-written module roles in
ucode/ge_modules.tsv. The prose above the marker is kept.

Reads ge_symbols, geif.u and arm1.u (IRIX 6.5.30m), the per-source
listings that ge_disasm.py writes, and the tables arm1_handlers.py and
ged_relocs.py write (arm1_handlers.tsv, ged_bound_table.tsv,
ged_relocs.tsv). For each label it records:

  source      the source file and first line the ge.u line table gives
  span        instructions up to the next label in the same listing
  slots       geif.u slots whose handler address is the label's address
  arm         arm1.u functions that load one of those slots from gepc
              (linear scan, the same patterns as arm1_handlers.py)
  tokens      host tokens whose ARM handler is one of those functions
  ged         distributor table index (ged_bound_table.tsv) or relocated
              distributor words (ged_relocs.tsv) that name the slot
  from        engine labels holding a transfer whose target is the label
  consts      engine labels that load the label's address as a constant
              (an immediate in a constant-load word, r215=3 in the listing)

The table is evidence for ucode/ge_handlers.md, which explains it.
"""
import bisect
import collections
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm1_disasm as A  # noqa: E402

GEPC = 0x04068654
PACKED = 0x48


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA'
    lst = sys.argv[2] if len(sys.argv) > 2 else 'ucode/ge_listing'
    out = sys.argv[3] if len(sys.argv) > 3 else 'ucode/ge_xref.tsv'

    labels = []
    for line in open(os.path.join(src, 'ge_symbols')):
        n, a = line.split()
        labels.append((int(a, 16), n))
    g = struct.unpack('>1024H', open(os.path.join(src, 'geif.u'), 'rb').read())
    slots_of = collections.defaultdict(list)
    for k in range(512):
        if g[2 * k + 1]:
            slots_of[g[2 * k + 1]].append(k)

    # listings: label -> (file, first line, span); transfers -> referring label
    where, span, refs = {}, {}, collections.defaultdict(set)
    body = collections.defaultdict(list)
    nextlab = {}
    consts = collections.defaultdict(set)
    addr_names = collections.defaultdict(list)
    for a, n in labels:
        addr_names[a].append(n)
    insn = re.compile(r'^([0-9a-f]{4}): ')
    for f in sorted(os.listdir(lst)):
        if not f.endswith('.lst'):
            continue
        sf = f[:-4]
        cur, pend = None, []
        for line in open(os.path.join(lst, f)):
            line = line.rstrip('\n')
            if line.endswith(':') and not line.startswith('#') and ' ' not in line:
                pend.append(line[:-1])
                continue
            m = insn.match(line)
            if not m:
                continue
            ln = re.search(r'; %s:(\d+)$' % re.escape(sf), line)
            for p in pend:
                where.setdefault(p, (sf, int(ln.group(1)) if ln else 0))
                span[p] = 0
            if pend:
                if cur:
                    for c in cur:
                        nextlab[c] = pend[0]
                cur = pend
                pend = []
            if cur:
                for c in cur:
                    span[c] += 1
                    body[c].append(line)
            t = re.search(r'-> [0-9a-f]{4} <([^>]+)>', line)
            if t and cur and t.group(1) != "HereWeGo":
                refs[t.group(1)].add(cur[0])
            k = re.search(r' imm=([0-9a-f]+) r215=3 ', line)
            if k and cur and int(k.group(1), 16) in addr_names and int(k.group(1), 16) >= 0x100:
                for nm in addr_names[int(k.group(1), 16)]:
                    consts[nm].add(cur[0])

    # ARM: which functions load each gepc slot
    mem, syms, base, ro, dbase, rw = A.load(os.path.join(src, 'arm1.u'))
    csyms = sorted((v, n) for v, f, n in syms if base <= v < base + ro)
    addrs = [v for v, n in csyms]

    def name_at(a):
        i = bisect.bisect_right(addrs, a) - 1
        return csyms[i][1] if i >= 0 else '?'

    arm = collections.defaultdict(set)
    gbase, fn = set(), None
    pcs = list(range(base, base + ro, 4))
    texts = {}
    for pc in pcs:
        t, _ = A.dis(mem[pc], pc)
        texts[pc] = re.sub(r'\s*<[^>]*>', '', t)
    for i, pc in enumerate(pcs):
        f = name_at(pc)
        if f != fn:
            fn, gbase = f, set()
        t = texts[pc]
        op, _, args = t.partition(' ')
        m = re.match(r'(r\d+), \[pc, #(-?)0x([0-9a-f]+)\]$', args)
        if op == 'ldr' and m:
            off = int(m.group(3), 16) * (-1 if m.group(2) else 1)
            if mem.get(pc + 8 + off, 0) == GEPC:
                gbase.add(m.group(1))
        m = re.match(r'(r\d+), \[(r\d+), #(0x[0-9a-f]+)\]!?$', args)
        if op == 'ldr' and m:
            off = int(m.group(3), 16)
            if m.group(2) in gbase and off % 4 == 0 and off < 0x800:
                arm[off // 4].add(fn)
            elif m.group(2) == 'r8' and PACKED <= off < PACKED + 0x100 and i + 1 < len(pcs):
                r = m.group(1)
                nxt = texts[pcs[i + 1]]
                b = 2 * ((off - PACKED) // 4)
                if nxt == 'mov %s, %s, lsl #16' % (r, r):
                    arm[b + 1].add(fn)
                elif nxt == 'mov %s, %s, lsr #16' % (r, r):
                    arm[b].add(fn)

    tok = collections.defaultdict(set)
    for line in open('ucode/arm1_handlers.tsv'):
        if line[0] == '#' or line.startswith('token'):
            continue
        f = line.rstrip('\n').split('\t')
        tok[f[2]].add(f[1])
    ged = collections.defaultdict(set)
    for line in open('ucode/ged_bound_table.tsv'):
        if line[0] == '#' or line.startswith('index'):
            continue
        i, h = line.split()
        ged[h].add('table %s' % i)
    for line in open('ucode/ged_relocs.tsv'):
        if line[0] == '#' or line.startswith('ged_word'):
            continue
        f = line.rstrip('\n').split('\t')
        ged[f[5]].add('reloc')

    with open(out, 'w') as fh:
        fh.write('# Every ge_symbols label of ge.u (IRIX 6.5.30m) with what reaches it. Produced by\n')
        fh.write('# scripts/ge_catalogue.py; explained in ucode/ge_handlers.md.\n')
        fh.write('address\tlabel\tsource\tline\tspan\tslots\tarm\ttokens\tged\tfrom\tconsts\n')
        for a, n in labels:
            s, ln = where.get(n, ('', 0))
            sl = slots_of.get(a, [])
            af = sorted(set().union(*[arm[k] for k in sl])) if sl else []
            tk = sorted(set().union(*[tok[x] for x in af])) if af else []
            gd = sorted(set().union(*[ged[x] for x, b in [(m, 0) for aa, m in labels if aa == a]])) if sl else []
            fr = sorted(refs.get(n, set()) - {n})
            cs = sorted(consts.get(n, set()) - {n})
            fh.write('0x%04x\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n' % (
                a, n, s, ln, span.get(n, 0), ','.join(map(str, sl)), ','.join(af),
                ','.join(tk), ','.join(gd), ','.join(fr), ','.join(cs)))

    write_md(out, body, nextlab)


MARK = '<!-- generated by scripts/ge_catalogue.py below this line -->'

# Operation names, from the diagnostic test and production readings of ucode/ge_ops.md.
# M[6:0] is unit 1's code (0x7f idle); M[10:7] is unit 2's k, code k << 3 | 7 (k 0xd idle).
UNIT1 = {0x40: 'integer add', 0x42: 'integer subtract or compare', 0x4a: 'move',
         0x4b: 'move of the second operand', 0x50: 'AND', 0x54: 'OR', 0x56: 'XOR',
         0x58: 'NOT', 0x60: 'float add', 0x62: 'float subtract', 0x66: 'minimum',
         0x68: 'maximum', 0x73: 'integer-to-float conversion', 0x7c: 'clamp at zero',
         0x20: 'double add', 0x22: 'double subtract', 0x5b: 'arithmetic shift right',
         0x5d: 'logical shift right', 0x5f: 'shift left', 0x71: 'float-to-integer conversion'}
UNIT2 = {0x47: 'float multiply', 0x4f: 'reciprocal Newton step',
         0x57: 'reciprocal square-root Newton step', 0x07: 'double multiply',
         0x27: 'second-unit move', 0x2f: 'second-unit move or minimum', 0x37: 'double move',
         0x3f: 'double move or minimum'}
A_FORMS = {1, 2, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15}
INSN = re.compile(r'^([0-9a-f]{4}): [0-9a-f]+ f(\d+)\s+(.*?)(?:\s+;.*)?$')


def parse(line):
    m = INSN.match(line)
    a, form, rest = int(m.group(1), 16), int(m.group(2)), m.group(3)
    x = re.search(r'(xfer\d)(\.rel)? c(\d+) cc=([0-9a-f]+) -> ([0-9a-f]+)(?: <([^>]+)>)?', rest)
    fl = dict(kv.split('=', 1) for kv in rest.split() if '=' in kv and not kv.startswith('cc='))
    return a, form, fl, x


CODE = {}    # instruction address -> label whose words hold it
LABELS = set()


def enum_like(v):
    """A value more often an enumerant or a mask than code: a low byte of zero, the pages
    0x0b00-0x2aff with a low byte below 0x40 (0x1200, 0x1b02), or 0x8000-0x86ff, where
    the extension enumerants sit."""
    return ((0x0b <= v >> 8 <= 0x2a and (v & 0xff) < 0x40) or 0x80 <= v >> 8 <= 0x86
            or not v & 0xff)


def flt(v):
    # small values and single-bit or low-mask patterns are more often masks than addresses
    if 0x1000 <= v < 0x10000 and v in CODE and v & (v - 1) and (v + 1) & v and (
            not enum_like(v) or (v in LABELS and 0x80 <= v >> 8 <= 0x86)):
        return '0x%x (code in `%s`)' % (v, CODE[v])
    f = struct.unpack('>f', struct.pack('>I', v))[0]
    e = (v >> 23) & 0xff
    if v == 0:
        return '0'
    if 0x60 <= e <= 0x9e and struct.unpack('>f', struct.pack('>f', float('%.7g' % f)))[0] == f:
        return '%s (0x%x)' % (repr(float('%.7g' % f)), v)
    return '0x%x' % v


def plural(n, word):
    return '%d %s' % (n, word if n == 1 else word + ('es' if word.endswith(('s', 'x', 'sh')) else 's'))


def others(n, noun):
    return '1 other %s' % noun if n == 1 else '%d other %ss' % (n, noun)


def span_text(vals):
    vals = sorted(vals)
    if len(vals) == 1:
        return 'command word %d' % vals[0]
    if vals == list(range(vals[0], vals[-1] + 1)):
        return 'command words %d to %d' % (vals[0], vals[-1])
    return '%d command words between offsets %d and %d' % (len(vals), vals[0], vals[-1])


def facts(name, addr, lines, nxt):
    """What the label's words do, in the readings of ucode/ge_ops.md and ge_isa.md:
    the sentence of operations and accesses, and the sentence saying how it ends."""
    ops = collections.Counter()
    reads, outs, stores, mreads, consts = set(), 0, collections.Counter(), set(), []
    flags = cond = loops = 0
    ctargets, ends = [], []
    for ln in lines:
        a, form, fl, x = parse(ln)
        if 'M' in fl:
            m = int(fl['M'], 16)
            k, u1 = m >> 7, m & 0x7f
            if k == 8 and u1 == 0x60:
                ops['float multiply-add'] += 1
            else:
                if u1 != 0x7f:
                    ops[UNIT1.get(u1, 'operation 0x%x' % (0x680 | u1))] += 1
                if k != 0xd:
                    ops[UNIT2.get(k << 3 | 7, 'second-unit operation 0x%x' % (k << 7 | 0x7f))] += 1
        r110 = fl.get('r110')
        if r110 == '6bf':
            ops['reciprocal seed'] += 1
        elif r110 == '2bf':
            ops['reciprocal square-root seed'] += 1
        if fl.get('r220') == '1' or fl.get('r221') == '1':
            flags += 1
        if form in A_FORMS and fl.get('A') == '1f':
            reads.add(int(fl.get('D', '0'), 16))
        if form in (10, 12) and fl.get('r213') == '3' and fl.get('B') in ('9', 'a', 'b'):
            outs += 1
        if form == 5 and fl.get('r213') == '3' and fl.get('B') == '1e' and 'imm' in fl:
            stores[int(fl['imm'], 16)] += 1
        if form == 14 and fl.get('C') == '1e' and fl.get('r95') == '17' and 'imm' in fl and not x:
            mreads.add(int(fl['imm'], 16))
        if form == 15 and fl.get('r215') == '3':
            consts.append(int(fl.get('imm', '0'), 16))
        if x:
            kind, rel, grp, cc, tgt, lab = x.groups()
            tgt = int(tgt, 16)
            if kind == 'xfer4':
                if lab == 'HereWeGo' and grp == '31':
                    ends.append('home')
                elif lab == 'HereWeGo':
                    ends.append('ret')
                elif grp == '0' and lab and lab != name:
                    ends.append('call:' + lab)
                elif rel and tgt == a:
                    ends.append('wait' if grp == '31' else 'wait%s' % grp)
                elif lab and lab != name:
                    ends.append(lab)
                else:
                    ends.append('local')
            elif kind == 'xfer3':
                loops += 1
            else:
                cond += 1
                if lab and lab != name and lab not in ctargets:
                    ctargets.append(lab)
    parts = []
    if reads:
        parts.append('reads %s' % span_text(reads))
    if ops:
        parts.append('operations ' + ', '.join(
            '%s (%d)' % (o, c) for o, c in sorted(ops.items(), key=lambda t: (-t[1], t[0]))))
    if flags:
        parts.append('sets the condition flags %s' % ('once' if flags == 1 else '%d times' % flags))
    bus = sum(c for v, c in stores.items() if 0x1f4 <= v <= 0x1f8)
    if bus:
        parts.append('writes %s to the raster-bus output addresses' % plural(bus, 'word'))
    other = sorted(v for v in stores if not 0x1f4 <= v <= 0x1f8)
    if other:
        n = sum(stores[v] for v in other)
        parts.append('stores %s to control-memory address%s' % (
            plural(n, 'word'), ' 0x%x' % other[0] if len(other) == 1 else
            'es from 0x%x to 0x%x' % (other[0], other[-1])))
    if mreads:
        mr = sorted(mreads)
        parts.append('reads engine memory at %s' % (
            '0x%x' % mr[0] if len(mr) == 1 else '%d addresses from 0x%x to 0x%x' % (len(mr), mr[0], mr[-1])))
    if outs:
        parts.append('%s stored through address registers 9-0xb (the diagnostic test\'s output form, an engine-memory store here)' % plural(outs, 'word'))
    if consts:
        parts.append('loads %s' % plural(len(consts), 'constant'))
    if cond:
        parts.append('takes %s' % plural(cond, 'conditional transfer'))
    if loops:
        parts.append('closes %s' % plural(loops, 'loop'))
    if not parts:
        parts.append('carries no operation, operand read, store or constant the field readings name')
    body = '; '.join(parts)
    # how it ends
    out = []
    named = [e for e in ends if e not in ('home', 'ret', 'wait', 'local') and not e.startswith(('wait', 'call:'))]
    calls = list(dict.fromkeys(e[5:] for e in ends if e.startswith('call:')))
    if calls:
        out.append('calls `%s`%s' % (calls[0], ' and `%s`' % calls[1] if len(calls) == 2 else
                                     ' and ' + others(len(calls) - 1, 'routine') if len(calls) > 2 else ''))
    if 'home' in ends:
        out.append('ends the command with an indirect transfer in condition group 31')
    if 'ret' in ends:
        out.append('returns to its caller or the next chained stage (an indirect transfer outside condition group 31)')
    if 'wait' in ends:
        out.append('ends with the end-of-command wait')
    if any(e.startswith('wait') and e != 'wait' for e in ends):
        out.append('waits on its own address under another condition group')
    if named:
        u = list(dict.fromkeys(named))
        out.append('jumps to `%s`%s' % (u[0], ' and ' + others(len(u) - 1, 'routine') if len(u) > 2 else
                                       ' and `%s`' % u[1] if len(u) == 2 else ''))
    if 'local' in ends:
        out.append('jumps within its own code')
    if not ends:
        out.append('has no jump of its own and runs on into `%s`' % nxt if nxt else
                   'has no jump of its own; it is the last code of its source file')
    end = '; '.join(out)
    if ctargets:
        end += '; conditional transfers reach `%s`%s' % (
            ctargets[0], ' and ' + others(len(ctargets) - 1, 'label') if len(ctargets) > 1 else '')
    cl = ''
    if consts:
        shown = list(dict.fromkeys(flt(v) for v in consts))
        cl = 'Constants loaded: %s%s.' % (', '.join(shown[:8]), ' and %d more' % (len(shown) - 8)
                                          if len(shown) > 8 else '')
    return body, end, cl


def write_md(xref, body=None, nextlab=None, md='ucode/ge_handlers.md', roles='ucode/ge_modules.tsv'):
    if body:
        LABELS.update(int(l.split('\t')[0], 16) for l in open(xref)
                      if l[0] != '#' and not l.startswith('address\t'))
        for nm, ls in body.items():
            for ln in ls:
                CODE.setdefault(int(ln[:4], 16), nm)
    role = {}
    for line in open(roles):
        if line[0] == '#' or line.startswith('source\t'):
            continue
        k, v = line.rstrip('\n').split('\t', 1)
        role[k] = v
    rows = [l.rstrip('\n').split('\t') for l in open(xref)
            if l[0] != '#' and not l.startswith('address\t')]
    by = collections.OrderedDict()
    for r in sorted(rows, key=lambda r: (r[2], int(r[3]), int(r[0], 16))):
        by.setdefault(r[2], []).append(r)
    head = open(md).read().split(MARK)[0] if os.path.exists(md) else ''
    o = [head.rstrip('\n'), '', MARK, '']
    for f in sorted(by, key=str.lower):
        o.append('### %s' % f)
        o.append('')
        rl = role.get(f, 'role not read').rstrip('.')
        o.append('%s%s. **Inferred** from its labels and callers.' % (rl[0].upper(), rl[1:]))
        o.append('')
        owner = None
        alias = {}
        sends = []
        for r in by[f]:
            alias.setdefault(r[0], r[1])
        for r in by[f]:
            a, n, s, ln, sp, sl, arm, tk, ged, fr, cs = r
            first = alias[a]
            how = []
            if first != n:
                how.append('second name for `%s` at the same address, so the same code' % first)
            else:
                if sl:
                    sl2 = sl.split(',')
                    how.append(' and '.join('geif slot %s (entry %d)' % (k, 2 * int(k) + 1) for k in sl2))
                if arm or tk:
                    how.append('the ARM functions that send it are in the table below')
                    sends.append((n, sl, arm, tk))
                if ged:
                    how.append('distributor %s' % ged.replace('reloc', 'relocated word').replace(',', ', '))
                fl_ = fr.split(',') if fr else []
                if fl_:
                    how.append('transfers in `%s`%s' % (fl_[0], ' and ' + others(len(fl_) - 1, 'label')
                                                        if len(fl_) > 1 else ''))
                c2 = cs.split(',') if cs else []
                if c2:
                    how.append('its address loaded as a constant in `%s`%s' % (
                        c2[0], ' and ' + others(len(c2) - 1, 'label') if len(c2) > 1 else ''))
                if n == 'HereWeGo':
                    how.append("the program's first word, where the engines start")
                if not (sl or arm or fr or cs) and owner and owner != n and n != 'HereWeGo':
                    how.append('inside `%s`, reached from that routine\'s own code' % owner)
                if not how:
                    how.append('no slot, ARM load, decoded transfer or address constant reaches it '
                               '(routes tried: [How to read the tables](#how-to-read-the-entries))')
            if sl or n.startswith(('mmo_', 'umo_', 'mge', 'uge')) or (n[0] in 'mu' and n[1:2].isupper()):
                owner = first
            o.append('- `%s`: address 0x%s, `%s` line %s (%s). Reached: %s.' % (
                n, a[2:], s, ln, plural(int(sp), 'word'), '; '.join(how)))
            rl = role.get(n) or role.get(first)
            if rl:
                o.append('  **Inferred** role: %s.' % rl.rstrip('.'))
            if body is not None:
                b, e, cl = facts(n, int(a, 16), body.get(first, body.get(n, [])), nextlab.get(n))
                o.append('  **Inferred** from the `ge.u` listing (6.5.30m, readings of ge_ops.md): %s.' % b)
                o.append('  It %s.' % e)
                if cl:
                    o.append('  ' + cl)
        o.append('')
        if sends:
            # kept apart from the entries above: naming an ARM function or a token there
            # would count as explaining it, and these rows only say who sends what
            o.append('ARM functions and host tokens that send these handlers:')
            o.append('')
            o.append('| Label | geif slot | ARM functions | Tokens |')
            o.append('|---|---|---|---|')
            for n, sl, arm, tk in sends:
                o.append('| `%s` | %s | %s | %s |' % (n, sl.replace(',', ', '),
                         ', '.join('`%s`' % x for x in arm.split(',')) if arm else '',
                         ', '.join('`%s`' % x for x in tk.split(',')) if tk else ''))
            o.append('')
    open(md, 'w').write('\n'.join(o))


if __name__ == '__main__':
    main()
