#!/usr/bin/env python3
"""Write data/languages/ia64.slaspec from the instruction table in ia64_isa.py.

Usage: gen_slaspec.py [OUT]   (default: ../data/languages/ia64.slaspec)

Each slot of a bundle is its own Ghidra instruction, at the address objdump
gives it: bundle+0 (6 bytes), bundle+6 (6 bytes) and bundle+0xc (4 bytes); the
L+X pair of an MLX bundle is one 10-byte instruction at bundle+6. A slot does
not start on a byte boundary, so the instruction before it hands over the
template and the slot's low bits in noflow context fields: `tmpl`, and `ca`
for slot 1 or `cb` for slot 2 (two fields, because a context write also
changes the instruction being decoded).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ia64_isa as isa  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'data', 'languages', 'ia64.slaspec')

# Layouts: token name, token bits, offset of slot bit 0 in the token, and the
# slot bit below which the bits come from a carry field in the context.
LAYOUTS = {
    's0': ('s0tok', 48, 5, 0),
    's1': ('s1tok', 48, -2, 2),
    's2': ('s2tok', 32, -9, 9),
    'lx': ('lxtok', 80, 39, 0),     # the X slot of MLX
    'll': ('lxtok', 80, -2, 2),     # the L slot of MLX
}
SLOT_OF = {'s0': 0, 's1': 1, 's2': 2, 'lx': 1}
# Which templates put which unit in which layout.
UNIT_LAYOUTS = {'M': ['s0', 's1'], 'I': ['s1', 's2'], 'F': ['s1', 's2'], 'B': ['s0', 's1', 's2'],
                'X': ['lx']}

token_fields = {}       # token -> {name: (lo, hi, attrs)}
ctx_fields = {}         # name -> (lo, hi)
attaches = {}           # (kind) -> set(field names)
subtables = {}          # name -> list of constructor text
sub_order = []
pcodeops = set()


def add_sub(name, lines):
    if name not in subtables:
        subtables[name] = lines
        sub_order.append(name)
    return name


def tokfield(layout, a, w, kind=''):
    tok = LAYOUTS[layout][0]
    name = '%s%s_%d_%d' % (tok[:-3], kind, a, w)
    token_fields.setdefault(tok, {})[name] = (a, a + w - 1)
    return name


CARRY = {'s1': ('ca', 15), 'll': ('ca', 15), 's2': ('cb', 24)}


def ctxfield(layout, a, w):
    # Context bits count from the most significant end: ca=(7,15) holds slot
    # bit 0 at context bit 15.
    field, last = CARRY[layout]
    name = '%s_%d_%d' % (field, a, w)
    ctx_fields[name] = (last - (a + w - 1), last - a)
    return name


def fparts(layout, lo, w):
    """[(sleigh field, slot bit, width)] low part first."""
    _, _, off, split = LAYOUTS[layout]
    out = []
    if lo < split:
        cw = min(w, split - lo)
        out.append((ctxfield(layout, lo, cw), lo, cw))
        lo, w = lo + cw, w - cw
    if w > 0:
        out.append((tokfield(layout, lo + off, w), lo, w))
    return out


def constraint(layout, field, value):
    lo, w = field
    return ' & '.join('%s=%d' % (name, (value >> (plo - lo)) & ((1 << pw) - 1))
                      for name, plo, pw in fparts(layout, lo, w))


def all_bits(layout):
    """A bare mention of the whole token, so a zero-width subtable has a length."""
    tok, n, _, _ = LAYOUTS[layout]
    name = '%s_all' % tok[:-3]
    token_fields.setdefault(tok, {})[name] = (0, n - 1)
    return name


# ------------------------------------------------------------- registers
REGS = {
    'gr': ['r%d' % i for i in range(128)],
    'fr': ['f%d' % i for i in range(128)],
    'pr': ['p%d' % i for i in range(64)],
    'br': ['b%d' % i for i in range(8)],
    'ar': [isa.ar_name(i) for i in range(128)],
    'cr': [isa.cr_name(i) for i in range(128)],
    'dahr': ['dahr%d' % i for i in range(8)],
}
F1_ONE = '0x3ff0000000000000'


def reg_sub(kind, layout, field, write):
    """Subtable exporting a register operand: reads of r0, f0, f1 and p0 are
    constants, writes to them go to a scratch value."""
    lo, w = field
    names = REGS[kind]
    name = '%s%s_%s_%d_%d' % (kind.upper(), 'd' if write else 's', layout, lo, w)
    if name in subtables:
        return name
    parts = fparts(layout, lo, w)
    lines = []
    special = {}
    if kind == 'gr':
        special = {0: ('0:8', 'z:8')}
    elif kind == 'fr':
        special = {0: ('0:8', 'z:8'), 1: (F1_ONE + ':8', 'z:8')}
    elif kind == 'pr':
        special = {0: ('1:1', 'z:1')}
    if len(parts) == 1 and parts[0][0].startswith(LAYOUTS[layout][0][:-3]):
        # Whole field in the token: attach the register names to it.
        fname = tokfield(layout, lo + LAYOUTS[layout][2], w, kind)
        attaches.setdefault((kind, w), set()).add(fname)
        lines.append('%s: %s is %s { export %s; }' % (name, fname, fname, fname))
        for v, (rd, wr) in special.items():
            body = ('local %s = 0; export z;' % wr) if write else 'export %s;' % rd
            lines.append('%s: %s is %s & %s { %s }' % (name, fname, fname, constraint(layout, field, v), body))
    else:
        for v in range(1 << w):
            if v in special:
                body = ('local %s = 0; export z;' % special[v][1]) if write else 'export %s;' % special[v][0]
            else:
                body = 'export %s;' % names[v]
            lines.append('%s: "%s" is %s %s{ %s }' % (name, names[v], constraint(layout, field, v),
                                                      '& ' + all_bits(layout) + ' ' if layout != 's0' else '',
                                                      body))
    return add_sub(name, lines)


def imm_sub(opid, layout):
    spec = isa.OPERANDS[opid]
    name = 'IMM_%s_%s' % (opid.replace('.', '_'), layout)
    if name in subtables:
        return name
    k = spec[0]
    if k in ('imm', 'rel'):
        parts = spec[1] if k == 'rel' else spec[1]
        terms, fields, tot = [], [], 0
        for lo, w in parts:
            for fname, plo, pw in fparts(layout, lo, w):
                terms.append('(%s << %d)' % (fname, tot + plo - lo))
                fields.append(fname)
            tot += w
        raw = ' | '.join(terms)
        if k == 'rel':
            sign = 1 << (tot - 1)
            expr = '(inst_start & 0xfffffffffffffff0) + (((((%s) ^ %d) - %d)) << 4)' % (raw, sign, sign)
            lines = ['%s: v is %s [ v = %s; ] { export *[ram]:8 v; }' % (name, ' & '.join(sorted(set(fields))), expr)]
            return add_sub(name, lines)
        _, _, signed, scale, add, xor, _ = spec
        expr = '(%s)' % raw
        if xor:
            expr = '(%s ^ %d)' % (expr, xor)
        if signed:
            sign = 1 << (tot - 1)
            expr = '((%s ^ %d) - %d)' % (expr, sign, sign)
        if scale:
            expr = '(%s << %d)' % (expr, scale)
        if add:
            expr = '(%s + %d)' % (expr, add)
        lines = ['%s: v is %s [ v = %s; ] { export *[const]:8 v; }' % (name, ' & '.join(sorted(set(fields))), expr)]
        return add_sub(name, lines)
    if k == 'map':
        field, table = spec[1], spec[2]
        lines = []
        for raw, val in table.items():
            disp = ('"%d"' % val)
            lines.append('%s: %s is %s { export %d:8; }' % (name, disp, constraint(layout, field, raw), val & (2 ** 64 - 1)))
        return add_sub(name, lines)
    if k == 'mbtype':
        lines = []
        for raw in range(16):
            disp = isa.MBTYPE_NAMES.get(raw, '0x%x' % raw)
            lines.append('%s: "%s" is %s { export %d:8; }' % (name, disp, constraint(layout, spec[1], raw), raw))
        return add_sub(name, lines)
    if k == 'immu64':
        # movl: imm7b, imm9d, imm5c, ic from X; the L slot's 41 bits; i from X.
        lp = fparts('ll', 0, 41)
        lterm = ' | '.join('(%s << %d)' % (f, plo) for f, plo, _ in lp)
        x = {nm: fparts('lx', lo, w)[0][0] for nm, (lo, w) in
             {'b': (13, 7), 'd': (27, 9), 'c': (22, 5), 'ic': (21, 1), 'i': (36, 1)}.items()}
        expr = ('%s | (%s << 7) | (%s << 16) | (%s << 21) | ((%s) << 22) | (%s << 63)'
                % (x['b'], x['d'], x['c'], x['ic'], lterm, x['i']))
        flds = sorted(set(list(x.values()) + [f for f, _, _ in lp]))
        lines = ['%s: v is %s [ v = %s; ] { export *[const]:8 v; }' % (name, ' & '.join(flds), expr)]
        return add_sub(name, lines)
    if k == 'immu62':
        lp = fparts('ll', 0, 41)
        lterm = ' | '.join('(%s << %d)' % (f, plo) for f, plo, _ in lp)
        a = fparts('lx', 6, 20)[0][0]
        i = fparts('lx', 36, 1)[0][0]
        flds = sorted(set([a, i] + [f for f, _, _ in lp]))
        lines = ['%s: v is %s [ v = ((%s) << 21) | (%s << 20) | %s; ] { export *[const]:8 v; }'
                 % (name, ' & '.join(flds), lterm, i, a)]
        return add_sub(name, lines)
    if k == 'tgt64':
        lp = fparts('ll', 2, 39)
        lterm = ' | '.join('(%s << %d)' % (f, plo - 2) for f, plo, _ in lp)
        a = fparts('lx', 13, 20)[0][0]
        i = fparts('lx', 36, 1)[0][0]
        flds = sorted(set([a, i] + [f for f, _, _ in lp]))
        lines = ['%s: v is %s [ v = (inst_start & 0xfffffffffffffff0) + ((%s | ((%s) << 20) | (%s << 59)) << 4); ]'
                 ' { export *[ram]:8 v; }' % (name, ' & '.join(flds), a, lterm, i)]
        return add_sub(name, lines)
    raise ValueError(opid)


INDEXED_SPACES = ['cpuid', 'dbr', 'ibr', 'pkr', 'pmc', 'pmd', 'msr', 'rr', 'dahr']


def operand_symbol(opid, layout, write=False):
    """(symbol for p-code or None, display text) for one operand."""
    spec = isa.OPERANDS.get(opid)
    if spec is None:
        return None, '"%s"' % opid
    k = spec[0]
    if k in REGS:
        s = reg_sub(k, layout, spec[1], write and k in ('gr', 'fr', 'pr'))
        return s, s
    if k == 'mem':
        s = reg_sub('gr', layout, (20, 7), False)
        return s, '"["^%s^"]"' % s
    if k == 'ind':
        s = reg_sub('gr', layout, (20, 7), False)
        return s, '"%s["^%s^"]"' % (spec[1], s)
    if k == 'const':
        return None, '"%s"' % spec[1]
    s = imm_sub(opid, layout)
    return s, s


QP_FIELD = (0, 6)


def qp_sub(layout, value_only):
    name = 'QP%s_%s' % ('V' if value_only else '', layout)
    if name in subtables:
        return name
    lines = []
    for v in range(64):
        cons = constraint(layout, QP_FIELD, v)
        tail = ' & ' + all_bits(layout) if layout != 's0' else ''
        if v == 0:
            body = 'export 1:1;' if value_only else ''
            lines.append('%s: is %s%s { %s }' % (name, cons, tail, body))
        else:
            body = 'export p%d;' % v if value_only else 'if (!p%d) goto inst_next;' % v
            lines.append('%s: "(p%d) " is %s%s { %s }' % (name, v, cons, tail, body))
    return add_sub(name, lines)


def comp_sub(comp, layout):
    name = 'CMP_%s_%s' % (comp, layout)
    if name not in subtables:
        fields, table = isa.COMPLETERS[comp]
        add_sub(name, ['%s: %s is %s { }' % (name, '"%s"' % suffix if suffix else '',
                                               ' & '.join(constraint(layout, f, v) for f, v in zip(fields, vals)))
                       for vals, suffix in table.items()])
    return name


def guard_sub(unit, layout):
    """One constructor per template that puts unit in this slot: shows the
    stop and hands the template and the next slot's low bits on."""
    name = 'G_%s_%s' % (unit, layout)
    if name in subtables:
        return name
    slot = SLOT_OF[layout]
    lines = []
    for t, (units, stops) in sorted(isa.TEMPLATES.items()):
        if layout == 'lx':
            if units != 'MLX':
                continue
            stop = 2 in stops
        else:
            if units[slot] != unit:
                continue
            stop = slot in stops
        lines.append(guard_line(name, layout, t, stop))
    return add_sub(name, lines)


def guard_line(name, layout, t, stop):
    disp = '";;"' if stop else ''
    if layout == 's0':
        return '%s: %s is %s=%d { }' % (name, disp, tokfield('s0', 0, 5), t)
    return '%s: %s is tmpl=%d & %s { }' % (name, disp, t, all_bits(layout))


def dispatch():
    """Root constructors: pick the unit's table from the slot and template and
    hand the template and the next slot's low bits to the next slot."""
    out = []
    carry0 = tokfield('s0', 46, 2)
    carry1 = tokfield('s1', 39, 9)
    for t in range(32):
        units = isa.TEMPLATES[t][0] if t in isa.TEMPLATES else None
        u0 = units[0] if units else 'R'
        out.append(':^%s_s0 is slot=0 & %s=%d & %s & %s_s0 [ tmpl = %d; globalset(inst_next, tmpl); '
                   'ca = %s; globalset(inst_next, ca); slot = 1; globalset(inst_next, slot); ] { }'
                   % (u0, tokfield('s0', 0, 5), t, carry0, u0, t, carry0))
        if units == 'MLX':
            out.append(':^X_lx is slot=1 & tmpl=%d & X_lx { }' % t)
            continue
        u1 = units[1] if units else 'R'
        out.append(':^%s_s1 is slot=1 & tmpl=%d & %s & %s_s1 [ tmpl = %d; globalset(inst_next, tmpl); '
                   'cb = %s; globalset(inst_next, cb); slot = 2; globalset(inst_next, slot); ] { }'
                   % (u1, t, carry1, u1, t, carry1))
        u2 = units[2] if units else 'R'
        out.append(':^%s_s2 is slot=2 & tmpl=%d & %s_s2 { }' % (u2, t, u2))
    return out


SPECIAL_SEM = {}


# The frames below the current one live in the rse space, indexed by bof (the
# bottom of the current frame, in bytes): a physical register file without the
# hardware's limit, so the model never spills to the backing store.
NSTACKED = 96


def phys(k):
    return '*[rse]:8 (bof + %#x)' % (8 * k)


def cfm_from(v):
    """Set CFM from a frame marker value (pfm in ar.pfs, ifm in cr.ifs)."""
    return ('cfm_sof = %s & 0x7f; cfm_sol = (%s >> 7) & 0x7f; cfm_sor = (%s >> 14) & 0xf; '
            'rrb_gr = (%s >> 18) & 0x7f; rrb_fr = (%s >> 25) & 0x7f; rrb_pr = (%s >> 32) & 0x3f;'
            % ((v,) * 6))


CFM_VALUE = ('(cfm_sof | (cfm_sol << 7) | (cfm_sor << 14) | (rrb_gr << 18) | (rrb_fr << 25)'
             ' | (rrb_pr << 32))')
CFM_CLEAR = 'cfm_sol = 0; cfm_sor = 0; rrb_gr = 0; rrb_fr = 0; rrb_pr = 0;'


def bsp_grow(n):
    """ar.bsp after n more registers join the dirty partition (SDM vol 2 table 6-2)."""
    return 'ar.bsp = ar.bsp + 8 * (%s + (((ar.bsp >> 3) & 63) + %s) / 63);' % (n, n)


def bsp_shrink(n):
    return 'ar.bsp = ar.bsp - 8 * (%s + ((62 - ((ar.bsp >> 3) & 63)) + %s) / 63);' % (n, n)


def call_sem(target, b1):
    # SDM vol 3 br (3:25): ar.pfs takes CFM, ar.ec and psr.cpl; the callee's frame is the outputs.
    return ('%s = (inst_start & 0xfffffffffffffff0) + 16; '
            'ar.pfs = %s | (ar.ec << 52) | (((psr >> 32) & 3) << 62); fsbsp = ar.bsp; %s '
            'build CallIn; cfm_sof = cfm_sof - cfm_sol; %s call %s; build CallOut;'
            % (b1, CFM_VALUE, bsp_grow('cfm_sol'), CFM_CLEAR, target))


def ret_sem(target):
    """br.ret: put the callee's frame where the caller's outputs are, take the
    caller's frame back from below it, and restore CFM and ar.ec from ar.pfs.
    Every one of the 96 is moved, because the caller's sol is only known at run time."""
    body = [phys(k) + ' = r%d;' % (32 + k) for k in range(NSTACKED)]
    body.append('local s:8 = (ar.pfs >> 7) & 0x7f; bof = bof - s:4 * 8;')
    body += ['r%d = %s;' % (32 + k, phys(k)) for k in range(NSTACKED)]
    body.append(bsp_shrink('((ar.pfs >> 7) & 0x7f)'))
    body.append(cfm_from('ar.pfs'))
    body.append('ar.ec = (ar.pfs >> 52) & 0x3f;')
    body.append('return %s;' % target)
    return ' '.join(body)


# cover saves the whole register stack, so rfi can take it back without knowing
# the covered frame's size before CFM is restored.
def cover_sem():
    body = [phys(k) + ' = r%d;' % (32 + k) for k in range(NSTACKED)]
    body.append('bof = bof + %d;' % (8 * NSTACKED))
    body.append(bsp_grow('cfm_sof'))
    # SDM vol 3 cover (3:48): with interruption collection off, CFM goes to cr.ifs.
    body.append('if ((psr & 0x2000) != 0) goto <ic>; cr.ifs = 0x8000000000000000 | %s; <ic>' % CFM_VALUE)
    body.append('cfm_sof = 0; ' + CFM_CLEAR)
    return ' '.join(body)


def rfi_sem():
    """rfi (SDM vol 3 3:236): psr from cr.ipsr; with cr.ifs.v the covered frame
    comes back; resume at cr.iip's bundle, slot psr.ri. A jump, not a return: cr.iip is any
    address, a fixed hand-off as often as a return address, so the decompiler follows a constant one."""
    body = ['psr = cr.ipsr;', 'if ((cr.ifs >> 63) == 0) goto <nofr>;',
            'bof = bof - %d;' % (8 * NSTACKED)]
    body += ['r%d = %s;' % (32 + k, phys(k)) for k in range(NSTACKED)]
    body.append(bsp_shrink('(cr.ifs & 0x7f)'))
    body.append(cfm_from('cr.ifs'))
    body.append('<nofr> local t:8 = (cr.iip & 0xfffffffffffffff0) + ((cr.ipsr >> 41) & 3) * 6;')
    body.append('goto [t];')
    return ' '.join(body)


def loop_sem(kind, tgt):
    """The modulo-scheduled loop branches (SDM vol 3 br, 3:26-27): counters and p63
    without branches, so one guard decides whether the registers rotate."""
    if kind in ('CTOP', 'CEXIT'):
        head = ('local go:1 = ar.lc != 0; local tk:1 = go || (ar.ec > 1); local rt:1 = go || (ar.ec != 0); '
                'ar.ec = ar.ec - zext(!go && (ar.ec != 0)); ar.lc = ar.lc - zext(go); p63 = go;')
    else:
        head = ('local go:1 = $qp; local tk:1 = go || (ar.ec > 1); local rt:1 = go || (ar.ec != 0); '
                'ar.ec = ar.ec - zext(!go && (ar.ec != 0)); p63 = 0;')
    taken = 'tk' if kind in ('CTOP', 'WTOP') else '!tk'
    return '%s if (!rt) goto <n>; build Rot; <n> if (%s) goto %s;' % (head, taken, tgt)


TOKEN_RE = re.compile(r'([$@])([A-Za-z][A-Za-z0-9_.]*[A-Za-z0-9_])')
BUILTIN_OPS = {'zext', 'sext', 'float2float', 'int2float', 'trunc', 'round', 'abs', 'nan',
               'popcount', 'lzcount', 'goto', 'if', 'local', 'call', 'return', 'export', 'build'}


def constructor(e, layout, unit):
    unit_layout_guard = guard_sub(unit, layout)
    pat = [unit_layout_guard]
    syms = []
    disp_ops = []
    for o in e.ops:
        s, d = operand_symbol(o, layout)
        disp_ops.append(d)
    # Display: outputs, '=', inputs, separated by commas.
    disp = ''
    for i, d in enumerate(disp_ops):
        disp += d
        if i + 1 < len(disp_ops):
            disp += '"="' if i + 1 == e.nout else '","'
    for o in e.ops:
        s, _ = operand_symbol(o, layout)
        if s:
            syms.append(s)
    sem = e.sem if e.sem is not None else ''
    kind = None
    if sem in ('CALL', 'CALLIND'):
        kind = sem
        tgt = '$tgt25c' if 'tgt25c' in e.ops else ('$tgt64' if 'tgt64' in e.ops else '[$b2]')
        sem = call_sem(tgt, '@b1')
    elif sem in ('CTOP', 'CEXIT', 'WTOP', 'WEXIT'):
        kind = 'LOOP'
        sem = loop_sem(sem, '$tgt25c')
    elif sem == 'RET':
        sem = ret_sem('[$b2]')
    elif sem == 'COVER':
        sem = cover_sem()
    elif sem == 'RFI':
        sem = rfi_sem()
    elif sem in ('CLRRRB', 'CLRRRB_PR'):
        kind, sem = sem, ''

    def repl(m):
        sigil, nm = m.group(1), m.group(2)
        if nm == 'qp':
            s = qp_sub(layout, True)
            syms.append(s)
            return s
        s, _ = operand_symbol(nm, layout, write=(sigil == '@'))
        if s is None:
            raise ValueError('%s: no symbol for %s' % (e.name, nm))
        syms.append(s)
        return s
    sem = TOKEN_RE.sub(repl, sem)
    sem = sem.replace('inst_start & ~0xf', 'inst_start & 0xfffffffffffffff0')
    for op in re.findall(r'\b([a-z][a-z0-9_]*)\(', sem):
        if op not in BUILTIN_OPS and op not in MACROS:
            pcodeops.add(op)
    predicated = 'nopred' not in e.flags
    qp = ''
    if predicated:
        if 'qpcustom' in e.flags:
            q = qp_sub(layout, True)
        else:
            q = qp_sub(layout, False)
        syms.append(q)
        qp = q
    cons = [constraint(layout, f, v) for f, v in sorted(e.cons.items())]
    cons += ['pal=1'] if 'pal' in e.flags else ['pal=0'] if 'nopal' in e.flags else []
    action = ''
    if 'alloc' in e.flags:
        sof = fparts(layout, 13, 7)[0][0]
        sol = fparts(layout, 20, 7)[0][0]
        sor = fparts(layout, 27, 4)[0][0]
        action = (' [ sol = %s; globalset(inst_next, sol); soo = %s - %s; globalset(inst_next, soo); '
                  'sor = %s; globalset(inst_next, sor); ]' % (sol, sof, sol, sor))
        cons += [sof, sol, sor]
    if e.excl:
        raise ValueError('exclusions are not generated')
    mnem = '"%s"' % e.name
    if e.comp:
        mnem += '^' + comp_sub(e.comp, layout)
        syms.append(comp_sub(e.comp, layout))
    display = (qp + '^' if qp else '') + (disp + '^' if disp else '') + unit_layout_guard
    if not disp and not qp:
        display = unit_layout_guard
    patt = ' & '.join(dict.fromkeys(pat + cons + syms))
    body = ''
    if qp and 'qpcustom' not in e.flags:
        body += 'build %s; ' % qp
    body += sem
    extra = ''
    if kind in ('CALL', 'CALLIND'):
        extra = ' & CallIn & CallOut'
    elif kind == 'LOOP':
        extra = ' & Rot'
    elif kind == 'CLRRRB':
        extra = ' & Unrot'
        body += 'build Unrot;'
    elif kind == 'CLRRRB_PR':
        extra = ' & UnrotPr'
        body += 'build UnrotPr;'
    return '%s_%s: %s %s is %s%s%s { %s }' % (unit, layout, mnem, display, patt, extra, action, body)


MACROS = {'pr_write', 'pr_read'}


def unknown_constructors():
    """The least specific constructor of each unit table, and the whole table
    for a reserved template: shows the slot's 41 bits, does nothing."""
    out = []
    for layout in ('s0', 's1', 's2', 'lx'):
        lo_parts = fparts(layout, 0, 41)
        raw = ' | '.join('(%s << %d)' % (f, plo) for f, plo, _ in lo_parts)
        flds = ' & '.join(sorted(set(f for f, _, _ in lo_parts)))
        sub = add_sub('RAW_%s' % layout, ['RAW_%s: v is %s [ v = %s; ] { export *[const]:8 v; }'
                                         % (layout, flds, raw)])
        units = {'s0': 'MB', 's1': 'MIFB', 's2': 'IFB', 'lx': 'X'}[layout]
        for u in units:
            g = guard_sub(u, layout)
            out.append('%s_%s: "unknown.%s" %s^%s is %s & %s { unknown_insn(%s); }'
                       % (u, layout, u.lower(), sub, g, g, sub, sub))
        if layout == 'lx':
            continue
        gname = 'G_rsv_%s' % layout
        if gname not in subtables:
            add_sub(gname, [guard_line(gname, layout, t, False) for t in range(32) if t not in isa.TEMPLATES])
        out.append('R_%s: "unknown" %s^%s is %s & %s { unknown_insn(%s); }' % (layout, sub, gname, gname, sub, sub))
    pcodeops.add('unknown_insn')
    return out


# soo before any alloc (the pspec's default; no alloc makes it 127): the frame's
# size is unknown, so a call passes r32.. on as they are.
NO_FRAME = 127


def call_frame_subs():
    """The register stack renames the caller's outputs r(32+sol).. to the
    callee's r32... The callee's view is made by copying: the caller's locals go
    to the physical registers below the callee's frame, the outputs move down,
    the rest of r32..r39 get the never-written `noarg` so no stale caller value
    (a saved gp) reads as an argument, and after the call the caller's r32..
    come back from fs* (what the decompiler sees; under emulation br.ret does
    it). sol and soo come from the frame's alloc."""
    spill, unspill, move, rest, noarg, save, restore = [], [], [], [], [], [], []
    for sol in range(NSTACKED + 1):
        body = [phys(i) + ' = r%d;' % (32 + i) for i in range(sol)]
        body.append('bof = bof + %d;' % (8 * sol))
        spill.append('CallSpill: is sol=%d { %s }' % (sol, ' '.join(body)))
        unspill.append('CallUnspill: is sol=%d { bof = bof - %d; }' % (sol, 8 * sol))
        n = NSTACKED - sol
        move.append('CallMove: is sol=%d { %s }'
                    % (sol, ' '.join('r%d = r%d;' % (32 + i, 32 + sol + i) for i in range(min(n, 8)))))
        rest.append('CallMoveRest: is sol=%d & soo>8 & soo<%d { %s }'
                    % (sol, NO_FRAME, ' '.join('r%d = r%d;' % (32 + i, 32 + sol + i) for i in range(8, n))))
    rest.append('CallMoveRest: is soo<9 { }')
    rest.append('CallMoveRest: is soo=%d { }' % NO_FRAME)
    rest.append('CallMoveRest: is sol { }')     # sol above 96 is no frame alloc can make
    for soo in range(NSTACKED + 1):
        n = max(8, soo)
        save.append('CallSave: is soo=%d { %s }' % (soo, ' '.join('fs%d = r%d;' % (i, 32 + i) for i in range(n))))
        restore.append('CallRestore: is soo=%d { %s }'
                       % (soo, ' '.join('r%d = fs%d;' % (32 + i, i) for i in range(n))))
        noarg.append('CallNoarg: is soo=%d { %s }' % (soo, ' '.join('r%d = noarg;' % (32 + i) for i in range(soo, 8))))
    for t in (save, restore, noarg):
        t.append('%s: is soo { }' % t[0].split(':')[0])
    for t in (spill, unspill, move):
        t.append('%s: is sol { }' % t[0].split(':')[0])
    for name, t in (('CallSpill', spill), ('CallUnspill', unspill), ('CallMove', move),
                    ('CallMoveRest', rest), ('CallSave', save), ('CallRestore', restore),
                    ('CallNoarg', noarg)):
        add_sub(name, t)
    add_sub('CallIn', ['CallIn: is CallSpill & CallSave & CallMove & CallMoveRest & CallNoarg { build CallSpill; '
                       'build CallSave; build CallMove; build CallMoveRest; build CallNoarg; }'])
    add_sub('CallOut', ['CallOut: is CallRestore & CallUnspill { build CallRestore; build CallUnspill; '
                        'ar.bsp = fsbsp; %s ar.ec = (ar.pfs >> 52) & 0x3f; }' % cfm_from('ar.pfs')])


def rotate(names):
    """Values move one register up, the last wraps to the first (SDM vol 1 4.5.1, 1:76)."""
    if not names:
        return []
    out = ['local %s_t = %s;' % (names[0], names[-1])]
    out += ['%s = %s;' % (names[i], names[i - 1]) for i in range(len(names) - 1, 0, -1)]
    out.append('%s = %s_t;' % (names[0], names[0]))
    return out


# clrrrb's scratch area in rse, far above any frame bof reaches.
UNROT = 0xf0000000


def unrotate(names, rrb, size):
    """Rotate up by rrb, back to rrb 0 (clrrrb): through a scratch area in rse, so
    the decompiler drops the copies it does not need and folds them for a known rrb."""
    n = len(names)
    out = ['*[rse]:%d %#x:4 = %s;' % (size, UNROT + 8 * i, names[i]) for i in range(n)]
    out.append('local %s_k:4 = %d - %s:4;' % (rrb, n, rrb))
    out += ['%s = *[rse]:%d (%#x + ((%d + %s_k) %% %d) * 8);' % (names[i], size, UNROT, i, rrb, n)
            for i in range(n)]
    out.append('%s = 0;' % rrb)
    return out


GR_ROT = lambda n: ["r%d" % (32 + i) for i in range(n)]  # noqa: E731
FR_ROT = ['f%d' % i for i in range(32, 128)]
PR_ROT = ['p%d' % i for i in range(16, 64)]


def rotation_subs():
    """Rot: one rotation of the rotating registers, for br.ctop and the other
    modulo-scheduled branches; the rrb's count down as in CFM. Unrot (clrrrb)
    and UnrotPr (clrrrb.pr) rotate the rest of the way round, back to rrb 0."""
    rot, unrot = [], []
    # sor above 12 (more than 96 rotating) is an illegal alloc: rotate no general registers.
    for sor in range(16):
        n = 8 * sor if sor < 13 else 0
        body = rotate(GR_ROT(n)) + rotate(FR_ROT) + rotate(PR_ROT)
        if n:
            body.append('rrb_gr = (rrb_gr + %d) %% %d;' % (n - 1, n))
        body += ['rrb_fr = (rrb_fr + 95) % 96;', 'rrb_pr = (rrb_pr + 47) % 48;']
        rot.append('Rot: is sor=%d { %s }' % (sor, ' '.join(body)))
        body = unrotate(GR_ROT(n), 'rrb_gr', 8) if n else ['rrb_gr = 0;']
        body += unrotate(FR_ROT, 'rrb_fr', 8) + unrotate(PR_ROT, 'rrb_pr', 1)
        unrot.append('Unrot: is sor=%d { %s }' % (sor, ' '.join(body)))
    add_sub('Rot', rot)
    add_sub('Unrot', unrot)
    add_sub('UnrotPr', ['UnrotPr: is sor { %s }' % ' '.join(unrotate(PR_ROT, 'rrb_pr', 1))])


def main():
    cons = []
    for unit in 'MIFBX':
        for layout in UNIT_LAYOUTS[unit]:
            for e in isa.entries(unit, completers=False):
                cons.append(constructor(e, layout, unit))
    cons += unknown_constructors()
    call_frame_subs()
    rotation_subs()
    write(cons + dispatch())


def reg_defs(offset, size, names):
    return ['define register offset=%#x size=%d [ %s ];' % (offset + i * size, size, ' '.join(names[i:i + 8]))
            for i in range(0, len(names), 8)]


def header():
    out = ['# IA-64 (Itanium) processor module, generated by tools/gen_slaspec.py from',
           '# tools/ia64_isa.py: edit those and regenerate, not this file.',
           'define endian=little;', 'define alignment=2;',
           'define space ram type=ram_space size=8 default;',
           'define space register type=register_space size=4;',
           '# The physical stacked registers below the current frame, indexed by bof.',
           'define space rse type=ram_space size=4;',
           '# Register files indexed by a general register (mov r1=msr[r3] and the like).']
    out += ['define space %s type=ram_space size=8;' % sp for sp in INDEXED_SPACES]
    out += reg_defs(0, 8, REGS['gr']) + reg_defs(0x1000, 8, REGS['fr']) + reg_defs(0x2000, 1, REGS['pr'])
    out += reg_defs(0x2100, 8, REGS['br']) + reg_defs(0x2200, 8, REGS['ar']) + reg_defs(0x2800, 8, REGS['cr'])
    out += reg_defs(0x3000, 8, REGS['dahr'])
    out.append('define register offset=0x3100 size=8 [ ip psr ];')
    out.append("# The caller's r32.. and ar.bsp while a call lends the registers to the callee, and a")
    out.append("# register nothing writes (the cspec lists it as unaffected, so it is never an argument).")
    out += reg_defs(0x3200, 8, ['fs%d' % i for i in range(NSTACKED)])
    out.append('define register offset=0x3600 size=8 [ fsbsp noarg ];')
    out.append('# CFM by field (SDM vol 1 3.1.7), and bof, the byte offset of the current frame in rse.')
    out.append('define register offset=0x3700 size=8 [ cfm_sof cfm_sol cfm_sor rrb_gr rrb_fr rrb_pr ];')
    out.append('define register offset=0x3800 size=4 [ bof ];')
    out.append('define register offset=0x4000 size=8 [ contextreg ];')
    return '\n'.join(out) + '\n'


def macros():
    # One expression, not 63 writes to res: a loop that reads and restores the predicates
    # (PAL's br.ia site) made the decompiler fail to hash a varnode.
    out = ['# All 64 predicates as one value; p0 reads as 1.', 'macro pr_read(res) {']
    out.append('  res = ' + ' | '.join(['1'] + ['(zext(p%d) << %d)' % (i, i) for i in range(1, 64)]) + ';')
    out += ['}', 'macro pr_write(val, mask) {']
    out += ['  p%d = (p%d && ((mask >> %d) & 1) == 0) || (((val >> %d) & 1) != 0 && ((mask >> %d) & 1) != 0);'
            % (i, i, i, i, i) for i in range(1, 64)]
    out.append('}')
    return '\n'.join(out)


def write(cons):
    out = [header()]
    out.append('define context contextreg')
    out.append('  slot=(0,1) noflow')
    out.append('  tmpl=(2,6) noflow')
    out.append('  ca=(7,15) noflow')
    out.append('  cb=(16,24) noflow')
    for name, (a, b) in sorted(ctx_fields.items()):
        out.append('  %s=(%d,%d) noflow' % (name, a, b))
    out.append('  sol=(32,38)')
    out.append('  soo=(39,45)')
    out.append('  pal=(46,46) noflow')
    out.append('  sor=(47,50)')
    out.append(';')
    for tok, fields in sorted(token_fields.items()):
        n = {'s0tok': 48, 's1tok': 48, 's2tok': 32, 'lxtok': 80}[tok]
        out.append('define token %s(%d)' % (tok, n))
        for name, (a, b) in sorted(fields.items(), key=lambda x: (x[1], x[0])):
            out.append('  %s=(%d,%d)' % (name, a, b))
        out.append(';')
    for (kind, w), fields in sorted(attaches.items()):
        names = REGS[kind][:1 << w]
        out.append('attach variables [ %s ] [ %s ];' % (' '.join(sorted(fields)), ' '.join(names)))
    for op in sorted(pcodeops):
        out.append('define pcodeop %s;' % op)
    out.append(macros())
    for name in sub_order:
        out.extend(subtables[name])
    out.extend(cons)
    with open(OUT, 'w') as f:
        f.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
