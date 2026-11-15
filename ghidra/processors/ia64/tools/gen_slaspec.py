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


def call_sem(target, b1):
    return ('%s = (inst_start & 0xfffffffffffffff0) + 16; build CallIn; call %s; build CallOut;'
            % (b1, target))


def loop_sem(kind, tgt):
    rot = 'rotate_regs();'
    if kind == 'CTOP' or kind == 'CEXIT':
        taken, fall = ('goto %s;' % tgt, 'goto inst_next;')
        if kind == 'CEXIT':
            taken, fall = fall, taken
        return ('if (ar.lc == 0) goto <epi>; ar.lc = ar.lc - 1; p63 = 1; %s %s '
                '<epi> if (ar.ec <= 1) goto <last>; ar.ec = ar.ec - 1; p63 = 0; %s %s '
                '<last> if (ar.ec == 0) goto <none>; ar.ec = ar.ec - 1; p63 = 0; %s %s '
                '<none> %s' % (rot, taken, rot, taken, rot, fall, fall))
    taken, fall = ('goto %s;' % tgt, 'goto inst_next;')
    if kind == 'WEXIT':
        taken, fall = fall, taken
    return ('if (!$qp) goto <epi>; p63 = 0; %s %s '
            '<epi> if (ar.ec <= 1) goto <last>; ar.ec = ar.ec - 1; p63 = 0; %s %s '
            '<last> if (ar.ec == 0) goto <none>; ar.ec = ar.ec - 1; p63 = 0; %s %s '
            '<none> %s' % (rot, taken, rot, taken, rot, fall, fall))


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
        sem = loop_sem(sem, '$tgt25c')

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
        action = (' [ sol = %s; globalset(inst_next, sol); soo = %s - %s; globalset(inst_next, soo); ]'
                  % (sol, sof, sol))
        cons += [sof, sol]
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
    if kind:
        extra = ' & CallIn & CallOut'
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


# sol and soo before any alloc (the pspec's default; no alloc makes either 127): a call
# there passes r32.. on as they are.
NO_FRAME = 127


def call_frame_subs():
    """The register stack renames the caller's outputs r(32+sol).. to the
    callee's r32..; copy up to eight of them there for the call, give the rest
    of r32..r39 the never-written `noarg` so no stale caller value (a saved gp)
    reads as an argument, and put the caller's r32..r39 back afterwards. sol and
    soo come from the frame's alloc; before one, a call leaves r32.. alone."""
    cin, cout = [], []
    for sol in range(97):
        for soo in range(10):
            n = min(soo, 8, 96 - sol)
            body = ['fs%d = r%d;' % (i, 32 + i) for i in range(8)]
            body += ['r%d = r%d;' % (32 + i, 32 + sol + i) for i in range(n)]
            body += ['r%d = noarg;' % (32 + i) for i in range(n, 8)]
            cond = 'sol=%d & soo=%d' % (sol, soo) if soo < 9 else 'sol=%d' % sol
            cin.append('CallIn: is %s { %s }' % (cond, ' '.join(body)))
    cin.append('CallIn: is sol { }')     # sol above 96 is no frame alloc can make
    body = ' '.join('r%d = fs%d;' % (32 + i, i) for i in range(8))
    cout.append('CallOut: is soo { %s }' % body)
    cout.append('CallOut: is soo=%d { }' % NO_FRAME)
    add_sub('CallIn', cin)
    add_sub('CallOut', cout)


def main():
    cons = []
    for unit in 'MIFBX':
        for layout in UNIT_LAYOUTS[unit]:
            for e in isa.entries(unit, completers=False):
                cons.append(constructor(e, layout, unit))
    cons += unknown_constructors()
    call_frame_subs()
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
           '# Register files indexed by a general register (mov r1=msr[r3] and the like).']
    out += ['define space %s type=ram_space size=8;' % sp for sp in INDEXED_SPACES]
    out += reg_defs(0, 8, REGS['gr']) + reg_defs(0x1000, 8, REGS['fr']) + reg_defs(0x2000, 1, REGS['pr'])
    out += reg_defs(0x2100, 8, REGS['br']) + reg_defs(0x2200, 8, REGS['ar']) + reg_defs(0x2800, 8, REGS['cr'])
    out += reg_defs(0x3000, 8, REGS['dahr'])
    out.append('define register offset=0x3100 size=8 [ ip psr cfm ];')
    out.append("# The caller's r32..r39 while a call lends them to the callee as arguments, and a")
    out.append("# register nothing writes (the cspec lists it as unaffected, so it is never an argument).")
    out += reg_defs(0x3200, 8, ['fs%d' % i for i in range(8)])
    out.append('define register offset=0x3300 size=8 [ noarg ];')
    out.append('define register offset=0x4000 size=8 [ contextreg ];')
    return '\n'.join(out) + '\n'


def macros():
    out = ['# All 64 predicates as one value; p0 reads as 1.', 'macro pr_read(res) {', '  res = 1;']
    out += ['  res = res | (zext(p%d) << %d);' % (i, i) for i in range(1, 64)]
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
