#!/usr/bin/env python3
"""The IA-64 instruction table: encodings, assembler syntax and p-code.

One table drives both gen_slaspec.py (the SLEIGH module) and the reference
decoder in this file (decode_bundle), which objdump_compare.py and the unit
tests use. Encodings follow the Intel Itanium Architecture Software
Developer's Manual rev 2.3, volume 3 (323207), chapter 4 "Instruction
Formats"; mnemonics and operand order follow the GNU assembler syntax so the
listing reads like ia64-linux-gnu-objdump's.

A field is (low bit, width) inside the 41-bit slot. An entry matches when
every constrained field holds its value; when several match, the one whose
constraints include all of another's wins, as in SLEIGH.
"""
import itertools

# ---------------------------------------------------------------- templates
# 5-bit template -> (slot units, stop after slot n) (SDM vol 3 table 3-10).
TEMPLATES = {}
for _t, _u, _stops in [
        (0x00, 'MII', ()), (0x01, 'MII', (2,)), (0x02, 'MII', (1,)), (0x03, 'MII', (1, 2)),
        (0x04, 'MLX', ()), (0x05, 'MLX', (2,)),
        (0x08, 'MMI', ()), (0x09, 'MMI', (2,)), (0x0a, 'MMI', (0,)), (0x0b, 'MMI', (0, 2)),
        (0x0c, 'MFI', ()), (0x0d, 'MFI', (2,)), (0x0e, 'MMF', ()), (0x0f, 'MMF', (2,)),
        (0x10, 'MIB', ()), (0x11, 'MIB', (2,)), (0x12, 'MBB', ()), (0x13, 'MBB', (2,)),
        (0x16, 'BBB', ()), (0x17, 'BBB', (2,)), (0x18, 'MMB', ()), (0x19, 'MMB', (2,)),
        (0x1c, 'MFB', ()), (0x1d, 'MFB', (2,))]:
    TEMPLATES[_t] = (_u, _stops)


def tname(t):
    """objdump's template label, '-x-' for a reserved one."""
    if t in TEMPLATES:
        return TEMPLATES[t][0]
    return '-%x-' % (t >> 1)


# ------------------------------------------------------------- register names
AR_NAMES = {**{i: 'ar.k%d' % i for i in range(8)},
            16: 'ar.rsc', 17: 'ar.bsp', 18: 'ar.bspstore', 19: 'ar.rnat', 21: 'ar.fcr',
            24: 'ar.eflag', 25: 'ar.csd', 26: 'ar.ssd', 27: 'ar.cflg', 28: 'ar.fsr',
            29: 'ar.fir', 30: 'ar.fdr', 32: 'ar.ccv', 36: 'ar.unat', 40: 'ar.fpsr',
            44: 'ar.itc', 45: 'ar.ruc', 64: 'ar.pfs', 65: 'ar.lc', 66: 'ar.ec'}
CR_NAMES = {0: 'cr.dcr', 1: 'cr.itm', 2: 'cr.iva', 8: 'cr.pta', 16: 'cr.ipsr', 17: 'cr.isr',
            19: 'cr.iip', 20: 'cr.ifa', 21: 'cr.itir', 22: 'cr.iipa', 23: 'cr.ifs',
            24: 'cr.iim', 25: 'cr.iha', 26: 'cr.iib0', 27: 'cr.iib1', 64: 'cr.lid',
            65: 'cr.ivr', 66: 'cr.tpr', 67: 'cr.eoi', 68: 'cr.irr0', 69: 'cr.irr1',
            70: 'cr.irr2', 71: 'cr.irr3', 72: 'cr.itv', 73: 'cr.pmv', 74: 'cr.cmcv',
            80: 'cr.lrr0', 81: 'cr.lrr1'}


def ar_name(n):
    return AR_NAMES.get(n, 'ar%d' % n)


def cr_name(n):
    return CR_NAMES.get(n, 'cr%d' % n)


# ------------------------------------------------------------------ operands
# kind, then what the kind needs. 'parts' lists (low bit, width), low part
# first; 'scale' shifts the assembled value left; 'signed' sign-extends it.
OPERANDS = {
    'r1': ('gr', (6, 7)), 'r2': ('gr', (13, 7)), 'r3': ('gr', (20, 7)), 'r3_2': ('gr', (20, 2)),
    'f1': ('fr', (6, 7)), 'f2': ('fr', (13, 7)), 'f3': ('fr', (20, 7)), 'f4': ('fr', (27, 7)),
    'p1': ('pr', (6, 6)), 'p2': ('pr', (27, 6)),
    'b1': ('br', (6, 3)), 'b2': ('br', (13, 3)),
    'ar3': ('ar', (20, 7)), 'cr3': ('cr', (20, 7)), 'dahr': ('dahr', (23, 3)),
    'mr3': ('mem', (20, 7)),
    'cpuid_r3': ('ind', 'cpuid'), 'dbr_r3': ('ind', 'dbr'), 'ibr_r3': ('ind', 'ibr'),
    'pkr_r3': ('ind', 'pkr'), 'pmc_r3': ('ind', 'pmc'), 'pmd_r3': ('ind', 'pmd'),
    'msr_r3': ('ind', 'msr'), 'rr_r3': ('ind', 'rr'), 'itr_r3': ('ind', 'itr'),
    'dtr_r3': ('ind', 'dtr'), 'dahr_r3': ('ind', 'dahr'),
    'ar.pfs': ('const', 'ar.pfs'), 'ar.ccv': ('const', 'ar.ccv'), 'ar.csd': ('const', 'ar.csd'),
    'ip': ('const', 'ip'), 'pr': ('const', 'pr'), 'pr.rot': ('const', 'pr.rot'),
    'psr': ('const', 'psr'), 'psr.l': ('const', 'psr.l'), 'psr.um': ('const', 'psr.um'),
    'r0': ('const', 'r0'),
    # immediates: (kind, parts, signed, scale, add, xor, print)
    'imm1': ('imm', [(36, 1)], True, 0, 0, 0, 'dec'),
    'immu2': ('imm', [(13, 2)], False, 0, 0, 0, 'dec'),
    'immu5b': ('imm', [(14, 5)], False, 0, 32, 0, 'dec'),
    'immu7a': ('imm', [(13, 7)], False, 0, 0, 0, 'hex'),
    'immu7b': ('imm', [(20, 7)], False, 0, 0, 0, 'hex'),
    'sof': ('imm', [(13, 7)], False, 0, 0, 0, 'dec'),
    'sol': ('imm', [(20, 7)], False, 0, 0, 0, 'dec'),
    'sor': ('imm', [(27, 4)], False, 3, 0, 0, 'dec'),
    'imm8': ('imm', [(13, 7), (36, 1)], True, 0, 0, 0, 'dec'),
    'imm8m1': ('imm', [(13, 7), (36, 1)], True, 0, 1, 0, 'dec'),
    'immu9': ('imm', [(33, 2), (20, 7)], False, 0, 0, 0, 'hex'),
    'imm9a': ('imm', [(6, 7), (27, 1), (36, 1)], True, 0, 0, 0, 'dec'),
    'imm9b': ('imm', [(13, 7), (27, 1), (36, 1)], True, 0, 0, 0, 'dec'),
    'imm14': ('imm', [(13, 7), (27, 6), (36, 1)], True, 0, 0, 0, 'dec'),
    'immu16': ('imm', [(6, 4), (12, 11), (36, 1)], False, 0, 0, 0, 'dec'),
    'imm17': ('imm', [(6, 7), (24, 8), (36, 1)], True, 1, 0, 0, 'hex'),
    'immu19': ('imm', [(6, 4), (12, 14), (36, 1)], False, 0, 0, 0, 'dec'),
    'immu21': ('imm', [(6, 20), (36, 1)], False, 0, 0, 0, 'hex'),
    'imm22': ('imm', [(13, 7), (27, 9), (22, 5), (36, 1)], True, 0, 0, 0, 'dec'),
    'immu24': ('imm', [(6, 21), (31, 2), (36, 1)], False, 0, 0, 0, 'hex'),
    'imm44': ('imm', [(6, 27), (36, 1)], True, 16, 0, 0, 'hex'),
    'cnt2a': ('imm', [(27, 2)], False, 0, 1, 0, 'dec'),
    'cnt2b': ('imm', [(27, 2)], False, 0, 1, 0, 'dec'),
    'cnt5': ('imm', [(14, 5)], False, 0, 0, 0, 'dec'),
    'cnt6': ('imm', [(27, 6)], False, 0, 0, 0, 'dec'),
    'ccnt5': ('imm', [(20, 5)], False, 0, 0, 31, 'dec'),
    'cpos6a': ('imm', [(20, 6)], False, 0, 0, 63, 'dec'),
    'cpos6b': ('imm', [(14, 6)], False, 0, 0, 63, 'dec'),
    'cpos6c': ('imm', [(31, 6)], False, 0, 0, 63, 'dec'),
    'pos6': ('imm', [(14, 6)], False, 0, 0, 0, 'dec'),
    'len4': ('imm', [(27, 4)], False, 0, 1, 0, 'dec'),
    'len6': ('imm', [(27, 6)], False, 0, 1, 0, 'dec'),
    'mbtype8': ('imm', [(20, 8)], False, 0, 0, 0, 'hex'),
    'cnt6a': ('imm', [(6, 6)], False, 0, 1, 0, 'dec'),
    'strd5b': ('imm', [(13, 5)], True, 6, 0, 0, 'dec'),
    'cnt2c': ('map', (30, 2), {0: 0, 1: 7, 2: 15, 3: 16}),
    'inc3': ('map', (13, 3), {0: 16, 1: 8, 2: 4, 3: 1, 4: -16, 5: -8, 6: -4, 7: -1}),
    'mbtype4': ('mbtype', (20, 4)),
    'tag13': ('rel', [(6, 7), (33, 2)]),
    'tag13b': ('rel', [(24, 9)]),
    'tgt25': ('rel', [(6, 20), (36, 1)]),
    'tgt25b': ('rel', [(6, 7), (20, 13), (36, 1)]),
    'tgt25c': ('rel', [(13, 20), (36, 1)]),
    'tgt64': ('tgt64',),
    'immu62': ('immu62',),
    'immu64': ('immu64',),
}
MBTYPE_NAMES = {0x0: '@brcst', 0x8: '@mix', 0x9: '@shuf', 0xa: '@alt', 0xb: '@rev'}


def bits(v, lo, w):
    return (v >> lo) & ((1 << w) - 1)


def sext(v, w):
    s = 1 << (w - 1)
    return (v ^ s) - s


def imm_value(spec, slot):
    _, parts, signed, scale, add, xor, _ = spec
    v, tot = 0, 0
    for lo, w in parts:
        v |= bits(slot, lo, w) << tot
        tot += w
    v ^= xor
    if signed:
        v = sext(v, tot)
    return (v << scale) + add


# ------------------------------------------------------------------- entries
class Entry:
    """One encoding. cons: {(lo, w): value}; ops: operand ids in order, the
    first nout of them are outputs; sem: SLEIGH p-code with $name for an
    operand's value and @name for a writable register (see gen_slaspec.py)."""
    __slots__ = ('unit', 'name', 'cons', 'ops', 'nout', 'flags', 'sem', 'excl', 'comp')

    def __init__(self, unit, name, cons, ops, nout, sem=None, flags=(), excl=None, comp=None):
        self.unit, self.name, self.cons, self.ops = unit, name, dict(cons), list(ops)
        self.nout, self.sem, self.flags = nout, sem, frozenset(flags)
        self.excl = excl            # field values that must not occur: [(field, value)]
        self.comp = comp            # a COMPLETERS key: a suffix chosen by more fields

    def mask_value(self):
        m = v = 0
        for (lo, w), val in self.cons.items():
            m |= ((1 << w) - 1) << lo
            v |= val << lo
        return m, v

    def matches(self, slot):
        if any(bits(slot, lo, w) != val for (lo, w), val in self.cons.items()):
            return False
        if self.excl and any(bits(slot, *f) == val for f, val in self.excl):
            return False
        return True


ENTRIES = []
OP = (37, 4)


def E(unit, name, cons, ops, nout=None, sem=None, flags=(), excl=None, comp=None):
    if nout is None:
        nout = 1 if ops and ops[0] not in ('mr3',) and not name.startswith(('st', 'br', 'brl', 'chk', 'nop', 'break', 'hint')) else 0
    ENTRIES.append(Entry(unit, name, cons, ops, nout, sem, flags, excl, comp))


def C(**kw):
    """Constraints by field name, for the field positions in FIELD."""
    return {FIELD[k]: v for k, v in kw.items()}


FIELD = {
    'op': (37, 4), 'qp': (0, 6),
    # A and I unit
    'x2a': (34, 2), 've': (33, 1), 'x4': (29, 4), 'x2b': (27, 2), 'za': (36, 1), 'zb': (33, 1),
    'tb': (36, 1), 'x2': (34, 2), 'ta': (33, 1), 'c': (12, 1), 'r3': (20, 7), 'r2': (13, 7),
    'i_ve': (32, 1), 'i_x2b': (28, 2), 'i_x2c': (30, 2), 'i_x': (33, 1), 'ya': (13, 1),
    'yb': (26, 1), 'xc': (19, 1), 'x3': (33, 3), 'x6': (27, 6), 'xb': (22, 1), 'ih': (23, 1),
    'wh': (20, 2), 'vc': (20, 1),
    # M unit
    'm': (36, 1), 'mx': (27, 1), 'm_x2': (31, 2), 'm_x4': (27, 4), 'x6a': (30, 6), 'hint': (28, 2),
    'y': (26, 1), 'y1': (19, 1), 'z': (10, 2), 'hlf': (12, 1), 'hlfa': (19, 1),
    # B unit
    'btype': (6, 3), 'd': (35, 1), 'pa': (12, 1), 'wha': (33, 2), 'whb': (3, 2), 'whc': (32, 3),
    'b_ih': (35, 1),
    # F unit
    'q': (36, 1), 'ra': (33, 1), 'rb': (36, 1), 'f_ta': (12, 1), 'sf': (34, 2), 'xa': (36, 1),
    'f_xb': (33, 1), 'f_x2': (34, 2), 'f2': (13, 7), 'f4': (27, 7), 'f_y': (26, 1),
}

# ------------------------------------------------------------- p-code pieces
# Compares: (relation on a, b) for the eq/lt/ltu families.
REL = {'eq': '{a} == {b}', 'ne': '{a} != {b}', 'lt': '{a} s< {b}', 'le': '{a} s<= {b}',
       'gt': '{a} s> {b}', 'ge': '{a} s>= {b}', 'ltu': '{a} < {b}', 'leu': '{a} <= {b}',
       'gtu': '{a} > {b}', 'geu': '{a} >= {b}'}


def cmp_sem(ctype, cond):
    """Predicate writes for a compare of type ctype (SDM vol 3 table 2-10)."""
    if cond.startswith('!') and '(' in cond:
        # A negated p-code op: give the op's result a size first.
        c = 'local n:1 = %s; local c:1 = !n; ' % cond[1:]
    else:
        c = 'local c:1 = %s; ' % cond
    if ctype == 'none':
        return c + '@p1 = c; @p2 = !c;'
    if ctype == 'unc':
        return c + '@p1 = $qp && c; @p2 = $qp && !c;'
    if ctype == 'and':
        return c + 'if (c) goto inst_next; @p1 = 0; @p2 = 0;'
    if ctype == 'or':
        return c + 'if (!c) goto inst_next; @p1 = 1; @p2 = 1;'
    if ctype == 'or.andcm':
        return c + 'if (!c) goto inst_next; @p1 = 1; @p2 = 0;'
    raise ValueError(ctype)


# ======================================================================= A
def build_a():
    a = C(op=8)
    alu = [('add', 0, 0, '$r2 + $r3'), ('add', 0, 1, '$r2 + $r3 + 1'),
           ('sub', 1, 1, '$r2 - $r3'), ('sub', 1, 0, '$r2 - $r3 - 1'),
           ('addp4', 2, 0, 'zext($r2:4 + $r3:4) | (zext($r3[30,2]) << 61)'),
           ('and', 3, 0, '$r2 & $r3'), ('andcm', 3, 1, '$r2 & ~$r3'),
           ('or', 3, 2, '$r2 | $r3'), ('xor', 3, 3, '$r2 ^ $r3')]
    for name, x4, x2b, expr in alu:
        ops = ['r1', 'r2', 'r3'] + (['1'] if (name, x2b) in (('add', 1), ('sub', 0)) else [])
        E('A', name, {**a, **C(x2a=0, ve=0, x4=x4, x2b=x2b)}, ops, 1, '@r1 = %s;' % expr)
    E('A', 'shladd', {**a, **C(x2a=0, ve=0, x4=4)}, ['r1', 'r2', 'cnt2a', 'r3'], 1,
      '@r1 = ($r2 << $cnt2a) + $r3;')
    E('A', 'shladdp4', {**a, **C(x2a=0, ve=0, x4=6)}, ['r1', 'r2', 'cnt2a', 'r3'], 1,
      'local s:4 = ($r2:4 << $cnt2a:4) + $r3:4; @r1 = zext(s) | (zext($r3[30,2]) << 61);')
    for name, x2b, expr in [('sub', 1, '$imm8 - $r3'), ('and', 0, '$imm8 & $r3'),
                            ('andcm', 1, '$imm8 & ~$r3'), ('or', 2, '$imm8 | $r3'),
                            ('xor', 3, '$imm8 ^ $r3')]:
        E('A', name, {**a, **C(x2a=0, ve=0, x4=9 if name == 'sub' else 0xb, x2b=x2b)},
          ['r1', 'imm8', 'r3'], 1,
          '@r1 = %s;' % expr)
    E('A', 'adds', {**a, **C(x2a=2, ve=0)}, ['r1', 'imm14', 'r3'], 1, '@r1 = $imm14 + $r3;')
    # adds with a zero immediate is the register move.
    E('A', 'mov', {**a, **C(x2a=2, ve=0), (13, 7): 0, (27, 6): 0, (36, 1): 0}, ['r1', 'r3'], 1,
      '@r1 = $r3;')
    E('A', 'addp4', {**a, **C(x2a=3, ve=0)}, ['r1', 'imm14', 'r3'], 1,
      'local s:4 = $imm14:4 + $r3:4; @r1 = zext(s) | (zext($r3[30,2]) << 61);')
    E('A', 'addl', C(op=9), ['r1', 'imm22', 'r3_2'], 1, '@r1 = $imm22 + $r3_2;')
    E('A', 'mov', {**C(op=9), (20, 2): 0}, ['r1', 'imm22'], 1, '@r1 = $imm22;')
    # Multimedia (A9, A10).
    mm = [('padd1', 0, 0, 0, 0), ('padd2', 0, 1, 0, 0), ('padd4', 1, 0, 0, 0),
          ('padd1.sss', 0, 0, 0, 1), ('padd2.sss', 0, 1, 0, 1), ('padd1.uuu', 0, 0, 0, 2),
          ('padd2.uuu', 0, 1, 0, 2), ('padd1.uus', 0, 0, 0, 3), ('padd2.uus', 0, 1, 0, 3),
          ('psub1', 0, 0, 1, 0), ('psub2', 0, 1, 1, 0), ('psub4', 1, 0, 1, 0),
          ('psub1.sss', 0, 0, 1, 1), ('psub2.sss', 0, 1, 1, 1), ('psub1.uuu', 0, 0, 1, 2),
          ('psub2.uuu', 0, 1, 1, 2), ('psub1.uus', 0, 0, 1, 3), ('psub2.uus', 0, 1, 1, 3),
          ('pavg1', 0, 0, 2, 2), ('pavg2', 0, 1, 2, 2), ('pavg1.raz', 0, 0, 2, 3),
          ('pavg2.raz', 0, 1, 2, 3), ('pavgsub1', 0, 0, 3, 2), ('pavgsub2', 0, 1, 3, 2),
          ('pcmp1.eq', 0, 0, 9, 0), ('pcmp2.eq', 0, 1, 9, 0), ('pcmp4.eq', 1, 0, 9, 0),
          ('pcmp1.gt', 0, 0, 9, 1), ('pcmp2.gt', 0, 1, 9, 1), ('pcmp4.gt', 1, 0, 9, 1)]
    for name, za, zb, x4, x2b in mm:
        E('A', name, {**a, **C(x2a=1, za=za, zb=zb, x4=x4, x2b=x2b)}, ['r1', 'r2', 'r3'], 1,
          '@r1 = %s($r2, $r3);' % pcop(name))
    E('A', 'pshladd2', {**a, **C(x2a=1, za=0, zb=1, x4=4)}, ['r1', 'r2', 'cnt2b', 'r3'], 1,
      '@r1 = pshladd2($r2, $cnt2b, $r3);')
    E('A', 'pshradd2', {**a, **C(x2a=1, za=0, zb=1, x4=6)}, ['r1', 'r2', 'cnt2b', 'r3'], 1,
      '@r1 = pshradd2($r2, $cnt2b, $r3);')
    # Integer compares (A6, A7, A8). Opcode C: lt, D: ltu, E: eq; x2 0/1 is
    # register 64/32-bit, 2/3 immediate 64/32-bit.
    for op, base in ((0xc, 'lt'), (0xd, 'ltu'), (0xe, 'eq')):
        for x2 in range(4):
            size = 'cmp4' if x2 & 1 else 'cmp'
            imm = x2 >= 2
            for ta in (0, 1):
                for c in (0, 1):
                    if not imm:
                        for tb in (0, 1):
                            add_cmp(op, base, size, x2, tb, ta, c, imm)
                    else:
                        add_cmp(op, base, size, x2, None, ta, c, imm)


def add_cmp(op, base, size, x2, tb, ta, c, imm):
    cons = C(op=op, x2=x2, ta=ta, c=c)
    if tb is not None:
        cons.update(C(tb=tb))
    w = 4 if size == 'cmp4' else 8

    def val(o):
        if o == 'r0':
            return '0:%d' % w
        return '$%s:%d' % (o, w) if w == 4 else '$%s' % o
    if tb == 1:
        # A7: compare r3 against zero; c selects the relation.
        if base == 'lt':
            ct = 'and'
        elif base == 'ltu':
            ct = 'or'
        else:
            ct = 'or.andcm'
        rel = {(0, 0): 'gt', (0, 1): 'le', (1, 0): 'ge', (1, 1): 'lt'}[(ta, c)]
        name = '%s.%s.%s' % (size, rel, ct)
        cond = REL[rel].format(a='0:%d' % w, b=val('r3'))
        E('A', name, cons, ['p1', 'p2', 'r0', 'r3'], 2, cmp_sem(ct, cond),
          flags=('qpcustom',) if ct == 'unc' else ())
        return
    if ta == 0:
        rel, ct = base, ('unc' if c else 'none')
    else:
        ct = {'lt': 'and', 'ltu': 'or', 'eq': 'or.andcm'}[base]
        rel = 'ne' if c else 'eq'
    name = '%s.%s' % (size, rel) + ('' if ct == 'none' else '.' + ct)
    src = 'imm8' if imm else 'r2'
    a = '$imm8:%d' % w if (imm and w == 4) else ('$imm8' if imm else val('r2'))
    cond = REL[rel].format(a=a, b=val('r3'))
    E('A', name, cons, ['p1', 'p2', src, 'r3'], 2, cmp_sem(ct, cond),
      flags=('qpcustom',) if ct == 'unc' else ())


def pcop(name):
    return name.replace('.', '_')


# ======================================================================= I
def build_i():
    i0 = C(op=0)
    E('I', 'break.i', {**i0, **C(x3=0, x6=0)}, ['immu21'], 0, 'break_insn($immu21);')
    E('I', 'nop.i', {**i0, **C(x3=0, x6=1, yb=0)}, ['immu21'], 0, '')
    E('I', 'hint.i', {**i0, **C(x3=0, x6=1, yb=1)}, ['immu21'], 0, 'hint($immu21);')
    E('I', 'chk.s.i', {**i0, **C(x3=1)}, ['r2', 'tgt25b'], 0,
      'local t:1 = nat($r2); if (t) goto $tgt25b;')
    # mov to b (I21): mov[.ret][.sptk|.dptk][.imp] b1=r2,tag13
    for xb, ret in ((0, ''), (1, '.ret')):
        for ih, imp in ((0, ''), (1, '.imp')):
            for wh, whn in ((0, '.sptk'), (1, ''), (2, '.dptk')):
                # objdump's table lists the tagless 'mov b1=r2' first for this one.
                ops = ['b1', 'r2'] if (xb, ih, wh) == (0, 0, 1) else ['b1', 'r2', 'tag13b']
                E('I', 'mov' + ret + whn + imp, {**i0, **C(x3=7, xb=xb, ih=ih, wh=wh)}, ops, 1,
                  '@b1 = $r2;')
    E('I', 'mov', {**i0, **C(x3=0, x6=0x31)}, ['r1', 'b2'], 1, '@r1 = $b2;')
    E('I', 'mov', {**i0, **C(x3=3)}, ['pr', 'r2', 'imm17'], 1, 'pr_write($r2, $imm17);')
    E('I', 'mov', {**i0, **C(x3=2)}, ['pr.rot', 'imm44'], 1, 'pr_write($imm44, 0xffffffffffff0000:8);')
    E('I', 'mov', {**i0, **C(x3=0, x6=0x30)}, ['r1', 'ip'], 1, '@r1 = inst_start & ~0xf;')
    E('I', 'mov', {**i0, **C(x3=0, x6=0x33)}, ['r1', 'pr'], 1, 'pr_read(@r1);')
    E('I', 'mov.i', {**i0, **C(x3=0, x6=0x2a)}, ['ar3', 'r2'], 1, '@ar3 = $r2;')
    E('I', 'mov.i', {**i0, **C(x3=0, x6=0x0a)}, ['ar3', 'imm8'], 1, '@ar3 = $imm8;')
    E('I', 'mov.i', {**i0, **C(x3=0, x6=0x32)}, ['r1', 'ar3'], 1, '@r1 = $ar3;')
    for name, x6, expr in [('zxt1', 0x10, 'zext($r3:1)'), ('zxt2', 0x11, 'zext($r3:2)'),
                           ('zxt4', 0x12, 'zext($r3:4)'), ('sxt1', 0x14, 'sext($r3:1)'),
                           ('sxt2', 0x15, 'sext($r3:2)'), ('sxt4', 0x16, 'sext($r3:4)'),
                           ('czx1.l', 0x18, 'czx1_l($r3)'), ('czx2.l', 0x19, 'czx2_l($r3)'),
                           ('czx1.r', 0x1c, 'czx1_r($r3)'), ('czx2.r', 0x1d, 'czx2_r($r3)')]:
        E('I', name, {**i0, **C(x3=0, x6=x6)}, ['r1', 'r3'], 1, '@r1 = %s;' % expr)
    E('I', 'dep', C(op=4), ['r1', 'r2', 'r3', 'cpos6c', 'len4'], 1,
      'local m:8 = ((1 << $len4) - 1) << $cpos6c; @r1 = ($r3 & ~m) | (($r2 << $cpos6c) & m);')
    i5 = C(op=5)
    E('I', 'shrp', {**i5, **C(x2=3, i_x=0)}, ['r1', 'r2', 'r3', 'cnt6'], 1,
      '@r1 = ($r3 >> $cnt6) | (($r2 << 1) << (63 - $cnt6));')
    E('I', 'extr.u', {**i5, **C(x2=1, i_x=0, ya=0)}, ['r1', 'r3', 'pos6', 'len6'], 1,
      '@r1 = ($r3 >> $pos6) & ((1 << $len6) - 1);', flags=('shr_u',))
    E('I', 'extr', {**i5, **C(x2=1, i_x=0, ya=1)}, ['r1', 'r3', 'pos6', 'len6'], 1,
      '@r1 = ($r3 << (64 - $pos6 - $len6)) s>> (64 - $len6);', flags=('shr',))
    E('I', 'dep.z', {**i5, **C(x2=1, i_x=1, yb=0)}, ['r1', 'r2', 'cpos6a', 'len6'], 1,
      '@r1 = ($r2 & ((1 << $len6) - 1)) << $cpos6a;', flags=('shl',))
    E('I', 'dep.z', {**i5, **C(x2=1, i_x=1, yb=1)}, ['r1', 'imm8', 'cpos6a', 'len6'], 1,
      '@r1 = ($imm8 & ((1 << $len6) - 1)) << $cpos6a;')
    E('I', 'dep', {**i5, **C(x2=3, i_x=1)}, ['r1', 'imm1', 'r3', 'cpos6b', 'len6'], 1,
      'local m:8 = ((1 << $len6) - 1) << $cpos6b; @r1 = ($r3 & ~m) | (($imm1 << $cpos6b) & m);')
    # tbit, tnat, tf (I16, I17, I30): ta, tb, ya, c and for tf xc.
    cts = {(0, 0): ('none', 'unc'), (0, 1): ('and', None), (1, 0): ('or', None),
           (1, 1): ('or.andcm', None)}
    for ta in (0, 1):
        for tb in (0, 1):
            for c in (0, 1):
                ct = cts[(ta, tb)][0] if (ta, tb) != (0, 0) else ('unc' if c else 'none')
                pol = 'z' if (ta, tb) == (0, 0) or c == 0 else 'nz'
                suffix = '' if ct == 'none' else '.' + ct
                cond = ('((%s) == 0)' if pol == 'z' else '((%s) != 0)') % '($r3 >> $pos6) & 1'
                E('I', 'tbit.%s%s' % (pol, suffix), {**i5, **C(x2=0, ta=ta, tb=tb, ya=0, c=c)},
                  ['p1', 'p2', 'r3', 'pos6'], 2, cmp_sem(ct, cond),
                  flags=('qpcustom',) if ct == 'unc' else ())
                ncond = '!nat($r3)' if pol == 'z' else 'nat($r3)'
                E('I', 'tnat.%s%s' % (pol, suffix),
                  {**i5, **C(x2=0, ta=ta, tb=tb, ya=1, c=c), (19, 1): 0},
                  ['p1', 'p2', 'r3'], 2, cmp_sem(ct, ncond),
                  flags=('qpcustom',) if ct == 'unc' else ())
                fcond = '!tf_bit($immu5b)' if pol == 'z' else 'tf_bit($immu5b)'
                E('I', 'tf.%s%s' % (pol, suffix),
                  {**i5, **C(x2=0, ta=ta, tb=tb, ya=1, c=c), (19, 1): 1},
                  ['p1', 'p2', 'immu5b'], 2, cmp_sem(ct, fcond),
                  flags=('qpcustom',) if ct == 'unc' else ())
    i7 = C(op=7)

    def mmi(name, za, zb, x2a, x2b, x2c, ops, sem):
        cons = {**i7, **C(za=za, zb=zb, i_ve=0, x2a=x2a, i_x2b=x2b)}
        if x2c is not None:
            cons.update(C(i_x2c=x2c))
        E('I', name, cons, ops, 1, sem)
    mmi('pmpyshr2', 0, 1, 0, 3, None, ['r1', 'r2', 'r3', 'cnt2c'], '@r1 = pmpyshr2($r2, $r3, $cnt2c);')
    mmi('pmpyshr2.u', 0, 1, 0, 1, None, ['r1', 'r2', 'r3', 'cnt2c'], '@r1 = pmpyshr2_u($r2, $r3, $cnt2c);')
    for name, za, zb, x2a, x2b, x2c in [
            ('pmpy2.r', 0, 1, 2, 1, 3), ('pmpy2.l', 0, 1, 2, 3, 3), ('mix1.r', 0, 0, 2, 0, 2),
            ('mix2.r', 0, 1, 2, 0, 2), ('mix4.r', 1, 0, 2, 0, 2), ('mix1.l', 0, 0, 2, 2, 2),
            ('mix2.l', 0, 1, 2, 2, 2), ('mix4.l', 1, 0, 2, 2, 2), ('pack2.uss', 0, 1, 2, 0, 0),
            ('pack2.sss', 0, 1, 2, 2, 0), ('pack4.sss', 1, 0, 2, 2, 0),
            ('unpack1.h', 0, 0, 2, 0, 1), ('unpack2.h', 0, 1, 2, 0, 1), ('unpack4.h', 1, 0, 2, 0, 1),
            ('unpack1.l', 0, 0, 2, 2, 1), ('unpack2.l', 0, 1, 2, 2, 1), ('unpack4.l', 1, 0, 2, 2, 1),
            ('pmin1.u', 0, 0, 2, 1, 0), ('pmax1.u', 0, 0, 2, 1, 1), ('pmin2', 0, 1, 2, 3, 0),
            ('pmax2', 0, 1, 2, 3, 1), ('psad1', 0, 0, 2, 3, 2),
            ('pshl2', 0, 1, 0, 0, 1), ('pshl4', 1, 0, 0, 0, 1), ('mpy4', 1, 0, 0, 1, 3),
            ('mpyshl4', 1, 0, 0, 3, 3)]:
        sem = '@r1 = %s($r2, $r3);' % pcop(name)
        if name == 'mpy4':
            sem = '@r1 = zext($r2:4) * zext($r3:4);'
        elif name == 'mpyshl4':
            sem = '@r1 = (zext($r2:4) * zext($r3[32,32])) << 32;'
        mmi(name, za, zb, x2a, x2b, x2c, ['r1', 'r2', 'r3'], sem)
    mmi('shl', 1, 1, 0, 0, 1, ['r1', 'r2', 'r3'], '@r1 = $r2 << $r3;')
    mmi('mux1', 0, 0, 3, 2, 2, ['r1', 'r2', 'mbtype4'], '@r1 = mux1($r2, $mbtype4);')
    mmi('mux2', 0, 1, 3, 2, 2, ['r1', 'r2', 'mbtype8'], '@r1 = mux2($r2, $mbtype8);')
    for name, za, zb, x2b in (('pshr2', 0, 1, 2), ('pshr4', 1, 0, 2), ('pshr2.u', 0, 1, 0),
                              ('pshr4.u', 1, 0, 0)):
        mmi(name, za, zb, 0, x2b, 0, ['r1', 'r3', 'r2'], '@r1 = %s($r3, $r2);' % pcop(name))
        mmi(name, za, zb, 1, x2b | 1, 0, ['r1', 'r3', 'cnt5'], '@r1 = %s($r3, $cnt5);' % pcop(name))
    mmi('shr', 1, 1, 0, 2, 0, ['r1', 'r3', 'r2'], '@r1 = $r3 s>> $r2;')
    mmi('shr.u', 1, 1, 0, 0, 0, ['r1', 'r3', 'r2'], '@r1 = $r3 >> $r2;')
    mmi('pshl2', 0, 1, 3, 1, 1, ['r1', 'r2', 'ccnt5'], '@r1 = pshl2($r2, $ccnt5);')
    mmi('pshl4', 1, 0, 3, 1, 1, ['r1', 'r2', 'ccnt5'], '@r1 = pshl4($r2, $ccnt5);')
    mmi('popcnt', 0, 1, 1, 1, 2, ['r1', 'r3'], '@r1 = popcount($r3);')
    mmi('clz', 0, 1, 1, 1, 3, ['r1', 'r3'], '@r1 = lzcount($r3);')


# ======================================================================= M
LD_TYPES = [(0x00, ''), (0x04, '.s'), (0x08, '.a'), (0x0c, '.sa'), (0x10, '.bias'),
            (0x14, '.acq'), (0x20, '.c.clr'), (0x24, '.c.nc'), (0x28, '.c.clr.acq')]
SIZES = [(0, 1), (1, 2), (2, 4), (3, 8)]
# Load hint completers: (hint, hlfa) -> suffix for the no-update form; the
# update forms have only the 2-bit hint.
LD_HINT_M1 = {(0, 0): '', (1, 0): '.nt1', (2, 0): '.d2', (3, 0): '.nta', (0, 1): '.d4',
              (1, 1): '.d5', (2, 1): '.d6', (3, 1): '.d7'}
LD_HINT_UPD = {0: '', 1: '.nt1', 3: '.nta'}
ST_HINT_M4 = {(0, 0): '', (1, 0): '.d1', (2, 0): '.d2', (3, 0): '.nta', (0, 1): '.d4',
              (1, 1): '.d5', (2, 1): '.d6', (3, 1): '.d7'}
ST_HINT_UPD = {0: '', 3: '.nta'}
LF_HINT = {(0, 0): '', (1, 0): '.nt1', (2, 0): '.nt2', (3, 0): '.nta', (0, 1): '.d4',
           (1, 1): '.d5', (2, 1): '.d6', (3, 1): '.d7'}


def ld_sem(size, acq=False):
    s = '@r1 = zext(*:%d $r3);' % size if size < 8 else '@r1 = *:8 $r3;'
    return s


def build_m():
    m0 = C(op=0)
    E('M', 'chk.a.nc', {**m0, **C(x3=4)}, ['r1', 'tgt25c'], 0, 'local t:1 = chk_a($r1); if (t) goto $tgt25c;')
    E('M', 'chk.a.clr', {**m0, **C(x3=5)}, ['r1', 'tgt25c'], 0, 'local t:1 = chk_a($r1); if (t) goto $tgt25c;')
    E('M', 'chk.a.nc', {**m0, **C(x3=6)}, ['f1', 'tgt25c'], 0, 'local t:1 = chk_a($f1); if (t) goto $tgt25c;')
    E('M', 'chk.a.clr', {**m0, **C(x3=7)}, ['f1', 'tgt25c'], 0, 'local t:1 = chk_a($f1); if (t) goto $tgt25c;')
    sys0 = [('invala', 0, 1, [], 'invala();'), ('fwb', 0, 2, [], 'fwb();'),
            ('mf', 2, 2, [], 'mf();'), ('mf.a', 3, 2, [], 'mf_a();'),
            ('srlz.d', 0, 3, [], 'srlz_d();'), ('srlz.i', 1, 3, [], 'srlz_i();'),
            ('sync.i', 3, 3, [], 'sync_i();'), ('flushrs', 0xc, 0, [], 'flushrs();'),
            ('loadrs', 0xa, 0, [], 'loadrs();'), ('invala.e', 2, 1, ['r1'], 'invala_e($r1);'),
            ('invala.e', 3, 1, ['f1'], 'invala_e($f1);')]
    for name, x4, x2, ops, sem in sys0:
        flags = ('nopred',) if name in ('flushrs', 'loadrs') else ()
        E('M', name, {**m0, **C(x3=0, m_x4=x4, m_x2=x2)}, ops, 0, sem, flags=flags)
    E('M', 'mov.m', {**m0, **C(x3=0, m_x4=8, m_x2=2)}, ['ar3', 'imm8'], 1, '@ar3 = $imm8;')
    E('M', 'break.m', {**m0, **C(x3=0, m_x4=0, m_x2=0)}, ['immu21'], 0, 'break_insn($immu21);')
    E('M', 'nop.m', {**m0, **C(x3=0, m_x4=1, m_x2=0, y=0)}, ['immu21'], 0, '')
    E('M', 'hint.m', {**m0, **C(x3=0, m_x4=1, m_x2=0, y=1, z=0)}, ['immu19'], 0, 'hint($immu19);')
    E('M', 'mov', {**m0, **C(x3=0, m_x4=1, m_x2=0, y=1, z=1)}, ['dahr', 'immu16'], 1,
      '@dahr = $immu16;')
    E('M', 'sum', {**m0, **C(x3=0, m_x4=4)}, ['immu24'], 0, 'psr = psr | $immu24;')
    E('M', 'rum', {**m0, **C(x3=0, m_x4=5)}, ['immu24'], 0, 'psr = psr & ~$immu24;')
    E('M', 'ssm', {**m0, **C(x3=0, m_x4=6)}, ['immu24'], 0, 'psr = psr | $immu24;')
    E('M', 'rsm', {**m0, **C(x3=0, m_x4=7)}, ['immu24'], 0, 'psr = psr & ~$immu24;')
    m1 = {**C(op=1), **C(x3=0)}

    def mx(x6, name, ops, nout, sem):
        E('M', name, {**m1, **C(x6=x6)}, ops, nout, sem)
    mx(0x2a, 'mov.m', ['ar3', 'r2'], 1, '@ar3 = $r2;')
    mx(0x22, 'mov.m', ['r1', 'ar3'], 1, '@r1 = $ar3;')
    mx(0x2c, 'mov', ['cr3', 'r2'], 1, '@cr3 = $r2;')
    mx(0x24, 'mov', ['r1', 'cr3'], 1, '@r1 = $cr3;')
    E('M', 'alloc', {**C(op=1), **C(x3=6)}, ['r1', 'ar.pfs', 'sof', 'sol', 'sor'], 1,
      '@r1 = ar.pfs; alloc_frame($sof, $sol, $sor);', flags=('nopred', 'alloc'))
    mx(0x2d, 'mov', ['psr.l', 'r2'], 1, 'psr = (psr & 0xffffffff00000000) | zext($r2:4);')
    mx(0x29, 'mov', ['psr.um', 'r2'], 1, 'psr = (psr & ~0x3f) | ($r2 & 0x3f);')
    mx(0x25, 'mov', ['r1', 'psr'], 1, '@r1 = psr;')
    mx(0x21, 'mov', ['r1', 'psr.um'], 1, '@r1 = psr & 0x3f;')
    mx(0x38, 'probe.r', ['r1', 'r3', 'r2'], 1, '@r1 = probe_r($r3, $r2);')
    mx(0x39, 'probe.w', ['r1', 'r3', 'r2'], 1, '@r1 = probe_w($r3, $r2);')
    mx(0x18, 'probe.r', ['r1', 'r3', 'immu2'], 1, '@r1 = probe_r($r3, $immu2);')
    mx(0x19, 'probe.w', ['r1', 'r3', 'immu2'], 1, '@r1 = probe_w($r3, $immu2);')
    mx(0x31, 'probe.rw.fault', ['r3', 'immu2'], 0, 'probe_fault($r3, $immu2);')
    mx(0x32, 'probe.r.fault', ['r3', 'immu2'], 0, 'probe_fault($r3, $immu2);')
    mx(0x33, 'probe.w.fault', ['r3', 'immu2'], 0, 'probe_fault($r3, $immu2);')
    mx(0x2e, 'itc.d', ['r2'], 0, 'itc_d($r2);')
    mx(0x2f, 'itc.i', ['r2'], 0, 'itc_i($r2);')
    for x6, space in ((0, 'rr'), (1, 'dbr'), (2, 'ibr'), (3, 'pkr'), (4, 'pmc'), (5, 'pmd'),
                      (6, 'msr')):
        mx(x6, 'mov', [space + '_r3', 'r2'], 1, '*[%s]:8 $r3 = $r2;' % space)
    mx(0x0e, 'itr.d', ['dtr_r3', 'r2'], 1, 'itr_d($r3, $r2);')
    mx(0x0f, 'itr.i', ['itr_r3', 'r2'], 1, 'itr_i($r3, $r2);')
    for x6, space in ((0x10, 'rr'), (0x11, 'dbr'), (0x12, 'ibr'), (0x13, 'pkr'), (0x14, 'pmc'),
                      (0x15, 'pmd'), (0x16, 'msr'), (0x17, 'cpuid'), (0x20, 'dahr')):
        mx(x6, 'mov', ['r1', space + '_r3'], 1, '@r1 = *[%s]:8 $r3;' % space)
    for x6, name in ((0x09, 'ptc.l'), (0x0a, 'ptc.g'), (0x0b, 'ptc.ga'), (0x0c, 'ptr.d'),
                     (0x0d, 'ptr.i')):
        mx(x6, name, ['r3', 'r2'], 0, '%s($r3, $r2);' % pcop(name))
    for x6, name in ((0x1a, 'thash'), (0x1b, 'ttag'), (0x1e, 'tpa'), (0x1f, 'tak')):
        mx(x6, name, ['r1', 'r3'], 1, '@r1 = %s($r3);' % name)
    E('M', 'chk.s.m', {**C(op=1), **C(x3=1)}, ['r2', 'tgt25b'], 0,
      'local t:1 = nat($r2); if (t) goto $tgt25b;')
    E('M', 'chk.s', {**C(op=1), **C(x3=3)}, ['f2', 'tgt25b'], 0,
      'local t:1 = nat($f2); if (t) goto $tgt25b;')
    E('M', 'fc', {**m1, **C(x6=0x30, m=0)}, ['r3'], 0, 'fc($r3);')
    E('M', 'fc.i', {**m1, **C(x6=0x30, m=1)}, ['r3'], 0, 'fc_i($r3);')
    mx(0x34, 'ptc.e', ['r3'], 0, 'ptc_e($r3);')

    # Integer loads and stores (M1-M5) and the semaphores (M16, M17).
    for base, sz in SIZES:
        for t, tn in LD_TYPES:
            x6 = t + base
            nm = 'ld%d%s' % (sz, tn)
            load = 'local v:%d = *:%d $r3; @r1 = zext(v);' % (sz, sz) if sz < 8 else '@r1 = *:8 $r3;'
            E('M', nm, C(op=4, m=0, mx=0, x6a=x6), ['r1', 'mr3'], 1, load, comp='ldh')
            for h, hs in LD_HINT_UPD.items():
                E('M', nm + hs, C(op=4, m=1, mx=0, x6a=x6, hint=h), ['r1', 'mr3', 'r2'], 1,
                  load + ' @r3 = $r3 + $r2;')
                E('M', nm + hs, C(op=5, x6a=x6, hint=h), ['r1', 'mr3', 'imm9b'], 1,
                  load + ' @r3 = $r3 + $imm9b;')
    E('M', 'ld8.fill', C(op=4, m=0, mx=0, x6a=0x1b), ['r1', 'mr3'], 1, '@r1 = *:8 $r3;', comp='ldh')
    for h, hs in LD_HINT_UPD.items():
        E('M', 'ld8.fill' + hs, C(op=4, m=1, mx=0, x6a=0x1b, hint=h), ['r1', 'mr3', 'r2'], 1,
          '@r1 = *:8 $r3; @r3 = $r3 + $r2;')
        E('M', 'ld8.fill' + hs, C(op=5, x6a=0x1b, hint=h), ['r1', 'mr3', 'imm9b'], 1,
          '@r1 = *:8 $r3; @r3 = $r3 + $imm9b;')
    for x6, tn in ((0x28, ''), (0x2c, '.acq')):
        E('M', 'ld16' + tn, C(op=4, m=0, mx=1, x6a=x6), ['r1', 'ar.csd', 'mr3'], 2,
          '@r1 = *:8 $r3; ar.csd = *:8 ($r3 + 8);', comp='ldh')
    stores = [(0x30, ''), (0x34, '.rel')]
    for base, sz in SIZES:
        for t, tn in stores:
            st = '*:%d $r3 = $r2:%d;' % (sz, sz) if sz < 8 else '*:8 $r3 = $r2;'
            E('M', 'st%d%s' % (sz, tn), C(op=4, m=0, mx=0, x6a=t + base), ['mr3', 'r2'], 1, st,
              comp='sth')
            for h, hs in ST_HINT_UPD.items():
                E('M', 'st%d%s%s' % (sz, tn, hs), C(op=5, x6a=t + base, hint=h),
                  ['mr3', 'r2', 'imm9a'], 1, st + ' @r3 = $r3 + $imm9a;')
    E('M', 'st8.spill', C(op=4, m=0, mx=0, x6a=0x3b), ['mr3', 'r2'], 1, '*:8 $r3 = $r2;', comp='sth')
    for x6, tn in ((0x30, ''), (0x34, '.rel')):
        E('M', 'st16' + tn, C(op=4, m=0, mx=1, x6a=x6), ['mr3', 'r2', 'ar.csd'], 1,
          '*:8 $r3 = $r2; *:8 ($r3 + 8) = ar.csd;', comp='sth')
    for h, hs in ST_HINT_UPD.items():
        E('M', 'st8.spill' + hs, C(op=5, x6a=0x3b, hint=h), ['mr3', 'r2', 'imm9a'], 1,
          '*:8 $r3 = $r2; @r3 = $r3 + $imm9a;')
    # Semaphores (M16, M17) and getf (M19).
    for base, sz in SIZES:
        for t, tn in ((0x00, '.acq'), (0x04, '.rel')):
            for h, hs in LD_HINT_UPD.items():
                E('M', 'cmpxchg%d%s%s' % (sz, tn, hs), C(op=4, m=0, mx=1, x6a=t + base, hint=h),
                  ['r1', 'mr3', 'r2', 'ar.ccv'], 1,
                  'local old:%d = *:%d $r3; if (old != ar.ccv:%d) goto <skip>; *:%d $r3 = $r2:%d; '
                  '<skip> @r1 = zext(old);' % ((sz,) * 5) if sz < 8 else
                  'local old:8 = *:8 $r3; if (old != ar.ccv) goto <skip>; *:8 $r3 = $r2; '
                  '<skip> @r1 = old;')
    for t, tn in ((0x20, '.acq'), (0x24, '.rel')):
        for h, hs in LD_HINT_UPD.items():
            E('M', 'cmp8xchg16' + tn + hs, C(op=4, m=0, mx=1, x6a=t, hint=h),
              ['r1', 'mr3', 'r2', 'ar.csd', 'ar.ccv'], 1,
              'local old:8 = *:8 $r3; if (old != ar.ccv) goto <skip>; *:8 $r3 = $r2; '
              '*:8 ($r3 + 8) = ar.csd; <skip> @r1 = old;')
    for base, sz in SIZES:
        for h, hs in LD_HINT_UPD.items():
            E('M', 'xchg%d%s' % (sz, hs), C(op=4, m=0, mx=1, x6a=0x08 + base, hint=h),
              ['r1', 'mr3', 'r2'], 1,
              ('local old:%d = *:%d $r3; *:%d $r3 = $r2:%d; @r1 = zext(old);' % ((sz,) * 4))
              if sz < 8 else 'local old:8 = *:8 $r3; *:8 $r3 = $r2; @r1 = old;')
    for x6, nm, sz in ((0x12, 'fetchadd4.acq', 4), (0x13, 'fetchadd8.acq', 8),
                       (0x16, 'fetchadd4.rel', 4), (0x17, 'fetchadd8.rel', 8)):
        for h, hs in LD_HINT_UPD.items():
            E('M', nm + hs, C(op=4, m=0, mx=1, x6a=x6, hint=h), ['r1', 'mr3', 'inc3'], 1,
              ('local old:4 = *:4 $r3; *:4 $r3 = old + $inc3:4; @r1 = zext(old);' if sz == 4 else
               'local old:8 = *:8 $r3; *:8 $r3 = old + $inc3; @r1 = old;'))
    for x6, nm, sem in ((0x1c, 'getf.sig', '@r1 = $f2;'), (0x1d, 'getf.exp', '@r1 = getf_exp($f2);'),
                        (0x1e, 'getf.s', 'local t:4 = float2float($f2); @r1 = zext(t);'),
                        (0x1f, 'getf.d', '@r1 = $f2;')):
        E('M', nm, C(op=4, m=0, mx=1, x6a=x6), ['r1', 'f2'], 1, sem)

    # Floating-point loads and stores (M6-M13), setf (M18), lfetch.
    fl = [(0x02, 'ldfs', 4), (0x03, 'ldfd', 8), (0x01, 'ldf8', 8), (0x00, 'ldfe', 10)]
    ftypes = [(0x00, ''), (0x04, '.s'), (0x08, '.a'), (0x0c, '.sa'), (0x20, '.c.clr'),
              (0x24, '.c.nc')]

    def fload(sz):
        if sz == 4:
            return '@f1 = float2float(*:4 $r3);'
        if sz == 10:
            return '@f1 = float2float(*:10 $r3);'
        return '@f1 = *:8 $r3;'
    for base, nm, sz in fl:
        for t, tn in ftypes:
            E('M', nm + tn, C(op=6, m=0, mx=0, x6a=t + base), ['f1', 'mr3'], 1, fload(sz), comp='ldh')
            for h, hs in LD_HINT_UPD.items():
                E('M', nm + tn + hs, C(op=6, m=1, mx=0, x6a=t + base, hint=h), ['f1', 'mr3', 'r2'], 1,
                  fload(sz) + ' @r3 = $r3 + $r2;')
                E('M', nm + tn + hs, C(op=7, x6a=t + base, hint=h), ['f1', 'mr3', 'imm9b'], 1,
                  fload(sz) + ' @r3 = $r3 + $imm9b;')
    E('M', 'ldf.fill', C(op=6, m=0, mx=0, x6a=0x1b), ['f1', 'mr3'], 1, '@f1 = *:8 $r3;', comp='ldh')
    for h, hs in LD_HINT_UPD.items():
        E('M', 'ldf.fill' + hs, C(op=6, m=1, mx=0, x6a=0x1b, hint=h), ['f1', 'mr3', 'r2'], 1,
          '@f1 = *:8 $r3; @r3 = $r3 + $r2;')
        E('M', 'ldf.fill' + hs, C(op=7, x6a=0x1b, hint=h), ['f1', 'mr3', 'imm9b'], 1,
          '@f1 = *:8 $r3; @r3 = $r3 + $imm9b;')
    fs = [(0x32, 'stfs', 4), (0x33, 'stfd', 8), (0x31, 'stf8', 8), (0x30, 'stfe', 10),
          (0x3b, 'stf.spill', 8)]

    def fstore(sz):
        if sz in (4, 10):
            return '*:%d $r3 = float2float($f2);' % sz
        return '*:8 $r3 = $f2;'
    for x6, nm, sz in fs:
        E('M', nm, C(op=6, m=0, mx=0, x6a=x6), ['mr3', 'f2'], 1, fstore(sz), comp='sth')
        for h, hs in ST_HINT_UPD.items():
            E('M', nm + hs, C(op=7, x6a=x6, hint=h), ['mr3', 'f2', 'imm9a'], 1,
              fstore(sz) + ' @r3 = $r3 + $imm9a;')
    # Load pair (M11, M12).
    fp = [(0x02, 'ldfps', 4), (0x03, 'ldfpd', 8), (0x01, 'ldfp8', 8)]
    fptypes = [(0x00, ''), (0x04, '.s'), (0x08, '.a'), (0x0c, '.sa'), (0x20, '.c.clr'),
               (0x24, '.c.nc')]
    for base, nm, sz in fp:
        for t, tn in fptypes:
            if sz == 4:
                pair = '@f1 = float2float(*:4 $r3); @f2 = float2float(*:4 ($r3 + 4));'
            else:
                pair = '@f1 = *:8 $r3; @f2 = *:8 ($r3 + 8);'
            for h, hs in LD_HINT_UPD.items():
                E('M', nm + tn + hs, C(op=6, m=0, mx=1, x6a=t + base, hint=h), ['f1', 'f2', 'mr3'], 2,
                  pair)
                E('M', nm + tn + hs, C(op=6, m=1, mx=1, x6a=t + base, hint=h),
                  ['f1', 'f2', 'mr3', str(2 * sz)], 2,
                  pair + ' @r3 = $r3 + %d;' % (2 * sz))
    for x6, nm, sem in ((0x1c, 'setf.sig', '@f1 = $r2;'), (0x1d, 'setf.exp', '@f1 = setf_exp($r2);'),
                        (0x1e, 'setf.s', '@f1 = float2float($r2:4);'), (0x1f, 'setf.d', '@f1 = $r2;')):
        E('M', nm, C(op=6, m=0, mx=1, x6a=x6), ['f1', 'r2'], 1, sem)
    lf = [(0x2c, 'lfetch'), (0x2d, 'lfetch.excl'), (0x2e, 'lfetch.fault'), (0x2f, 'lfetch.fault.excl')]
    for x6, nm in lf:
        extra = C(y1=0) if x6 == 0x2c else {}
        E('M', nm, {**C(op=6, m=0, mx=0, x6a=x6), **extra}, ['mr3'], 0, 'lfetch($r3);', comp='lfh')
        E('M', nm, C(op=6, m=1, mx=0, x6a=x6), ['mr3', 'r2'], 0, 'lfetch($r3); @r3 = $r3 + $r2;',
          comp='lfh')
        E('M', nm, C(op=7, x6a=x6), ['mr3', 'imm9b'], 0, 'lfetch($r3); @r3 = $r3 + $imm9b;', comp='lfh')
    E('M', 'lfetch.count', C(op=6, m=0, mx=0, x6a=0x2c, y1=1), ['mr3', 'cnt6a', 'strd5b'], 0,
      'lfetch($r3);', comp='lfh')


# ======================================================================= B
PH = {0: '.sptk', 1: '.spnt', 2: '.dptk', 3: '.dpnt'}
PHC = {1: '.sptk', 3: '.spnt', 5: '.dptk', 7: '.dpnt'}


def build_b():
    def bh(unit, base, cons, ops, sem, flags=(), whf='wha', whmap=PH):
        nout = 1 if ops[0] == 'b1' else 0
        for wh, whs in whmap.items():
            for d, ds in ((0, ''), (1, '.clr')):
                for p, ps in ((0, '.few'), (1, '.many')):
                    E(unit, base + whs + ps + ds, {**cons, **C(**{whf: wh}), **C(d=d, pa=p)}, ops,
                      nout, sem, flags)
    b0 = C(op=0)
    bh('B', 'br.cond', {**b0, **C(x6=0x20, btype=0)}, ['b2'], 'goto [$b2];')
    E('B', 'br.few', {**b0, **C(x6=0x20, btype=0, pa=0, wha=0, d=0, qp=0)}, ['b2'], 0, 'goto [$b2];')
    E('B', 'br.few.clr', {**b0, **C(x6=0x20, btype=0, pa=0, wha=0, d=1, qp=0)}, ['b2'], 0,
      'goto [$b2];')
    E('B', 'br.many', {**b0, **C(x6=0x20, btype=0, pa=1, wha=0, d=0, qp=0)}, ['b2'], 0, 'goto [$b2];')
    E('B', 'br.many.clr', {**b0, **C(x6=0x20, btype=0, pa=1, wha=0, d=1, qp=0)}, ['b2'], 0,
      'goto [$b2];')
    bh('B', 'br.ia', {**b0, **C(x6=0x20, btype=1)}, ['b2'], 'br_ia($b2); goto [$b2];')
    bh('B', 'br.ret', {**b0, **C(x6=0x21, btype=4)}, ['b2'], 'return [$b2];')
    for x6, nm, sem in ((0x02, 'cover', 'cover();'), (0x04, 'clrrrb', 'clrrrb();'),
                        (0x05, 'clrrrb.pr', 'clrrrb_pr();'), (0x08, 'rfi', 'rfi();'),
                        (0x0c, 'bsw.0', 'bsw_0();'), (0x0d, 'bsw.1', 'bsw_1();'),
                        (0x10, 'epc', 'epc();'), (0x18, 'vmsw.0', 'vmsw_0();'),
                        (0x19, 'vmsw.1', 'vmsw_1();')):
        E('B', nm, {**b0, **C(x6=x6)}, [], 0, sem, flags=('nopred',) + (('rfi',) if nm == 'rfi' else ()))
    E('B', 'break.b', {**b0, **C(x6=0)}, ['immu21'], 0, 'break_insn($immu21);')
    bh('B', 'br.call', {**C(op=1)}, ['b1', 'b2'], 'CALLIND', whf='whc', whmap=PHC)
    for x6, nm in ((0x10, 'brp'), (0x11, 'brp.ret')):
        for ih, ihs in ((0, ''), (1, '.imp')):
            for wh, whs in ((0, '.sptk'), (2, '.dptk')):
                E('B', nm + whs + ihs, {**C(op=2, x6=x6, b_ih=ih, whb=wh)}, ['b2', 'tag13'], 0, '',
                  flags=('nopred',))
    E('B', 'nop.b', C(op=2, x6=0), ['immu21'], 0, '')
    E('B', 'hint.b', C(op=2, x6=1), ['immu21'], 0, 'hint($immu21);')
    bh('B', 'br.cond', C(op=4, btype=0), ['tgt25c'], 'goto $tgt25c;')
    for p, ps in ((0, '.few'), (1, '.many')):
        for d, ds in ((0, ''), (1, '.clr')):
            E('B', 'br' + ps + ds, C(op=4, btype=0, pa=p, wha=0, d=d, qp=0), ['tgt25c'], 0,
              'goto $tgt25c;')
    bh('B', 'br.wexit', C(op=4, btype=2), ['tgt25c'], 'WEXIT', flags=('qpcustom',))
    bh('B', 'br.wtop', C(op=4, btype=3), ['tgt25c'], 'WTOP', flags=('qpcustom',))
    bh('B', 'br.cloop', C(op=4, btype=5), ['tgt25c'],
       'if (ar.lc == 0) goto inst_next; ar.lc = ar.lc - 1; goto $tgt25c;', flags=('nopred',))
    bh('B', 'br.cexit', C(op=4, btype=6), ['tgt25c'], 'CEXIT', flags=('nopred',))
    bh('B', 'br.ctop', C(op=4, btype=7), ['tgt25c'], 'CTOP', flags=('nopred',))
    bh('B', 'br.call', C(op=5), ['b1', 'tgt25c'], 'CALL')
    for ih, ihs in ((0, ''), (1, '.imp')):
        for wh, whs in ((0, '.sptk'), (1, '.loop'), (2, '.dptk'), (3, '.exit')):
            E('B', 'brp' + whs + ihs, C(op=7, b_ih=ih, whb=wh), ['tgt25c', 'tag13'], 0, '',
              flags=('nopred',))


# ======================================================================= F
SF = {0: '.s0', 1: '.s1', 2: '.s2', 3: '.s3'}


def build_f():
    def fsf(name, cons, ops, nout, sem, flags=()):
        E('F', name, cons, ops, nout, sem, flags, comp='sf')
    f0 = C(op=0)
    f1 = C(op=1)
    fsf('frcpa', {**f0, **C(f_xb=1, q=0)}, ['f1', 'p2', 'f2', 'f3'], 2,
        '@f1 = frcpa($f2, $f3); @p2 = frcpa_ok($f2, $f3);')
    fsf('frsqrta', {**f0, **C(f_xb=1, q=1)}, ['f1', 'p2', 'f3'], 2,
        '@f1 = frsqrta($f3); @p2 = frsqrta_ok($f3);')
    fsf('fprcpa', {**f1, **C(f_xb=1, q=0)}, ['f1', 'p2', 'f2', 'f3'], 2,
        '@f1 = fprcpa($f2, $f3); @p2 = frcpa_ok($f2, $f3);')
    fsf('fprsqrta', {**f1, **C(f_xb=1, q=1)}, ['f1', 'p2', 'f3'], 2,
        '@f1 = fprsqrta($f3); @p2 = frsqrta_ok($f3);')
    for x6, nm, sem in ((0x14, 'fmin', '@f1 = fmin($f2, $f3);'), (0x15, 'fmax', '@f1 = fmax($f2, $f3);'),
                        (0x16, 'famin', '@f1 = famin($f2, $f3);'), (0x17, 'famax', '@f1 = famax($f2, $f3);')):
        fsf(nm, {**f0, **C(f_xb=0, x6=x6)}, ['f1', 'f2', 'f3'], 1, sem)
        fsf('fp' + nm[1:], {**f1, **C(f_xb=0, x6=x6)}, ['f1', 'f2', 'f3'], 1,
            sem.replace('= f', '= fp'))
    # fmerge and its pseudo-ops (F9). mov/fneg need f2 == f3; fabs/fnegabs f2 = 0.
    E('F', 'fmerge.s', {**f0, **C(f_xb=0, x6=0x10)}, ['f1', 'f2', 'f3'], 1, '@f1 = fmerge_s($f2, $f3);')
    E('F', 'fmerge.ns', {**f0, **C(f_xb=0, x6=0x11)}, ['f1', 'f2', 'f3'], 1, '@f1 = fmerge_ns($f2, $f3);')
    E('F', 'mov', {**f0, **C(f_xb=0, x6=0x10)}, ['f1', 'f3'], 1, '@f1 = $f3;', flags=('f2eqf3',))
    E('F', 'fneg', {**f0, **C(f_xb=0, x6=0x11)}, ['f1', 'f3'], 1, '@f1 = f- $f3;', flags=('f2eqf3',))
    E('F', 'fabs', {**f0, **C(f_xb=0, x6=0x10, f2=0)}, ['f1', 'f3'], 1, '@f1 = abs($f3);')
    E('F', 'fnegabs', {**f0, **C(f_xb=0, x6=0x11, f2=0)}, ['f1', 'f3'], 1, '@f1 = f- abs($f3);')
    E('F', 'fpmerge.s', {**f1, **C(f_xb=0, x6=0x10)}, ['f1', 'f2', 'f3'], 1, '@f1 = fpmerge_s($f2, $f3);')
    E('F', 'fpmerge.ns', {**f1, **C(f_xb=0, x6=0x11)}, ['f1', 'f2', 'f3'], 1, '@f1 = fpmerge_ns($f2, $f3);')
    E('F', 'fpneg', {**f1, **C(f_xb=0, x6=0x11)}, ['f1', 'f3'], 1, '@f1 = fpneg($f3);', flags=('f2eqf3',))
    E('F', 'fpabs', {**f1, **C(f_xb=0, x6=0x10, f2=0)}, ['f1', 'f3'], 1, '@f1 = fpabs($f3);')
    E('F', 'fpnegabs', {**f1, **C(f_xb=0, x6=0x11, f2=0)}, ['f1', 'f3'], 1, '@f1 = fpnegabs($f3);')
    for x6, nm in ((0x12, 'fmerge.se'), (0x39, 'fmix.lr'), (0x3a, 'fmix.r'), (0x3b, 'fmix.l'),
                   (0x3c, 'fsxt.r'), (0x3d, 'fsxt.l'), (0x28, 'fpack'), (0x34, 'fswap'),
                   (0x35, 'fswap.nl'), (0x36, 'fswap.nr')):
        E('F', nm, {**f0, **C(f_xb=0, x6=x6)}, ['f1', 'f2', 'f3'], 1, '@f1 = %s($f2, $f3);' % pcop(nm))
    E('F', 'fpmerge.se', {**f1, **C(f_xb=0, x6=0x12)}, ['f1', 'f2', 'f3'], 1, '@f1 = fpmerge_se($f2, $f3);')
    for x6, nm, op in ((0x2c, 'fand', '&'), (0x2d, 'fandcm', '& ~'), (0x2e, 'for', '|'), (0x2f, 'fxor', '^')):
        E('F', nm, {**f0, **C(f_xb=0, x6=x6)}, ['f1', 'f2', 'f3'], 1, '@f1 = $f2 %s $f3;' % op)
    for x6, nm, sem in ((0x18, 'fcvt.fx', '@f1 = trunc(round($f2));'),
                        (0x19, 'fcvt.fxu', '@f1 = trunc(round($f2));'),
                        (0x1a, 'fcvt.fx.trunc', '@f1 = trunc($f2);'),
                        (0x1b, 'fcvt.fxu.trunc', '@f1 = trunc($f2);')):
        fsf(nm, {**f0, **C(f_xb=0, x6=x6)}, ['f1', 'f2'], 1, sem)
        fsf('fp' + nm[1:], {**f1, **C(f_xb=0, x6=x6)}, ['f1', 'f2'], 1,
            '@f1 = %s($f2);' % pcop('fp' + nm[1:]))
    E('F', 'fcvt.xf', {**f0, **C(f_xb=0, x6=0x1c)}, ['f1', 'f2'], 1, '@f1 = int2float($f2);')
    fsf('fsetc', {**f0, **C(f_xb=0, x6=0x04)}, ['immu7a', 'immu7b'], 0, 'fsetc($immu7a, $immu7b);')
    fsf('fclrf', {**f0, **C(f_xb=0, x6=0x05)}, [], 0, 'fclrf();')
    fsf('fchkf', {**f0, **C(f_xb=0, x6=0x08)}, ['tgt25'], 0, 'local t:1 = fchkf(); if (t) goto $tgt25;')
    E('F', 'break.f', {**f0, **C(f_xb=0, x6=0)}, ['immu21'], 0, 'break_insn($immu21);')
    E('F', 'nop.f', {**f0, **C(f_xb=0, x6=1, f_y=0)}, ['immu21'], 0, '')
    E('F', 'hint.f', {**f0, **C(f_xb=0, x6=1, f_y=1)}, ['immu21'], 0, 'hint($immu21);')
    for x6, nm in ((0x30, 'eq'), (0x31, 'lt'), (0x32, 'le'), (0x33, 'unord'), (0x34, 'neq'),
                   (0x35, 'nlt'), (0x36, 'nle'), (0x37, 'ord')):
        fsf('fpcmp.' + nm, {**f1, **C(f_xb=0, x6=x6)}, ['f1', 'f2', 'f3'], 1,
            '@f1 = fpcmp_%s($f2, $f3);' % nm)
    # fcmp (F4)
    fc = {(0, 0): ('eq', 'f=='), (0, 1): ('lt', 'f<'), (1, 0): ('le', 'f<='), (1, 1): ('unord', 'nan')}
    for (ra, rb), (nm, op) in fc.items():
        for ta, unc in ((0, ''), (1, '.unc')):
            cond = 'nan($f2) || nan($f3)' if op == 'nan' else '$f2 %s $f3' % op
            fsf('fcmp.%s%s' % (nm, unc), C(op=4, ra=ra, rb=rb, f_ta=ta), ['p1', 'p2', 'f2', 'f3'], 2,
                cmp_sem('unc' if ta else 'none', cond), flags=('qpcustom',) if ta else ())
    E('F', 'fclass.m', C(op=5, f_ta=0), ['p1', 'p2', 'f2', 'immu9'], 2,
      cmp_sem('none', 'fclass($f2, $immu9)'))
    E('F', 'fclass.m.unc', C(op=5, f_ta=1), ['p1', 'p2', 'f2', 'immu9'], 2,
      cmp_sem('unc', 'fclass($f2, $immu9)'), flags=('qpcustom',))
    # fma family (F1). The F2 = f0 and F4 = f1 forms print as fmpy and fadd,
    # and both zero as fnorm.
    fma = [(0x8, 0, 'fma', '.s', 'fnorm', 'fadd', 'fmpy'), (0x9, 0, 'fma.d', None, 'fnorm.d', 'fadd.d', 'fmpy.d'),
           (0x9, 1, 'fpma', None, None, None, 'fpmpy'), (0xa, 0, 'fms', '.s', None, 'fsub', None),
           (0xb, 0, 'fms.d', None, None, 'fsub.d', None), (0xb, 1, 'fpms', None, None, None, None),
           (0xc, 0, 'fnma', '.s', None, None, 'fnmpy'), (0xd, 0, 'fnma.d', None, None, None, 'fnmpy.d'),
           (0xd, 1, 'fpnma', None, None, None, 'fpnmpy')]
    for op, xa, nm, single, norm, add, mpy in fma:
        variants = [(xa, nm, norm, add, mpy)]
        if single:
            variants.append((1, nm + single, norm and norm + '.s', add and add + '.s', mpy and mpy + '.s'))
        for xav, n, nrm, ad, mp in variants:
            neg = 'f- ' if 'nma' in n else ''
            sub = '-' if n.startswith('fms') else '+'
            if n.startswith('fp'):
                body = '@f1 = %s($f3, $f4, $f2);' % pcop(n)
            else:
                body = '@f1 = %s($f3 f* $f4) f%s $f2;' % (neg, sub)
                if neg:
                    body = '@f1 = (f- ($f3 f* $f4)) f%s $f2;' % sub
            fsf(n, C(op=op, xa=xav), ['f1', 'f3', 'f4', 'f2'], 1, body)
            if mp:
                fsf(mp, {**C(op=op, xa=xav), **C(f2=0)}, ['f1', 'f3', 'f4'], 1,
                    ('@f1 = %s($f3, $f4);' % pcop(mp)) if mp.startswith('fp') else
                    ('@f1 = %s($f3 f* $f4);' % ('f- ' if 'nm' in mp else '')))
            if ad:
                fsf(ad, {**C(op=op, xa=xav), **C(f4=1)}, ['f1', 'f3', 'f2'], 1,
                    '@f1 = $f3 f%s $f2;' % sub)
            if nrm:
                fsf(nrm, {**C(op=op, xa=xav), **C(f4=1, f2=0)}, ['f1', 'f3'], 1, '@f1 = $f3;')
    # xma (F2) and fselect (F3); xmpy is xma with f2 = f0.
    for x2, nm, mp, sem in ((0, 'xma.l', 'xmpy.l', '$f3 * $f4'), (3, 'xma.h', 'xmpy.h', 'xma_h($f3, $f4)'),
                            (2, 'xma.hu', 'xmpy.hu', 'xma_hu($f3, $f4)')):
        E('F', nm, C(op=0xe, xa=1, f_x2=x2), ['f1', 'f3', 'f4', 'f2'], 1, '@f1 = %s + $f2;' % sem)
        E('F', mp, {**C(op=0xe, xa=1, f_x2=x2), **C(f2=0)}, ['f1', 'f3', 'f4'], 1, '@f1 = %s;' % sem)
    E('F', 'fselect', C(op=0xe, xa=0), ['f1', 'f3', 'f4', 'f2'], 1,
      '@f1 = ($f3 & $f2) | ($f4 & ~$f2);')


# ======================================================================= X
def build_x():
    E('X', 'break.x', C(op=0, x3=0, x6=0), ['immu62'], 0, 'break_insn($immu62);')
    E('X', 'nop.x', C(op=0, x3=0, x6=1, y=0), ['immu62'], 0, '')
    E('X', 'hint.x', C(op=0, x3=0, x6=1, y=1), ['immu62'], 0, 'hint($immu62);')
    E('X', 'movl', C(op=6, vc=0), ['r1', 'immu64'], 1, '@r1 = $immu64;')
    for wh, whs in PH.items():
        for p, ps in ((0, '.few'), (1, '.many')):
            for d, ds in ((0, ''), (1, '.clr')):
                E('X', 'brl.cond' + whs + ps + ds, C(op=0xc, btype=0, pa=p, wha=wh, d=d), ['tgt64'],
                  0, 'goto $tgt64;')
                E('X', 'brl.call' + whs + ps + ds, C(op=0xd, pa=p, wha=wh, d=d), ['b1', 'tgt64'], 1,
                  'CALL')
    for p, ps in ((0, '.few'), (1, '.many')):
        for d, ds in ((0, ''), (1, '.clr')):
            E('X', 'brl' + ps + ds, C(op=0xc, btype=0, pa=p, wha=0, d=d, qp=0), ['tgt64'], 0,
              'goto $tgt64;')


build_a()
build_i()
build_m()
build_b()
build_f()
build_x()

# Unit membership: A-unit entries run in both M and I slots.
UNIT_ENTRIES = {
    'M': [e for e in ENTRIES if e.unit in ('M', 'A')],
    'I': [e for e in ENTRIES if e.unit in ('I', 'A')],
    'F': [e for e in ENTRIES if e.unit == 'F'],
    'B': [e for e in ENTRIES if e.unit == 'B'],
    'X': [e for e in ENTRIES if e.unit == 'X'],
}


def expand_pseudo(e):
    """Pseudo-ops that depend on two fields agreeing, as plain encodings: the
    shift forms of extr/dep.z need len = 64 - pos, the fmerge moves f2 = f3."""
    out = []
    if 'shr_u' in e.flags or 'shr' in e.flags:
        for pos in range(64):
            out.append(Entry(e.unit, 'shr.u' if 'shr_u' in e.flags else 'shr',
                             {**e.cons, (14, 6): pos, (27, 6): 63 - pos}, ['r1', 'r3', 'pos6'], 1,
                             '@r1 = $r3 %s $pos6;' % ('>>' if 'shr_u' in e.flags else 's>>')))
    if 'shl' in e.flags:
        for pos in range(64):
            out.append(Entry(e.unit, 'shl', {**e.cons, (20, 6): 63 - pos, (27, 6): 63 - pos},
                             ['r1', 'r2', 'cpos6a'], 1, '@r1 = $r2 << $cpos6a;'))
    return out


# Completers that pick a mnemonic suffix from more fields: fields, then
# {field values: suffix}. Every combination is an encoding.
COMPLETERS = {
    'ldh': ([FIELD['hint'], FIELD['hlfa']], LD_HINT_M1),
    'sth': ([FIELD['hint'], FIELD['hlf']], ST_HINT_M4),
    'lfh': ([FIELD['hint'], FIELD['hlf']], LF_HINT),
    'sf': ([FIELD['sf']], {(k,): v for k, v in SF.items()}),
}


def expand_completer(e):
    fields, table = COMPLETERS[e.comp]
    return [Entry(e.unit, e.name + suffix, {**e.cons, **dict(zip(fields, vals))}, e.ops, e.nout,
                  e.sem, e.flags) for vals, suffix in table.items()]


def entries(unit, completers=True):
    """The unit's encodings with the pseudo-ops spelled out; completers=False
    keeps a completer entry as one (the generator makes it a subtable)."""
    res = []
    for e in UNIT_ENTRIES[unit]:
        if e.comp and completers:
            res.extend(expand_completer(e))
            continue
        if 'f2eqf3' in e.flags:
            for r in range(128):
                res.append(Entry(e.unit, e.name, {**e.cons, (13, 7): r, (20, 7): r}, e.ops, e.nout,
                                 e.sem, e.flags - {'f2eqf3'}))
            continue
        res.append(e)
        res.extend(expand_pseudo(e))
    return res


_CACHE = {}


def unit_table(unit):
    if unit not in _CACHE:
        tab = entries(unit)
        idx = {}
        for e in tab:
            idx.setdefault(e.cons.get(OP), []).append(e)
        _CACHE[unit] = idx
    return _CACHE[unit]


def more_specific(a, b):
    """a's constraints include b's (so SLEIGH picks a over b)."""
    ma, va = a.mask_value()
    mb, vb = b.mask_value()
    return (ma & mb) == mb and (va & mb) == vb and ma != mb


def lookup(unit, slot):
    cands = [e for e in unit_table(unit).get(bits(slot, *OP), []) if e.matches(slot)]
    if not cands:
        return None
    best = [e for e in cands if not any(more_specific(o, e) for o in cands if o is not e)]
    if len(best) != 1:
        raise ValueError('ambiguous %s slot %#x: %s' % (unit, slot, [e.name for e in best]))
    return best[0]


# --------------------------------------------------------- reference decoder
def fmt_operand(op, slot, addr, lslot):
    spec = OPERANDS.get(op)
    if spec is None:
        return op              # a literal such as '1' or '16'
    k = spec[0]
    if k in ('gr', 'fr', 'pr', 'br'):
        return '%s%d' % ({'gr': 'r'}.get(k, k[0]), bits(slot, *spec[1]))
    if k == 'ar':
        return ar_name(bits(slot, *spec[1]))
    if k == 'cr':
        return cr_name(bits(slot, *spec[1]))
    if k == 'dahr':
        return 'dahr%d' % bits(slot, *spec[1])
    if k == 'mem':
        return '[r%d]' % bits(slot, 20, 7)
    if k == 'ind':
        return '%s[r%d]' % (spec[1], bits(slot, 20, 7))
    if k == 'const':
        return spec[1]
    if k == 'imm':
        v = imm_value(spec, slot)
        if spec[6] == 'dec':
            return '%d' % v
        return '0x%x' % (v & (2 ** 64 - 1))
    if k == 'map':
        return '%d' % spec[2][bits(slot, *spec[1])]
    if k == 'mbtype':
        v = bits(slot, *spec[1])
        return MBTYPE_NAMES.get(v, '0x%x' % v)
    if k == 'rel':
        v, tot = 0, 0
        for lo, w in spec[1]:
            v |= bits(slot, lo, w) << tot
            tot += w
        return '0x%x' % ((addr + (sext(v, tot) << 4)) & (2 ** 64 - 1))
    if k == 'immu64':
        v = (bits(slot, 13, 7) | (bits(slot, 27, 9) << 7) | (bits(slot, 22, 5) << 16)
             | (bits(slot, 21, 1) << 21) | (lslot << 22) | (bits(slot, 36, 1) << 63))
        return '0x%x' % v
    if k == 'immu62':
        return '0x%x' % ((lslot << 21) | (bits(slot, 36, 1) << 20) | bits(slot, 6, 20))
    if k == 'tgt64':
        v = (bits(slot, 13, 20) | (bits(slot, 36, 1) << 59) | (bits(lslot, 2, 39) << 20)) << 4
        return '0x%x' % ((addr + v) & (2 ** 64 - 1))
    raise ValueError(op)


def format_insn(e, slot, addr, lslot=0):
    text = e.name
    if e.ops:
        parts = [fmt_operand(o, slot, addr, lslot) for o in e.ops]
        s = ''
        for i, p in enumerate(parts):
            s += p
            if i + 1 == e.nout and i + 1 < len(parts):
                s += '='
            elif i + 1 < len(parts):
                s += ','
        text += ' ' + s
    qp = bits(slot, 0, 6)
    pred = qp if qp and 'nopred' not in e.flags else 0
    return pred, text


def split_bundle(b):
    lo = int.from_bytes(b[:8], 'little')
    hi = int.from_bytes(b[8:16], 'little')
    t = lo & 0x1f
    s0 = (lo >> 5) & (2 ** 41 - 1)
    s1 = ((lo >> 46) | (hi << 18)) & (2 ** 41 - 1)
    s2 = (hi >> 23) & (2 ** 41 - 1)
    return t, (s0, s1, s2)


def decode_bundle(b, addr):
    """[(slot address, predicate, text or None, stop after)] for one bundle;
    text is None where no entry matches. The L slot of MLX has no line."""
    t, slots = split_bundle(b)
    out = []
    if t not in TEMPLATES:
        return [(addr + 6 * i, 0, None, False) for i in range(3)]
    units, stops = TEMPLATES[t]
    for i in range(3):
        if units[i] == 'L':
            continue
        unit = units[i]
        e = lookup(unit, slots[i])
        stop = i in stops
        if e is None:
            out.append((addr + (6 if unit == 'X' else 6 * i), 0, None, stop))
            continue
        if unit == 'X':
            pred, text = format_insn(e, slots[2], addr, slots[1])
            out.append((addr + 6, pred, text, stop))
        else:
            pred, text = format_insn(e, slots[i], addr)
            out.append((addr + 6 * i, pred, text, stop))
    return out


if __name__ == '__main__':
    import sys
    data = open(sys.argv[1], 'rb').read()
    base = int(sys.argv[2], 0)
    for off in range(0, len(data) - 15, 16):
        for a, p, txt, stop in decode_bundle(data[off:off + 16], base + off):
            print('%x: %s%s%s' % (a, '(p%02d) ' % p if p else '', txt or '<unknown>', ';;' if stop else ''))
