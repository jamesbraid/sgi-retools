#!/usr/bin/env python3
"""Disassembler for the Motorola/NXP DSP56300 family (24-bit program words).

Usage: python3 tools/hdsp/dsp56300dis.py [--base ADDR] [--bin | --bin-le] [FILE|-]

FILE holds the program words, by default as text (whitespace-separated hex words, `0x`, `$` or
bare, `;` starts a comment) or, with --bin / --bin-le, as packed 3-byte big/little-endian words.
Each output line is `ADDRESS: RAW WORDS  TEXT`. Words the tables do not decode print as `?`.

Library: disassemble(words, pc) -> (text, length_in_words)
    words   list of 24-bit ints: the opcode word and the (up to two) words after it
    pc      word address of the first word (branch and loop targets are printed absolute)
  decode_stream(words, base=0) yields Insn(address, length, text, words); Insn.valid is False
  for an entry printed as `?` (UNDECODED).  Nothing here raises on any word value.

Output is Motorola assembler syntax, lower case: `mac x0,y0,a x:(r0)+,x0 y:(r4)+n4,y0`,
`move #$123456,r0`, `jsr $0123`, `do #8,$0123`. Short absolute addresses print as `x:<$12`,
I/O short addresses as `x:<<$ffffc5`, long (extension word) addresses as `x:$1234`. Loop and
branch operands are absolute word addresses.

Sources: NXP/Freescale DSP56300 Family Manual rev. 5 (DSP56300FM): chapter 12 section 12.5
(partial encodings, tables 12-13 to 12-21) and the "Instruction Formats and Opcodes" diagram of
each instruction in chapter 13, including the parallel move descriptions (X:, Y:, L:, X:Y:,
X:R, R:Y, I, R, U) and MOVEC/MOVEM/MOVEP. Written from those diagrams; no emulator or
disassembler source was used. The instruction patterns below are the manual's bit strings.

Where the manual is ambiguous or wrong (decisions made, listed so they can be revisited):
  * Bit number of BCHG/BCLR/BSET/BTST/JCLR/JSET/JSCLR/JSSET/BRCLR/BRSET/BSCLR/BSSET: several
    diagrams print `0 S 0 0 b b b b` / `0 1 1 0 b b b b`, a fixed 0 in bit 4 and four b's, but
    the field list says the bit number is 0-23 (five bits). Bits 4-0 are decoded as the number
    and bit 5 as the set/clear selector.
  * MPY/MAC/MPYR/MACR S,#n,D: the diagrams for MPY and MAC show four s bits, MPYR shows five.
    The immediate shift n needs 5 bits (1-22), so bits 12-8 are n and bits 15-13 must be 0.
  * Bcc xxxx (long displacement) is printed in the manual with the short Bcc encoding. The
    long form is taken as 0x0D1040|cc plus extension word, by analogy with BRA/BSR xxxx and
    BScc xxxx (which the manual prints correctly). Inferred, not read.
  * Short displacement MOVE X:(Rn+xxx),D / LUA (Rn+aa),D: the 7-bit signed displacement is
    assembled most-significant bit first in the diagram's left-to-right order (the loose bit
    in bit 6 is the least significant bit). The manual never states the bit order.
  * MOVE X:(Rn+xxxx) / Y:(Rn+xxxx) uses ea field 110RRR, which is the long absolute mode (RRR=000)
    elsewhere. The manual's JCLR/JSET/JSCLR/JSSET descriptions allow only indirect, short
    absolute and I/O short absolute operands, so no bit-test jump should carry 110RRR, and the
    displacement MOVE can win without a conflict in valid code.
  * DO/DOR: the extension word is printed as the manual's `expr`: DO shows extension+1 (the
    manual says the assembler stores expr-1 in LA). DOR shows pc+displacement+1 by analogy;
    the manual only says PC+xxxx -> LA.
  * MOVEC/MOVEM/MOVEP read-versus-write is taken from the diagram's W bit (W=1 writes the
    register or peripheral).
  * MACsu/MPYsu operand order is printed in the QQQQ table order S1,S2 as in the diagrams
    (the syntax lines in the manual list S2,S1).
  * `TRAP` (0x000006) is printed as `trap`; the manual has no SWI.
  * The manual heads two diagrams PUNLOCK; the 0x0B.. one (the first, under PLOCK) is printed
    as plock, the 0x0A.. one as punlock.

Known gaps: sixteen-bit arithmetic mode and register-set differences between core versions
are not modelled (the encodings are the same). Reserved or unassigned bit patterns decode as
`?`: reserved register codes, the reserved ALU opcode slots, and ea modes the manual does not
define. Whether the hardware accepts every encoding the tables accept (for example a long
absolute ea in a bit-test jump, or a write-only register as a source) is not checked, nor are
the parallel-move rules (duplicate destinations, which move pairs an ALU op may carry).
"""
import argparse
import sys
from typing import List, NamedTuple, Tuple

MASK24 = 0xFFFFFF
UNDECODED = '?'


class _Bad(Exception):
    """The word is not a valid encoding (reserved bits, missing extension word)."""


class Insn(NamedTuple):
    address: int
    length: int
    text: str
    words: Tuple[int, ...]

    @property
    def valid(self):
        return self.text != UNDECODED


# ---------------------------------------------------------------------------------------------
# Register and condition tables (DSP56300FM tables 12-13, 12-14, 12-16, 12-18)

REG6: List = [None] * 64
for _i, _n in enumerate(['x0', 'x1', 'y0', 'y1']):
    REG6[4 + _i] = _n
for _i, _n in enumerate(['a0', 'b0', 'a2', 'b2', 'a1', 'b1', 'a', 'b']):
    REG6[8 + _i] = _n
for _i in range(8):
    REG6[16 + _i] = 'r%d' % _i
    REG6[24 + _i] = 'n%d' % _i
    REG6[32 + _i] = 'm%d' % _i
REG6[42] = 'ep'
REG6[48] = 'vba'
REG6[49] = 'sc'
for _i, _n in enumerate(['sz', 'sr', 'omr', 'sp', 'ssh', 'ssl', 'la', 'lc']):
    REG6[56 + _i] = _n

CC = ['cc', 'ge', 'ne', 'pl', 'nn', 'ec', 'lc', 'gt', 'cs', 'lt', 'eq', 'mi', 'nr', 'es', 'ls', 'le']
# Table 12-13 "SSS/sss" (A1,B1,X0,Y0,X1,Y1) and "qqq" (A0,B0,X0,Y0,X1,Y1)
SSS = {2: 'a1', 3: 'b1', 4: 'x0', 5: 'y0', 6: 'x1', 7: 'y1'}
QQQ_INS = {2: 'a0', 3: 'b0', 4: 'x0', 5: 'y0', 6: 'x1', 7: 'y1'}
# Table 12-16 multiply operand encodings (QQQ: parallel; QQQQ: mixed-sign and DMAC)
MUL3 = ['x0,x0', 'y0,y0', 'x1,x0', 'y1,y0', 'x0,y1', 'y0,x0', 'x1,y0', 'y1,x1']
MUL4 = MUL3 + ['x1,x1', 'y1,y1', 'x0,x1', 'y0,y1', 'y1,x0', 'x0,y0', 'y0,x1', 'x1,y1']
MULQQ = ['y1', 'x0', 'y0', 'x1']   # S,#n,D multiplier register
MULqq = ['x0', 'y0', 'x1', 'y1']   # #xxxx,S,D multiplier register
REG4 = ['x0', 'y0', 'x1', 'y1']    # JJ


def sext(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def addr(v):
    return '$%04x' % v if v <= 0xFFFF else '$%06x' % v


def imm24(v):
    return '#$%06x' % v


def reg6(code):
    n = REG6[code]
    if n is None:
        raise _Bad
    return n


def accname(i):
    return 'ab'[i]


def space(i):
    return 'xy'[i]


class _Ctx:
    def __init__(self, words, pc):
        self.words = words
        self.pc = pc
        self.n = 1
        self.f = {}

    def ext(self):
        if self.n >= len(self.words):
            raise _Bad
        v = self.words[self.n]
        self.n += 1
        return v

    def rel(self, disp):
        return (self.pc + disp) & MASK24


# ---------------------------------------------------------------------------------------------
# Effective addresses (table 12-13, "Effective Addressing Mode Encoding 1")

_EA = ['(r%d)-n%d', '(r%d)+n%d', '(r%d)-', '(r%d)+', '(r%d)', '(r%d+n%d)', None, '-(r%d)']


def ea_parse(c, v):
    """Return (kind, text): kind is 'reg', 'abs' or 'imm'. Consumes the extension word."""
    m, r = v >> 3, v & 7
    if m == 6:
        if r == 0:
            return 'abs', addr(c.ext())
        if r == 4:
            return 'imm', imm24(c.ext())
        raise _Bad
    t = _EA[m]
    return 'reg', t % ((r, r) if t.count('%d') == 2 else (r,))


def ea_mem(c, sp, v, store=False):
    kind, t = ea_parse(c, v)
    if kind == 'imm':
        if store:
            raise _Bad
        return t
    return '%s:%s' % (sp, t)


def ea_jump(c, v):
    kind, t = ea_parse(c, v)
    if kind == 'imm':
        raise _Bad
    return t


def ea5(mm, rrr):
    """MMRRR encoding 4 (U move, LUA): (Rn)-Nn, (Rn)+Nn, (Rn)-, (Rn)+."""
    return ['(r%d)-n%d', '(r%d)+n%d', '(r%d)-', '(r%d)+'][mm] % ((rrr, rrr) if mm < 2 else (rrr,))


# ---------------------------------------------------------------------------------------------
# Data ALU opcode byte of the parallel instructions (tables 12-19, 12-20, 12-21)

_NM = {
    0: ['move', ('tfr', 'b'), ('addr', 'b'), ('tst', 'd'), None, ('cmp', 'b'), ('subr', 'b'),
        ('cmpm', 'b')],
    1: [('add', 'b'), ('rnd', 'd'), ('addl', 'b'), ('clr', 'd'), ('sub', 'b'), None, ('subl', 'b'),
        ('not', 'd')],
    2: [('add', 'x'), ('adc', 'x'), ('asr', 'd'), ('lsr', 'd'), ('sub', 'x'), ('sbc', 'x'),
        ('abs', 'd'), ('ror', 'd')],
    3: [('add', 'y'), ('adc', 'y'), ('asl', 'd'), ('lsl', 'd'), ('sub', 'y'), ('sbc', 'y'),
        ('neg', 'd'), ('rol', 'd')],
}
for _j in range(4, 8):
    _NM[_j] = [('add', 'r'), ('tfr', 'r'), ('or', 'r'), ('eor', 'r'), ('sub', 'r'), ('cmp', 'r'),
               ('and', 'r'), ('cmpm', 'r')]


def alu(op):
    d = (op >> 3) & 1
    D = accname(d)
    if op & 0x80:
        qqq, k, kk = (op >> 4) & 7, (op >> 2) & 1, op & 3
        mn = ['mpy', 'mpyr', 'mac', 'macr'][kk]
        return '%s %s%s,%s' % (mn, '-' if k else '', MUL3[qqq], D)
    jjj, kkk = (op >> 4) & 7, op & 7
    if jjj == 1 and kkk == 5:
        if op == 0x1D:
            return 'max a,b'
        if op == 0x15:
            return 'maxm a,b'
        raise _Bad
    ent = _NM[jjj][kkk]
    if ent is None:
        raise _Bad
    if ent == 'move':
        if d:
            raise _Bad
        return 'move'
    mn, src = ent
    if src == 'd':
        return '%s %s' % (mn, D)
    if src == 'b':
        s = accname(1 - d)
    elif src in ('x', 'y'):
        s = src
    else:
        s = REG4[jjj & 3]
    return '%s %s,%s' % (mn, s, D)


# ---------------------------------------------------------------------------------------------
# Parallel moves (chapter 13, "Parallel Move Descriptions")

_XYMODE = ['(r%d)', '(r%d)+n%d', '(r%d)-', '(r%d)+']
_LLL = ['a10', 'b10', 'x', 'y', 'a', 'b', 'ab', 'ba']


def _xymode(mode, r):
    t = _XYMODE[mode]
    return t % ((r, r) if mode == 1 else (r,))


def _pm_xy(w):
    # 1 w mm ee ff W rr MM RRR (X:Y move); the Y address register is in the other bank
    wy = (w >> 22) & 1
    mm = (w >> 20) & 3
    ee = (w >> 18) & 3
    ff = (w >> 16) & 3
    wx = (w >> 15) & 1
    rr = (w >> 13) & 3
    mx = (w >> 11) & 3
    rx = (w >> 8) & 7
    ry = rr + (4 if rx < 4 else 0)
    xr = ['x0', 'x1', 'a', 'b'][ee]
    yr = ['y0', 'y1', 'a', 'b'][ff]
    xe = 'x:' + _xymode(mx, rx)
    ye = 'y:' + _xymode(mm, ry)
    xs = '%s,%s' % (xe, xr) if wx else '%s,%s' % (xr, xe)
    ys = '%s,%s' % (ye, yr) if wy else '%s,%s' % (yr, ye)
    return xs + ' ' + ys


def _pm_xy_mem(c, w):
    # 01 dd s ddd W 1 MMMRRR (ea) / W 0 aaaaaa (short absolute): X: and Y: moves
    b = (w >> 16) & 0xFF
    sp = space((b >> 3) & 1)
    reg = reg6(((b >> 4) & 3) << 3 | (b & 7))
    wr = (w >> 15) & 1
    if (w >> 14) & 1:
        mem = ea_mem(c, sp, (w >> 8) & 0x3F, store=not wr)
    else:
        mem = '%s:<$%02x' % (sp, (w >> 8) & 0x3F)
    return '%s,%s' % (mem, reg) if wr else '%s,%s' % (reg, mem)


def _pm_long(c, w):
    b = (w >> 16) & 0xFF
    reg = _LLL[((b >> 3) & 1) << 2 | (b & 3)]
    wr = (w >> 15) & 1
    if (w >> 14) & 1:
        mem = ea_mem(c, 'l', (w >> 8) & 0x3F, store=True)
    else:
        mem = 'l:<$%02x' % ((w >> 8) & 0x3F)
    return '%s,%s' % (mem, reg) if wr else '%s,%s' % (reg, mem)


def _pm_rr_u(w):
    b = (w >> 16) & 0xFF
    hi = (w >> 8) & 0xFF
    if b == 0x20 and hi == 0:
        return ''
    if b == 0x20 and (hi >> 5) == 2:   # 010MMRRR address register update (the "U" move)
        return ea5((hi >> 3) & 3, hi & 7)
    e = (b & 3) << 3 | (hi >> 5)
    return '%s,%s' % (reg6(e), reg6(hi & 0x1F))


def _pm_class1(c, w):
    # 0001 ffdF W 0 MMMRRR  X:R class I ; 0001 deff W 1 MMMRRR  R:Y class I
    b = (w >> 16) & 0xFF
    wr = (w >> 15) & 1
    ea = (w >> 8) & 0x3F
    if (w >> 14) & 1:
        s1 = 'ab'[(b >> 3) & 1]
        d1 = ['x0', 'x1'][(b >> 2) & 1]
        s2 = ['y0', 'y1', 'a', 'b'][b & 3]
        mem = ea_mem(c, 'y', ea, store=not wr)
        second = '%s,%s' % (mem, s2) if wr else '%s,%s' % (s2, mem)
        return '%s,%s %s' % (s1, d1, second)
    ff = ['x0', 'x1', 'a', 'b'][(b >> 2) & 3]
    s2 = 'ab'[(b >> 1) & 1]
    d2 = ['y0', 'y1'][b & 1]
    mem = ea_mem(c, 'x', ea, store=not wr)
    first = '%s,%s' % (mem, ff) if wr else '%s,%s' % (ff, mem)
    return '%s %s,%s' % (first, s2, d2)


def _pm_class2(c, w):
    # 0000 100d 00 MMMRRR (X:R class II), 0000 100d 10 MMMRRR (R:Y class II)
    b = (w >> 16) & 0xFF
    sel = (w >> 14) & 3
    if b not in (0x08, 0x09) or sel not in (0, 2):
        raise _Bad
    acc = 'ab'[b & 1]
    kind, t = ea_parse(c, (w >> 8) & 0x3F)
    if kind != 'reg':
        raise _Bad
    if sel == 0:
        return '%s,x:%s x0,%s' % (acc, t, acc)
    return 'y0,%s %s,y:%s' % (acc, acc, t)


def pmove(c, w):
    """Decode the move field (bits 23-8) of a parallel instruction; '' for no move."""
    b = (w >> 16) & 0xFF
    if b >= 0x80:
        return _pm_xy(w)
    if b >= 0x40:
        return _pm_long(c, w) if (b & 0xF4) == 0x40 else _pm_xy_mem(c, w)
    if b >= 0x20:
        if b <= 0x23:
            return _pm_rr_u(w)
        return '#$%02x,%s' % ((w >> 8) & 0xFF, reg6(b & 0x1F))
    if b >= 0x10:
        return _pm_class1(c, w)
    return _pm_class2(c, w)


def parallel(c, w):
    b = (w >> 16) & 0xFF
    if b == 0x20 and ((w >> 12) & 0xF) in (2, 3):
        # IFcc / IFcc.U: the move field is replaced by the condition
        return alu(w & 0xFF) + ' if' + CC[(w >> 8) & 0xF] + ('.u' if (w >> 12) & 1 else '')
    moves = pmove(c, w)
    a = alu(w & 0xFF)
    return a + (' ' + moves if moves else '')


# ---------------------------------------------------------------------------------------------
# Pattern table for everything that is not a parallel ALU+move word. Patterns are the manual's
# 24-bit diagrams (bit 23 first): digits are fixed bits, a letter is a field, and repeated
# letters join most-significant first.

class Pat:
    __slots__ = ('name', 'text', 'mask', 'value', 'fields', 'fn', 'fixed')

    def __init__(self, name, pattern, fn):
        bits = pattern.replace(' ', '')
        if len(bits) != 24:
            raise ValueError('%s: pattern %r is %d bits' % (name, pattern, len(bits)))
        self.name = name
        self.text = bits
        self.fn = fn
        mask = value = 0
        fields = {}
        for i, ch in enumerate(bits):
            pos = 23 - i
            if ch in '01':
                mask |= 1 << pos
                value |= int(ch) << pos
            else:
                fields.setdefault(ch, []).append(pos)
        self.mask, self.value, self.fields = mask, value, fields
        self.fixed = bin(mask).count('1')

    def extract(self, w):
        f = {}
        for ch, poss in self.fields.items():
            v = 0
            for p in poss:
                v = v << 1 | (w >> p) & 1
            f[ch] = v
        return f


PATS: List[Pat] = []


def add(name, pattern, fn):
    PATS.append(Pat(name, pattern, fn))


def fixed(name, word):
    add(name, format(word, '024b'), lambda c, t=name: t)


def _ea(c):
    return c.f['M'] << 3 | c.f['R']


def _cc(c):
    return CC[c.f['C']]


def _sss(v):
    if v not in SSS:
        raise _Bad
    return SSS[v]


def _qqq_ins(v):
    if v not in QQQ_INS:
        raise _Bad
    return QQQ_INS[v]


def _wr(c, mem, reg):
    """W=1 writes the register or peripheral (memory -> reg), W=0 reads it."""
    return '%s,%s' % ((mem, reg) if c.f['W'] else (reg, mem))


def _operand(c, kind):
    f = c.f
    if kind == 'ea':
        return ea_mem(c, space(f['S']), _ea(c))
    if kind == 'aa':
        return '%s:<$%02x' % (space(f['S']), f['a'])
    if kind == 'pp':
        return '%s:<<$%06x' % (space(f['S']), 0xFFFFC0 + f['p'])
    if kind == 'qq':
        return '%s:<<$%06x' % (space(f['S']), 0xFFFF80 + f['q'])
    return reg6(f['D'])


# Bit manipulation. For each form: ea, aa (short absolute), pp (high I/O), qq (low I/O), register.
for _mn, _fb, _t in [('bclr', '1010', '0'), ('bset', '1010', '1'),
                     ('bchg', '1011', '0'), ('btst', '1011', '1')]:
    def _h(kind, mn=_mn):
        return lambda c: '%s #%d,%s' % (mn, c.f['b'], _operand(c, kind))
    add(_mn, '0000' + _fb + '01MMMRRR' + '0S' + _t + 'bbbbb', _h('ea'))
    add(_mn, '0000' + _fb + '00aaaaaa' + '0S' + _t + 'bbbbb', _h('aa'))
    add(_mn, '0000' + _fb + '10pppppp' + '0S' + _t + 'bbbbb', _h('pp'))
    add(_mn, '00000001' + ('00' if _fb == '1010' else '01') + 'qqqqqq' + '0S' + _t + 'bbbbb',
        _h('qq'))
    add(_mn, '0000' + _fb + '11DDDDDD' + '01' + _t + 'bbbbb', _h('reg'))

# Jump on bit: JCLR/JSET (0x0A) and JSCLR/JSSET (0x0B); absolute target in the extension word.
for _mn, _fb, _t in [('jclr', '1010', '0'), ('jset', '1010', '1'),
                     ('jsclr', '1011', '0'), ('jsset', '1011', '1')]:
    def _hj(kind, mn=_mn):
        def h(c):
            op = _operand(c, kind)
            return '%s #%d,%s,%s' % (mn, c.f['b'], op, addr(c.ext()))
        return h
    add(_mn, '0000' + _fb + '01MMMRRR' + '1S' + _t + 'bbbbb', _hj('ea'))
    add(_mn, '0000' + _fb + '00aaaaaa' + '1S' + _t + 'bbbbb', _hj('aa'))
    add(_mn, '0000' + _fb + '10pppppp' + '1S' + _t + 'bbbbb', _hj('pp'))
    add(_mn, '00000001' + ('10' if _fb == '1010' else '11') + 'qqqqqq' + '1S' + _t + 'bbbbb',
        _hj('qq'))
    add(_mn, '0000' + _fb + '11DDDDDD' + '00' + _t + 'bbbbb', _hj('reg'))

# Branch on bit: BRCLR/BRSET (0x0C) and BSCLR/BSSET (0x0D); PC-relative displacement word.
for _mn, _fb, _t in [('brclr', '1100', '0'), ('brset', '1100', '1'),
                     ('bsclr', '1101', '0'), ('bsset', '1101', '1')]:
    def _hb(kind, mn=_mn):
        def h(c):
            op = _operand(c, kind)
            return '%s #%d,%s,%s' % (mn, c.f['b'], op, addr(c.rel(sext(c.ext(), 24))))
        return h
    _bs = '1' if _fb == '1101' else '0'
    add(_mn, '0000' + _fb + '10MMMRRR' + '0S' + _t + 'bbbbb', _hb('ea'))
    add(_mn, '0000' + _fb + '10aaaaaa' + '1S' + _t + 'bbbbb', _hb('aa'))
    add(_mn, '0000' + _fb + '11pppppp' + '0S' + _t + 'bbbbb', _hb('pp'))
    add(_mn, '00000100' + '10qqqqqq' + _bs + 'S' + _t + 'bbbbb', _hb('qq'))
    add(_mn, '0000' + _fb + '11DDDDDD' + '10' + _t + 'bbbbb', _hb('reg'))

# ALU immediates: ADD/SUB/CMP/AND/EOR/OR #xx,D and #xxxx,D
for _mn, _k in [('add', '000'), ('sub', '100'), ('cmp', '101'), ('and', '110'), ('eor', '011'),
                ('or', '010')]:
    add(_mn, '00000001' + '01iiiiii' + '1000d' + _k,
        lambda c, mn=_mn: '%s #$%02x,%s' % (mn, c.f['i'], accname(c.f['d'])))
    add(_mn, '00000001' + '01000000' + '1100d' + _k,
        lambda c, mn=_mn: '%s %s,%s' % (mn, imm24(c.ext()), accname(c.f['d'])))

_EE = ['mr', 'ccr', 'com', 'eom']
add('andi', '00000000' + 'iiiiiiii' + '101110EE',
    lambda c: 'andi #$%02x,%s' % (c.f['i'], _EE[c.f['E']]))
add('ori', '00000000' + 'iiiiiiii' + '111110EE',
    lambda c: 'ori #$%02x,%s' % (c.f['i'], _EE[c.f['E']]))

# 0x0C1x group: shifts, bit fields, normalisation
add('asl', '0000110000011101' + 'SiiiiiiD', lambda c: 'asl #%d,%s,%s' % (
    c.f['i'], accname(c.f['S']), accname(c.f['D'])))
add('asr', '0000110000011100' + 'SiiiiiiD', lambda c: 'asr #%d,%s,%s' % (
    c.f['i'], accname(c.f['S']), accname(c.f['D'])))
add('asl', '0000110000011110' + '010SsssD', lambda c: 'asl %s,%s,%s' % (
    _sss(c.f['s']), accname(c.f['S']), accname(c.f['D'])))
add('asr', '0000110000011110' + '011SsssD', lambda c: 'asr %s,%s,%s' % (
    _sss(c.f['s']), accname(c.f['S']), accname(c.f['D'])))
add('lsl', '0000110000011110' + '10iiiiiD', lambda c: 'lsl #%d,%s' % (c.f['i'], accname(c.f['D'])))
add('lsr', '0000110000011110' + '11iiiiiD', lambda c: 'lsr #%d,%s' % (c.f['i'], accname(c.f['D'])))
add('lsl', '0000110000011110' + '0001sssD', lambda c: 'lsl %s,%s' % (
    _sss(c.f['s']), accname(c.f['D'])))
add('lsr', '0000110000011110' + '0011sssD', lambda c: 'lsr %s,%s' % (
    _sss(c.f['s']), accname(c.f['D'])))
add('normf', '0000110000011110' + '0010sssD', lambda c: 'normf %s,%s' % (
    _sss(c.f['s']), accname(c.f['D'])))
add('clb', '0000110000011110' + '000000SD', lambda c: 'clb %s,%s' % (
    accname(c.f['S']), accname(c.f['D'])))


def _ggg(c):
    g, d = c.f['g'], c.f['d']
    if g == 0:
        return accname(1 - d)
    if g >= 4:
        return REG4[g - 4]
    raise _Bad


add('cmpu', '0000110000011111' + '1111gggd', lambda c: 'cmpu %s,%s' % (_ggg(c), accname(c.f['d'])))
add('merge', '0000110000011011' + '1000SSSD', lambda c: 'merge %s,%s' % (
    _sss(c.f['S']), accname(c.f['D'])))
add('extract', '0000110000011010' + '000sSSSD', lambda c: 'extract %s,%s,%s' % (
    _sss(c.f['S']), accname(c.f['s']), accname(c.f['D'])))
add('extractu', '0000110000011010' + '100sSSSD', lambda c: 'extractu %s,%s,%s' % (
    _sss(c.f['S']), accname(c.f['s']), accname(c.f['D'])))
add('extract', '0000110000011000' + '000s000D', lambda c: 'extract %s,%s,%s' % (
    imm24(c.ext()), accname(c.f['s']), accname(c.f['D'])))
add('extractu', '0000110000011000' + '100s000D', lambda c: 'extractu %s,%s,%s' % (
    imm24(c.ext()), accname(c.f['s']), accname(c.f['D'])))
add('insert', '0000110000011011' + '0qqqSSSD', lambda c: 'insert %s,%s,%s' % (
    _sss(c.f['S']), _qqq_ins(c.f['q']), accname(c.f['D'])))
add('insert', '0000110000011001' + '0qqq000D', lambda c: 'insert %s,%s,%s' % (
    imm24(c.ext()), _qqq_ins(c.f['q']), accname(c.f['D'])))

# Multiplies without a parallel move: S,#n,D and #xxxx,S,D (kk: 00 mpy, 01 mpyr, 10 mac, 11 macr)
for _kk, _mn in enumerate(['mpy', 'mpyr', 'mac', 'macr']):
    def _hmi(mn=_mn):
        def h(c):
            n = c.f['s']
            if not 1 <= n <= 22:
                raise _Bad
            return '%s %s%s,#%d,%s' % (mn, '-' if c.f['k'] else '', MULQQ[c.f['Q']], n,
                                       accname(c.f['d']))
        return h

    def _hil(mn=_mn + 'i'):
        return lambda c: '%s %s%s,%s,%s' % (mn, '-' if c.f['k'] else '', imm24(c.ext()),
                                            MULqq[c.f['q']], accname(c.f['d']))
    add(_mn, '00000001' + '000sssss' + '11QQdk' + format(_kk, '02b'), _hmi())
    add(_mn + 'i', '00000001' + '01000001' + '11qqdk' + format(_kk, '02b'), _hil())

_SU = {0: 'ss', 2: 'su', 3: 'uu'}


def _hdmac(c):
    ss = c.f['s']
    if ss not in _SU:
        raise _Bad
    return 'dmac%s %s%s,%s' % (_SU[ss], '-' if c.f['k'] else '', MUL4[c.f['Q']], accname(c.f['d']))


add('dmac', '000000010010010s' + '1sdkQQQQ', _hdmac)
add('macsu', '0000000100100110' + '1sdkQQQQ', lambda c: 'mac%s %s%s,%s' % (
    'uu' if c.f['s'] else 'su', '-' if c.f['k'] else '', MUL4[c.f['Q']], accname(c.f['d'])))
add('mpysu', '0000000100100111' + '1sdkQQQQ', lambda c: 'mpy%s %s%s,%s' % (
    'uu' if c.f['s'] else 'su', '-' if c.f['k'] else '', MUL4[c.f['Q']], accname(c.f['d'])))

add('div', '00000001' + '10000000' + '01JJd000', lambda c: 'div %s,%s' % (
    REG4[c.f['J']], accname(c.f['d'])))
add('norm', '00000001' + '11011RRR' + '0001d101', lambda c: 'norm r%d,%s' % (
    c.f['R'], accname(c.f['d'])))

# Jumps and branches
add('jmp', '0000101011MMMRRR10000000', lambda c: 'jmp ' + ea_jump(c, _ea(c)))
add('jsr', '0000101111MMMRRR10000000', lambda c: 'jsr ' + ea_jump(c, _ea(c)))
add('jcc', '0000101011MMMRRR1010CCCC', lambda c: 'j%s %s' % (_cc(c), ea_jump(c, _ea(c))))
add('jscc', '0000101111MMMRRR1010CCCC', lambda c: 'js%s %s' % (_cc(c), ea_jump(c, _ea(c))))
add('plock', '0000101111MMMRRR10000001', lambda c: 'plock ' + ea_jump(c, _ea(c)))
add('punlock', '0000101011MMMRRR10000001', lambda c: 'punlock ' + ea_jump(c, _ea(c)))
add('jmp', '000011000000aaaaaaaaaaaa', lambda c: 'jmp ' + addr(c.f['a']))
add('jsr', '000011010000aaaaaaaaaaaa', lambda c: 'jsr ' + addr(c.f['a']))
add('jcc', '00001110CCCCaaaaaaaaaaaa', lambda c: 'j%s %s' % (_cc(c), addr(c.f['a'])))
add('jscc', '00001111CCCCaaaaaaaaaaaa', lambda c: 'js%s %s' % (_cc(c), addr(c.f['a'])))
add('bcc', '00000101CCCC01aaaa0aaaaa', lambda c: 'b%s %s' % (
    _cc(c), addr(c.rel(sext(c.f['a'], 9)))))
add('bscc', '00000101CCCC00aaaa0aaaaa', lambda c: 'bs%s %s' % (
    _cc(c), addr(c.rel(sext(c.f['a'], 9)))))
add('bra', '000001010000' + '11aaaa0aaaaa', lambda c: 'bra ' + addr(c.rel(sext(c.f['a'], 9))))
add('bsr', '000001010000' + '10aaaa0aaaaa', lambda c: 'bsr ' + addr(c.rel(sext(c.f['a'], 9))))
add('bra', '000011010001000011000000', lambda c: 'bra ' + addr(c.rel(sext(c.ext(), 24))))
add('bsr', '000011010001000010000000', lambda c: 'bsr ' + addr(c.rel(sext(c.ext(), 24))))
add('bra', '0000110100011RRR11000000', lambda c: 'bra r%d' % c.f['R'])
add('bsr', '0000110100011RRR10000000', lambda c: 'bsr r%d' % c.f['R'])
add('bcc', '00001101000100000100CCCC', lambda c: 'b%s %s' % (
    _cc(c), addr(c.rel(sext(c.ext(), 24)))))
add('bscc', '00001101000100000000CCCC', lambda c: 'bs%s %s' % (
    _cc(c), addr(c.rel(sext(c.ext(), 24)))))
add('bcc', '0000110100011RRR0100CCCC', lambda c: 'b%s r%d' % (_cc(c), c.f['R']))
add('bscc', '0000110100011RRR0000CCCC', lambda c: 'bs%s r%d' % (_cc(c), c.f['R']))


# Loops: DO/DOR/REP take a count from memory (ea or aa), an immediate (12 bits) or a register
def _count(c, kind):
    f = c.f
    if kind == 'ea':
        return ea_mem(c, space(f['S']), _ea(c), store=True)
    if kind == 'aa':
        return '%s:<$%02x' % (space(f['S']), f['a'])
    if kind == 'imm':
        return '#%d' % (f['h'] << 8 | f['i'])
    return reg6(f['D'])


for _mn, _t, _rel in [('do', '00', False), ('dor', '01', True)]:
    def _hd(kind, mn=_mn, rel=_rel):
        def h(c):
            src = _count(c, kind)
            e = c.ext()
            tgt = (c.rel(sext(e, 24)) if rel else e) + 1
            return '%s %s,%s' % (mn, src, addr(tgt & MASK24))
        return h
    add(_mn, '0000011001MMMRRR' + '0S' + _t + '0000', _hd('ea'))
    add(_mn, '0000011000aaaaaa' + '0S' + _t + '0000', _hd('aa'))
    add(_mn, '00000110iiiiiiii' + '100' + str(int(_rel)) + 'hhhh', _hd('imm'))
    add(_mn, '0000011011DDDDDD' + '000' + str(int(_rel)) + '0000', _hd('reg'))
add('do forever', format(0x000203, '024b'),
    lambda c: 'do forever,' + addr((c.ext() + 1) & MASK24))
add('dor forever', format(0x000202, '024b'),
    lambda c: 'dor forever,' + addr((c.rel(sext(c.ext(), 24)) + 1) & MASK24))

add('rep', '0000011001MMMRRR' + '0S100000', lambda c: 'rep ' + _count(c, 'ea'))
add('rep', '0000011000aaaaaa' + '0S100000', lambda c: 'rep ' + _count(c, 'aa'))
add('rep', '00000110iiiiiiii' + '1010hhhh', lambda c: 'rep ' + _count(c, 'imm'))
add('rep', '0000011011DDDDDD' + '00100000', lambda c: 'rep ' + _count(c, 'reg'))

# No-operand and conditional system instructions
for _n, _w in [('nop', 0), ('pflushun', 1), ('pfree', 2), ('pflush', 3), ('rti', 4),
               ('illegal', 5), ('trap', 6), ('rts', 0xC), ('reset', 0x84), ('wait', 0x86),
               ('stop', 0x87), ('enddo', 0x8C), ('debug', 0x200)]:
    fixed(_n, _w)
add('inc', '0000000000000000' + '0000100d', lambda c: 'inc ' + accname(c.f['d']))
add('dec', '0000000000000000' + '0000101d', lambda c: 'dec ' + accname(c.f['d']))
add('trapcc', '0000000000000000' + '0001CCCC', lambda c: 'trap' + _cc(c))
add('brkcc', '0000000000000010' + '0001CCCC', lambda c: 'brk' + _cc(c))
add('debugcc', '0000000000000011' + '0000CCCC', lambda c: 'debug' + _cc(c))
add('plockr', format(0x00000F, '024b'), lambda c: 'plockr ' + addr(c.rel(sext(c.ext(), 24))))
add('punlockr', format(0x00000E, '024b'), lambda c: 'punlockr ' + addr(c.rel(sext(c.ext(), 24))))


# Tcc
def _tcc(c, form):
    f = c.f
    parts = []
    if form in ('S1', 'both'):
        j, d = f['J'], f['d']
        if j == 0:
            s = accname(1 - d)
        elif j >= 4:
            s = REG4[j - 4]
        else:
            raise _Bad
        parts.append('%s,%s' % (s, accname(d)))
    if form in ('S2', 'both'):
        parts.append('r%d,r%d' % (f['t'], f['T']))
    return 't' + _cc(c) + ' ' + ' '.join(parts)


add('tcc', '00000010CCCC00000JJJd000', lambda c: _tcc(c, 'S1'))
add('tcc', '00000011CCCC0ttt0JJJdTTT', lambda c: _tcc(c, 'both'))
add('tcc', '00000010CCCC1ttt00000TTT', lambda c: _tcc(c, 'S2'))

# LRA / LUA
add('lra', '00000100' + '11000RRR' + '000ddddd', lambda c: 'lra r%d,%s' % (
    c.f['R'], reg6(c.f['d'])))
add('lra', '00000100' + '01000000' + '010ddddd', lambda c: 'lra %s,%s' % (
    addr(c.rel(sext(c.ext(), 24))), reg6(c.f['d'])))
add('lua', '00000100' + '010MMRRR' + '000ddddd', lambda c: 'lua %s,%s' % (
    ea5(c.f['M'], c.f['R']), reg6(c.f['d'])))


def _lua_disp(c):
    f = c.f
    disp = sext(f['a'], 7)
    d = f['d']    # 0nnn = Rn, 1nnn = Nn
    return 'lua (r%d%s$%02x),%s' % (f['R'], '-' if disp < 0 else '+', abs(disp),
                                    ('n%d' if d & 8 else 'r%d') % (d & 7))


add('lua', '00000100' + '00aaaRRR' + 'aaaadddd', _lua_disp)


# MOVEC / MOVEM / MOVEP. The 5-bit control register field is the 6-bit table with bit 5 set.
def _creg(v):
    return reg6(0x20 | v)


add('movec', '00000101' + 'W1MMMRRR' + '0S1ddddd', lambda c: 'movec ' + _wr(
    c, ea_mem(c, space(c.f['S']), _ea(c), store=not c.f['W']), _creg(c.f['d'])))
add('movec', '00000101' + 'W0aaaaaa' + '0S1ddddd', lambda c: 'movec ' + _wr(
    c, '%s:<$%02x' % (space(c.f['S']), c.f['a']), _creg(c.f['d'])))
add('movec', '00000100' + 'W1eeeeee' + '101ddddd', lambda c: 'movec ' + _wr(
    c, reg6(c.f['e']), _creg(c.f['d'])))
add('movec', '00000101' + 'iiiiiiii' + '101ddddd', lambda c: 'movec #$%02x,%s' % (
    c.f['i'], _creg(c.f['d'])))

add('movem', '00000111' + 'W1MMMRRR' + '10dddddd', lambda c: 'movem ' + _wr(
    c, ea_mem(c, 'p', _ea(c), store=not c.f['W']), reg6(c.f['d'])))
add('movem', '00000111' + 'W0aaaaaa' + '00dddddd', lambda c: 'movem ' + _wr(
    c, 'p:<$%02x' % c.f['a'], reg6(c.f['d'])))


def _pp(sp, v):
    return '%s:<<$%06x' % (space(sp), 0xFFFFC0 + v)


def _qq(sp, v):
    return '%s:<<$%06x' % (space(sp), 0xFFFF80 + v)


add('movep', '0000100s' + 'W1MMMRRR' + '1Spppppp', lambda c: 'movep ' + _wr(
    c, ea_mem(c, space(c.f['S']), _ea(c), store=not c.f['W']), _pp(c.f['s'], c.f['p'])))
add('movep', '0000100s' + 'W1MMMRRR' + '01pppppp', lambda c: 'movep ' + _wr(
    c, ea_mem(c, 'p', _ea(c), store=not c.f['W']), _pp(c.f['s'], c.f['p'])))
add('movep', '0000100s' + 'W1dddddd' + '00pppppp', lambda c: 'movep ' + _wr(
    c, reg6(c.f['d']), _pp(c.f['s'], c.f['p'])))
add('movep', '00000111' + 'W1MMMRRR' + '0Sqqqqqq', lambda c: 'movep ' + _wr(
    c, ea_mem(c, space(c.f['S']), _ea(c), store=not c.f['W']), _qq(0, c.f['q'])))
add('movep', '00000111' + 'W0MMMRRR' + '1Sqqqqqq', lambda c: 'movep ' + _wr(
    c, ea_mem(c, space(c.f['S']), _ea(c), store=not c.f['W']), _qq(1, c.f['q'])))
add('movep', '00000000' + '1WMMMRRR' + '0Sqqqqqq', lambda c: 'movep ' + _wr(
    c, ea_mem(c, 'p', _ea(c), store=not c.f['W']), _qq(c.f['S'], c.f['q'])))
add('movep', '00000100' + 'W1dddddd' + '1q0qqqqq', lambda c: 'movep ' + _wr(
    c, reg6(c.f['d']), _qq(0, c.f['q'])))
add('movep', '00000100' + 'W1dddddd' + '0q1qqqqq', lambda c: 'movep ' + _wr(
    c, reg6(c.f['d']), _qq(1, c.f['q'])))


# MOVE with displacement addressing (non-parallel)
def _move_long_disp(sp):
    def h(c):
        f = c.f
        disp = sext(c.ext(), 24)
        mem = '%s:(r%d%s$%04x)' % (sp, f['R'], '-' if disp < 0 else '+', abs(disp))
        return 'move ' + _wr(c, mem, reg6(f['D']))
    return h


def _move_short_disp(sp):
    def h(c):
        f = c.f
        disp = sext(f['a'], 7)
        mem = '%s:(r%d%s$%02x)' % (sp, f['R'], '-' if disp < 0 else '+', abs(disp))
        return 'move ' + _wr(c, mem, reg6(f['D']))   # DDDD (01DD/1DDD) equals the 6-bit code
    return h


add('move', '000010100111' + '0RRR1WDDDDDD', _move_long_disp('x'))
add('move', '000010110111' + '0RRR1WDDDDDD', _move_long_disp('y'))
add('move', '0000001aaaaaaRRR1a0WDDDD', _move_short_disp('x'))
add('move', '0000001aaaaaaRRR1a1WDDDD', _move_short_disp('y'))

add('vsl', '0000101S11MMMRRR110i0000', lambda c: 'vsl %s,%d,l:%s' % (
    accname(c.f['S']), c.f['i'], ea_jump(c, _ea(c))))


# Lookup index: patterns that can match each top byte, most specific first.
_INDEX: List[List[Pat]] = [[] for _ in range(256)]
for _p in sorted(PATS, key=lambda p: -p.fixed):
    for _b in range(256):
        if (_b & (_p.mask >> 16)) == (_p.value >> 16):
            _INDEX[_b].append(_p)


def match(word):
    """Return the first (most specific) table pattern matching the word, or None."""
    for p in _INDEX[(word >> 16) & 0xFF]:
        if (word & p.mask) == p.value:
            return p
    return None


def _dis(words, pc):
    c = _Ctx([x & MASK24 for x in words], pc)
    w = c.words[0]
    p = match(w)
    if p is not None:
        c.f = p.extract(w)
        return p.fn(c), c.n
    b = w >> 16
    if b >= 0x10 or (b in (0x08, 0x09) and ((w >> 14) & 3) in (0, 2)):
        return parallel(c, w), c.n
    raise _Bad


def disassemble(words, pc=0):
    """Disassemble the instruction at words[0]; returns (text, length in words).

    Undecodable words (and an instruction whose extension word is missing from `words`) come
    back as (UNDECODED, 1).
    """
    if not words:
        raise ValueError('no words to disassemble')
    try:
        return _dis(words, pc)
    except _Bad:
        return UNDECODED, 1


def decode_stream(words, base=0):
    """Yield Insn for each instruction in a list of 24-bit words starting at word address base."""
    i = 0
    n = len(words)
    while i < n:
        text, ln = disassemble(list(words[i:i + 3]), base + i)
        yield Insn(base + i, ln, text, tuple(w & MASK24 for w in words[i:i + ln]))
        i += ln


# ---------------------------------------------------------------------------------------------
# Command line

def _parse_text(data):
    words = []
    for line in data.splitlines():
        for tok in line.split(';', 1)[0].split():
            tok = tok.lower()
            if tok.startswith('$'):
                tok = tok[1:]
            elif tok.startswith('0x'):
                tok = tok[2:]
            words.append(int(tok, 16) & MASK24)
    return words


def main(argv=None):
    ap = argparse.ArgumentParser(description='DSP56300 disassembler for 24-bit program words')
    ap.add_argument('file', nargs='?', default='-', help='input file (default stdin)')
    ap.add_argument('--base', type=lambda s: int(s, 0), default=0,
                    help='word address of the first word')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--bin', action='store_true', help='input is packed 3-byte big-endian words')
    g.add_argument('--bin-le', action='store_true', help='input is packed 3-byte little-endian words')
    args = ap.parse_args(argv)
    if args.bin or args.bin_le:
        if args.file == '-':
            raw = sys.stdin.buffer.read()
        else:
            with open(args.file, 'rb') as fh:
                raw = fh.read()
        order = 'big' if args.bin else 'little'
        words = [int.from_bytes(raw[i:i + 3], order) for i in range(0, len(raw) - 2, 3)]
    else:
        if args.file == '-':
            text = sys.stdin.read()
        else:
            with open(args.file) as fh:
                text = fh.read()
        words = _parse_text(text)
    for ins in decode_stream(words, args.base):
        raw = ' '.join('%06x' % w for w in ins.words)
        print('%06x: %-20s %s' % (ins.address, raw, ins.text))
    return 0


if __name__ == '__main__':
    sys.exit(main())
