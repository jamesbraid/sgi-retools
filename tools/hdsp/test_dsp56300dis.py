#!/usr/bin/env python3
"""Tests of dsp56300dis.py. They need no program image.

Run from the repository root: python3 tools/hdsp/test_dsp56300dis.py

Every test word is built from a bit diagram copied from the NXP DSP56300 Family Manual rev. 5
("DSP56300FM"): the "Instruction Formats and Opcodes" box of the instruction's page in chapter
13, with the field values filled in by `enc` below, and the field encodings of chapter 12
tables 12-13 (effective addresses, registers, JJJ/JJ/D), 12-16 (multiply operands, long-move
registers, X:Y fields), 12-18 (condition codes) and 12-20/12-21 (non-multiply opcode map). The
expected text is worked out by hand from those tables and the instruction's assembler syntax,
not from the decoder. Where a manual diagram is known to be misprinted (see the module
docstring of dsp56300dis.py) the test says which reading it checks.
"""
import contextlib
import io
import os
import random
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dsp56300dis as dis  # noqa: E402


def enc(pattern, **fields):
    """Build a word from a manual bit diagram: digits are fixed bits, letters are fields.

    Repeated letters form one field, most significant bit first.
    """
    bits = pattern.replace(' ', '')
    pos = {}
    for i, ch in enumerate(bits):
        if ch not in '01':
            pos.setdefault(ch, []).append(i)
    unused = set(fields) - set(pos)
    missing = set(pos) - set(fields)
    assert not unused and not missing, (pattern, unused, missing)
    out = [int(c) if c in '01' else 0 for c in bits]
    for ch, v in fields.items():
        n = len(pos[ch])
        assert 0 <= v < (1 << n), (pattern, ch, v)
        for k, i in enumerate(pos[ch]):
            out[i] = (v >> (n - 1 - k)) & 1
    return int(''.join(map(str, out)), 2)


def par(move, op, **fields):
    """A parallel instruction: 16-bit move field diagram plus 8-bit opcode diagram.

    Field values are split by name: keys ending in '_' belong to the move field (without the
    underscore), the rest to the opcode, because the diagrams reuse letters (d, J, k ...).
    """
    mf = {k[:-1]: v for k, v in fields.items() if k.endswith('_')}
    of = {k: v for k, v in fields.items() if not k.endswith('_')}
    return enc(move, **mf) << 8 | enc(op, **of)


NOMOVE = '0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0'           # parallel move chapter: "No Parallel Data Move"
ADD_X0 = ('0 J J J d 0 0 0', dict(J=0b100, d=0))     # ADD X0,A  (ADD page, JJJ=100)


def nm(op, **f):
    return par(NOMOVE, op, **f)


class Case:
    def __init__(self, words, text, pc=0, source=''):
        self.words, self.text, self.pc, self.source = words, text, pc, source


CASES = []


def case(text, *words, pc=0x100):
    CASES.append(Case(list(words), text, pc))


# --------------------------------------------------------------------------------------------
# Data ALU opcodes with no parallel move. Table 12-20 and each instruction's "Instruction
# Formats and Opcodes" (ABS, ADC, ADD, ADDL, ADDR, AND, ASL, ASR, CLR, CMP, CMPM, EOR, LSL,
# LSR, NEG, NOT, OR, RND, ROL, ROR, SBC, SUB, SUBL, SUBR, TFR, TST, MAX, MAXM).
for text, op, f in [
    ('abs a', '0 0 1 0 d 1 1 0', dict(d=0)),
    ('abs b', '0 0 1 0 d 1 1 0', dict(d=1)),
    ('adc y,a', '0 0 1 J d 0 0 1', dict(J=1, d=0)),
    ('adc x,b', '0 0 1 J d 0 0 1', dict(J=0, d=1)),
    ('add b,a', '0 J J J d 0 0 0', dict(J=0b001, d=0)),
    ('add a,b', '0 J J J d 0 0 0', dict(J=0b001, d=1)),
    ('add x,a', '0 J J J d 0 0 0', dict(J=0b010, d=0)),
    ('add y,b', '0 J J J d 0 0 0', dict(J=0b011, d=1)),
    ('add x0,a', '0 J J J d 0 0 0', dict(J=0b100, d=0)),
    ('add y0,a', '0 J J J d 0 0 0', dict(J=0b101, d=0)),
    ('add x1,b', '0 J J J d 0 0 0', dict(J=0b110, d=1)),
    ('add y1,a', '0 J J J d 0 0 0', dict(J=0b111, d=0)),
    ('addl b,a', '0 0 0 1 d 0 1 0', dict(d=0)),
    ('addl a,b', '0 0 0 1 d 0 1 0', dict(d=1)),
    ('addr b,a', '0 0 0 0 d 0 1 0', dict(d=0)),
    ('addr a,b', '0 0 0 0 d 0 1 0', dict(d=1)),
    ('and x0,b', '0 1 J J d 1 1 0', dict(J=0, d=1)),
    ('and y1,a', '0 1 J J d 1 1 0', dict(J=3, d=0)),
    ('asl a', '0 0 1 1 d 0 1 0', dict(d=0)),
    ('asl b', '0 0 1 1 d 0 1 0', dict(d=1)),
    ('asr a', '0 0 1 0 d 0 1 0', dict(d=0)),
    ('asr b', '0 0 1 0 d 0 1 0', dict(d=1)),
    ('clr a', '0 0 0 1 d 0 1 1', dict(d=0)),
    ('clr b', '0 0 0 1 d 0 1 1', dict(d=1)),
    ('cmp b,a', '0 J J J d 1 0 1', dict(J=0, d=0)),
    ('cmp a,b', '0 J J J d 1 0 1', dict(J=0, d=1)),
    ('cmp x1,a', '0 J J J d 1 0 1', dict(J=0b110, d=0)),
    ('cmp x0,b', '0 J J J d 1 0 1', dict(J=0b100, d=1)),
    ('cmpm b,a', '0 J J J d 1 1 1', dict(J=0, d=0)),
    ('cmpm y0,b', '0 J J J d 1 1 1', dict(J=0b101, d=1)),
    ('eor y0,a', '0 1 J J d 0 1 1', dict(J=1, d=0)),
    ('eor x1,b', '0 1 J J d 0 1 1', dict(J=2, d=1)),
    ('lsl a', '0 0 1 1 d 0 1 1', dict(d=0)),
    ('lsl b', '0 0 1 1 d 0 1 1', dict(d=1)),
    ('lsr a', '0 0 1 0 d 0 1 1', dict(d=0)),
    ('lsr b', '0 0 1 0 d 0 1 1', dict(d=1)),
    ('neg a', '0 0 1 1 d 1 1 0', dict(d=0)),
    ('neg b', '0 0 1 1 d 1 1 0', dict(d=1)),
    ('not a', '0 0 0 1 d 1 1 1', dict(d=0)),
    ('not b', '0 0 0 1 d 1 1 1', dict(d=1)),
    ('or x1,b', '0 1 J J d 0 1 0', dict(J=2, d=1)),
    ('or y1,a', '0 1 J J d 0 1 0', dict(J=3, d=0)),
    ('rnd a', '0 0 0 1 d 0 0 1', dict(d=0)),
    ('rnd b', '0 0 0 1 d 0 0 1', dict(d=1)),
    ('rol a', '0 0 1 1 d 1 1 1', dict(d=0)),
    ('rol b', '0 0 1 1 d 1 1 1', dict(d=1)),
    ('ror a', '0 0 1 0 d 1 1 1', dict(d=0)),
    ('ror b', '0 0 1 0 d 1 1 1', dict(d=1)),
    ('sbc y,b', '0 0 1 J d 1 0 1', dict(J=1, d=1)),
    ('sbc x,a', '0 0 1 J d 1 0 1', dict(J=0, d=0)),
    ('sub b,a', '0 J J J d 1 0 0', dict(J=0b001, d=0)),
    ('sub y,b', '0 J J J d 1 0 0', dict(J=0b011, d=1)),
    ('sub y0,b', '0 J J J d 1 0 0', dict(J=0b101, d=1)),
    ('subl a,b', '0 0 0 1 d 1 1 0', dict(d=1)),
    ('subr b,a', '0 0 0 0 d 1 1 0', dict(d=0)),
    ('tfr b,a', '0 J J J d 0 0 1', dict(J=0, d=0)),
    ('tfr a,b', '0 J J J d 0 0 1', dict(J=0, d=1)),
    ('tfr y0,b', '0 J J J d 0 0 1', dict(J=0b101, d=1)),
    ('tst a', '0 0 0 0 d 0 1 1', dict(d=0)),
    ('tst b', '0 0 0 0 d 0 1 1', dict(d=1)),
    ('max a,b', '0 0 0 1 1 1 0 1', {}),
    ('maxm a,b', '0 0 0 1 0 1 0 1', {}),
    ('move', '0 0 0 0 0 0 0 0', {}),
]:
    case(text, nm(op, **f))

# Multiplies with the parallel opcode 1QQQdkkk (tables 12-16, 12-19): kk 00 mpy 01 mpyr 10 mac 11 macr.
for text, op, f in [
    ('mpy x0,x0,a', '1 Q Q Q d k 0 0', dict(Q=0b000, d=0, k=0)),
    ('mpy y0,y0,a', '1 Q Q Q d k 0 0', dict(Q=0b001, d=0, k=0)),
    ('mpy x1,x0,a', '1 Q Q Q d k 0 0', dict(Q=0b010, d=0, k=0)),
    ('mpy y1,y0,a', '1 Q Q Q d k 0 0', dict(Q=0b011, d=0, k=0)),
    ('mpy -x0,y1,b', '1 Q Q Q d k 0 0', dict(Q=0b100, d=1, k=1)),
    ('mpy y0,x0,a', '1 Q Q Q d k 0 0', dict(Q=0b101, d=0, k=0)),
    ('mpy x1,y0,a', '1 Q Q Q d k 0 0', dict(Q=0b110, d=0, k=0)),
    ('mpy y1,x1,a', '1 Q Q Q d k 0 0', dict(Q=0b111, d=0, k=0)),
    ('mpyr x1,x0,a', '1 Q Q Q d k 0 1', dict(Q=0b010, d=0, k=0)),
    ('mpyr -y0,y0,b', '1 Q Q Q d k 0 1', dict(Q=0b001, d=1, k=1)),
    ('mac y0,x0,a', '1 Q Q Q d k 1 0', dict(Q=0b101, d=0, k=0)),
    ('mac -x0,x0,b', '1 Q Q Q d k 1 0', dict(Q=0b000, d=1, k=1)),
    ('macr -y1,x1,b', '1 Q Q Q d k 1 1', dict(Q=0b111, d=1, k=1)),
    ('macr x0,y1,a', '1 Q Q Q d k 1 1', dict(Q=0b100, d=0, k=0)),
]:
    case(text, nm(op, **f))

# Parallel move fields (chapter 13 "Parallel Move Descriptions"), ALU op ADD X0,A throughout.
OP, OPF = ADD_X0


def pcase(text, move, ext=(), **mf):
    case('add x0,a ' + text if text else 'add x0,a', par(move, OP, **dict(OPF, **mf)), *ext)


# I: immediate short move; R: register to register; U: address register update
pcase('#$7f,y0', '0 0 1 d d d d d i i i i i i i i', d_=0b00110, i_=0x7F)
pcase('a,x1', '0 0 1 0 0 0 e e e e e d d d d d', e_=0b01110, d_=0b00101)
pcase('r3,n2', '0 0 1 0 0 0 e e e e e d d d d d', e_=0b10011, d_=0b11010)
pcase('(r6)+n6', '0 0 1 0 0 0 0 0 0 1 0 M M R R R', M_=0b01, R_=6)
pcase('(r1)-', '0 0 1 0 0 0 0 0 0 1 0 M M R R R', M_=0b10, R_=1)
pcase('', '0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0')

# X: and Y: memory moves with every effective-address mode (Table 12-13 encoding 1)
EA = [('(r%d)-n%d', 0b000), ('(r%d)+n%d', 0b001), ('(r%d)-', 0b010), ('(r%d)+', 0b011),
      ('(r%d)', 0b100), ('(r%d+n%d)', 0b101), ('-(r%d)', 0b111)]
for fmt, mmm in EA:
    t = fmt % ((5, 5) if fmt.count('%d') == 2 else (5,))
    pcase('x:%s,x0' % t, '0 1 d d 0 d d d W 1 M M M R R R', d_=0b00100, W_=1, M_=mmm, R_=5)
    pcase('b,y:%s' % t, '0 1 d d 1 d d d W 1 M M M R R R', d_=0b01111, W_=0, M_=mmm, R_=5)
pcase('x:$1234,a', '0 1 d d 0 d d d W 1 M M M R R R', (0x001234,), d_=0b01110, W_=1, M_=0b110, R_=0)
pcase('y1,y:$123456', '0 1 d d 1 d d d W 1 M M M R R R', (0x123456,), d_=0b00111, W_=0, M_=0b110, R_=0)
pcase('#$123456,r0', '0 1 d d 0 d d d W 1 M M M R R R', (0x123456,), d_=0b10000, W_=1, M_=0b110, R_=0b100)
pcase('x:<$2a,n7', '0 1 d d 0 d d d W 0 a a a a a a', d_=0b11111, W_=1, a_=0x2A)
pcase('a2,y:<$3f', '0 1 d d 1 d d d W 0 a a a a a a', d_=0b01010, W_=0, a_=0x3F)
# L: long moves, every register pair of Table 12-15
for name, lll in [('a10', 0), ('b10', 1), ('x', 2), ('y', 3), ('a', 4), ('b', 5), ('ab', 6), ('ba', 7)]:
    pcase('l:(r2),%s' % name, '0 1 0 0 L 0 L L W 1 M M M R R R', L_=lll, W_=1, M_=0b100, R_=2)
pcase('ab,l:$1234', '0 1 0 0 L 0 L L W 1 M M M R R R', (0x1234,), L_=6, W_=0, M_=0b110, R_=0)
pcase('l:<$2a,b', '0 1 0 0 L 0 L L W 0 a a a a a a', L_=5, W_=1, a_=0x2A)
pcase('x,l:<$01', '0 1 0 0 L 0 L L W 0 a a a a a a', L_=2, W_=0, a_=1)
# X:Y double moves. Y address register bank is the one X does not use.
pcase('x:(r2)+,x0 y:(r5)+,y0', '1 w m m e e f f W r r M M R R R',
      w_=1, m_=0b11, e_=0, f_=0, W_=1, r_=0b01, M_=0b11, R_=2)
pcase('a,x:(r5)- b,y:(r3)+n3', '1 w m m e e f f W r r M M R R R',
      w_=0, m_=0b01, e_=0b10, f_=0b11, W_=0, r_=0b11, M_=0b10, R_=5)
# X:Y pair, mm = 00 on the X side: this decoder prints (Rn) (no update), reading the manual's
# 2-bit mode table as 00 = no update. MAME's xyeax table treats mm = 00 differently; the manual
# is the source here and the choice has not been checked on hardware.
pcase('x:(r0),x1 a,y:(r6)', '1 w m m e e f f W r r M M R R R',
      w_=0, m_=0b00, e_=0b01, f_=0b10, W_=1, r_=0b10, M_=0b00, R_=0)
pcase('b,x:(r7)+n7 y:(r1)-,y1', '1 w m m e e f f W r r M M R R R',
      w_=1, m_=0b10, e_=0b11, f_=0b01, W_=0, r_=0b01, M_=0b01, R_=7)
# X:R and R:Y, class I and II
pcase('x:(r1)+,a b,y1', '0 0 0 1 f f d F W 0 M M M R R R', f_=0b10, d_=1, F_=1, W_=1, M_=0b011, R_=1)
pcase('x1,x:(r1)+ a,y0', '0 0 0 1 f f d F W 0 M M M R R R', f_=0b01, d_=0, F_=0, W_=0, M_=0b011, R_=1)
pcase('#$123456,x0 b,y0', '0 0 0 1 f f d F W 0 M M M R R R', (0x123456,),
      f_=0b00, d_=1, F_=0, W_=1, M_=0b110, R_=0b100)
pcase('b,x:(r6)+ x0,b', '0 0 0 0 1 0 0 d 0 0 M M M R R R', d_=1, M_=0b011, R_=6)
pcase('b,x1 y:(r4)-,a', '0 0 0 1 d e f f W 1 M M M R R R', d_=1, e_=1, f_=0b10, W_=1, M_=0b010, R_=4)
pcase('a,x0 y0,y:(r2)', '0 0 0 1 d e f f W 1 M M M R R R', d_=0, e_=0, f_=0b00, W_=0, M_=0b100, R_=2)
pcase('y0,a a,y:(r7)', '0 0 0 0 1 0 0 d 1 0 M M M R R R', d_=0, M_=0b100, R_=7)
# IFcc / IFcc.U replace the move field (IFcc, IFcc.U pages, Table 12-18 codes)
case('add x0,a ifge', par('0 0 1 0 0 0 0 0 0 0 1 0 C C C C', OP, C_=0b0001, **OPF))
case('add x0,a ifeq.u', par('0 0 1 0 0 0 0 0 0 0 1 1 C C C C', OP, C_=0b1010, **OPF))
case('mac x0,x0,a ifcc', par('0 0 1 0 0 0 0 0 0 0 1 0 C C C C', '1 Q Q Q d k 1 0', C_=0,
                             Q=0, d=0, k=0))
# MOVE with a move field and no ALU op
case('move x:(r0)+,x0', par('0 1 d d 0 d d d W 1 M M M R R R', '0 0 0 0 0 0 0 0',
                            d_=0b00100, W_=1, M_=0b011, R_=0))
case('move (r3)+n3', par('0 0 1 0 0 0 0 0 0 1 0 M M R R R', '0 0 0 0 0 0 0 0', M_=0b01, R_=3))
# Condition code mnemonics (Table 12-18) through Jcc xxx
for i, cc in enumerate(['cc', 'ge', 'ne', 'pl', 'nn', 'ec', 'lc', 'gt', 'cs', 'lt', 'eq', 'mi',
                        'nr', 'es', 'ls', 'le']):
    case('j%s $0123' % cc, enc('0 0 0 0 1 1 1 0 C C C C a a a a a a a a a a a a', C=i, a=0x123))
    case('t%s x0,a' % cc, enc('0 0 0 0 0 0 1 0 C C C C 0 0 0 0 0 J J J d 0 0 0', C=i, J=4, d=0))

# --------------------------------------------------------------------------------------------
# ALU immediates (ADD, SUB, CMP, AND, EOR, OR pages)
for mn, k in [('add', 0b000), ('sub', 0b100), ('cmp', 0b101), ('and', 0b110), ('eor', 0b011),
              ('or', 0b010)]:
    case('%s #$3f,b' % mn, enc('0 0 0 0 0 0 0 1 0 1 i i i i i i 1 0 0 0 d K K K', i=0x3F, d=1, K=k))
    case('%s #$000001,a' % mn,
         enc('0 0 0 0 0 0 0 1 0 1 0 0 0 0 0 0 1 1 0 0 d K K K', d=0, K=k), 0x000001)
    case('%s #$ffff00,b' % mn,
         enc('0 0 0 0 0 0 0 1 0 1 0 0 0 0 0 0 1 1 0 0 d K K K', d=1, K=k), 0xFFFF00)
# ANDI / ORI (EE: MR, CCR, COM, EOM)
for e, nme in enumerate(['mr', 'ccr', 'com', 'eom']):
    case('andi #$fe,%s' % nme, enc('0 0 0 0 0 0 0 0 i i i i i i i i 1 0 1 1 1 0 E E', i=0xFE, E=e))
    case('ori #$03,%s' % nme, enc('0 0 0 0 0 0 0 0 i i i i i i i i 1 1 1 1 1 0 E E', i=3, E=e))

# Shifts, bit field, normalisation (0x0C1x group)
case('asl #5,b,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 0 1 S i i i i i i D', S=1, i=5, D=0))
case('asr #23,a,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 0 0 S i i i i i i D', S=0, i=23, D=1))
case('asl x0,a,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 1 0 S s s s D', S=0, s=0b100, D=1))
case('asr a1,b,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 1 1 S s s s D', S=1, s=0b010, D=0))
case('lsl #1,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 1 0 i i i i i D', i=1, D=0))
case('lsr #23,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 1 1 i i i i i D', i=23, D=1))
case('lsl y0,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 0 0 1 s s s D', s=0b101, D=1))
case('lsr x1,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 0 1 1 s s s D', s=0b110, D=0))
case('normf y1,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 0 1 0 s s s D', s=0b111, D=0))
case('normf b1,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 0 1 0 s s s D', s=0b011, D=1))
case('clb b,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 0 0 0 0 0 S D', S=1, D=0))
case('cmpu b,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 1 1 1 1 1 g g g d', g=0, d=0))
case('cmpu x0,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 1 1 1 1 1 g g g d', g=0b100, d=1))
case('cmpu y1,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 1 1 1 1 1 g g g d', g=0b111, d=0))
case('merge b1,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 1 1 1 0 0 0 S S S D', S=0b011, D=1))
case('extract x0,b,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 1 0 0 0 0 s S S S D', s=1, S=0b100, D=0))
case('extractu y1,a,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 1 0 1 0 0 s S S S D', s=0, S=0b111, D=1))
case('extract #$00c004,a,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 0 0 0 0 0 s 0 0 0 D', s=0, D=1),
     0x00C004)
case('extractu #$006008,b,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 0 0 1 0 0 s 0 0 0 D', s=1, D=0),
     0x006008)
case('insert x0,a0,a', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 1 1 0 q q q S S S D', q=0b010, S=0b100, D=0))
case('insert #$001000,y1,b', enc('0 0 0 0 1 1 0 0 0 0 0 1 1 0 0 1 0 q q q 0 0 0 D', q=0b111, D=1),
     0x001000)

# Branches. PC-relative targets are absolute word addresses (pc = address of the opcode word).
case('bge $010a', enc('0 0 0 0 0 1 0 1 C C C C 0 1 a a a a 0 a a a a a', C=1, a=10), pc=0x100)
case('bge $00fe', enc('0 0 0 0 0 1 0 1 C C C C 0 1 a a a a 0 a a a a a', C=1, a=0b111111110),
     pc=0x100)
case('bne r3', enc('0 0 0 0 1 1 0 1 0 0 0 1 1 R R R 0 1 0 0 C C C C', R=3, C=2))
case('bra $0210', enc('0 0 0 0 1 1 0 1 0 0 0 1 0 0 0 0 1 1 0 0 0 0 0 0'), 0x10, pc=0x200)
case('bra $0300', enc('0 0 0 0 1 1 0 1 0 0 0 1 0 0 0 0 1 1 0 0 0 0 0 0'), 0xFFFF00, pc=0x400)
case('bra $0143', enc('0 0 0 0 0 1 0 1 0 0 0 0 1 1 a a a a 0 a a a a a', a=0x43), pc=0x100)
case('bra r7', enc('0 0 0 0 1 1 0 1 0 0 0 1 1 R R R 1 1 0 0 0 0 0 0', R=7))
case('bsr $0110', enc('0 0 0 0 1 1 0 1 0 0 0 1 0 0 0 0 1 0 0 0 0 0 0 0'), 0x10, pc=0x100)
case('bsr $0105', enc('0 0 0 0 0 1 0 1 0 0 0 0 1 0 a a a a 0 a a a a a', a=5), pc=0x100)
case('bsr r2', enc('0 0 0 0 1 1 0 1 0 0 0 1 1 R R R 1 0 0 0 0 0 0 0', R=2))
case('bscs $0120', enc('0 0 0 0 0 1 0 1 C C C C 0 0 a a a a 0 a a a a a', C=0b1000, a=0x20), pc=0x100)
case('bsgt r2', enc('0 0 0 0 1 1 0 1 0 0 0 1 1 R R R 0 0 0 0 C C C C', R=2, C=0b0111))
case('bsle $0111', enc('0 0 0 0 1 1 0 1 0 0 0 1 0 0 0 0 0 0 0 0 C C C C', C=0b1111), 0x11, pc=0x100)
# Inferred (the manual prints Bcc xxxx with the short encoding): 0x0D1040|cc beside BRA/BSR xxxx
case('bne $0110', 0x0D1042, 0x10, pc=0x100)

# Jumps
case('jmp $0abc', enc('0 0 0 0 1 1 0 0 0 0 0 0 a a a a a a a a a a a a', a=0xABC))
case('jsr $0123', enc('0 0 0 0 1 1 0 1 0 0 0 0 a a a a a a a a a a a a', a=0x123))
case('jmp (r2)+', enc('0 0 0 0 1 0 1 0 1 1 M M M R R R 1 0 0 0 0 0 0 0', M=3, R=2))
case('jmp $1234', enc('0 0 0 0 1 0 1 0 1 1 M M M R R R 1 0 0 0 0 0 0 0', M=0b110, R=0), 0x1234)
case('jsr -(r1)', enc('0 0 0 0 1 0 1 1 1 1 M M M R R R 1 0 0 0 0 0 0 0', M=7, R=1))
case('jsr $023456', enc('0 0 0 0 1 0 1 1 1 1 M M M R R R 1 0 0 0 0 0 0 0', M=0b110, R=0), 0x023456)
case('jne (r1)+', enc('0 0 0 0 1 0 1 0 1 1 M M M R R R 1 0 1 0 C C C C', M=3, R=1, C=2))
case('jscs (r4)', enc('0 0 0 0 1 0 1 1 1 1 M M M R R R 1 0 1 0 C C C C', M=4, R=4, C=8))
case('jscc $0123', enc('0 0 0 0 1 1 1 1 C C C C a a a a a a a a a a a a', C=0, a=0x123))
# Bit-test jumps: ea, aa, pp, qq, register forms (the manual's four-bit b is read as five bits)
for mn, ea_hi, bits_t, qbit in [('jclr', '1010', '0', '0'), ('jset', '1010', '1', '0'),
                                ('jsclr', '1011', '0', '1'), ('jsset', '1011', '1', '1')]:
    h = '0 0 0 0 ' + ' '.join(ea_hi)
    t = ' '.join(bits_t)
    case('%s #3,x:(r0)+,$0123' % mn,
         enc(h + ' 0 1 M M M R R R 1 S ' + t + ' b b b b b', M=3, R=0, S=0, b=3), 0x123)
    case('%s #23,y:(r5)-n5,$ffff' % mn,
         enc(h + ' 0 1 M M M R R R 1 S ' + t + ' b b b b b', M=0, R=5, S=1, b=23), 0xFFFF)
    case('%s #0,x:<$15,$0200' % mn,
         enc(h + ' 0 0 a a a a a a 1 S ' + t + ' b b b b b', a=0x15, S=0, b=0), 0x200)
    case('%s #7,y:<<$ffffc5,$0200' % mn,
         enc(h + ' 1 0 p p p p p p 1 S ' + t + ' b b b b b', p=5, S=1, b=7), 0x200)
    case('%s #1,x:<<$ffff90,$0200' % mn,
         enc('0 0 0 0 0 0 0 1 1 ' + qbit + ' q q q q q q 1 S ' + t + ' b b b b b', q=0x10, S=0, b=1),
         0x200)
    case('%s #4,x0,$0200' % mn,
         enc(h + ' 1 1 D D D D D D 0 0 ' + t + ' b b b b b', D=0b000100, b=4), 0x200)
# Branch on bit: displacement relative to the opcode word address
for mn, hi4, t, qs in [('brclr', '1100', '0', '0'), ('brset', '1100', '1', '0'),
                       ('bsclr', '1101', '0', '1'), ('bsset', '1101', '1', '1')]:
    h = '0 0 0 0 ' + ' '.join(hi4)
    tb = ' '.join(t)
    case('%s #3,x:(r0)+,$0310' % mn, enc(h + ' 1 0 M M M R R R 0 S ' + tb + ' b b b b b', M=3, R=0, S=0, b=3), 0x10, pc=0x300)
    case('%s #5,y:<$15,$02f0' % mn, enc(h + ' 1 0 a a a a a a 1 S ' + tb + ' b b b b b', a=0x15, S=1, b=5), 0xFFFFF0, pc=0x300)
    case('%s #2,x:<<$ffffd0,$0310' % mn, enc(h + ' 1 1 p p p p p p 0 S ' + tb + ' b b b b b', p=0x10, S=0, b=2), 0x10, pc=0x300)
    case('%s #9,y:<<$ffff81,$0310' % mn, enc('0 0 0 0 0 1 0 0 1 0 q q q q q q ' + qs + ' S ' + tb + ' b b b b b', q=1, S=1, b=9), 0x10, pc=0x300)
    case('%s #6,a1,$0310' % mn, enc(h + ' 1 1 D D D D D D 1 0 ' + tb + ' b b b b b', D=0b001100, b=6), 0x10, pc=0x300)

# Bit manipulation. BCLR/BSET share 0x0A, BCHG/BTST 0x0B; bit 5 selects set/test (0 clr/chg).
for mn, hi4, t, qsub in [('bclr', '1010', '0', '00'), ('bset', '1010', '1', '00'),
                         ('bchg', '1011', '0', '01'), ('btst', '1011', '1', '01')]:
    h = '0 0 0 0 ' + ' '.join(hi4)
    tb = ' '.join(t)
    case('%s #7,y:(r2)' % mn, enc(h + ' 0 1 M M M R R R 0 S ' + tb + ' b b b b b', M=0b100, R=2, S=1, b=7))
    case('%s #4,x:$1234' % mn, enc(h + ' 0 1 M M M R R R 0 S ' + tb + ' b b b b b', M=0b110, R=0, S=0, b=4), 0x1234)
    case('%s #0,x:<$15' % mn, enc(h + ' 0 0 a a a a a a 0 S ' + tb + ' b b b b b', a=0x15, S=0, b=0))
    case('%s #3,y:<<$ffffc5' % mn, enc(h + ' 1 0 p p p p p p 0 S ' + tb + ' b b b b b', p=5, S=1, b=3))
    case('%s #1,x:<<$ffff90' % mn, enc('0 0 0 0 0 0 0 1 ' + ' '.join(qsub) + ' q q q q q q 0 S ' + tb + ' b b b b b', q=0x10, S=0, b=1))
    case('%s #2,a2' % mn, enc(h + ' 1 1 D D D D D D 0 1 ' + tb + ' b b b b b', D=0b001010, b=2))
    case('%s #20,sr' % mn, enc(h + ' 1 1 D D D D D D 0 1 ' + tb + ' b b b b b', D=0b111001, b=20))

# Loops
case('do #8,$0123', enc('0 0 0 0 0 1 1 0 i i i i i i i i 1 0 0 0 h h h h', i=8, h=0), 0x122)
case('do #4095,$0200', enc('0 0 0 0 0 1 1 0 i i i i i i i i 1 0 0 0 h h h h', i=0xFF, h=0xF), 0x1FF)
case('do y:(r0),$0123', enc('0 0 0 0 0 1 1 0 0 1 M M M R R R 0 S 0 0 0 0 0 0', M=0b100, R=0, S=1), 0x122)
case('do x:<$20,$0123', enc('0 0 0 0 0 1 1 0 0 0 a a a a a a 0 S 0 0 0 0 0 0', a=0x20, S=0), 0x122)
case('do a1,$0123', enc('0 0 0 0 0 1 1 0 1 1 D D D D D D 0 0 0 0 0 0 0 0', D=0b001100), 0x122)
case('do forever,$0123', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 1 1'), 0x122)
case('dor #8,$0111', enc('0 0 0 0 0 1 1 0 i i i i i i i i 1 0 0 1 h h h h', i=8, h=0), 0x10, pc=0x100)
case('dor x:(r1)+,$0111', enc('0 0 0 0 0 1 1 0 0 1 M M M R R R 0 S 0 1 0 0 0 0', M=3, R=1, S=0), 0x10, pc=0x100)
case('dor y:<$20,$0111', enc('0 0 0 0 0 1 1 0 0 0 a a a a a a 0 S 0 1 0 0 0 0', a=0x20, S=1), 0x10, pc=0x100)
case('dor r3,$0111', enc('0 0 0 0 0 1 1 0 1 1 D D D D D D 0 0 0 1 0 0 0 0', D=0b010011), 0x10, pc=0x100)
case('dor forever,$0111', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 1 0'), 0x10, pc=0x100)
case('rep #5', enc('0 0 0 0 0 1 1 0 i i i i i i i i 1 0 1 0 h h h h', i=5, h=0))
case('rep x:(r1)', enc('0 0 0 0 0 1 1 0 0 1 M M M R R R 0 S 1 0 0 0 0 0', M=4, R=1, S=0))
case('rep y:<$20', enc('0 0 0 0 0 1 1 0 0 0 a a a a a a 0 S 1 0 0 0 0 0', a=0x20, S=1))
case('rep r3', enc('0 0 0 0 0 1 1 0 1 1 d d d d d d 0 0 1 0 0 0 0 0', d=0b010011))
case('enddo', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 1 1 0 0'))
case('brkne', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 1 C C C C', C=2))

# No-operand instructions (each page's opcode)
for text, bits in [
    ('nop', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0'),
    ('rti', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0'),
    ('rts', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 0'),
    ('illegal', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 1'),
    ('trap', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0'),
    ('reset', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 1 0 0'),
    ('stop', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 1 1 1'),
    ('wait', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 1 1 0'),
    ('debug', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0'),
    ('pflush', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1'),
    ('pflushun', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1'),
    ('pfree', '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0'),
]:
    case(text, enc(bits))
case('inc a', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 d', d=0))
case('inc b', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 d', d=1))
case('dec a', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 1 d', d=0))
case('dec b', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 1 d', d=1))
case('debugpl', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 0 0 0 C C C C', C=3))
case('trapmi', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 C C C C', C=0b1011))
case('plock (r1)+', enc('0 0 0 0 1 0 1 1 1 1 M M M R R R 1 0 0 0 0 0 0 1', M=3, R=1))
case('punlock (r1)+', enc('0 0 0 0 1 0 1 0 1 1 M M M R R R 1 0 0 0 0 0 0 1', M=3, R=1))
case('plockr $0110', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1'), 0x10, pc=0x100)
case('punlockr $0110', enc('0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 0'), 0x10, pc=0x100)

# Tcc (three forms)
case('tge x0,a', enc('0 0 0 0 0 0 1 0 C C C C 0 0 0 0 0 J J J d 0 0 0', C=1, J=0b100, d=0))
case('tge a,b', enc('0 0 0 0 0 0 1 0 C C C C 0 0 0 0 0 J J J d 0 0 0', C=1, J=0, d=1))
case('tne y0,b r3,r5', enc('0 0 0 0 0 0 1 1 C C C C 0 t t t 0 J J J d T T T', C=2, t=3, J=0b101, d=1, T=5))
case('teq r0,r7', enc('0 0 0 0 0 0 1 0 C C C C 1 t t t 0 0 0 0 0 T T T', C=0b1010, t=0, T=7))

# Multiplies without parallel move
case('div y0,b', enc('0 0 0 0 0 0 0 1 1 0 0 0 0 0 0 0 0 1 J J d 0 0 0', J=1, d=1))
case('norm r4,b', enc('0 0 0 0 0 0 0 1 1 1 0 1 1 R R R 0 0 0 1 d 1 0 1', R=4, d=1))
for ss, nme, qqqq, k, d, txt in [(0b00, 'ss', 0b0000, 0, 0, 'x0,x0'), (0b10, 'su', 0b1100, 1, 1, 'y1,x0'),
                                 (0b11, 'uu', 0b1111, 0, 0, 'x1,y1')]:
    case('dmac%s %s%s,%s' % (nme, '-' if k else '', txt, 'ab'[d]),
         enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 0 s 1 s d k Q Q Q Q', s=ss, d=d, k=k, Q=qqqq))
case('macsu y0,x0,a', enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 1 0 1 s d k Q Q Q Q', s=0, d=0, k=0, Q=0b0101))
case('macuu -x0,x1,b', enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 1 0 1 s d k Q Q Q Q', s=1, d=1, k=1, Q=0b1010))
case('mpysu x1,y0,a', enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 1 1 1 s d k Q Q Q Q', s=0, d=0, k=0, Q=0b0110))
case('mpyuu y0,y1,b', enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 1 1 1 s d k Q Q Q Q', s=1, d=1, k=0, Q=0b1011))
case('macsu y1,y1,a', enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 1 0 1 s d k Q Q Q Q', s=0, d=0, k=0, Q=0b1001))
# S,#n,D uses a five-bit n (bits 12-8) even where the diagram shows four
for mn, kk in [('mpy', 0b00), ('mpyr', 0b01), ('mac', 0b10), ('macr', 0b11)]:
    case('%s x0,#3,a' % mn, enc('0 0 0 0 0 0 0 1 0 0 0 s s s s s 1 1 Q Q d k K K', s=3, Q=1, d=0, k=0, K=kk))
    case('%s -y1,#22,b' % mn, enc('0 0 0 0 0 0 0 1 0 0 0 s s s s s 1 1 Q Q d k K K', s=22, Q=0, d=1, k=1, K=kk))
    case('%si #$400000,y0,a' % mn, enc('0 0 0 0 0 0 0 1 0 1 0 0 0 0 0 1 1 1 q q d k K K', q=1, d=0, k=0, K=kk), 0x400000)
    case('%si -#$000100,x1,b' % mn, enc('0 0 0 0 0 0 0 1 0 1 0 0 0 0 0 1 1 1 q q d k K K', q=2, d=1, k=1, K=kk), 0x000100)

# LRA, LUA
case('lra r1,x0', enc('0 0 0 0 0 1 0 0 1 1 0 0 0 R R R 0 0 0 d d d d d', R=1, d=0b00100))
case('lra $0120,n2', enc('0 0 0 0 0 1 0 0 0 1 0 0 0 0 0 0 0 1 0 d d d d d', d=0b11010), 0x20, pc=0x100)
case('lua (r2)+,r3', enc('0 0 0 0 0 1 0 0 0 1 0 M M R R R 0 0 0 d d d d d', M=3, R=2, d=0b10011))
case('lua (r0)-n0,n7', enc('0 0 0 0 0 1 0 0 0 1 0 M M R R R 0 0 0 d d d d d', M=0, R=0, d=0b11111))
case('lua (r1+$05),n3', enc('0 0 0 0 0 1 0 0 0 0 a a a R R R a a a a d d d d', a=5, R=1, d=0b1011))
case('lua (r1-$01),r0', enc('0 0 0 0 0 1 0 0 0 0 a a a R R R a a a a d d d d', a=0x7F, R=1, d=0))

# MOVEC / MOVEM / MOVEP / MOVE with displacement
case('movec x:(r0)+,sr', enc('0 0 0 0 0 1 0 1 W 1 M M M R R R 0 S 1 d d d d d', W=1, M=3, R=0, S=0, d=0b11001))
case('movec sr,x:(r0)+', enc('0 0 0 0 0 1 0 1 W 1 M M M R R R 0 S 1 d d d d d', W=0, M=3, R=0, S=0, d=0b11001))
case('movec y:<$10,sp', enc('0 0 0 0 0 1 0 1 W 0 a a a a a a 0 S 1 d d d d d', W=1, a=0x10, S=1, d=0b11011))
case('movec la,y:<$3f', enc('0 0 0 0 0 1 0 1 W 0 a a a a a a 0 S 1 d d d d d', W=0, a=0x3F, S=1, d=0b11110))
case('movec r3,m0', enc('0 0 0 0 0 1 0 0 W 1 e e e e e e 1 0 1 d d d d d', W=1, e=0b010011, d=0))
case('movec m0,r3', enc('0 0 0 0 0 1 0 0 W 1 e e e e e e 1 0 1 d d d d d', W=0, e=0b010011, d=0))
case('movec #$08,omr', enc('0 0 0 0 0 1 0 1 i i i i i i i i 1 0 1 d d d d d', i=8, d=0b11010))
case('movec #$123456,m1', enc('0 0 0 0 0 1 0 1 W 1 M M M R R R 0 S 1 d d d d d', W=1, M=0b110, R=0b100, S=0, d=1), 0x123456)
case('movec x:$0012,ssh', enc('0 0 0 0 0 1 0 1 W 1 M M M R R R 0 S 1 d d d d d', W=1, M=0b110, R=0, S=0, d=0b11100), 0x12)
case('movem p:(r2)+,a', enc('0 0 0 0 0 1 1 1 W 1 M M M R R R 1 0 d d d d d d', W=1, M=3, R=2, d=0b001110))
case('movem a,p:(r2)+', enc('0 0 0 0 0 1 1 1 W 1 M M M R R R 1 0 d d d d d d', W=0, M=3, R=2, d=0b001110))
case('movem p:<$3f,x0', enc('0 0 0 0 0 1 1 1 W 0 a a a a a a 0 0 d d d d d d', W=1, a=0x3F, d=0b000100))
case('movem r5,p:<$01', enc('0 0 0 0 0 1 1 1 W 0 a a a a a a 0 0 d d d d d d', W=0, a=1, d=0b010101))
# MOVEP: high I/O with X/Y ea, P ea and register; low I/O X:qq / Y:qq / P; register low forms
case('movep y:(r0)+,x:<<$ffffff', enc('0 0 0 0 1 0 0 s W 1 M M M R R R 1 S p p p p p p', s=0, W=1, M=3, R=0, S=1, p=0x3F))
case('movep x:<<$ffffff,y:(r0)+', enc('0 0 0 0 1 0 0 s W 1 M M M R R R 1 S p p p p p p', s=0, W=0, M=3, R=0, S=1, p=0x3F))
case('movep p:(r1),y:<<$ffffc0', enc('0 0 0 0 1 0 0 s W 1 M M M R R R 0 1 p p p p p p', s=1, W=1, M=4, R=1, p=0))
case('movep y:<<$ffffc3,p:(r1)+', enc('0 0 0 0 1 0 0 s W 1 M M M R R R 0 1 p p p p p p', s=1, W=0, M=3, R=1, p=3))
case('movep x:<<$ffffe0,a', enc('0 0 0 0 1 0 0 s W 1 d d d d d d 0 0 p p p p p p', s=0, W=0, d=0b001110, p=0x20))
case('movep r2,y:<<$ffffd1', enc('0 0 0 0 1 0 0 s W 1 d d d d d d 0 0 p p p p p p', s=1, W=1, d=0b010010, p=0x11))
case('movep #$000200,x:<<$fffffe', enc('0 0 0 0 1 0 0 s W 1 M M M R R R 1 S p p p p p p', s=0, W=1, M=0b110, R=0b100, S=0, p=0x3E), 0x000200)
case('movep x:(r2)+,x:<<$ffff85', enc('0 0 0 0 0 1 1 1 W 1 M M M R R R 0 S q q q q q q', W=1, M=3, R=2, S=0, q=5))
case('movep x:<<$ffffbf,y:(r2)+', enc('0 0 0 0 0 1 1 1 W 1 M M M R R R 0 S q q q q q q', W=0, M=3, R=2, S=1, q=0x3F))
case('movep x:(r3),y:<<$ffff81', enc('0 0 0 0 0 1 1 1 W 0 M M M R R R 1 S q q q q q q', W=1, M=4, R=3, S=0, q=1))
case('movep y:<<$ffff90,y:(r3)-', enc('0 0 0 0 0 1 1 1 W 0 M M M R R R 1 S q q q q q q', W=0, M=2, R=3, S=1, q=0x10))
case('movep p:(r4)+,y:<<$ffff90', enc('0 0 0 0 0 0 0 0 1 W M M M R R R 0 S q q q q q q', W=1, M=3, R=4, S=1, q=0x10))
case('movep x:<<$ffff82,p:(r4)+', enc('0 0 0 0 0 0 0 0 1 W M M M R R R 0 S q q q q q q', W=0, M=3, R=4, S=0, q=2))
case('movep x0,x:<<$ffffa1', enc('0 0 0 0 0 1 0 0 W 1 d d d d d d 1 q 0 q q q q q', W=1, d=0b000100, q=0x21))
case('movep y:<<$ffff82,r0', enc('0 0 0 0 0 1 0 0 W 1 d d d d d d 0 q 1 q q q q q', W=0, d=0b010000, q=2))
case('move x:(r2+$0010),x0', enc('0 0 0 0 1 0 1 0 0 1 1 1 0 R R R 1 W D D D D D D', R=2, W=1, D=0b000100), 0x10)
case('move x0,x:(r2-$0010)', enc('0 0 0 0 1 0 1 0 0 1 1 1 0 R R R 1 W D D D D D D', R=2, W=0, D=0b000100), 0xFFFFF0)
case('move y:(r7+$1234),r3', enc('0 0 0 0 1 0 1 1 0 1 1 1 0 R R R 1 W D D D D D D', R=7, W=1, D=0b010011), 0x1234)
# Short displacement: the seven bits are read left to right, most significant first
case('move x:(r3+$05),x0', enc('0 0 0 0 0 0 1 a a a a a a R R R 1 a 0 W D D D D', a=5, R=3, W=1, D=0b0100))
case('move a,y:(r1-$01)', enc('0 0 0 0 0 0 1 a a a a a a R R R 1 a 1 W D D D D', a=0x7F, R=1, W=0, D=0b1110))
case('move y:(r0+$3f),b0', enc('0 0 0 0 0 0 1 a a a a a a R R R 1 a 1 W D D D D', a=0x3F, R=0, W=1, D=0b1001))
case('vsl b,1,l:(r0)+', enc('0 0 0 0 1 0 1 S 1 1 M M M R R R 1 1 0 i 0 0 0 0', S=1, M=3, R=0, i=1))
case('vsl a,0,l:(r5)', enc('0 0 0 0 1 0 1 S 1 1 M M M R R R 1 1 0 i 0 0 0 0', S=0, M=4, R=5, i=0))

# Words the tables do not decode print as '?'
for w in [0x200008,    # JJJ=000 D=1 kkk=000: reserved (Table 12-21)
          0x200004,    # JJJ=000 kkk=100: reserved (Table 12-20)
          0x0000B0,    # no instruction in this part of the 0x0000xx block
          0x0000F0,
          0x21E000,    # R-R move into reserved register code 0
          0x0C1F00,    # CMPU needs 1111 in bits 7-4
          0x0D1020,    # long-form Bcc/BScc with a reserved low byte
          enc('0 0 0 0 0 0 0 1 0 0 1 0 0 1 0 s 1 s d k Q Q Q Q', s=0b01, d=0, k=0, Q=0),  # DMAC ss=01
          enc('0 0 0 0 0 0 0 1 0 0 0 s s s s s 1 1 Q Q d k 0 0', s=0, Q=0, d=0, k=0),     # n=0
          enc('0 0 0 0 0 0 0 1 0 0 0 s s s s s 1 1 Q Q d k 0 0', s=23, Q=0, d=0, k=0),    # n=23
          enc('0 0 0 0 1 1 0 0 0 0 0 1 1 1 1 0 0 1 0 S s s s D', S=0, s=0b001, D=0),      # sss=001
          enc('0 0 0 0 0 1 0 1 W 1 M M M R R R 0 S 1 d d d d d', W=1, M=3, R=0, S=0, d=0b01000),  # reg 101000
          enc('0 0 0 0 0 0 1 0 C C C C 0 0 0 0 0 J J J d 0 0 0', C=0, J=0b001, d=0),      # Tcc JJJ=001
          par('0 1 d d 0 d d d W 1 M M M R R R', '0 0 0 0 0 0 0 0', d_=4, W_=0, M_=0b110, R_=0b100),  # store imm
          enc('0 0 0 0 1 0 1 0 1 1 M M M R R R 1 0 0 0 0 0 0 0', M=0b110, R=0b100),       # jmp #imm
          ]:
    case('?', w)


class Dis(unittest.TestCase):
    def test_cases(self):
        for cs in CASES:
            with self.subTest(text=cs.text, words=['%06x' % w for w in cs.words]):
                # Extension words follow; the decoder must also be given extra junk words.
                words = cs.words + [0xAAAAAA, 0x555555]
                text, n = dis.disassemble(words, cs.pc)
                self.assertEqual(text, cs.text)
                if text != '?':
                    self.assertEqual(n, len(cs.words))
                    # Same answer with exactly the words the instruction uses
                    self.assertEqual(dis.disassemble(cs.words, cs.pc), (text, n))
                else:
                    self.assertEqual(n, 1)

    def test_missing_extension_word_is_undecoded(self):
        word = enc('0 0 0 0 0 1 1 0 i i i i i i i i 1 0 0 0 h h h h', i=8, h=0)   # DO #8,expr
        self.assertEqual(dis.disassemble([word], 0), ('?', 1))
        self.assertEqual(dis.disassemble([word, 0x000122], 0), ('do #8,$0123', 2))

    def test_empty_input_is_a_caller_error(self):
        with self.assertRaises(ValueError):
            dis.disassemble([], 0)

    def test_wide_ints_are_masked_to_24_bits(self):
        self.assertEqual(dis.disassemble([0x1000000 | 0x200010], 0), ('add b,a', 1))

    def test_stream(self):
        words = [0x060880, 0x000122, 0x200010, 0x200008, 0x0D0123, 0x44F400]   # last: ext missing
        got = list(dis.decode_stream(words, 0x100))
        self.assertEqual([(i.address, i.length) for i in got],
                         [(0x100, 2), (0x102, 1), (0x103, 1), (0x104, 1), (0x105, 1)])
        self.assertEqual(got[0].text, 'do #8,$0123')
        self.assertEqual(got[0].words, (0x060880, 0x000122))
        self.assertEqual(got[1].text, 'add b,a')
        self.assertFalse(got[2].valid)
        self.assertEqual(got[2].text, dis.UNDECODED)
        self.assertEqual(got[3].text, 'jsr $0123')
        self.assertFalse(got[4].valid)     # long immediate with no extension word left
        self.assertTrue(got[1].valid)

    def test_stream_branch_targets_use_the_instruction_address(self):
        # BRA xxx at 0x100 with displacement +0x43
        w = enc('0 0 0 0 0 1 0 1 0 0 0 0 1 1 a a a a 0 a a a a a', a=0x43)
        got = list(dis.decode_stream([0, 0, w], 0x0FE))
        self.assertEqual(got[2].address, 0x100)
        self.assertEqual(got[2].text, 'bra $0143')

    def test_text_parser_and_cli(self):
        self.assertEqual(dis._parse_text('200010 ; add\n$0d0123 0x44F400\n'),
                         [0x200010, 0x0D0123, 0x44F400])
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'prog.txt')
            with open(p, 'w') as fh:
                fh.write('060880 000122\n200010\n')
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(dis.main(['--base', '0x40', p]), 0)
            self.assertEqual(buf.getvalue().splitlines(), [
                '000040: 060880 000122        do #8,$0123',
                '000042: 200010               add b,a'])
            pb = os.path.join(d, 'prog.bin')
            with open(pb, 'wb') as fh:
                fh.write(bytes([0x20, 0x00, 0x10, 0x0D, 0x01, 0x23]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                dis.main(['--bin', pb])
            self.assertEqual([l.split(None, 2)[-1] for l in buf.getvalue().splitlines()],
                             ['add b,a', 'jsr $0123'])
            with open(pb, 'wb') as fh:
                fh.write(bytes([0x10, 0x00, 0x20]))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                dis.main(['--bin-le', pb])
            self.assertTrue(buf.getvalue().strip().endswith('add b,a'))


class Tables(unittest.TestCase):
    def test_every_pattern_wins_on_its_own_words(self):
        # Fill each pattern's variable bits at random: the table must pick that pattern. The only
        # documented exception is a long absolute/immediate ea (110xxx) in the bit-test jumps,
        # which the manual's MOVE X:(Rn+xxxx) diagram claims.
        rnd = random.Random(1)
        for p in dis.PATS:
            for _ in range(300):
                w = p.value | (rnd.getrandbits(24) & ~p.mask & 0xFFFFFF)
                m = dis.match(w)
                if m is p:
                    continue
                self.assertEqual(m.name, 'move', (p.name, p.text, '%06x' % w, m.name))
                self.assertIn(p.name, ('jclr', 'jset', 'jsclr', 'jsset'))
                self.assertEqual((w >> 11) & 7, 0b110, '%06x' % w)

    def test_only_the_documented_pairs_overlap(self):
        pats = dis.PATS
        found = set()
        for i, a in enumerate(pats):
            for b in pats[i + 1:]:
                common = a.mask & b.mask
                if (a.value & common) == (b.value & common):
                    found.add(tuple(sorted((a.name, b.name))))
        self.assertEqual(found, {('jclr', 'move'), ('jset', 'move'), ('jsclr', 'move'),
                                 ('jsset', 'move')})

    def test_register_table(self):
        # Table 12-14 triple-bit encodings, spot checks of every group
        want = {0b000100: 'x0', 0b000111: 'y1', 0b001000: 'a0', 0b001010: 'a2', 0b001110: 'a',
                0b001111: 'b', 0b010000: 'r0', 0b010111: 'r7', 0b011000: 'n0', 0b011111: 'n7',
                0b100000: 'm0', 0b100111: 'm7', 0b101010: 'ep', 0b110000: 'vba', 0b110001: 'sc',
                0b111000: 'sz', 0b111001: 'sr', 0b111010: 'omr', 0b111011: 'sp', 0b111100: 'ssh',
                0b111101: 'ssl', 0b111110: 'la', 0b111111: 'lc'}
        for code, name in want.items():
            self.assertEqual(dis.REG6[code], name)
        for code in [0, 1, 2, 3, 0b101000, 0b101001, 0b101011, 0b110010, 0b110111]:
            self.assertIsNone(dis.REG6[code])

    def test_never_raises_on_structured_words(self):
        # Every top 16 bits with a spread of low bytes, with and without extension words, and
        # every low 16 bits under every top byte pattern of the instruction groups.
        un = 0
        for hi in range(1 << 16):
            for lo in (0x00, 0x01, 0x08, 0x2A, 0x55, 0x80, 0xB7, 0xFF):
                w = hi << 8 | lo
                t, n = dis.disassemble([w, 0x123456, 0xFFFFFF], 0xFFFFF0)
                self.assertTrue(1 <= n <= 3)
                un += t == '?'
                t1, n1 = dis.disassemble([w], 0)
                self.assertTrue(n1 == 1 or t1 != '?')
        self.assertGreater(un, 0)
        for top in range(256):
            for lo16 in range(0, 1 << 16, 7):
                t, n = dis.disassemble([top << 16 | lo16, 0, 0], 0)
                self.assertTrue(1 <= n <= 3)


if __name__ == '__main__':
    unittest.main()
