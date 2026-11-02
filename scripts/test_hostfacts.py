#!/usr/bin/env python3
"""Tests of scripts/hostfacts.py on small hand-assembled code blobs.

Run: uv run --with capstone --with pyelftools python -I scripts/test_hostfacts.py
(skipped when Capstone or pyelftools is missing). The blobs are loaded as flat payloads at 0x1000.
"""
import os
import struct
import sys
import tempfile
import unittest
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import capstone  # noqa: F401
    import elftools  # noqa: F401
except ImportError:
    print('test_hostfacts: needs capstone and pyelftools; skipped')
    sys.exit(0)

import hostfacts  # noqa: E402

warnings.simplefilter('ignore', ResourceWarning)    # facts.Image reads its file without closing it

BASE = 0x1000
A0, A1, A2, A3, V0, RA = 4, 5, 6, 7, 2, 31


def I(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xffff)


def Rt(rs, rt, rd, fn, sh=0):
    return (rs << 21) | (rt << 16) | (rd << 11) | (sh << 6) | fn


def lui(rt, v):
    return I(0x0f, 0, rt, v)


def ori(rt, rs, v):
    return I(0x0d, rs, rt, v)


def daddiu(rt, rs, v):
    return I(0x19, rs, rt, v)


def lw(rt, off, base):
    return I(0x23, base, rt, off)


def sw(rt, off, base):
    return I(0x2b, base, rt, off)


def daddu(rd, rs, rt):
    return Rt(rs, rt, rd, 0x2d)


def sltu(rd, rs, rt):
    return Rt(rs, rt, rd, 0x2b)


def jr(rs):
    return Rt(rs, 0, 0, 0x08)


def jal(target):
    return (3 << 26) | ((target >> 2) & 0x3ffffff)


def br(op, rs, rt, at, target):
    return I(op, rs, rt, (target - (at + 4)) >> 2)


NOP = 0


def routine(words):
    """The hostfacts Routine and its fact sheet for a flat blob of instruction words."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, 'blob.bin')
        with open(p, 'wb') as f:
            f.write(b''.join(struct.pack('>I', w) for w in words))
        r = hostfacts.routine_for(p, hex(BASE), flat=True, load=BASE, size=4 * len(words))
        fs = r.facts(False)
        fs['routine']['file'] = 'blob.bin'
        return r, fs, hostfacts.render(r, fs)


class Decode(unittest.TestCase):
    def test_objdump_numeric_forms(self):
        cases = [
            (0x00000000, 'sll', ['$0', '$0', '0x0']),
            (0x00802021, 'addu', ['$4', '$4', '$0']),          # capstone calls it move
            (0x00042023, 'subu', ['$4', '$0', '$4']),          # negu
            (0x3c050001, 'lui', ['$5', '0x1']),
            (0x24a5ffff, 'addiu', ['$5', '$5', '-1']),
            (0x8fbf0010, 'lw', ['$31', '16($29)']),
            (0x000420c0, 'sll', ['$4', '$4', '0x3']),
            (0x1000fffe, 'beq', ['$0', '$0', 'ffc']),           # b
            (0x10800003, 'beq', ['$4', '$0', '1010']),          # beqz
            (0x54800003, 'bnel', ['$4', '$0', '1010']),
            (0x0c000800, 'jal', ['2000']),
            (0x03e00008, 'jr', ['$31']),
        ]
        for w, mn, ops in cases:
            self.assertEqual(hostfacts.decode(w, BASE), (mn, ops), hex(w))


class NegativeDisplacement(unittest.TestCase):
    WORDS = [
        lui(8, 1),                  # $8 = 0x10000
        daddu(8, 8, A0),            # $8 = a0 + 0x10000
        lw(9, -0x6954, 8),          # a0 + 0x96ac, not a0 - 0x6954 and not a0 + 0x6954
        lui(10, 3),
        sw(A1, -0x7000, 10),        # absolute 0x29000
        jr(RA),
        NOP,
    ]

    def test_resolved_offsets(self):
        r, fs, text = routine(self.WORDS)
        ld, st = fs['accesses']
        self.assertEqual((ld['origin'], ld['origin_offset'], ld['offset']), ('a0', 0x96ac, -0x6954))
        self.assertEqual(st['absolute'], '0x29000')
        self.assertIn('disp -0x6954 => a0 (arg0 at entry) +0x96ac', text)
        self.assertIn('disp -0x7000 => abs 0x29000', text)


class BranchLikely(unittest.TestCase):
    WORDS = [
        br(0x14, A0, 0, BASE, BASE + 0x14),     # 1000 beql a0,zero,1014
        sw(A1, 0, A2),                          # 1004 delay slot
        lw(V0, 4, A0),                          # 1008
        jr(RA),                                 # 100c
        NOP,                                    # 1010
        jr(RA),                                 # 1014
        daddiu(V0, 0, 7),                       # 1018
    ]

    def test_condition_and_annulment(self):
        r, fs, text = routine(self.WORDS)
        self.assertIn('taken when a0 == 0 -> B', text)
        self.assertIn('falls through when a0 != 0 -> B', text)
        self.assertIn('branch-likely: runs only when taken, annulled on fall-through', text)
        self.assertEqual(fs['branch_likely'], ['0x1000'])

    def test_returns_see_the_right_arm(self):
        r, fs, text = routine(self.WORDS)
        v0 = {e['address']: e['v0'] for e in fs['exits']}
        self.assertEqual(v0['0x100c'], '[a0+4]')
        self.assertEqual(v0['0x1014'], '0x7')


class PlainBranch(unittest.TestCase):
    def test_unsigned_compare_in_words(self):
        words = [
            sltu(8, A0, A1),                    # t = a0 < a1 (unsigned)
            br(0x05, 8, 0, BASE + 4, BASE + 0x10),   # bne t,zero
            NOP,
            jr(RA),
            NOP,
            jr(RA),
            NOP,
        ]
        r, fs, text = routine(words)
        self.assertIn('taken when a0 < a1 (unsigned)', text)
        self.assertIn('falls through when a0 >= a1 (unsigned)', text)
        self.assertIn('runs on both paths', text)


class CallArguments(unittest.TestCase):
    def test_arguments_before_the_call(self):
        words = [
            lui(A1, 0x1234),
            ori(A1, A1, 0x5678),
            jal(0x2000),
            daddiu(A2, 0, 5),                   # delay slot sets a2
            jr(RA),
            NOP,
        ]
        r, fs, text = routine(words)
        self.assertIn('jal (unnamed) [0x2000]', text)
        self.assertIn('a0=a0 at entry (arg0), a1=0x12345678, a2=0x5, a3=a3 at entry (arg3)', text)


if __name__ == '__main__':
    unittest.main()
