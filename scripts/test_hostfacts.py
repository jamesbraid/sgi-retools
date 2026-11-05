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


def cop1x(rs, rt, rd, sh, fn):
    return (0x13 << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (sh << 6) | fn


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

    def test_mips_iv_cop1x_opcodes(self):
        cases = [
            (cop1x(1, 2, 3, 4, 0x20), 'madd.s', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x21), 'madd.d', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x28), 'msub.s', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x29), 'msub.d', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x30), 'nmadd.s', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x31), 'nmadd.d', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x38), 'nmsub.s', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(1, 2, 3, 4, 0x39), 'nmsub.d', ['$f4', '$f1', '$f3', '$f2']),
            (cop1x(8, 9, 10, 0, 0x00), 'lwxc1', ['$f10', '$8', '$9']),
            (cop1x(8, 9, 10, 0, 0x01), 'ldxc1', ['$f10', '$8', '$9']),
            (cop1x(8, 9, 10, 0, 0x08), 'swxc1', ['$f10', '$8', '$9']),
            (cop1x(8, 9, 10, 0, 0x09), 'sdxc1', ['$f10', '$8', '$9']),
            (cop1x(8, 9, 10, 0, 0x0f), 'prefx', ['$10', '$8', '$9']),
        ]
        for word, mnemonic, operands in cases:
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(hostfacts.decode(word, BASE), (mnemonic, operands))


class Cop1xAccesses(unittest.TestCase):
    def test_indexed_fp_accesses_have_their_architectural_width(self):
        words = [
            cop1x(8, 9, 10, 0, 0x00),
            cop1x(8, 9, 10, 0, 0x01),
            cop1x(8, 9, 10, 0, 0x08),
            cop1x(8, 9, 10, 0, 0x09),
            jr(RA), NOP,
        ]
        _, fs, _ = routine(words)
        self.assertEqual([(a['mnemonic'], a['width']) for a in fs['accesses']], [
            ('lwxc1', 4), ('ldxc1', 8), ('swxc1', 4), ('sdxc1', 8),
        ])
        self.assertTrue(all(a['base'] == 'a4' and a['origin'] == '(a4 + a5)'
                            for a in fs['accesses']))

    def test_standard_fp_load_store_widths(self):
        words = [I(0x31, 8, 10, 4), I(0x35, 8, 10, 8),
                 I(0x39, 8, 10, 12), I(0x3d, 8, 10, 16), jr(RA), NOP]
        _, fs, _ = routine(words)
        self.assertEqual([(a['mnemonic'], a['width']) for a in fs['accesses']], [
            ('lwc1', 4), ('ldc1', 8), ('swc1', 4), ('sdc1', 8),
        ])


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


class UnconditionalBranchDelay(unittest.TestCase):
    def test_return_uses_delay_slot_write(self):
        words = [
            I(4, 0, 0, 2),             # b 0x100c
            daddu(V0, 0, 0),           # move v0,zero in the delay slot
            daddiu(V0, 0, 1),          # skipped
            jr(RA),
            NOP,
        ]
        _, fs, text = routine(words)
        self.assertEqual(fs['exits'][0]['v0'], '0x0')
        self.assertIn('delay slot 0x1004', text)


class DelaySlotThatIsAlsoATarget(unittest.TestCase):
    """One instruction is one access, whichever way it was reached."""
    T0 = 8
    WORDS = [
        daddu(T0, A1, 0),                           # 1000 t0 = a1
        br(0x04, A3, 0, BASE + 4, BASE + 0x14),     # 1004 beq a3,zero,1014: jumps to the slot below
        NOP,                                        # 1008
        daddu(T0, A2, 0),                           # 100c t0 = a2
        br(0x04, A0, A1, BASE + 0x10, BASE + 0x1c),  # 1010 beq a0,a1,101c
        lw(V0, 8, T0),                              # 1014 its delay slot, and the target of 1004
        jr(RA),                                     # 1018
        NOP,                                        # 101c
        jr(RA),
        NOP,
    ]

    def test_one_record_and_the_paths_disagree(self):
        _, fs, text = routine(self.WORDS)
        loads = [a for a in fs['accesses'] if a['address'] == '0x1014']
        self.assertEqual(len(loads), 1)
        # a1 on one path and a2 on the other: the base is unknown, not whichever path came first
        self.assertEqual(loads[0]['base_origin'], '?')
        self.assertNotIn('origin', loads[0])
        self.assertEqual(text.count('0x1014 load'), 1)
        self.assertIn('=> ? (base unknown)', text)

    def test_agreeing_paths_keep_the_base(self):
        words = list(self.WORDS)
        words[3] = daddu(self.T0, A1, 0)            # both paths hold a1
        _, fs, _ = routine(words)
        loads = [a for a in fs['accesses'] if a['address'] == '0x1014']
        self.assertEqual(len(loads), 1)
        self.assertEqual((loads[0]['origin'], loads[0]['origin_offset']), ('a1', 8))


class IndirectJumpTable(unittest.TestCase):
    def test_unresolved_indexed_table_is_explicit(self):
        t0, t1, t9 = 8, 9, 25
        words = [
            lui(t0, 0x1001),
            Rt(0, A0, t1, 0x00, 2),  # sll t1,a0,2
            daddu(t0, t0, t1),
            lw(t9, 0, t0),
            jr(t9),
            NOP,
            jr(RA),
            NOP,
        ]
        _, _, text = routine(words)
        self.assertIn('(jump table; successors unresolved)', text)
        self.assertIn('CFG incomplete', text)


class RecognisedTableEntry(unittest.TestCase):
    """A table-entry value the analyzer could not expand is still a jump table."""

    class Stub:
        insns = [{'mn': 'jr', 'ops': ['$4'], 'addr': 0x58}]

        def __init__(self, v):
            self.in_states = {0: hostfacts.facts.State({4: v})}

    def test_entry_value_is_unresolved_table(self):
        self.assertTrue(hostfacts.unresolved_table_jump(self.Stub(('tent', ('sym', '.rodata', 0), 8)), 0))
        self.assertTrue(hostfacts.unresolved_table_jump(self.Stub(('tent_gp', 0x100, 4, 0x2000)), 0))

    def test_unknown_value_is_not_called_a_table(self):
        self.assertFalse(hostfacts.unresolved_table_jump(self.Stub(('in', 'a0')), 0))


class UnreachableBranch(unittest.TestCase):
    def test_unreachable_branch_does_not_require_an_input_state(self):
        words = [
            I(4, 0, 0, 2),             # b 0x1010
            NOP,
            I(4, 0, 0, 2),             # unreachable branch
            NOP,
            jr(RA),
            NOP,
        ]
        _, _, text = routine(words)
        self.assertIn('(never reached)', text)

    def test_unreachable_block_is_not_a_predecessor(self):
        words = [
            I(4, 0, 0, 3),             # b 0x1010
            NOP,
            I(4, 0, 0, 1),             # unreachable: branches to 0x100c
            NOP,
            jr(RA),                    # 0x1010
            NOP,
        ]
        r, fs, text = routine(words)
        blocks = [l for l in text.splitlines() if l.startswith('  B') and 'preds:' in l]
        target = [l for l in blocks if '0x1010-' in l][0]
        self.assertIn('preds: B0', target)
        self.assertNotIn('B1', target.split('preds:')[1])


class UnreachableDefinition(unittest.TestCase):
    def test_last_definition_skips_unreachable_instruction(self):
        class Stub:
            insns = [
                {'mn': 'daddiu', 'ops': ['$8', '$4', '1']},
                {'mn': 'daddiu', 'ops': ['$8', '$4', '2']},
                {'mn': 'bne', 'ops': ['$8', '$0', '20']},
            ]
            in_states = {0: {}, 2: {8: ('in', 'a0')}}

        block = hostfacts.Block('B0', 0, 2)
        self.assertEqual(hostfacts.find_def(Stub(), block, 2, 8), 0)


class UnanalyzedConditionSource(unittest.TestCase):
    def test_fp_branch_reports_missing_comparison_state(self):
        class Stub:
            insns = [
                {'mn': 'c.eq.s', 'ops': ['$fcc0', '$f2', '$f4'], 'addr': BASE},
                {'mn': 'bc1t', 'ops': ['$fcc0', '1010'], 'addr': BASE + 4},
            ]
            in_states = {1: object()}

        block = hostfacts.Block('B0', 0, 1)
        self.assertEqual(hostfacts.cond_words(Stub(), block, 1),
                         ('(condition not analyzed)', '(condition not analyzed)'))


class OptionalKonaGfxRepro(unittest.TestCase):
    ROOT = '/path/to/re-roots/kona/root'
    OBJECTS = (
        ('usr/cpu/sysgen/IP27boot/gfx.o', None),
        ('usr/cpu/sysgen/IP35boot/gfx.o', None),
        ('usr/cpu/sysgen/IP27boot/gfxs.a', 'gfx.o'),
        ('usr/cpu/sysgen/IP35boot/gfxs.a', 'gfx.o'),
    )

    @unittest.skipUnless(os.path.isdir(ROOT), 'optional Kona root is not present')
    def test_gfx_shcheck_renders(self):
        for relative, member in self.OBJECTS:
            path = os.path.join(self.ROOT, relative)
            if not os.path.isfile(path):
                continue
            with self.subTest(binary=relative):
                r = hostfacts.routine_for(path, 'gfx_shcheck', member=member)
                self.assertIn('blocks (', hostfacts.render(r, r.facts(False)))


class OptionalLibGLRepro(unittest.TestCase):
    BINARY = ('/path/to/re-roots/odsy/root/builds/'
              '6.5.30-media/usr/gfx/arch/IP30ODSY/libGL.so')
    ROUTINES = ('__glXGetDrawableAttributes', '__glXSendMakeCurrentRead', 'GetFBConfigsSGIX')

    @unittest.skipUnless(os.path.isfile(BINARY), 'optional libGL root is not present')
    def test_real_routines_render(self):
        for name in self.ROUTINES:
            with self.subTest(routine=name):
                r = hostfacts.routine_for(self.BINARY, name)
                fs = r.facts(False)
                self.assertIn('blocks (', hostfacts.render(r, fs))


class OptionalOdsyLibGLCoreRepro(unittest.TestCase):
    BINARY = ('/path/to/re-roots/odsy/root/builds/'
              '6.5.30-media/usr/gfx/arch/IP30ODSY/libGLcore.so')
    ROUTINES = ('ImageChainAddOpConvolve', 'ImageChainAddOpConvolveResidue', 'Clampf')
    CLAMPF_ADDRESSES = ('0xd9eb61c', '0xda91338')

    @unittest.skipUnless(os.path.isfile(BINARY), 'optional ODSY libGLcore root is not present')
    def test_reported_routines_render_missing_conditions(self):
        for name in self.ROUTINES[:2]:
            with self.subTest(routine=name):
                r = hostfacts.routine_for(self.BINARY, name)
                text = hostfacts.render(r, r.facts(False))
                self.assertIn('blocks (', text)
                self.assertIn('(condition not analyzed)', text)
        for address in self.CLAMPF_ADDRESSES:
            with self.subTest(routine='Clampf', address=address):
                r = hostfacts.routine_for(self.BINARY, address, size=0x40)
                text = hostfacts.render(r, r.facts(False))
                self.assertIn('blocks (', text)
                self.assertIn('(condition not analyzed)', text)


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
