#!/usr/bin/env python3
"""Tests of capability_tree.py that need no binary: branch-likely tests on loaded words and jumps
through a table, on small hand-written instruction sequences.

Run from the repository root through tools/re-run: python3 scripts/test_capability_tree.py
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('capability_tree', os.path.join(HERE, 'capability_tree.py'))
ct = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ct)


class FakeImage:
    """Big-endian words at fixed addresses, a gp, and 32-bit GOT slots."""
    gsz = 4

    def __init__(self, gp, words):
        self.gp = gp
        self.words = words

    def read(self, addr, width):
        if width == 4 and addr in self.words:
            return (self.words[addr] & 0xffffffff).to_bytes(4, 'big')
        return None


def sheet(lines, tables=()):
    """lines: (address, text) pairs; the first is the routine's entry."""
    return {'insns': [['0x%x' % a, t] for a, t in lines], 'calls': [],
            'routine': {'address': '0x%x' % lines[0][0]}, 'jump_tables': list(tables)}


def summary(paths):
    """(conditions, return value) per path, sorted, with each path's stores."""
    out = []
    for ev, conds, fin in paths:
        out.append((tuple((c[1], c[2]) for c in conds), [e[0] for e in ev], fin[1]))
    return sorted(out, key=repr)


class BranchLikely(unittest.TestCase):
    def prog(self, branch):
        return sheet([
            (0x1000, 'lw t0,24(a1)'),
            (0x1004, branch),
            (0x1008, 'sw a0,0(a2)'),            # delay slot: runs only when the branch is taken
            (0x100c, 'ori v0,zero,0x2'),
            (0x1010, 'jr ra'),
            (0x1014, 'nop'),
            (0x1018, 'ori v0,zero,0x1'),
            (0x101c, 'jr ra'),
            (0x1020, 'nop'),
        ])

    def test_beql_on_loaded_value_forks_and_skips_the_slot_when_not_taken(self):
        w = ct.Walker(self.prog('beql t0,zero,1018'))
        got = summary(w.run(0))
        self.assertEqual(len(got), 2)
        taken = [g for g in got if g[0][0][1] is True][0]
        fall = [g for g in got if g[0][0][1] is False][0]
        self.assertEqual(taken[0][0][0], '[a1+24] == 0')
        self.assertEqual(taken[1], ['store'])       # the delay slot ran
        self.assertEqual(taken[2], '1')
        self.assertEqual(fall[1], [])               # the delay slot was skipped
        self.assertEqual(fall[2], '2')

    def test_bnel_takes_the_opposite_sense(self):
        w = ct.Walker(self.prog('bnel t0,zero,1018'))
        got = summary(w.run(0))
        self.assertEqual({(g[0][0][1], g[2]) for g in got}, {(True, '1'), (False, '2')})
        self.assertIn('!= 0', [g for g in got if g[0][0][1]][0][0][0][0])

    def test_zero_compare_forms(self):
        for mn, rel in (('bnezl', '!='), ('beqzl', '=='), ('bgtzl', '>'), ('bltzl', '<'), ('blezl', '<='), ('bgezl', '>=')):
            text = '%s t0,1018' % mn
            got = summary(ct.Walker(self.prog(text)).run(0))
            self.assertEqual(len(got), 2, mn)
            self.assertIn(' %s 0' % rel, [g for g in got if g[0][0][1]][0][0][0][0], mn)

    def test_decided_branch_likely_does_not_fork(self):
        s = self.prog('beql a0,zero,1018')            # a0 is a concrete 0
        self.assertEqual(len(ct.Walker(s).run(0)), 1)
        self.assertEqual(ct.Walker(s).run(0)[0][2][1], '1')
        self.assertEqual(ct.Walker(s).run(5)[0][2][1], '2')


class O32Spellings(unittest.TestCase):
    def test_page_address_in_a_register_names_the_same_word_as_a_zero_base(self):
        s = sheet([(0x1000, 'addiu v0,zero,4096'), (0x1004, 'lw v1,16(v0)'), (0x1008, 'lw t0,1792(v1)'),
                   (0x100c, 'ori t0,t0,0x40'), (0x1010, 'sw t0,1792(v1)'), (0x1014, 'jr ra'), (0x1018, 'nop')])
        ((ev, _, _),) = ct.Walker(s).run(0)
        self.assertEqual(ct.describe(ev, ('ret', ''), False), '[ctx+1792] |= 0x40; return')

    def test_byte_masked_truth_value_reads_like_the_unmasked_one(self):
        s = sheet([(0x1000, 'lw t0,1792(a1)'), (0x1004, 'andi t0,t0,0x40'), (0x1008, 'sltu v0,zero,t0'),
                   (0x100c, 'andi v0,v0,0xff'), (0x1010, 'jr ra'), (0x1014, 'nop')])
        ((ev, _, fin),) = ct.Walker(s).run(0)
        self.assertEqual(ct.describe(ev, fin, True),
                         'return 1 if ([a1+1792] & 0x40) is nonzero, else 0')


def table_program(index_lines, with_table=True):
    """An o32-style routine at 0x1000 whose gp is 0x3000; case targets 0x1060, 0x1070, 0x1080."""
    gp = 0x3000
    targets = [0x1060, 0x1070, 0x1060]
    lines = [
        (0x1000, 'lui gp,0x0'),
        (0x1004, 'addiu gp,gp,8192'),
        (0x1008, 'addu gp,gp,t9'),
    ] + index_lines
    a = 0x100c + 4 * len(index_lines)
    tail = [
        (a, 'sll t7,t7,0x2'),
        (a + 4, 'addu at,at,t7'),
        (a + 8, 'lw t7,16(at)'),
        (a + 12, 'addu t7,t7,gp'),
        (a + 16, 'jr t7'),
        (a + 20, 'nop'),
    ]
    lines += tail
    assert a + 24 <= 0x1050, hex(a)
    lines += [(0x1050, 'ori v0,zero,0x63'), (0x1054, 'jr ra'), (0x1058, 'nop')]       # out of range
    lines += [(0x1060, 'ori v0,zero,0x1'), (0x1064, 'jr ra'), (0x1068, 'nop')]
    lines += [(0x1070, 'ori v0,zero,0x2'), (0x1074, 'jr ra'), (0x1078, 'nop')]
    words = {0x3000 - 16: 0x5000}                                  # GOT slot: the table's page
    for i, t in enumerate(targets):
        words[0x5010 + 4 * i] = t - gp                             # gp-relative, negative
    t = [{'jump': '0x%x' % (a + 16), 'table': '0x5010', 'entry_width': 4,
          'targets': ['0x%x' % x for x in targets]}] if with_table else []
    return lines, FakeImage(gp, words), t


INDEX_FROM_A0 = [
    (0x100c, 'move t7,a0'),
    (0x1010, 'sltiu at,t7,3'),
    (0x1014, 'beq at,zero,1050'),
    (0x1018, 'nop'),
    (0x101c, 'lw at,-16(gp)'),
]
INDEX_FROM_MEMORY = [
    (0x100c, 'lw t7,0(a1)'),
    (0x1010, 'nop'),
    (0x1014, 'nop'),
    (0x1018, 'nop'),
    (0x101c, 'lw at,-16(gp)'),
]


class JumpTable(unittest.TestCase):
    def test_table_resolved_from_the_image_per_value(self):
        lines, img, tabs = table_program(INDEX_FROM_A0)
        w = ct.Walker(sheet(lines, tabs), img)
        self.assertEqual([summary(w.run(v))[0][2] for v in range(5)], ['1', '2', '1', '0x63', '0x63'])
        for v in range(3):
            self.assertEqual(len(w.run(v)), 1)          # one case, no fork

    def test_resolves_without_the_fact_sheet_table(self):
        lines, img, _ = table_program(INDEX_FROM_A0, with_table=False)
        w = ct.Walker(sheet(lines), img)
        self.assertEqual(summary(w.run(1))[0][2], '2')

    def test_symbolic_index_forks_per_distinct_target(self):
        lines, img, tabs = table_program(INDEX_FROM_MEMORY)
        w = ct.Walker(sheet(lines, tabs), img)
        got = summary(w.run(0))
        self.assertEqual(sorted(g[2] for g in got), ['1', '2'])
        self.assertTrue(all(g[0][-1][1] and 'jump table' in g[0][-1][0] for g in got))

    def test_unresolvable_table_is_refused(self):
        lines, img, _ = table_program(INDEX_FROM_MEMORY, with_table=False)
        w = ct.Walker(sheet(lines), img)
        with self.assertRaises(ct.Unsupported):
            w.run(0)

    def test_target_outside_the_table_is_refused(self):
        lines, img, tabs = table_program(INDEX_FROM_A0)
        tabs[0]['targets'] = ['0x1060']                  # the image says 0x1070 for index 1
        w = ct.Walker(sheet(lines, tabs), img)
        with self.assertRaises(ct.Unsupported):
            w.run(1)

    def test_jr_ra_is_still_a_return(self):
        w = ct.Walker(sheet([(0x1000, 'ori v0,zero,0x7'), (0x1004, 'jr ra'), (0x1008, 'nop')]))
        self.assertEqual(summary(w.run(0))[0][2], '7')


if __name__ == '__main__':
    unittest.main()
