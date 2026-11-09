#!/usr/bin/env python3
"""Tests of fifo_words.py that need no binary: constant folding, the stack, joins and delay slots.

Run from the repository root: python3 scripts/test_fifo_words.py
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('fifo_words', os.path.join(HERE, 'fifo_words.py'))
fw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fw)


class FakeImage:
    def read32(self, addr):
        return None, None

    def name(self, addr):
        return None


def program(lines):
    """Build Insn records from (op, args) pairs at consecutive addresses from 0x1000."""
    return [fw.Insn(0x1000 + 4 * i, 0, op, args) for i, (op, args) in enumerate(lines)]


def stores(insns):
    ctx = fw.Ctx(FakeImage(), (0x10000, 0x11000), 0x1000)
    entry = fw.State()
    entry.r['sp'] = ('S', 'sp', 0)
    for n in ('a0', 'a1'):
        entry.r[n] = ('S', n, 0)
    blocks, succ, instate, by_addr = fw.fixpoint(insns, ctx, entry)
    out = []
    for b in sorted(blocks):
        if b not in instate:
            continue
        st = instate[b].copy()
        ev = []
        fw.run_block(ctx, st, blocks[b], succ[b][0], by_addr, ev)
        out += [e for e in ev if e[0] == 'store' and e[4] is not None and e[4][0] == 'C'
                and 0x10000 <= e[4][1] < 0x11000]
    return out


class FifoWords(unittest.TestCase):
    def test_constants_and_context_loads(self):
        ins = program([
            ('lui', 'a4,0x1'), ('ori', 'a5,a4,0x443'), ('sw', 'a5,0(a4)'),
            ('lw', 'a6,27964(a0)'), ('sw', 'a6,0(a4)'), ('jr', 'ra'), ('nop', ''),
        ])
        ev = stores(ins)
        self.assertEqual(fw.fmt_word(ev[0][5]), '0x00010443')
        self.assertEqual(fw.fmt_word(ev[1][5]), 'u32[a0+0x6d3c]')

    def test_stack_spill_keeps_the_value(self):
        ins = program([
            ('sd', 'a0,16(sp)'), ('lui', 'a4,0x1'), ('ld', 'a5,16(sp)'),
            ('lw', 'a6,8(a5)'), ('sw', 'a6,0(a4)'), ('jr', 'ra'), ('nop', ''),
        ])
        ev = stores(ins)
        self.assertEqual(fw.fmt_word(ev[0][5]), 'u32[a0+0x8]')

    def test_join_keeps_only_agreeing_values(self):
        ins = program([
            ('lui', 'a4,0x1'),           # 1000
            ('beqz', 'a1,0x1014'),       # 1004
            ('nop', ''),                 # 1008 delay slot
            ('li', 'a5,1'),              # 100c
            ('b', '0x1018'),             # 1010 (never both) -> falls to join
            ('nop', ''),                 # 1014
            ('sw', 'a5,0(a4)'),          # 1018
            ('jr', 'ra'), ('nop', ''),
        ])
        ev = stores(ins)
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0][5], fw.UNK)

    def test_delay_slot_runs_before_the_branch_effect(self):
        ins = program([
            ('lui', 'a4,0x1'), ('b', '0x1010'), ('sw', 'a0,0(a4)'), ('nop', ''),
            ('jr', 'ra'), ('nop', ''),
        ])
        ev = stores(ins)
        self.assertEqual([fw.render(e[5]) for e in ev], ['a0'])


if __name__ == '__main__':
    unittest.main()
