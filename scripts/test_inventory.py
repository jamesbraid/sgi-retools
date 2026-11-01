#!/usr/bin/env python3
"""Tests of the rules in inventory.py that do not need root/: the `computes` count, the scope filter, the
per-build credit of the functions table, the template cap, the
function boundaries of the register-access scan and the credit of same-named functions.

Run from the repository root: python3 scripts/test_inventory.py
"""
import importlib.util
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('inventory', os.path.join(HERE, 'inventory.py'))
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)

FILLER_ONLY = ('- `mCramToWram` (`memove.S` line 32, at 0xd4a2): **inferred**, copies a block from control memory '
               'to working memory. It gives lanes 1 and 2 their own register-1 offsets (adds of 1 and 2 at 0xd4a3 '
               'and 0xd4a7) and stores the loaded words through register 1 (0xd4ab, 0xd4ae). Its input is the '
               'block at register 0 and its output the same words in working memory.')
REAL = ('- `odsy_EdidCksum` (`odsy_ddc.o`, offset 0x1c58): **established.** Computes the EDID block checksum: it '
        'adds the 128 bytes at its argument, keeps the sum modulo 256 and returns it, so a valid block gives 0.')
CONVERTS = ('- `mgeb_LineStipple` (`line.S` line 1520, at 0x62a7): **inferred**, glLineStipple. Its operands are the '
            'repeat factor (command word 0) and the pattern (word 1). It converts the factor to float (code 0x73), '
            'computes its reciprocal with a seed and a Newton step and stores that result at engine word 0x25e.')
NEGATED = ('- `mmo_DebugGE` (`debug.S` line 215, at 0x4a8d): **inferred**, a vertex-path stage that does no '
           'arithmetic. It takes the successor word, passes the batch on and returns the batch unchanged.')
MOVER_WITH_TWO_OPS = ('- `f` (`x.S` line 1, at 0x1): **inferred**, copies the input words to the output. It scales '
                      'the first by 16.0 and clamps the second to 1.0, and the result is the block.')


class Computes(unittest.TestCase):
    def test_filler_closing_sentence_does_not_count(self):
        self.assertFalse(inv.computes(FILLER_ONLY))

    def test_input_output_words_alone_do_not_count(self):
        self.assertFalse(inv.computes('Copies a block. Its input is the source, its output the target and the '
                                      'result is the same words.'))

    def test_an_operation_without_inputs_and_outputs_does_not_count(self):
        self.assertFalse(inv.computes('**inferred**, converts the factor to float and scales it.'))

    def test_described_operation_counts(self):
        self.assertTrue(inv.computes(REAL))
        self.assertTrue(inv.computes(CONVERTS))

    def test_no_arithmetic_does_not_count(self):
        self.assertFalse(inv.computes(NEGATED))

    def test_a_mover_needs_two_operations(self):
        self.assertTrue(inv.computes(MOVER_WITH_TWO_OPS))
        self.assertFalse(inv.computes('**inferred**, copies the input words to the output. It scales the first by 16.0; the result is the block.'))


def fake_images(*specs):
    return [{'label': lab, 'path': lab.split('(')[0], 'copies': copies} for lab, copies in specs]


def fake_rows(binary, *names):
    return [{'binary': binary, 'name': n, 'status': 'undocumented'} for n in names]


class Scope(unittest.TestCase):
    def setUp(self):
        self.imgs = fake_images(('usr/k/kernel.o', ['usr/k/kernel-copy.o']), ('usr/x/Xserver', []))
        self.rows = (fake_rows('usr/k/kernel.o', 'bcopy', 'cpu_idle', 'crimeIoctl', 'vfs_open') +
                     fake_rows('usr/x/Xserver', 'XDrawLine', 'xfs_read'))

    def run_rules(self, rules, touch=()):
        rows = [dict(r) for r in self.rows]
        rep, problems = inv.apply_scope({'scope': rules}, self.imgs, rows, set(touch))
        return rows, rep, problems

    def test_no_rules_leaves_everything_in(self):
        rows, rep, problems = self.run_rules([])
        self.assertEqual(problems, [])
        self.assertEqual({r['scope'] for r in rows}, {'in'})

    def test_names_and_patterns_exclude(self):
        rows, rep, problems = self.run_rules([
            {'binaries': ['usr/k/kernel.o'], 'names': ['bcopy'], 'patterns': ['vfs_.*'], 'reason': 'generic kernel'}])
        self.assertEqual(problems, [])
        out = sorted(r['name'] for r in rows if r['scope'] == 'out:1')
        self.assertEqual(out, ['bcopy', 'vfs_open'])
        self.assertEqual(rep[0]['rows'], 2)

    def test_a_rule_reaches_only_its_binaries(self):
        rows, rep, problems = self.run_rules([
            {'binaries': ['usr/x/Xserver'], 'patterns': ['x.*'], 'reason': 'generic'}])
        self.assertEqual([r['name'] for r in rows if r['scope'] != 'in'], ['xfs_read'])

    def test_a_copy_label_selects_the_binary(self):
        rows, rep, problems = self.run_rules([
            {'binaries': ['usr/k/kernel-copy.o'], 'names': ['bcopy'], 'reason': 'generic'}])
        self.assertEqual(problems, [])
        self.assertEqual(rep[0]['rows'], 1)

    def test_refuses_to_exclude_a_function_that_touches_graphics(self):
        rows, rep, problems = self.run_rules(
            [{'binaries': ['usr/k/kernel.o'], 'patterns': ['.*Ioctl'], 'reason': 'generic'}],
            touch=[('usr/k/kernel.o', 'crimeIoctl')])
        self.assertEqual(len(problems), 1)
        self.assertIn('crimeIoctl', problems[0])
        self.assertIn('register window', problems[0])

    def test_touch_in_another_binary_does_not_block(self):
        rows, rep, problems = self.run_rules(
            [{'binaries': ['usr/k/kernel.o'], 'names': ['bcopy'], 'reason': 'generic'}],
            touch=[('usr/x/Xserver', 'bcopy')])
        self.assertEqual(problems, [])

    def test_a_rule_needs_a_reason_and_matches(self):
        _, _, problems = self.run_rules([{'binaries': ['usr/k/kernel.o'], 'names': ['bcopy']}])
        self.assertTrue(any('no reason' in p for p in problems))
        _, _, problems = self.run_rules([{'binaries': ['usr/k/kernel.o'], 'names': ['gone', 'bcopy'],
                                          'patterns': ['nomatch_.*'], 'reason': 'r'}])
        self.assertTrue(any('name gone' in p for p in problems))
        self.assertTrue(any('pattern nomatch_' in p for p in problems))
        _, _, problems = self.run_rules([{'binaries': ['usr/k/kernel.o'], 'reason': 'r'}])
        self.assertTrue(any('no names and no patterns' in p for p in problems))

    def test_out_of_scope_rows_leave_the_counts_and_are_reported(self):
        rows, _, _ = self.run_rules([{'binaries': ['usr/k/kernel.o'], 'patterns': ['.*'], 'reason': 'generic'}])
        row = inv.summary_row('functions', rows, '', sum(1 for r in rows if r.get('_out')))
        self.assertEqual((row['rows'], row['out_of_scope'], row['undocumented']), (2, 4, 2))
        self.assertEqual(row['pct_understood'], '0.0')


class CodeGroups(unittest.TestCase):
    FUNCS = {'usr/diags/irsaudit': {'nic_setup': ('.text', 0x1007af50, 72, {'dynsym'}, 'ec74f03d23e6'),
                                    'only_here': ('.text', 0x1007b000, 8, {'dynsym'}, 'aaaa')},
             'usr/lib/a.so': {'shared': ('.text', 0x100, 8, {'dynsym'}, 'bbbb')},
             'usr/lib/b.so': {'shared': ('.text', 0x200, 8, {'dynsym'}, 'bbbb')}}

    def test_a_microcode_symbol_of_the_same_name_is_a_second_build(self):
        g = inv.code_groups(self.FUNCS, [{'program': 'arm1.u', 'kind': 'symbol', 'name': 'nic_setup'}])
        # two different codes: an entry about the arm1.u routine no longer credits the ELF function by name
        self.assertEqual(len(set(g['nic_setup'].values())), 2)
        self.assertEqual(len(set(g['only_here'].values())), 1)

    def test_equal_code_shares_a_group_and_nameless_rows_add_nothing(self):
        g = inv.code_groups(self.FUNCS, [{'program': 'ge.u', 'kind': 'label', 'name': ''},
                                         {'program': 'ge.u', 'kind': 'label', 'name': 'not_an_elf_name'}])
        self.assertEqual(len(set(g['shared'].values())), 1)
        self.assertNotIn('not_an_elf_name', g)


class TemplateCap(unittest.TestCase):
    ROWS = ['| `HP_COLOR3B` | 3 | `__glkonim_Color3b` | Current colour from three signed bytes scaled into the colour range. | inferred |',
            '| `HP_COLOR3S` | 3 | `__glkonim_Color3s` | Current colour from three signed shorts scaled into the colour range. | inferred |',
            '| `HP_COLOR3I` | 3 | `__glkonim_Color3i` | Current colour from three signed integers scaled into the colour range. | inferred |',
            '| `HP_COLOR4UB` | 4 | `__glkonim_Color4ub` | Current colour from four unsigned bytes scaled into the colour range. | inferred |',
            '| `HP_COLOR4US` | 4 | `__glkonim_Color4us` | Current colour from four unsigned shorts scaled into the colour range. | inferred |',
            '| `HP_COLOR4UI` | 4 | `__glkonim_Color4ui` | Current colour from four unsigned integers scaled into the colour range. | inferred |']

    def capped(self, rows, data=True):
        ents = [inv.Entry(r, 'understood', data=data) for r in rows]
        count = inv.collections.Counter(sk for e in ents for sk in {sk for sk, n, ev in e.sents if sk is not None})
        return [e.cap(count) for e in ents]

    def test_a_frame_filled_with_different_types_is_one_sentence(self):
        self.assertEqual(len({inv.cap_key(r.split('|')[4]) for r in self.ROWS}), 1)
        self.assertEqual(self.capped(self.ROWS), [True] * 6)
        self.assertEqual(self.capped(self.ROWS[:5]), [False] * 5)

    def test_different_sentences_stay_apart(self):
        self.assertNotEqual(inv.cap_key('Current colour from three signed bytes scaled into the colour range.'),
                            inv.cap_key('Current normal from three signed bytes scaled to unit length.'))

    def test_a_short_cell_repeated_word_for_word_counts(self):
        rows = ['| `row_a%d` | 0x%x | prints payload, then hangs | **Established** |' % (i, i) for i in range(6)]
        self.assertEqual(self.capped(rows), [True] * 6)
        self.assertEqual(self.capped(rows[:5]), [False] * 5)

    def test_short_cells_around_different_values_stay_apart(self):
        rows = ['| `DoReq%d` | 0x%x | writes register 0x%x | **Established** |' % (i, i, 0x2300 + i) for i in range(6)]
        self.assertEqual(self.capped(rows), [False] * 6)


class SplitRuns(unittest.TestCase):
    @staticmethod
    def ins(*addrs):
        return [[a, 'sw', ['$2', '0($3)'], None, None] for a in addrs]

    def test_a_stripped_routine_leaves_the_exported_label_before_it(self):
        # objdump labels only the 108-byte exported routine; the stores after it are another routine's
        runs = [['__glCrmEnableDepthTest', self.ins(0x1000, 0x1068, 0x106c, 0x1070, 0x10a0)]]
        table = {'__glCrmEnableDepthTest': ['.text', 0x1000, 108, {'dynsym'}, '']}
        got = [(n, [i[0] for i in ii]) for n, ii in inv.split_runs(runs, table)]
        self.assertEqual(got, [('__glCrmEnableDepthTest', [0x1000, 0x1068]),
                               ('routine@0x106c', [0x106c, 0x1070, 0x10a0])])

    def test_a_procedure_table_start_names_the_routine(self):
        runs = [['f', self.ins(0x1000, 0x1004, 0x1010, 0x1014)]]
        table = {'f': ['.text', 0x1000, 8, {'dynsym'}, ''], 'ClearDepth': ['.text', 0x1010, 0, {'mdebug'}, '']}
        got = [(n, [i[0] for i in ii]) for n, ii in inv.split_runs(runs, table)]
        self.assertEqual(got, [('f', [0x1000, 0x1004]), ('ClearDepth', [0x1010, 0x1014])])

    def test_a_tail_reached_by_a_branch_stays_with_the_routine(self):
        # a slow path the routine branches into keeps its live registers, so it is not cut off
        runs = [['f', self.ins(0x1000) + [[0x1004, 'bc1f', ['1010'], None, None]] + self.ins(0x1008, 0x1010, 0x1014)]]
        table = {'f': ['.text', 0x1000, 0x10, {'dynsym'}, ''], 'tail': ['.text', 0x1010, 8, {'dwarf'}, '']}
        self.assertEqual([n for n, ii in inv.split_runs(runs, table)], ['f'])

    def test_runs_that_match_the_table_are_kept(self):
        runs = [['f', self.ins(0x1000, 0x1004)], ['g', self.ins(0x1008)]]
        table = {'f': ['.text', 0x1000, 8, {'symtab'}, ''], 'g': ['.text', 0x1008, 4, {'symtab'}, '']}
        self.assertEqual([n for n, ii in inv.split_runs(runs, table)], ['f', 'g'])


class MultiUnit(unittest.TestCase):
    # EramAlloc is defined in two compilation units; the row is the one at 0xd981360, 0x40 bytes
    def test_an_address_inside_the_function_ties_the_entry_to_its_unit(self):
        self.assertTrue(inv.cites_range('`EramAlloc` (0xd981360): carves a block from the free list.', 0xd981360, 0x40))
        self.assertTrue(inv.cites_range('`EramAlloc` stores the size at 0xd98137c.', 0xd981360, 0x40))

    def test_the_other_unit_or_the_name_alone_does_not(self):
        self.assertFalse(inv.cites_range('`EramAlloc` (0xd9848d0): the other unit.', 0xd981360, 0x40))
        self.assertFalse(inv.cites_range('`EramAlloc` carves a block from the free list.', 0xd981360, 0x40))
        self.assertFalse(inv.cites_range('`EramAlloc` loads the word at +0x10.', 0x0, 0x40))
        self.assertFalse(inv.cites_range('`EramAlloc` at 0xd981360.', 0xd981360, 0))


class Unverified(unittest.TestCase):
    SUBJ = frozenset(inv.unit_keys('`odsy_EdidCksum`'))
    BODY = ('`odsy_EdidCksum` (`odsy_ddc.o`, offset 0x1c58): Computes the EDID block checksum: it adds the 128 '
            'bytes at its argument, keeps the sum modulo 256 and returns it, so a valid block gives 0. ')

    def test_the_same_entry_is_understood_when_labelled_and_located_when_unverified(self):
        self.assertEqual(inv.classify(self.BODY + 'Inferred.', self.SUBJ), ('understood', False))
        self.assertEqual(inv.classify(self.BODY + 'Established.', self.SUBJ), ('understood', False))
        self.assertEqual(inv.classify(self.BODY + 'Unverified.', self.SUBJ), ('located', False))

    def test_a_table_row_ending_in_the_label_is_capped_too(self):
        row = '| `odsy_EdidCksum` | ' + self.BODY + 'Unverified. |'
        self.assertEqual(inv.classify(row, self.SUBJ)[0], 'located')

    def test_a_label_with_an_open_sub_fact_is_capped(self):
        text = self.BODY + 'The width of the result is unknown. Unverified.'
        self.assertEqual(inv.classify(text, self.SUBJ)[0], 'located')

    def test_the_cap_does_not_rest_on_the_hedge_words(self):
        saved = inv.HEDGE
        inv.HEDGE = re.compile(r'(?!)')
        try:
            self.assertEqual(inv.classify(self.BODY + 'Unverified.', self.SUBJ)[0], 'located')
        finally:
            inv.HEDGE = saved

    def test_an_entry_below_located_stays_there(self):
        self.assertEqual(inv.classify('`odsy_EdidCksum` checksums. Unverified.', self.SUBJ)[0], 'named-only')


if __name__ == '__main__':
    unittest.main()
