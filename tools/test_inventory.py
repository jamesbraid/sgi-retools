#!/usr/bin/env python3
"""Tests of the rules in inventory.py that do not need root/: the `computes` count, the scope filter, the
per-build credit of the functions table, the template cap, the
function boundaries of the register-access scan and the credit of same-named functions.

Run from the repository root: python3 tools/test_inventory.py
"""
import hashlib
import importlib.util
import io
import os
import re
import shutil
import tempfile
import unittest

try:
    from elftools.elf.elffile import ELFFile
except ImportError:      # the toolchain image has pyelftools; a bare host may not
    ELFFile = None

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('inventory', os.path.join(HERE, 'inventory.py'))
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)
mips_xlate = inv.mips_xlate

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

    def test_rows_with_no_address_leave_the_counts_and_are_reported(self):
        rows = [{'name': 'a', 'status': 'undocumented', '_multi': False, '_shared': False, '_unknown': False},
                {'name': 'b', 'status': 'understood', '_multi': False, '_shared': False, '_unknown': False},
                {'name': 'c', 'status': 'named-only', '_multi': False, '_shared': False, '_unknown': True},
                {'name': 'd', 'status': 'undocumented', '_multi': False, '_shared': False, '_unknown': True,
                 '_out': True}]
        row = inv.summary_row('functions', rows, '', 1)
        # d is out of scope and counted there only; c is address-unknown and in no status count
        self.assertEqual((row['rows'], row['out_of_scope'], row['address_unknown']), (2, 1, 1))
        self.assertEqual((row['undocumented'], row['named_only'], row['understood']), (1, 0, 1))
        self.assertEqual(row['pct_understood'], '50.0')


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


class SharedAddress(unittest.TestCase):
    # glTexImage3D and glTexImage3DEXT are one function under two names
    BIN = 'builds/p/usr/gfx/arch/IP30ODSY64/libGLcore.so'
    NAMES = ['glTexImage3D', 'glTexImage3DEXT']
    ADDR = 0xb499950

    def ent(self, text, name='glTexImage3DEXT'):
        return inv.Entry(text, 'understood', frozenset({('id', name)}))

    def cites(self, toks):
        return self.BIN in toks

    def test_an_entry_with_the_binary_and_exact_address_ties_to_the_row(self):
        e = self.ent('- `glTexImage3DEXT` in `%s` at 0xb499950 (n64).' % self.BIN)
        self.assertTrue(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))

    def test_either_alias_may_be_the_entry_subject(self):
        e = self.ent('- `glTexImage3D` in `%s` at 0xb499950 (n64).' % self.BIN, 'glTexImage3D')
        self.assertTrue(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))

    def test_a_name_only_mention_does_not(self):
        e = self.ent('- `glTexImage3DEXT` uploads a volume texture.')
        self.assertFalse(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))

    def test_another_address_or_an_offset_does_not(self):
        e = self.ent('- `glTexImage3DEXT` in `%s` at 0xb49995c (n64).' % self.BIN)
        self.assertFalse(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))
        e = self.ent('- `glTexImage3DEXT` in `%s` at +0xb499950.' % self.BIN)
        self.assertFalse(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))

    def test_another_binary_does_not(self):
        e = self.ent('- `glTexImage3DEXT` in `builds/q/libGLcore.so` at 0xb499950 (n64).')
        self.assertFalse(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))

    def test_an_entry_about_a_third_name_does_not(self):
        e = self.ent('- `glResetMinmaxEXT` in `%s` at 0xb499950 (n64).' % self.BIN, 'glResetMinmaxEXT')
        self.assertFalse(inv.names_row_by_address(e, self.NAMES, self.ADDR, self.cites))


class CitesBinary(unittest.TestCase):
    def img(self, label, copies=()):
        return {'label': label, 'copies': list(copies)}

    def check(self, imgs, label, toks):
        owners = inv.path_owners(imgs)
        return inv.cites_binary(toks, next(i for i in imgs if i['label'] == label), owners)

    def test_a_bare_path_names_the_bare_label_but_not_a_build_that_shares_its_tail(self):
        imgs = [self.img('usr/gfx/X.so'), self.img('builds/vpro-patch-4103/usr/gfx/X.so')]
        self.assertTrue(self.check(imgs, 'usr/gfx/X.so', {'usr/gfx/X.so'}))
        self.assertFalse(self.check(imgs, 'builds/vpro-patch-4103/usr/gfx/X.so', {'usr/gfx/X.so'}))

    def test_a_full_build_path_names_only_its_own_build(self):
        imgs = [self.img('usr/gfx/X.so'), self.img('builds/vpro-patch-4103/usr/gfx/X.so')]
        self.assertTrue(self.check(imgs, 'builds/vpro-patch-4103/usr/gfx/X.so', {'builds/vpro-patch-4103/usr/gfx/X.so'}))
        self.assertFalse(self.check(imgs, 'usr/gfx/X.so', {'builds/vpro-patch-4103/usr/gfx/X.so'}))

    def test_a_tail_shared_by_two_builds_names_neither(self):
        imgs = [self.img('builds/a/usr/gfx/X.so'), self.img('builds/b/usr/gfx/X.so')]
        self.assertFalse(self.check(imgs, 'builds/a/usr/gfx/X.so', {'usr/gfx/X.so'}))
        self.assertFalse(self.check(imgs, 'builds/b/usr/gfx/X.so', {'usr/gfx/X.so'}))

    def test_the_path_of_a_byte_identical_copy_names_the_image(self):
        imgs = [self.img('usr/gfx/libGL.so', ['builds/b/usr/gfx/libGL.so'])]
        self.assertTrue(self.check(imgs, 'usr/gfx/libGL.so', {'builds/b/usr/gfx/libGL.so'}))
        self.assertTrue(self.check(imgs, 'usr/gfx/libGL.so', {'b/usr/gfx/libGL.so'}))

    def test_a_root_or_dot_prefix_is_dropped(self):
        imgs = [self.img('usr/gfx/X.so')]
        self.assertTrue(self.check(imgs, 'usr/gfx/X.so', {'root/usr/gfx/X.so'}))
        self.assertTrue(self.check(imgs, 'usr/gfx/X.so', {'./usr/gfx/X.so'}))

    def test_an_archive_member_is_named_by_archive_and_member(self):
        imgs = [self.img('usr/lib/lib.a(m.o)'), self.img('usr/lib/lib.a(n.o)')]
        self.assertTrue(self.check(imgs, 'usr/lib/lib.a(m.o)', {'usr/lib/lib.a(m.o)'}))
        self.assertTrue(self.check(imgs, 'usr/lib/lib.a(m.o)', {'lib.a(m.o)'}))
        self.assertFalse(self.check(imgs, 'usr/lib/lib.a(m.o)', {'usr/lib/lib.a(n.o)'}))

    def test_an_unrelated_path_does_not(self):
        self.assertFalse(self.check([self.img('usr/gfx/X.so')], 'usr/gfx/X.so', {'usr/gfx/Y.so'}))


class HeaderSite(unittest.TestCase):
    # save_hub_md_error is one routine in two builds of the same binary; each build's routine is at its own
    # address, and the entry's header names one build and one address
    NAME = 'save_hub_md_error'
    CITED = ('6.5.22/unix.IP27', 0xc00000000002f8f0)
    OTHER = ('6.5.30/unix.IP27', 0xc00000000002fb8c)

    def funcs(self, other_code='7d05', cited_code='7d05'):
        return {self.CITED[0]: {self.NAME: ('.text', self.CITED[1], 108, ['symtab'], cited_code)},
                self.OTHER[0]: {self.NAME: ('.text', self.OTHER[1], 108, ['symtab'], other_code)}}

    def status(self, text, funcs=None, subj=None, name=NAME):
        funcs = funcs or self.funcs()
        imgs = fake_images(*[(lab, []) for lab in funcs])
        owners = inv.path_owners(imgs)
        name_rows = inv.code_groups(funcs, [])
        ent = inv.Entry(text, 'understood', subj or frozenset({('id', name)}))
        out = {}
        for img in imgs:
            lab = img['label']
            addr = funcs[lab][name][1]
            hits = [inv.Hit('doc.md', 1, 'doc.md', '', 'understood', False, False, '', 0, ent)]
            hits = [h for h in hits if inv.header_keeps(h.ent, name, img, addr, name_rows[name][lab], owners,
                                                        funcs, name_rows)]
            out[lab] = inv.DocIndex.best(hits)[0]
        return out

    def cited(self, rest='stores the error block and returns.'):
        return '- `save_hub_md_error` at %s 0x%x: **established.** %s' % (self.CITED[0], self.CITED[1], rest)

    def test_identical_code_in_another_build_shares_the_credit(self):
        self.assertEqual(self.status(self.cited()), {self.CITED[0]: 'understood', self.OTHER[0]: 'understood'})

    def test_different_code_in_another_build_is_not_credited(self):
        got = self.status(self.cited(), funcs=self.funcs(other_code='ffc3'))
        self.assertEqual(got, {self.CITED[0]: 'understood', self.OTHER[0]: 'undocumented'})

    def test_another_address_in_the_cited_build_credits_nothing(self):
        got = self.status('- `save_hub_md_error` at %s 0xc00000000002f8f4: **established.** Stores the block.'
                          % self.CITED[0])
        self.assertEqual(got, {self.CITED[0]: 'undocumented', self.OTHER[0]: 'undocumented'})

    def test_an_entry_giving_no_binary_or_address_keeps_name_only_matching(self):
        got = self.status('- `save_hub_md_error` stores the error block and returns.',
                          funcs=self.funcs(other_code='ffc3'))
        self.assertEqual(got, {self.CITED[0]: 'understood', self.OTHER[0]: 'understood'})

    def test_an_entry_giving_a_binary_but_no_address_keeps_name_only_matching(self):
        got = self.status('- `save_hub_md_error` in %s stores the error block and returns.' % self.CITED[0],
                          funcs=self.funcs(other_code='ffc3'))
        self.assertEqual(got, {self.CITED[0]: 'understood', self.OTHER[0]: 'understood'})

    def test_an_address_in_the_description_is_not_the_header_address(self):
        got = self.status('- `save_hub_md_error` in %s: stores the error block at 0xc00000000002f8f0.'
                          % self.CITED[0], funcs=self.funcs(other_code='ffc3'))
        self.assertEqual(got, {self.CITED[0]: 'understood', self.OTHER[0]: 'understood'})

    def test_an_entry_about_another_routine_that_mentions_this_one_keeps_name_only_matching(self):
        got = self.status('- `other_fn` at %s 0x%x: calls `save_hub_md_error`, which returns the block.'
                          % (self.CITED[0], self.CITED[1]), funcs=self.funcs(other_code='ffc3'),
                          subj=frozenset({('id', 'other_fn')}))
        self.assertEqual(got, {self.CITED[0]: 'understood', self.OTHER[0]: 'understood'})

    def test_a_bare_file_name_shared_by_builds_credits_each_at_that_address(self):
        funcs = {lab: {self.NAME: ('.text', self.CITED[1], 108, ['symtab'], code)}
                 for lab, code in (('usr/a/gfx.o', 'aa'), ('usr/b/gfx.o', 'bb'), ('usr/c/gfx.o', 'cc'))}
        got = self.status('- `save_hub_md_error` (`gfx.o` at 0x%x): **established.** Stores the block.'
                          % self.CITED[1], funcs=funcs)
        self.assertEqual(got, {'usr/a/gfx.o': 'understood', 'usr/b/gfx.o': 'understood',
                               'usr/c/gfx.o': 'understood'})


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


@unittest.skipIf(ELFFile is None, 'pyelftools is not installed')
class AddressZero(unittest.TestCase):
    """A relocatable object's first function is at address 0; that is an address, not a missing one."""

    @staticmethod
    def relocatable(code, funcs):
        """A big-endian 32-bit MIPS ET_REL image with one .text and a .symtab of (name, value, size) FUNC symbols."""
        import struct
        names = b'\0' + b''.join(n.encode() + b'\0' for n, _, _ in funcs)
        offs, o = [], 1
        for n, _, _ in funcs:
            offs.append(o)
            o += len(n) + 1
        syms = struct.pack('>IIIBBH', 0, 0, 0, 0, 0, 0)
        for (n, v, sz), no in zip(funcs, offs):
            syms += struct.pack('>IIIBBH', no, v, sz, 0x12, 0, 1)     # GLOBAL FUNC in section 1
        shstr = b'\0.text\0.symtab\0.strtab\0.shstrtab\0'
        parts = [(b'', 0, 0, 0, 0, 0, 0, 0), (code, 1, 1, 6, 4, 0, 0, 0), (syms, 7, 2, 0, 4, 3, 2, 16),
                 (names, 15, 3, 0, 1, 0, 0, 0), (shstr, 23, 3, 0, 1, 0, 0, 0)]
        # parts: (data, name offset, type, flags, align, link, info, entsize)
        shdrs, off = b'', 52
        for data, nm, ty, fl, al, link, info, ent in parts:
            if ty == 0:
                shdrs += struct.pack('>10I', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                continue
            shdrs += struct.pack('>10I', nm, ty, fl, 0, off, len(data), link, info, al, ent)
            off += len(data)
        body = b''.join(d for d, *_ in parts[1:])
        ehdr = b'\x7fELF\x01\x02\x01' + b'\0' * 9 + struct.pack('>HHIIIIIHHHHHH', 1, 8, 1, 0, 0, 52 + len(body), 0x20000000,
                                                                  52, 0, 0, 40, 5, 4)
        return ehdr + body + shdrs

    def test_first_function_keeps_section_size_and_hash(self):
        code = bytes(range(64))
        data = self.relocatable(code, [('first', 0, 16), ('second', 16, 48)])
        elf = ELFFile(io.BytesIO(data))
        funcs, info = inv.functions_of({'group': {}, 'data': data, 'label': 'x.o'}, elf, '/nonexistent')
        sec, addr, size, srcs, sha = funcs['first']
        self.assertEqual((sec, addr, size), ('.text', 0, 16))
        self.assertEqual(sha, hashlib.sha256(code[:16]).hexdigest()[:12])
        self.assertEqual(funcs['second'][1:3], [16, 48])
        self.assertEqual(info['address_source'], 'symtab')


@unittest.skipIf(ELFFile is None, 'pyelftools is not installed')
class StaleDwarf(unittest.TestCase):
    """DWARF addresses are dropped only when the code moved after the debug information was written."""

    class WithDebug(ELFFile if ELFFile else object):
        def get_section_by_name(self, name):
            return object() if name == '.debug_info' else super().get_section_by_name(name)

    def functions(self, symbols, dwarf, linked=False, xlate=None):
        code = bytes(range(128))
        data = AddressZero.relocatable(code, symbols)
        if linked:      # the same image as an executable whose only code section, .init, sits at 0x1000
            data = data.replace(b'.text\0', b'.init\0')
            data = data[:16] + b'\x00\x02' + data[18:]
            o = int.from_bytes(data[32:36], 'big') + 40      # section header 1 is .text
            data = data[:o + 12] + (0x1000).to_bytes(4, 'big') + data[o + 16:]
        real, real_xlate = inv.dwarf_subprograms, inv.mips_xlate.of_elf
        inv.dwarf_subprograms = lambda path: dwarf
        inv.mips_xlate.of_elf = lambda elf: xlate
        try:
            return inv.functions_of({'group': {}, 'data': data, 'label': 'x.o'},
                                    self.WithDebug(io.BytesIO(data)), '/nonexistent')
        finally:
            inv.dwarf_subprograms, inv.mips_xlate.of_elf = real, real_xlate

    def test_a_name_defined_in_two_units_does_not_make_dwarf_stale(self):
        # `dup` is static in two units and the symbol table keeps one; `hidden` is a static the table lacks
        funcs, info = self.functions([('dup', 32, 32), ('plain', 0, 32)],
                                     [('plain', 0, 32), ('dup', 32, 64), ('dup', 96, 112), ('hidden', 64, 96)])
        self.assertEqual(funcs['hidden'][:3], ['.text', 64, 32])
        self.assertEqual(funcs['hidden'][4], hashlib.sha256(bytes(range(64, 96))).hexdigest()[:12])
        self.assertEqual(funcs['dup'][1], 32)
        self.assertEqual(info['address_source'], 'symtab+dwarf')

    def test_dwarf_that_shares_no_address_with_the_symbols_is_dropped(self):
        funcs, info = self.functions([('moved', 32, 32)], [('moved', 0x4000, 0x4020), ('hidden', 0x4040, 0x4060)])
        self.assertEqual(funcs['moved'][1], 32)
        self.assertIsNone(funcs['hidden'][1])
        self.assertEqual(info['address_source'], 'symtab (dwarf addresses stale, dropped)')

    def test_a_function_that_fills_a_section_of_its_own_keeps_its_address_in_stale_dwarf(self):
        # `_init` is at the start of .init, the one code section here; DWARF puts the other names elsewhere
        funcs, info = self.functions([('moved', 0x1020, 32)], [('moved', 0x4000, 0x4020), ('_init', 0x1000, 0x1020),
                                                              ('other', 0x4040, 0x4060)], linked=True)
        self.assertEqual(funcs['_init'][:3], ['.init', 0x1000, 0x20])
        self.assertEqual(funcs['_init'][4], hashlib.sha256(bytes(range(32))).hexdigest()[:12])
        self.assertEqual(funcs['moved'][1], 0x1020)
        self.assertIsNone(funcs['other'][1])
        self.assertEqual(info['address_source'],
                         'symtab+dwarf (dwarf addresses stale, dropped except sections of their own)')

    # the linked image has its code at 0x1000..0x1080; DWARF puts the functions at 0x4000.. before a reorder
    TABLE = [(0x4000, 0x1020, 32), (0x4040, 0x1040, 32), (0x4060, 0x1060, 8)]

    def test_xlate_gives_the_dwarf_only_functions_their_real_addresses(self):
        funcs, info = self.functions([('moved', 0x1020, 32)],
                                     [('moved', 0x4000, 0x4020), ('hidden', 0x4040, 0x4060), ('_init', 0x1000, 0x1020)],
                                     linked=True, xlate=mips_xlate.Xlate(0x1000, 0x1068, self.TABLE))
        self.assertEqual(funcs['hidden'][:3], ['.init', 0x1040, 32])
        self.assertEqual(funcs['hidden'][4], hashlib.sha256(bytes(range(0x40, 0x60))).hexdigest()[:12])
        self.assertEqual(funcs['moved'][1], 0x1020)
        self.assertEqual(funcs['_init'][1:3], [0x1000, 0x20])      # a section of its own stays where it is
        self.assertEqual(info['address_source'], 'symtab+dwarf (dwarf addresses translated through .MIPS.Xlate)')

    def test_xlate_leaves_a_function_that_leaves_its_range_without_an_address(self):
        funcs, info = self.functions([('moved', 0x1020, 32)],
                                     [('moved', 0x4000, 0x4020), ('hidden', 0x4040, 0x4060), ('wide', 0x4060, 0x4080),
                                      ('lost', 0x9000, 0x9010)],
                                     linked=True, xlate=mips_xlate.Xlate(0x1000, 0x1068, self.TABLE))
        self.assertEqual(funcs['hidden'][1], 0x1040)
        self.assertIsNone(funcs['wide'][1])       # 32 bytes in a range of 8
        self.assertIsNone(funcs['lost'][1])       # in no range
        self.assertEqual(info['address_source'], 'symtab+dwarf (dwarf addresses translated through .MIPS.Xlate)')

    def test_xlate_that_contradicts_the_symbols_is_not_trusted(self):
        wrong = mips_xlate.Xlate(0x1000, 0x1068, [(0x4000, 0x1040, 32), (0x4040, 0x1060, 8)])
        funcs, info = self.functions([('moved', 0x1020, 32)], [('moved', 0x4000, 0x4020), ('hidden', 0x4040, 0x4060)],
                                     linked=True, xlate=wrong)
        self.assertIsNone(funcs['hidden'][1])
        self.assertEqual(funcs['moved'][1], 0x1020)
        self.assertEqual(info['address_source'], 'symtab (dwarf addresses stale, dropped)')


@unittest.skipIf(ELFFile is None, 'pyelftools is not installed')
class GpLiterals(unittest.TestCase):
    """A linked kernel without a GOT keeps its address constants in small-data sections and loads them through
    gp; the scan reads them only for the images a gp_literals rule names."""
    POOL = 0xc000000001000000       # .sdata address
    GP = POOL + 0x10
    LIT = 0x9200000001000000        # the literal at POOL + 8

    @classmethod
    def kernel(cls):
        """A big-endian 64-bit MIPS ET_EXEC image: .MIPS.options (gp), .sdata (the literal), .shstrtab."""
        import struct
        opts = struct.pack('>BBHI', 1, 40, 0, 0) + struct.pack('>II4IQ', 0, 0, 0, 0, 0, 0, cls.GP)
        sdata = struct.pack('>QQQQ', 0, cls.LIT, 0, 0)
        shstr = b'\0.MIPS.options\0.sdata\0.shstrtab\0'
        parts = [(opts, 1, 0x7000000d, 2, cls.POOL - 0x1000), (sdata, 15, 1, 3, cls.POOL), (shstr, 22, 3, 0, 0)]
        shdrs, off = struct.pack('>2I4Q2I2Q', *([0] * 10)), 64
        for data, nm, ty, fl, addr in parts:
            shdrs += struct.pack('>2I4Q2I2Q', nm, ty, fl, addr, off, len(data), 0, 0, 8, 0)
            off += len(data)
        body = b''.join(d for d, *_ in parts)
        ehdr = b'\x7fELF\x02\x02\x01' + b'\0' * 9 + struct.pack('>HHIQQQIHHHHHH', 2, 8, 1, 0, 0, 64 + len(body),
                                                                  0x30000000, 64, 0, 0, 64, 4, 3)
        return ehdr + body + shdrs

    def info(self, sections):
        return inv.ImageInfo(ELFFile(io.BytesIO(self.kernel())), sections)

    def test_reads_the_literal_at_gp_plus_displacement(self):
        info = self.info(['.sdata'])
        self.assertEqual(info.gp0 & (1 << 64) - 1, self.GP)
        self.assertEqual(info.read_gp(-8, 8) & (1 << 64) - 1, self.LIT)
        self.assertEqual(info.read_gp(-16, 8), 0)
        self.assertIsNone(info.read_gp(0x100, 8))         # past the section
        self.assertIsNone(info.read_gp(-0x1000, 8))       # before it

    def test_an_image_the_config_does_not_name_reads_nothing(self):
        info = self.info([])
        self.assertEqual(info.gp_lit, [])
        self.assertIsNone(info.read_gp(-8, 8))

    def replayed(self, rules):
        """Offsets the Hub window reaches in `ld t0,-8(gp); ld t1,0x90(t0); jr ra`, under the given gp_literals."""
        cfg = {'windows': [{'name': 'HUB', 'size': '0x800000'}],
               'bases': [{'type': 'constant', 'lo': '0x9200000001000000', 'hi': '0x9200000001800000',
                          'window': 'HUB', 'translate': False}],
               'gp_literals': rules}
        insns = [[0x1000, 'ld', ['$8', '-8($28)'], None, None], [0x1004, 'ld', ['$9', '144($8)'], None, None],
                 [0x1008, 'jr', ['$31'], None, None], [0x100c, 'nop', [], None, None]]
        img = {'elf': ELFFile(io.BytesIO(self.kernel())), 'tmp': 'unused', 'label': '6.5.30/unix.IP99',
               'path': '6.5.30/unix.IP99', 'group': {}, 'functab': {}}
        saved = inv.run_objdump, inv.split_runs
        inv.run_objdump, inv.split_runs = (lambda path: [('f', insns)]), (lambda funcs, tab: funcs)
        try:
            u = inv.Unit(inv.Model(cfg), cfg, [img]).run()
        finally:
            inv.run_objdump, inv.split_runs = saved
        return sorted(k for k in u.out_mmio), u.touch

    def test_a_gp_load_of_a_window_literal_reaches_the_window(self):
        keys, touch = self.replayed([{'binaries': ['*unix.IP99'], 'sections': ['.sdata']}])
        self.assertEqual(keys, [('HUB', 0x90)])
        self.assertEqual(touch, {('6.5.30/unix.IP99', 'f')})

    def test_without_a_rule_the_same_load_reaches_nothing(self):
        for rules in ([], [{'binaries': ['*unix.IP27'], 'sections': ['.sdata']}]):
            keys, touch = self.replayed(rules)
            self.assertEqual((keys, touch), ([], set()))

    def test_a_returned_window_pointer_without_an_offset_counts_as_unresolved(self):
        """`return` bases with a null offset: the routine maps a window at a caller-chosen offset."""
        cfg = {'windows': [{'name': 'XTALK', 'size': '0x1000000'}],
               'bases': [{'type': 'return', 'function': 'map_window', 'window': 'XTALK', 'offset': None}]}
        insns = [[0x1000, 'jal', ['4000'], None, 'map_window'], [0x1004, 'nop', [], None, None],
                 [0x1008, 'ld', ['$9', '16($2)'], None, None], [0x100c, 'jr', ['$31'], None, None],
                 [0x1010, 'nop', [], None, None]]
        img = {'elf': ELFFile(io.BytesIO(self.kernel())), 'tmp': 'unused', 'label': '6.5.30/unix.IP99',
               'path': '6.5.30/unix.IP99', 'group': {}, 'functab': {}}
        saved = inv.run_objdump, inv.split_runs
        inv.run_objdump, inv.split_runs = (lambda path: [('f', insns)]), (lambda funcs, tab: funcs)
        try:
            u = inv.Unit(inv.Model(cfg), cfg, [img]).run()
        finally:
            inv.run_objdump, inv.split_runs = saved
        self.assertEqual(u.out_mmio, {})
        self.assertEqual(dict(u.unresolved), {('6.5.30/unix.IP99', 'XTALK'): 1})
        self.assertEqual(u.touch, {('6.5.30/unix.IP99', 'f')})


class RequestLabels(unittest.TestCase):
    """A vendor driver-request name in a function row is written as its label."""

    def test_functions_row_gets_the_label(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, 'functions.tsv')
        inv.write_tsv(path, 'functions', [{'binary': '6.5.30/unix.IP30', 'name': 'ODSY_SET_GC', 'address': '0x30'}])
        with open(path, encoding='utf-8') as f:
            text = f.read()
        self.assertIn('the set graphics-context Odyssey driver request', text)
        self.assertNotIn('ODSY_SET_GC', text)


class DeviceModules(unittest.TestCase):
    """A module a config names is found under tools/ or one device directory below it."""

    def test_a_module_moved_under_a_device_directory_is_found(self):
        mod = inv.import_device_module('buzz_ucode_disasm')
        self.assertEqual(os.path.dirname(os.path.abspath(mod.__file__)), os.path.join(HERE, 'odsy'))

    def test_a_module_already_on_the_path_is_not_searched_for(self):
        mod = inv.import_device_module('mips_xlate')
        self.assertEqual(os.path.dirname(os.path.abspath(mod.__file__)), HERE)


try:
    import capstone  # noqa: F401
except ImportError:
    capstone = None


FIRMWARE_WINDOWS = {'windows': [
    {'name': 'MBAR', 'size': '0x200', 'physical': '0x10000000'},
    {'name': 'NVRAM', 'size': '0x800', 'physical': '0x20000000'},
    {'name': 'FLASH', 'size': '0x100000', 'physical': '0xffe00000', 'memory': True},
    {'name': 'IMMR', 'physical': '0xfa200000'}]}


def firmware_scan(arch, load, words):
    """Run the firmware scan over a synthetic image; returns (the unit, the function rows)."""
    d = tempfile.mkdtemp()
    body = b''.join(words)
    path = os.path.join(d, 'image.bin')
    with open(path, 'wb') as f:
        f.write(body)
    try:
        u = inv.Unit(inv.Model(FIRMWARE_WINDOWS), FIRMWARE_WINDOWS, [])
        img = {'label': 'fw.bin(image)', 'data': body, 'fw': {'arch': arch, 'load': load}}
        return u, u.firmware(img, path)
    finally:
        shutil.rmtree(d)


def hexbytes(*parts):
    return [bytes.fromhex(p) for p in parts]


class FirmwareLayout(unittest.TestCase):
    def test_a_flat_layout_maps_the_file_from_its_offset(self):
        seg = inv.firmware_segments({'layout': 'flat', 'load': '0x2000', 'offset': '4'}, 'x.bin', b'abcdefgh')
        self.assertEqual(seg, [('', b'efgh', 0x2000)])


@unittest.skipIf(capstone is None, 'capstone is not installed')
class FirmwareMmio(unittest.TestCase):
    """A load or store at a constant address inside a configured window of a firmware image is a site."""

    def test_coldfire_absolute_addresses(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',                 # link.w a6,#0: the routine entry
            '203910000014',             # move.l (0x10000014).l,d0: a read in MBAR
            '13c020000010',             # move.b d0,(0x20000010).l: a write in NVRAM
            '4e5e', '4e75'))            # unlk a6; rts
        self.assertEqual(sorted(u.out_mmio), [('MBAR', 0x14), ('NVRAM', 0x10)])
        self.assertEqual(u.out_mmio[('MBAR', 0x14)]['acc'], {'r4'})
        self.assertEqual(u.out_mmio[('NVRAM', 0x10)]['acc'], {'w1'})
        self.assertEqual(u.out_mmio[('MBAR', 0x14)]['funcs'], {'sub_1000'})
        self.assertEqual(u.out_mmio[('MBAR', 0x14)]['bins'], {'fw.bin(image)'})
        self.assertEqual(list(funcs), ['sub_1000'])
        self.assertEqual(funcs['sub_1000'][1], 0x1000)

    def test_coldfire_address_in_no_window_is_not_a_site(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '13c060000000',             # move.b d0,(0x60000000).l: outside every window
            '4e5e', '4e75'))
        self.assertEqual(u.out_mmio, {})
        self.assertEqual(funcs, {})

    def test_coldfire_stack_traffic_is_not_a_site(self):
        u, funcs = firmware_scan('coldfire', 0x10000000, hexbytes('4e560000', '4e5e', '4e75'))
        self.assertEqual(u.out_mmio, {})

    def test_ppc_lis_relative_load_and_store(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0',                 # stwu r1,-16(r1): the routine entry
            '3d20fa20',                 # lis r9,0xfa20
            '80090280',                 # lwz r0,0x280(r9): a read of IMMR+0x280
            '90090284',                 # stw r0,0x284(r9): a write of IMMR+0x284
            '38210010', '4e800020'))    # addi r1,r1,16; blr
        self.assertEqual(sorted(u.out_mmio), [('IMMR', 0x280), ('IMMR', 0x284)])
        self.assertEqual(u.out_mmio[('IMMR', 0x280)]['acc'], {'r4'})
        self.assertEqual(u.out_mmio[('IMMR', 0x284)]['acc'], {'w4'})
        self.assertEqual(u.out_mmio[('IMMR', 0x280)]['funcs'], {'sub_fe000000'})

    def test_ppc_lis_ori_pair_halfword_store(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0', '3d40fa20',     # lis r10,0xfa20
            '614a0300',                 # ori r10,r10,0x300
            'b00a000e',                 # sth r0,0xe(r10): IMMR+0x30e
            '38210010', '4e800020'))
        self.assertEqual(sorted(u.out_mmio), [('IMMR', 0x30e)])
        self.assertEqual(u.out_mmio[('IMMR', 0x30e)]['acc'], {'w2'})

    def test_ppc_address_in_no_window_is_not_a_site(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0', '3d406000',     # lis r10,0x6000
            '900a0000',                 # stw r0,0(r10): outside every window
            '38210010', '4e800020'))
        self.assertEqual(u.out_mmio, {})
        self.assertEqual(funcs, {})

    def test_a_routine_that_reaches_only_memory_is_a_site_but_not_a_function_row(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '2039ffe00040',             # move.l (0xffe00040).l,d0: a read in FLASH, a memory window
            '4e5e', '4e75'))
        self.assertEqual(sorted(u.out_mmio), [('FLASH', 0x40)])
        self.assertEqual(funcs, {})

    def test_the_smaller_window_wins_where_windows_nest(self):
        m = inv.Model(FIRMWARE_WINDOWS)
        self.assertEqual(inv.window_at(m, 0xffe00040), ('FLASH', 0x40))
        self.assertEqual(inv.window_at(m, 0xfa200284), ('IMMR', 0x284))
        self.assertIsNone(inv.window_at(m, 0x60000000))


if __name__ == '__main__':
    unittest.main()
