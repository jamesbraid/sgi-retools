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

    def test_a_root_link_from_a_deep_page_names_the_build(self):
        imgs = [self.img('usr/gfx/X.so')]
        for tok in ('root/usr/gfx/X.so', '../root/usr/gfx/X.so', '../../root/usr/gfx/X.so'):
            self.assertTrue(self.check(imgs, 'usr/gfx/X.so', {tok}), tok)

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

    BARE = '- `save_hub_md_error` (`gfx.o` at 0x%x): **established.** Stores the block.' % CITED[1]

    def bare_funcs(self, *codes):
        return {'usr/%s/gfx.o' % lab: {self.NAME: ('.text', self.CITED[1], 108, ['symtab'], code)}
                for lab, code in zip('abc', codes)}

    def test_a_bare_file_name_shared_by_builds_with_one_code_there_credits_each(self):
        got = self.status(self.BARE, funcs=self.bare_funcs('aa', 'aa', 'aa'))
        self.assertEqual(set(got.values()), {'understood'})
        self.assertEqual(len(got), 3)

    def test_a_bare_file_name_cannot_pick_between_builds_that_differ_there(self):
        got = self.status(self.BARE, funcs=self.bare_funcs('aa', 'bb', 'cc'))
        self.assertEqual(set(got.values()), {'undocumented'})

    def test_a_bare_file_name_beside_a_full_path_names_the_full_path_build(self):
        funcs = self.bare_funcs('aa', 'bb', 'cc')
        got = self.status('- `save_hub_md_error` (`usr/b/gfx.o` at 0x%x): **established.** Stores the block.'
                          % self.CITED[1], funcs=funcs)
        self.assertEqual(got, {'usr/a/gfx.o': 'undocumented', 'usr/b/gfx.o': 'understood',
                               'usr/c/gfx.o': 'undocumented'})


class ReadingEntries(unittest.TestCase):
    """The shapes a routine-reading round writes into docs/routines/*.md, and what each credits in a
    table of builds that share a routine name: swfio_mount sits at a different address in every build
    and its code differs in some."""
    NAME = 'swfio_mount'
    SW22 = 'sw22_474-ip30-flame834/var/sysgen/boot/swfs.o'
    BUILDS = (('sw22_474-ip30-flame834/var/sysgen/boot/swfs.o', 0x1f80, 'aa'),
              ('sw23_566-ip27-inferno55/var/sysgen/boot/swfs.o', 0x1fe0, 'bb'),
              ('sw24_681-ip30-flame90/var/sysgen/boot/swfs.o', 0x2040, 'cc'),
              ('sw25_793-ip27-inferno625/var/sysgen/boot/swfs.o', 0x1f8c, 'dd'))
    ROLE = ('It copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The return is either '
            'the constant 0xe or the mount result, and the facts do not show which one is an error code, so '
            'that reading is unconfirmed.')

    def index(self, doc):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.makedirs(os.path.join(root, 'docs', 'routines'))
        with open(os.path.join(root, 'docs', 'routines', 'b000.md'), 'w') as f:
            f.write(doc)
        saved, inv.REPO = inv.REPO, root
        try:
            return inv.DocIndex({'docs': {'prose': ['docs/routines/*.md'], 'index': [], 'skip': []}})
        finally:
            inv.REPO = saved

    def statuses(self, doc, builds=None):
        builds = builds or self.BUILDS
        docs = self.index(doc)
        funcs = {lab: {self.NAME: ('.text', addr, 292, ['symtab'], code)} for lab, addr, code in builds}
        imgs = fake_images(*[(lab, []) for lab, _a, _c in builds])
        name_rows = inv.code_groups(funcs, [])
        owners, cache, out = inv.path_owners(imgs), {}, {}
        for img in imgs:
            hits, demote = inv.function_hits(docs, self.NAME, img, funcs[img['label']][self.NAME][1], 292, funcs,
                                             name_rows, owners, cache)
            out[img['label']] = inv.function_status(docs, self.NAME, hits, demote)[0]
        return out

    def only_sw22(self):
        return {lab: ('located' if lab == self.SW22 else 'named-only') for lab, _a, _c in self.BUILDS}

    def test_a_header_line_and_its_text_credit_only_the_cited_row(self):
        doc = '- `swfio_mount` in `%s` at 0x1f80: %s\n' % (self.SW22, self.ROLE)
        self.assertEqual(self.statuses(doc), self.only_sw22())

    def test_a_heading_and_its_paragraph_credit_only_the_cited_row(self):
        doc = '### `swfio_mount` in `%s` at 0x1f80\n\n%s\n\nGrade: inferred.\n' % (self.SW22, self.ROLE)
        self.assertEqual(self.statuses(doc), self.only_sw22())

    def test_a_heading_with_the_build_and_address_and_a_paragraph_that_names_the_routine(self):
        doc = '### `%s` at 0x1f80\n\n`swfio_mount`, 292 bytes. %s\n' % (self.SW22, self.ROLE)
        self.assertEqual(self.statuses(doc), self.only_sw22())

    def test_a_heading_with_the_build_the_address_and_the_name_after_them(self):
        doc = '### %s:0x1f80 swfio_mount\n\n%s\n' % (self.SW22, self.ROLE)
        self.assertEqual(self.statuses(doc), self.only_sw22())

    def test_a_bare_file_name_credits_the_builds_that_have_the_routine_at_that_address(self):
        doc = '### swfs.o at 0x1f80\n\n`swfio_mount`, 292 bytes. %s\n' % self.ROLE
        self.assertEqual(self.statuses(doc), self.only_sw22())

    def test_a_bare_file_name_credits_nothing_when_another_build_differs_at_that_address(self):
        doc = '### swfs.o at 0x1f80\n\n`swfio_mount`, 292 bytes. %s\n' % self.ROLE
        got = self.statuses(doc, builds=(self.BUILDS[0], (self.BUILDS[3][0], 0x1f80, 'dd')))
        self.assertEqual(set(got.values()), {'named-only'})

    def test_a_build_line_under_a_bare_file_name_names_the_build(self):
        # the shape driver-functions.md uses: a shared member name in the header, the full path on a Build line
        doc = ('- `swfio_mount` (`swfs.o`, offset 0x1f80, 292 bytes): **established.**\n'
               '  Build: `%s`.\n  %s\n' % (self.SW22, self.ROLE))
        other = (self.BUILDS[3][0], 0x1f80, 'dd')     # same address, different code
        got = self.statuses(doc, builds=(self.BUILDS[0], other))
        self.assertEqual(got, {self.SW22: 'located', other[0]: 'named-only'})

    def test_a_long_paragraph_naming_many_callees_still_credits_its_routine(self):
        callees = ', '.join('`swf_callee_%d` at 0x%x' % (k, 0x2000 + 4 * k) for k in range(inv.MAX_ITEMS + 4))
        doc = '### `%s` at 0x1f80\n\n`swfio_mount`, 292 bytes. It calls %s. Grade: inferred.\n' % (self.SW22, callees)
        self.assertEqual(self.statuses(doc)[self.SW22], 'understood')

    def test_a_header_line_with_an_indented_paragraph_after_a_blank_line_is_one_entry(self):
        doc = '- `swfio_mount` in `%s` at 0x1f80\n\n  %s\n' % (self.SW22, self.ROLE)
        self.assertEqual(self.statuses(doc), self.only_sw22())

    def test_identical_code_in_another_build_shares_the_credit(self):
        doc = '### `swfio_mount` in `%s` at 0x1f80\n\n%s\n' % (self.SW22, self.ROLE)
        same = self.statuses(doc, builds=(self.BUILDS[0], (self.BUILDS[3][0], 0x1f8c, 'aa')))
        self.assertEqual(set(same.values()), {'located'})

    def test_a_heading_without_an_address_is_not_folded_into_its_paragraph(self):
        doc = '### Mounting\n\n`swfio_mount` in `%s`: %s\n' % (self.SW22, self.ROLE)
        self.assertFalse(any(e.text.startswith('Mounting') for e in self.index(doc).entries))

    def test_a_heading_with_an_address_and_no_binary_is_not_folded_into_its_paragraph(self):
        doc = '### Register 0x2000\n\n`swfio_mount` writes it. %s\n' % self.ROLE
        self.assertFalse(any(e.text.startswith('Register') for e in self.index(doc).entries))

    def test_text_after_a_list_under_a_routine_heading_is_not_folded_in(self):
        doc = '### `%s` at 0x1f80\n\n- Something else.\n\nLater prose about the area.\n' % self.SW22
        texts = [e.text for e in self.index(doc).entries]
        self.assertFalse(any('Later prose' in t and '0x1f80' in t for t in texts))


class ReviewCap(unittest.TestCase):
    """A repository that lists files in review_required credits an entry in them beyond located only when the
    entry carries a Reviewed line. Other files, and repositories with no such list, are not affected."""
    ENTRY = ('- `swfio_mount` in `sw22_474-ip30-flame834/var/sysgen/boot/swfs.o` at 0x1f80\n'
             '  **Inferred.** Copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The\n'
             '  return is the constant 0xe or the mount result at 0x2084.\n')

    def levels(self, files, review=None):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.makedirs(os.path.join(root, 'docs', 'routines'))
        for name, doc in files.items():
            with open(os.path.join(root, 'docs', 'routines', name), 'w') as f:
                f.write(doc)
        cfg = {'docs': {'prose': ['docs/routines/*.md'], 'index': [], 'skip': []}}
        if review is not None:
            cfg['review_required'] = review
        saved, inv.REPO = inv.REPO, root
        try:
            index = inv.DocIndex(cfg)
        finally:
            inv.REPO = saved
        return [e.level for e in index.entries]

    def test_the_default_list_is_empty_and_changes_nothing(self):
        self.assertEqual(self.levels({'b.md': self.ENTRY}), ['understood'])
        self.assertEqual(self.levels({'b.md': self.ENTRY}, review=[]), ['understood'])

    def test_an_unreviewed_entry_in_a_listed_file_is_capped_at_located(self):
        self.assertEqual(self.levels({'b.md': self.ENTRY}, review=['docs/routines/*.md']), ['located'])

    def test_a_reviewed_line_in_the_entry_lifts_the_cap(self):
        doc = self.ENTRY + '  Reviewed: 2026-11-12\n'
        self.assertEqual(self.levels({'b.md': doc}, review=['docs/routines/*.md']), ['understood'])

    def test_a_reviewed_line_needs_a_date(self):
        doc = self.ENTRY + '  Reviewed: yes\n'
        self.assertEqual(self.levels({'b.md': doc}, review=['docs/routines/*.md']), ['located'])

    def test_the_cap_applies_per_entry_and_per_file(self):
        two = self.ENTRY + '  Reviewed: 2026-11-12\n\n' + self.ENTRY.replace('swfio_mount', 'swfio_other')
        got = self.levels({'t2-a.md': two, 'other.md': self.ENTRY}, review=['docs/routines/t2-*.md'])
        self.assertEqual(sorted(got), ['located', 'understood', 'understood'])

    def test_a_role_from_the_name_is_capped_at_located_even_when_reviewed(self):
        named = self.ENTRY.rstrip('\n') + ' Role (from name): a mount helper.\n  Reviewed: 2026-11-12\n'
        self.assertEqual(self.levels({'b.md': named}), ['located'])
        self.assertEqual(self.levels({'b.md': named}, review=['docs/routines/*.md']), ['located'])

    def test_a_role_from_the_facts_is_not_capped(self):
        cited = self.ENTRY.rstrip('\n') + ' Role (from facts): copies a block, then mounts it.\n'
        self.assertEqual(self.levels({'b.md': cited}), ['understood'])

    def test_a_cap_does_not_raise_an_entry_that_is_already_below_located(self):
        weak = '- `swfio_mount` in `sw22_474-ip30-flame834/var/sysgen/boot/swfs.o` at 0x1f80\n  It exists.\n'
        self.assertEqual(self.levels({'b.md': weak}, review=['docs/routines/*.md']),
                         self.levels({'b.md': weak}))


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


@unittest.skipIf(ELFFile is None, 'pyelftools is not installed')
class PacketHeaders(unittest.TestCase):
    """A constant that fits a command-packet header form counts as a site of the register it names when it is
    stored through a buffer pointer, the data words follow it and the pointer is stepped past the packet."""
    RULE = {'label': 'type-0 header', 'window': 'mmio',
            'type': {'shift': 30, 'mask': '0x3', 'eq': 0},
            'count': {'shift': 16, 'mask': '0x3fff', 'bias': 1},
            'index': {'shift': 0, 'mask': '0x1fff', 'scale': 4},
            'same_register': {'mask': '0x8000'}, 'reserved': '0x6000', 'max_words': 8, 'registers': 'spec'}
    ROWS = [['T', '1', 'mmio', '0x2180', 'A', 1, 0, 32, 'RW'], ['T', '1', 'mmio', '0x2310', 'B', 4, 4, 32, 'RW'],
            ['T', '1', 'mmio', '0x221c', 'C', 1, 0, 32, 'RW']]

    def replayed(self, body, rule=None, rows=None):
        """(sites by offset, their access sets) of `body`, one function, under the packet rule."""
        cfg = {'windows': [{'name': 'mmio', 'size': '0x10000'}],
               'packets': [rule or self.RULE],
               'spec_registers': [{'type': 'rows', 'spec': 's', 'rows': self.ROWS if rows is None else rows}]}
        insns = [[0x1000 + 4 * i] + list(x) + [None, None] for i, x in enumerate(body + [('jr', ['$31']), ('nop', [])])]
        img = {'elf': ELFFile(io.BytesIO(GpLiterals.kernel())), 'tmp': 'unused', 'label': 'x/dri.so',
               'path': 'x/dri.so', 'group': {}, 'functab': {}}
        saved = inv.run_objdump, inv.split_runs
        inv.run_objdump, inv.split_runs = (lambda path: [('f', insns)]), (lambda funcs, tab: funcs)
        try:
            u = inv.Unit(inv.Model(cfg), cfg, [img]).run()
        finally:
            inv.run_objdump, inv.split_runs = saved
        return {k[1]: sorted(e['acc']) for k, e in sorted(u.out_mmio.items())}

    def test_a_header_and_its_data_through_a_stepped_pointer_is_a_site(self):
        got = self.replayed([('li', ['$9', '0x860']),          # count 0, index 0x860: the register at 0x2180
                             ('sw', ['$9', '16($11)']), ('sw', ['$5', '20($11)']),
                             ('addiu', ['$11', '$11', '24'])])
        self.assertEqual(got, {0x2180: ['packet']})

    def test_a_run_credits_every_register_it_covers(self):
        got = self.replayed([('lui', ['$9', '0x2']), ('ori', ['$9', '$9', '0x8c4']),    # 3 words from 0x2310
                             ('sw', ['$9', '0($4)']), ('sw', ['$5', '4($4)']), ('swc1', ['$f4', '8($4)']),
                             ('sd', ['$6', '12($4)']), ('addiu', ['$4', '$4', '16'])])
        self.assertEqual(got, {0x2310: ['packet'], 0x2314: ['packet'], 0x2318: ['packet']})

    def test_the_step_may_come_before_the_stores_and_data_may_precede_the_header(self):
        got = self.replayed([('addiu', ['$11', '$11', '8']), ('li', ['$9', '0x860']),
                             ('sw', ['$5', '-8($11)']), ('sw', ['$9', '-4($11)']), ('sw', ['$6', '0($11)']),
                             ('addiu', ['$11', '$11', '8'])])
        self.assertEqual(got, {0x2180: ['packet']})

    def test_a_same_register_header_credits_the_one_register(self):
        got = self.replayed([('lui', ['$9', '0x1']), ('ori', ['$9', '$9', '0x8887']),   # 2 words, all to 0x221c
                             ('sw', ['$9', '0($4)']), ('sw', ['$5', '4($4)']), ('sw', ['$6', '8($4)']),
                             ('addiu', ['$4', '$4', '12'])])
        self.assertEqual(got, {0x221c: ['packet']})

    def test_the_pointer_may_move_to_another_register_by_a_constant_register(self):
        """The 64-bit build steps the cursor with `daddu next,cursor,r` where r holds the byte count."""
        got = self.replayed([('li', ['$12', '8']), ('li', ['$9', '0x860']),
                             ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)']),
                             ('daddu', ['$13', '$11', '$12']),
                             ('li', ['$9', '0x887']),
                             ('sw', ['$9', '0($13)']), ('sw', ['$5', '4($13)']),
                             ('daddu', ['$13', '$13', '$12'])])
        self.assertEqual(got, {0x2180: ['packet'], 0x221c: ['packet']})

    def test_a_step_by_an_unknown_amount_ends_the_stream(self):
        got = self.replayed([('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)']),
                             ('daddu', ['$11', '$11', '$6'])])
        self.assertEqual(got, {})

    def test_a_data_word_that_reads_as_a_header_makes_the_pair_ambiguous(self):
        """A table fill stores one small constant after another; a packet's data is rarely a header too."""
        got = self.replayed([('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('sw', ['$9', '4($11)']),
                             ('sw', ['$9', '8($11)']), ('addiu', ['$11', '$11', '12'])])
        self.assertEqual(got, {})

    def test_min_chain_wants_packets_that_begin_where_the_last_ended(self):
        rule = dict(self.RULE, min_chain=2)
        one = [('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)']),
               ('addiu', ['$11', '$11', '8'])]
        two = one[:3] + [('li', ['$10', '0x887']), ('sw', ['$10', '8($11)']), ('sw', ['$5', '12($11)']),
                         ('addiu', ['$11', '$11', '16'])]
        gap = one[:3] + [('li', ['$10', '0x887']), ('sw', ['$10', '16($11)']), ('sw', ['$5', '20($11)']),
                         ('addiu', ['$11', '$11', '24'])]
        self.assertEqual(self.replayed(one, rule), {})
        self.assertEqual(self.replayed(two, rule), {0x2180: ['packet'], 0x221c: ['packet']})
        self.assertEqual(self.replayed(gap, rule), {})

    def test_function_patterns_limit_the_routines_that_count(self):
        body = [('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)']),
                ('addiu', ['$11', '$11', '8'])]
        self.assertEqual(self.replayed(body, dict(self.RULE, functions=['f'])), {0x2180: ['packet']})
        self.assertEqual(self.replayed(body, dict(self.RULE, functions=['g'])), {})
        self.assertEqual(self.replayed(body, dict(self.RULE, exclude_functions=['f.*'])), {})

    def test_max_displacement_rejects_a_field_far_into_a_record(self):
        body = [('li', ['$9', '0x860']), ('sw', ['$9', '2000($11)']), ('sw', ['$5', '2004($11)']),
                ('addiu', ['$11', '$11', '2008'])]
        self.assertEqual(self.replayed(body), {0x2180: ['packet']})
        self.assertEqual(self.replayed(body, dict(self.RULE, max_displacement=1024)), {})

    def test_a_header_without_its_data_words_is_not_a_site(self):
        got = self.replayed([('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('addiu', ['$11', '$11', '8'])])
        self.assertEqual(got, {})

    def test_a_pointer_that_is_never_stepped_is_not_a_stream(self):
        got = self.replayed([('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)'])])
        self.assertEqual(got, {})

    def test_a_pointer_reloaded_between_header_and_data_is_not_a_stream(self):
        got = self.replayed([('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('lw', ['$11', '8($4)']),
                             ('sw', ['$5', '4($11)']), ('addiu', ['$11', '$11', '8'])])
        self.assertEqual(got, {})

    def test_a_pointer_stepped_short_of_the_packet_end_is_not_a_stream(self):
        got = self.replayed([('lui', ['$9', '0x2']), ('ori', ['$9', '$9', '0x8c4']),
                             ('sw', ['$9', '0($4)']), ('sw', ['$5', '4($4)']), ('sw', ['$5', '8($4)']),
                             ('sw', ['$5', '12($4)']), ('addiu', ['$4', '$4', '8'])])
        self.assertEqual(got, {})

    def test_frame_global_and_window_stores_are_not_streams(self):
        for base in ('$29', '$28', '$0'):
            got = self.replayed([('li', ['$9', '0x860']), ('sw', ['$9', '0(%s)' % base]),
                                 ('sw', ['$5', '4(%s)' % base]), ('addiu', [base, base, '8'])])
            self.assertEqual(got, {}, base)

    def test_a_constant_outside_the_header_form_is_not_a_header(self):
        for hdr in ('0xc0000860',      # type 3
                    '0x2860',          # a reserved bit set
                    '0x90860',         # more data words than the rule allows
                    '0x0'):            # no words
            body = [('lui', ['$9', hex(int(hdr, 16) >> 16)]), ('ori', ['$9', '$9', hex(int(hdr, 16) & 0xffff)]),
                    ('sw', ['$9', '0($11)'])] + [('sw', ['$5', '%d($11)' % (4 * i)]) for i in range(1, 12)] + \
                   [('addiu', ['$11', '$11', '48'])]
            self.assertEqual(self.replayed(body), {}, hdr)

    def test_a_register_the_spec_does_not_list_is_not_credited(self):
        got = self.replayed([('li', ['$9', '0x861']), ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)']),
                             ('addiu', ['$11', '$11', '8'])])
        self.assertEqual(got, {})

    def test_without_a_packets_entry_nothing_is_credited(self):
        cfg_body = [('li', ['$9', '0x860']), ('sw', ['$9', '0($11)']), ('sw', ['$5', '4($11)']),
                    ('addiu', ['$11', '$11', '8'])]
        rule = dict(self.RULE, window='mmio', binaries=['*other.so'])
        self.assertEqual(self.replayed(cfg_body, rule), {})


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

    def test_coldfire_base_in_an_address_register_with_a_displacement(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '207c10000000',             # movea.l #0x10000000,a0
            '20280014',                 # move.l 0x14(a0),d0: MBAR+0x14
            '11400016',                 # move.b d0,0x16(a0): MBAR+0x16
            '4e5e', '4e75'))
        self.assertEqual(sorted(u.out_mmio), [('MBAR', 0x14), ('MBAR', 0x16)])
        self.assertEqual(u.out_mmio[('MBAR', 0x16)]['acc'], {'w1'})

    def test_coldfire_lea_absolute_base_and_post_increment(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '41f910000020',             # lea (0x10000020).l,a0
            '1018',             # move.b (a0)+,d0: MBAR+0x20
            '1018',             # move.b (a0)+,d0: MBAR+0x21
            '4e5e', '4e75'))
        self.assertEqual(sorted(u.out_mmio), [('MBAR', 0x20), ('MBAR', 0x21)])

    def test_coldfire_base_survives_a_call_in_a_callee_saved_register_only(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '247c10000000',             # movea.l #0x10000000,a2
            '207c10000000',             # movea.l #0x10000000,a0
            '4eb900002000',             # jsr 0x2000.l
            '102a0004',                 # move.b 4(a2),d0: a2 is kept across the call
            '10280008',                 # move.b 8(a0),d0: a0 is not
            '4e5e', '4e75'))
        self.assertEqual(sorted(u.out_mmio), [('MBAR', 0x4)])

    def test_coldfire_unknown_index_records_the_base_and_marks_the_index(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '207c10000000',             # movea.l #0x10000000,a0
            '20301810',                 # move.l 0x10(a0,d1.l),d0: d1 is not known
            '4e5e', '4e75'))
        self.assertEqual(sorted(u.out_mmio), [('MBAR', 0x10)])
        self.assertEqual(u.out_mmio[('MBAR', 0x10)]['acc'], {'r4 indexed'})
        self.assertEqual(u.out_mmio[('MBAR', 0x10)]['ev'], {'constant base, unknown index'})
        self.assertEqual(list(funcs), ['sub_1000'])

    def test_coldfire_known_index_is_an_ordinary_constant_site(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '207c10000000',
            '7204',                     # moveq #4,d1
            '20301810',                 # move.l 0x10(a0,d1.l),d0: MBAR+0x14
            '4e5e', '4e75'))
        self.assertEqual(sorted(u.out_mmio), [('MBAR', 0x14)])
        self.assertEqual(u.out_mmio[('MBAR', 0x14)]['acc'], {'r4'})

    def test_coldfire_base_loaded_from_memory_is_not_resolved(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '206e0008',                 # movea.l 8(a6),a0: a pointer argument
            '20280014',                 # move.l 0x14(a0),d0
            '20301810',                 # move.l 0x10(a0,d1.l),d0
            '4e5e', '4e75'))
        self.assertEqual(u.out_mmio, {})
        self.assertEqual(funcs, {})

    def test_coldfire_indexed_table_in_a_memory_window_is_not_a_site(self):
        u, funcs = firmware_scan('coldfire', 0x1000, hexbytes(
            '4e560000',
            '207cffe00000',             # movea.l #0xffe00000,a0: the flash
            '20301810',                 # move.l 0x10(a0,d1.l),d0: a table lookup
            '4e5e', '4e75'))
        self.assertEqual(u.out_mmio, {})

    def test_ppc_indexed_with_an_unknown_index_register(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0',
            '3d60fa20',                 # lis r11,0xfa20
            '7c0b182e',                 # lwzx r0,r11,r3: r3 is not known
            '7c0b19ae',                 # stbx r0,r11,r3
            '38210010', '4e800020'))
        self.assertEqual(sorted(u.out_mmio), [('IMMR', 0x0)])
        self.assertEqual(u.out_mmio[('IMMR', 0x0)]['acc'], {'r4 indexed', 'w1 indexed'})

    def test_ppc_indexed_with_both_registers_known_is_a_constant_site(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0',
            '3d60fa20',                 # lis r11,0xfa20
            '38800010',                 # li r4,0x10
            '7c0b222e',                 # lhzx r0,r11,r4: IMMR+0x10
            '38210010', '4e800020'))
        self.assertEqual(sorted(u.out_mmio), [('IMMR', 0x10)])
        self.assertEqual(u.out_mmio[('IMMR', 0x10)]['acc'], {'r2'})

    def test_ppc_indexed_with_neither_register_known_is_not_a_site(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0',
            '7c0b182e',                 # lwzx r0,r11,r3: nothing is known
            '38210010', '4e800020'))
        self.assertEqual(u.out_mmio, {})

    def test_ppc_base_with_a_displacement_from_memory_is_not_resolved(self):
        u, funcs = firmware_scan('ppc32', 0xfe000000, hexbytes(
            '9421fff0',
            '8161000c',                 # lwz r11,12(r1): a pointer from the stack
            '800b0014',                 # lwz r0,0x14(r11)
            '38210010', '4e800020'))
        self.assertEqual(u.out_mmio, {})

    def test_the_smaller_window_wins_where_windows_nest(self):
        m = inv.Model(FIRMWARE_WINDOWS)
        self.assertEqual(inv.window_at(m, 0xffe00040), ('FLASH', 0x40))
        self.assertEqual(inv.window_at(m, 0xfa200284), ('IMMR', 0x284))
        self.assertIsNone(inv.window_at(m, 0x60000000))


class RoleSignature(unittest.TestCase):
    """The role clause the cross-workspace check compares."""

    def test_a_size_only_opening_sentence_is_not_a_role(self):
        # Every routine reading opens "`f` is a N-byte routine." That sentence names no role, so two
        # workspaces' readings of different routines share it and must not be called the same text.
        odsy = ('`glXSwapIntervalSGI` is a 440-byte n32 routine. It walks from abs 0x1014 to the current '
                'drawable record, then calls `ioctl` with request 0x3ee on the device descriptor.')
        kona = ('`glXSwapIntervalSGI` is a 440-byte routine. It uses the same descriptor lookup and calls '
                '`ioctl` with request 0x3ee and a stack buffer at sp-64.')
        self.assertEqual(inv.role_signature(odsy), '')
        self.assertEqual(inv.role_signature(kona), '')

    def test_a_stated_role_is_kept(self):
        t = ('- `__glScaleMatrix` in builds/x/libGLcore.so: scales the first three rows of a matrix record in '
             'place by three factors, and it occupies 160 bytes at address 0x0da9e570; the rest.')
        self.assertEqual(inv.role_signature(t), 'scales the first three rows of a matrix record in place by '
                                                'three factors')


class RoleHedge(unittest.TestCase):
    """A sentence that says the routine's whole role is open holds the entry at located; a sentence that
    says one fact of it is unknown does not."""
    SUBJ = frozenset({('id', 'swfio_mount')})
    ROLE = ('Copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The return is the '
            'constant 0xe or the mount result at 0x2084.')

    def read(self, extra):
        return inv.read_why('- `swfio_mount` in `swfs.o` at 0x1f80\n  **Inferred.** %s %s' % (self.ROLE, extra), self.SUBJ)

    def test_the_bare_role_is_understood(self):
        self.assertEqual(self.read('')[0], 'understood')

    def test_a_statement_that_the_role_is_open_caps_the_entry_at_located(self):
        for sentence in ('The role is open.', 'Beyond the mount call the role stays open.',
                         'The role is not derived.', 'Its role is not shown in the facts.',
                         'The facts do not show the role.', 'The purpose is left open.',
                         'The name points at a mount, but the reading is open.',
                         'What the routine does is not established.', 'What it does is unknown.',
                         'What `swfio_mount` does is not established.',
                         'The meaning of the result is unknown.',
                         'The role beyond the mount call is open.',
                         'The name suggests a mount, so its role is open.', 'Its role is not settled.'):
            status, open_, why = self.read(sentence)
            self.assertEqual((status, open_), ('located', False), sentence)
            self.assertIn('role', why, sentence)

    def test_an_unknown_sub_fact_does_not_cap_the_role(self):
        for sentence in ('The stored value is unknown.', 'What the callee does is not visible.',
                         'The purpose of the 0x2084 word is open.', 'The facts do not say what the flag byte means.',
                         'What `swf_mount_fs` does is open.',
                         'The role is only partly open.', 'The reads are not used, so their purpose is open.',
                         'The role in the retry path is open.',
                         'The field at +0x128 is used but its role is not settled.', 'The width of the stored word is unknown.'):
            self.assertEqual(self.read(sentence)[0], 'understood', sentence)

    def test_an_entry_without_a_citation_stays_named_only(self):
        self.assertEqual(inv.read_why('- `swfio_mount`: **Inferred.** Mounts it. The role is open.', self.SUBJ)[0],
                         'named-only')


if __name__ == '__main__':
    unittest.main()
