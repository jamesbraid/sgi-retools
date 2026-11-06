"""Tests of how check_claims.py finds the routine and binary of an entry; they need no root/ and no toolchain."""
import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

import check_claims  # noqa: E402

RELEASES = ('6.5.28', '6.5.29', '6.5.30')


def binaries(keys):
    b = check_claims.Binaries.__new__(check_claims.Binaries)
    b.keys = set(keys)
    b._index()
    return b


def entries_of(text):
    ents, pre = check_claims.read_entries('docs/t.md', text)
    return ents, pre


class Resolution(unittest.TestCase):
    def setUp(self):
        self.bins = binaries(['%s/usr/sbin/l1cmd' % r for r in RELEASES] + ['%s/usr/sbin/l2cmd' % r for r in RELEASES])

    def ident(self, text, hints=(), default=None):
        ents, _ = entries_of(text)
        e = ents[0]
        check_claims.identify(e, self.bins, list(hints), default)
        return e

    def test_release_qualified_table_cell_resolves(self):
        e = self.ident('| binary | routine | address |\n|---|---|---|\n| `6.5.30/usr/sbin/l1cmd` | `sn1SCInit` | `0x10007990` |\n')
        self.assertEqual(e.binary, '6.5.30/usr/sbin/l1cmd')
        self.assertEqual(e.name, 'sn1SCInit')

    def test_unqualified_cell_in_many_releases_stays_unresolved(self):
        e = self.ident('| binary | routine |\n|---|---|\n| `usr/sbin/l1cmd` | `f` |\n')
        self.assertIsNone(e.binary)

    def test_qualified_cell_falls_back_to_the_plain_path(self):
        self.bins = binaries(['usr/sbin/only'])
        e = self.ident('| binary | routine |\n|---|---|\n| `6.5.30/usr/sbin/only` | `f` |\n')
        self.assertEqual(e.binary, 'usr/sbin/only')

    def test_release_qualified_bullet_resolves(self):
        e = self.ident('- `f` (`6.5.29/usr/sbin/l2cmd`, `0x10`, 16 bytes). Established.\n')
        self.assertEqual(e.binary, '6.5.29/usr/sbin/l2cmd')

    def test_release_named_in_prose_picks_the_binary(self):
        e = self.ident('- `f` (`usr/sbin/l1cmd`, 6.5.29, `0x10`, 16 bytes). Established.\n')
        self.assertEqual(e.binary, '6.5.29/usr/sbin/l1cmd')

    def test_two_releases_in_prose_do_not_guess(self):
        e = self.ident('- `f` (`usr/sbin/l1cmd`, 6.5.29 and 6.5.30, `0x10`, 16 bytes). Established.\n')
        self.assertIsNone(e.binary)

    def test_release_does_not_override_a_unique_binary(self):
        self.bins = binaries(['usr/sbin/only'])
        e = self.ident('- `f` (`usr/sbin/only`, 6.5.29, `0x10`, 16 bytes). Established.\n')
        self.assertEqual(e.binary, 'usr/sbin/only')

    def test_routine_size_is_read_from_a_range_header(self):
        e = self.ident('- `f` in `usr/sbin/l1cmd` at 0x10. Range: 0x10-0x20 (16 bytes). Established.\n')
        self.assertEqual((e.address, e.size), (0x10, 16))


class RootFallback(unittest.TestCase):
    def test_release_in_prose_finds_a_file_the_inventory_lacks(self):
        with tempfile.TemporaryDirectory() as td:
            for r in ('6.5.29', '6.5.30'):
                os.makedirs(os.path.join(td, 'root', r, 'usr', 'cpu'))
                open(os.path.join(td, 'root', r, 'usr', 'cpu', 'elsc.o'), 'w').close()
            old, check_claims.REPO = check_claims.REPO, td
            try:
                bins = binaries(['6.5.30/usr/sbin/l1cmd'])
                ents, _ = entries_of('- `f` (`usr/cpu/elsc.o`, 6.5.30, `0x10`, 16 bytes). Established.\n')
                check_claims.identify(ents[0], bins, [], None)
            finally:
                check_claims.REPO = old
        self.assertEqual(ents[0].binary, '6.5.30/usr/cpu/elsc.o')


class CitedPath(unittest.TestCase):
    """A cited path names its image whatever its first component, and a suffix shared by two images stays unresolved."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        for f in ('IP27/unix', 'IP30/unix', 'IP30/usr/cpu/sysgen/IP30boot/pcibr.o', 'IP27/usr/cpu/sysgen/IP27boot/pcibr.o',
                  'sbin/stand', 'IP30/usr/lib/libx.a'):
            os.makedirs(os.path.dirname(os.path.join(self.td.name, 'root', f)), exist_ok=True)
            open(os.path.join(self.td.name, 'root', f), 'w').close()
        os.makedirs(os.path.join(self.td.name, 'root', 'IP30', 'dir'))
        old, check_claims.REPO = check_claims.REPO, self.td.name
        self.addCleanup(setattr, check_claims, 'REPO', old)
        self.bins = binaries([])

    def ident(self, text, default=None):
        ents, _ = entries_of(text)
        check_claims.identify(ents[0], self.bins, [], default)
        return ents[0]

    def test_path_with_no_usr_prefix_resolves(self):
        e = self.ident('- `flushbus` in `IP30/unix` at 0xa80000002001c1c4 (n64).\n  Exact binary: `IP30/unix`.\n')
        self.assertEqual((e.name, e.binary), ('flushbus', 'IP30/unix'))

    def test_top_level_sbin_resolves(self):
        e = self.ident('- `f` in `sbin/stand` at 0x10 (n32).\n  Exact binary: `sbin/stand`.\n')
        self.assertEqual(e.binary, 'sbin/stand')

    def test_leading_image_directory_is_not_dropped(self):
        e = self.ident('- `f` in `IP30/usr/cpu/sysgen/IP30boot/pcibr.o` at 0x10 (n64).\n'
                       '  Exact binary: `IP30/usr/cpu/sysgen/IP30boot/pcibr.o`.\n')
        self.assertEqual(e.binary, 'IP30/usr/cpu/sysgen/IP30boot/pcibr.o')

    def test_archive_member_of_an_existing_archive_resolves(self):
        e = self.ident('- `f` in `IP30/usr/lib/libx.a(m.o)` at 0x10 (n64).\n')
        self.assertEqual(e.binary, 'IP30/usr/lib/libx.a(m.o)')

    def test_header_path_alone_resolves(self):
        e = self.ident('- `f` in `IP27/unix` at 0x10 (n64).\n')
        self.assertEqual(e.binary, 'IP27/unix')

    def test_suffix_shared_by_two_images_stays_unresolved(self):
        e = self.ident('- `f` in `unix` at 0x10 (n64).\n')
        self.assertIsNone(e.binary)
        e = self.ident('- `f` in `usr/cpu/sysgen/IP30boot/../pcibr.o` at 0x10.\n')
        self.assertIsNone(e.binary)

    def test_directory_and_missing_path_do_not_resolve(self):
        self.assertIsNone(self.ident('- `f` in `IP30/dir` at 0x10 (n64).\n').binary)
        self.assertIsNone(self.ident('- `f` in `IP35/unix` at 0x10 (n64).\n').binary)

    def test_table_cell_without_usr_prefix_resolves(self):
        e = self.ident('| binary | routine | address |\n|---|---|---|\n| `IP30/unix` | `f` | `0x10` |\n')
        self.assertEqual(e.binary, 'IP30/unix')


class StatedRoutineSize(unittest.TestCase):
    def test_size_is_passed_when_the_symbol_size_is_missing_or_smaller(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, 'root', 'usr', 'bin'))
            binary = os.path.join(td, 'root', 'usr', 'bin', 'x')
            open(binary, 'wb').close()
            old, check_claims.REPO = check_claims.REPO, td
            try:
                for symbol_size in (0, 556):
                    f = check_claims.Facts()
                    f.image = lambda _: types.SimpleNamespace(
                        byname={'f': [(0x1000, symbol_size, 'f', '.text', True, 'symtab')]})
                    seen = []
                    def fact_sheet(path, routine, member, size=None, with_insns=True):
                        seen.append((routine, size))
                        return {'routine': {'address': '0x1000', 'size': size, 'size_source': 'given'}}
                    with mock.patch.object(check_claims.facts, 'fact_sheet', fact_sheet):
                        result, err = f.get('usr/bin/x', 'f', 0x1000, 7008)
                    self.assertIsNone(err)
                    self.assertEqual(seen, [('0x1000', 7008)])
                    self.assertEqual(result['routine']['size'], 7008)
            finally:
                check_claims.REPO = old


class Tables(unittest.TestCase):
    DOC = ('# Doc\n\n'
           '| Option | Meaning |\n|---|---|\n| `--l2` | host |\n\n'
           '| binary | routine | status |\n|---|---|---|\n| `x.o` | `f` | Established. |\n')

    def test_rows_of_a_table_without_a_routine_column_are_not_entries(self):
        keys = {e.table.get('option') or e.table.get('routine') for e in entries_of(self.DOC)[0]}
        self.assertEqual(keys, {'`--l2`', '`f`'})   # read_entries still reads them (chip documents use other columns)
        kept = [e for e in entries_of(self.DOC)[0] if any(k in e.table for k in check_claims.NAME_COLUMNS)]
        self.assertEqual([e.table['routine'] for e in kept], ['`f`'])


class Notice(unittest.TestCase):
    """main() lists the unresolved entries that carry a status, even with --quiet."""

    def run_main(self, doc, *args):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, 'docs', 'inventory'))
            with open(os.path.join(td, 'docs', 'inventory', 'functions.tsv'), 'w') as f:
                f.write('binary\tname\n6.5.29/usr/sbin/l1cmd\tg\n6.5.30/usr/sbin/l1cmd\tg\n')
            with open(os.path.join(td, 'docs', 't.md'), 'w') as f:
                f.write(doc)
            old = check_claims.REPO
            check_claims.REPO = td
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    check_claims.main(['--status', 'all', '--quiet'] + list(args))
            finally:
                check_claims.REPO = old
        return out.getvalue()

    DOC = ('# Doc\n\n'
           '| Option | Meaning |\n|---|---|\n| `--l2` | host |\n| `--sc` | default |\n\n'
           '- `h` (`usr/sbin/nowhere`, `0x10`, 16 bytes). Established.\n'
           '- A prose bullet with no status and no routine.\n')

    def test_notice_lists_only_claims(self):
        out = self.run_main(self.DOC, '--list-unresolved')
        self.assertIn('notice: 1 claim entries', out)
        self.assertIn('UNRESOLVED\tdocs/t.md:8\th', out)
        self.assertNotIn('docs/t.md:5', out)    # option table rows are not claims
        self.assertNotIn('docs/t.md:9', out)    # a bullet without a status is not a claim

    def test_quiet_without_the_flag_prints_no_notice(self):
        self.assertNotIn('UNRESOLVED', self.run_main(self.DOC))

    def test_option_rows_are_not_counted_as_entries(self):
        self.assertIn('summary: 0 entries checked, 2 unresolved', self.run_main(self.DOC))


class FakeImg:
    abi = None

    def __init__(self, words):
        self.words = words

    def read(self, addr, width):
        return self.words[addr].to_bytes(4, 'big') if addr in self.words else None


class FakeCtx:
    """The parts of Ctx that the width and offset checks read."""

    def __init__(self, insns, accesses=(), addresses=(), img=None):
        self.insn_at, self.img, self.addr, self.end = dict(insns), img, 0x1000, 0x3000
        self.offsets_access, self.raw_offsets, self.offsets_addr, self.abs_loads = {}, {}, {}, {}
        self.numbers, self.fs = set(), {'loops': []}
        for a in accesses:     # the non-stack accesses the flow walk found: (offset, width, text)
            rec = {'offset': a[0], 'origin_offset': a[0], 'width': a[1], 'text': a[2]}
            self.offsets_access.setdefault(a[0], []).append(rec)
            self.raw_offsets.setdefault(a[0], []).append(rec)
        for a in addresses:
            self.offsets_addr.setdefault(a[0], []).append({'offset': a[0], 'text': a[1]})


class AtLocator(unittest.TestCase):
    def run_checks(self, text, ctx):
        e = types.SimpleNamespace(text=text, table=None, binary=None, id='t', name='f', status='established')
        rep = []
        chk = check_claims.Checker(e, ctx, rep, None, None)
        chk.width()
        chk.offsets()
        return rep

    def verdicts(self, rep):
        return [(r['class'], r['verdict']) for r in rep]

    def test_stack_access_at_the_locator_holds(self):
        # the only non-stack thing at +56 is an address formed with daddiu: the old reading
        ctx = FakeCtx({0x23b0: 'lw t1,56(sp)', 0x2410: 'sw t1,56(sp)'}, addresses=[(56, 'daddiu a0,v0,56')])
        rep = self.run_checks('The header word at +56 (of the copied request: `lw` at 0x23b0, `sw` at 0x2410) is set.', ctx)
        self.assertEqual(self.verdicts(rep), [('width', 'ok'), ('width', 'ok')])

    def test_narrow_stack_access_at_the_locator_holds(self):
        ctx = FakeCtx({0x11dc: 'lhu a6,8(sp)'}, accesses=[(8, 8, 'ld a1,-30712(gp)')])
        rep = self.run_checks('It needs the slot halfword at +8 (`lhu` at 0x11dc) below 16.', ctx)
        self.assertEqual(self.verdicts(rep), [('width-narrow', 'ok')])

    def test_wrong_width_at_the_locator_mismatches(self):
        ctx = FakeCtx({0x11dc: 'lw a6,8(sp)'})
        rep = self.run_checks('It needs the slot halfword at +8 (`lw` at 0x11dc) below 16.', ctx)
        self.assertEqual(self.verdicts(rep), [('width-narrow', 'mismatch')])

    def test_other_displacement_at_the_locator_is_not_this_access(self):
        # "the word at +16 is loaded (...) and stored (`sw` at 0xd95911c)": the store goes to a port, not +16
        ctx = FakeCtx({0x11dc: 'sw t6,16384(zero)'}, accesses=[(16, 4, 'lw t6,16(a0)')])
        rep = self.run_checks('The word at +16 is loaded and stored later (`sw` at 0x11dc).', ctx)
        self.assertEqual(self.verdicts(rep), [('width', 'ok'), ('offset', 'ok')])

    def test_locator_on_a_non_memory_instruction_mismatches(self):
        ctx = FakeCtx({0x11dc: 'addu a0,a1,a2'})
        rep = self.run_checks('It needs the slot halfword at +8 (`lhu` at 0x11dc) below 16.', ctx)
        self.assertEqual(self.verdicts(rep), [('width-narrow', 'mismatch')])

    def test_unreached_instruction_is_decoded_from_the_image(self):
        lhu_s1_0 = (0x25 << 26) | (17 << 21) | (8 << 16)      # lhu t0,0(s1)
        ctx = FakeCtx({}, accesses=[(0, 8, 'ld v0,-30720(gp)')], img=FakeImg({0x25a8: lhu_s1_0}))
        rep = self.run_checks('It selects by the request halfword at +0 (`lhu` at 0x25a8) and stops.', ctx)
        self.assertEqual(self.verdicts(rep), [('width-narrow', 'ok')])

    def test_unreadable_locator_leaves_the_old_check(self):
        ctx = FakeCtx({}, accesses=[(0, 8, 'ld v0,-30720(gp)')])
        rep = self.run_checks('It selects by the request halfword at +0 (`lhu` at 0x25a8) and stops.', ctx)
        self.assertEqual(self.verdicts(rep), [('width-narrow', 'mismatch'), ('offset', 'ok')])

    def test_locator_of_the_next_claim_is_not_borrowed(self):
        ctx = FakeCtx({0x100: 'lw a0,12(sp)'}, accesses=[(8, 2, 'lhu a1,8(a0)')])
        rep = self.run_checks('The halfword at +8 and the word at +12 (`lw` at 0x100) are read.', ctx)
        self.assertIn(('width-narrow', 'ok'), self.verdicts(rep))
        self.assertIn(('width', 'ok'), self.verdicts(rep))
        self.assertNotIn('mismatch', [v for _, v in self.verdicts(rep)])

    def test_no_locator_keeps_the_old_behaviour(self):
        ctx = FakeCtx({0x11dc: 'lhu a6,8(sp)'}, accesses=[(8, 8, 'ld a1,-30712(gp)')])
        rep = self.run_checks('It needs the slot halfword at +8 below 16.', ctx)
        self.assertEqual(self.verdicts(rep), [('width-narrow', 'mismatch'), ('offset', 'ok')])


class InsnAddressList(unittest.TestCase):
    """"`sw` at 0xA, 0xB and 0xC" names three instructions; each is judged against the mnemonic."""

    INSNS = {0x1100: 'sw a0,0(s0)', 0x1104: 'sll zero,zero,0x0', 0x1108: 'lw a1,4(s0)', 0x110c: 'dsll32 t0,t1,0x2',
             0x1110: 'beq a0,zero,0x1200', 0x1114: 'beq zero,zero,0x1200', 0x1118: 'or a0,s1,zero', 0x111c: 'sw a2,8(s0)',
             0x1120: 'sw a3,12(s0)'}

    def verdicts(self, text):
        e = types.SimpleNamespace(text=text, table=None, binary=None, id='t', name='f', status='established')
        rep = []
        check_claims.Checker(e, FakeCtx(self.INSNS), rep, None, None).insn_address()
        return [(r['claim'], r['verdict']) for r in rep]

    def test_every_member_of_a_comma_list_is_checked(self):
        v = self.verdicts('The stores are `sw` at 0x1100, 0x111c, 0x1120.')
        self.assertEqual([x[1] for x in v], ['ok', 'ok', 'ok'])

    def test_wrong_second_address_mismatches(self):
        v = self.verdicts('The stores are `sw` at 0x1100, 0x1108.')
        self.assertEqual([x[1] for x in v], ['ok', 'mismatch'])
        self.assertIn('0x1108', v[1][0])

    def test_and_and_or_separate_members(self):
        self.assertEqual([x[1] for x in self.verdicts('`sw` at 0x1100, 0x111c and 0x1108.')], ['ok', 'ok', 'mismatch'])
        self.assertEqual([x[1] for x in self.verdicts('`sw` at 0x1100 or 0x1104.')], ['ok', 'mismatch'])
        self.assertEqual([x[1] for x in self.verdicts('`sw` at 0x1100, and 0x1120.')], ['ok', 'ok'])

    def test_parenthesised_list(self):
        self.assertEqual([x[1] for x in self.verdicts('Stores (`sw` at 0x1100, 0x1108) follow.')], ['ok', 'mismatch'])

    def test_list_stops_at_the_end_of_the_clause(self):
        # the second clause is another claim, judged on its own; 0x1108 is not a `sw` member
        v = self.verdicts('`sw` at 0x1100; then 0x1108 is reloaded, and `lw` at 0x1108.')
        self.assertEqual([x[1] for x in v], ['ok', 'ok'])

    def test_range_is_not_a_list_member(self):
        self.assertEqual([x[1] for x in self.verdicts('`sw` at 0x1100, 0x1108 to 0x1110.')], ['ok'])

    def test_address_outside_the_routine_is_not_judged_as_this_routines_instruction(self):
        # it is reported as insn-outside instead (OutsideRoutine)
        self.assertEqual([x[1] for x in self.verdicts('`sw` at 0x1100, 0x9000.')], ['ok', 'mismatch'])

    def test_aliases_match_in_later_positions(self):
        v = self.verdicts('Nops at `nop` at 0x1104, 0x1104; `dsll` at 0x110c; `b` at 0x1114; `beqz` at 0x1110; `move` at 0x1118.')
        self.assertTrue(v and all(x[1] == 'ok' for x in v), v)
        self.assertEqual([x[1] for x in self.verdicts('`nop` at 0x1104, 0x1118.')], ['ok', 'mismatch'])
        self.assertEqual([x[1] for x in self.verdicts('`b` at 0x1114, 0x1110.')], ['ok', 'mismatch'])
        self.assertEqual([x[1] for x in self.verdicts('`beqz` at 0x1110, 0x1114.')], ['ok', 'ok'])    # beq zero,zero is also beqz
        self.assertEqual([x[1] for x in self.verdicts('`move` at 0x1118, 0x1100.')], ['ok', 'mismatch'])

    def test_kind_list(self):
        v = self.verdicts('The stores at 0x1100, 0x111c and 0x1108 follow.')
        self.assertEqual([x[1] for x in v], ['ok', 'ok', 'mismatch'])


class OutsideRoutine(unittest.TestCase):
    """An instruction address cited in an entry must lie in the entry's routine (FakeCtx: 0x1000-0x3000),
    unless the clause says it is in another place."""

    INSNS = {0x1100: 'sw a0,0(s0)', 0x1104: 'jal 0x4000', 0x1108: 'lw a1,4(s0)'}

    def results(self, text):
        e = types.SimpleNamespace(text=text, table=None, binary=None, id='t', name='f', status='established')
        rep = []
        check_claims.Checker(e, FakeCtx(self.INSNS), rep, None, None).insn_address()
        return [(r['class'], r['verdict'], r['fact']) for r in rep if r['class'] == 'insn-outside']

    def test_in_range_citation_passes(self):
        self.assertEqual(self.results('The `sw` at 0x1100 stores it and the call at 0x1104 follows.'), [])

    def test_out_of_range_mnemonic_citation_is_flagged_with_the_range(self):
        r = self.results('The `lw` at 0x9000 loads the length.')
        self.assertEqual([x[:2] for x in r], [('insn-outside', 'mismatch')])
        self.assertIn('[0x1000, 0x3000)', r[0][2])

    def test_out_of_range_call_citation_is_flagged(self):
        self.assertEqual([x[:2] for x in self.results('The call at 0x9004 reports it.')], [('insn-outside', 'mismatch')])

    def test_list_members_are_checked_individually(self):
        r = self.results('The stores are `sw` at 0x1100, 0x9000 and 0xa000.')
        self.assertEqual([x[1] for x in r], ['mismatch', 'mismatch'])

    def test_class_blocks(self):
        self.assertIn('insn-outside', check_claims.BLOCKING)

    def test_explicit_other_routine_phrasing_is_exempt(self):
        for text in ('The caller reaches it with the `jal` at 0x9000.',
                     'It is called by the call at 0x9000 in `other_routine`.',
                     'The `sw` at 0x9000 in `other_routine` stores it.',
                     'The `jal` at 0x9000 of the `other_routine` handler calls it.',
                     'The call in other_routine at 0x9000 passes the flag.',
                     'It returns to 0x9004 after the `jal` at 0x9000.'):
            r = self.results(text)
            self.assertEqual([x[1] for x in r], ['ok'] * len(r), text)
            self.assertTrue(r, text)

    def test_branch_target_outside_the_routine_is_exempt(self):
        self.assertEqual(self.results('The `bne` at 0x1100 branches to 0x9000 on error.'), [])
        r = self.results('The `beq` at 0x1100, 0x1104 branches to 0x9000; the `b` at 0x9008 is the target.')
        self.assertEqual([x[1] for x in r], ['ok'])

    def test_object_of_the_verb_is_not_an_instruction_address(self):
        # "calls X at A" and "stores the result at A" give the address of the callee or the data
        for text in ('It calls the loader at 0x9000 with the context.', 'The routine calls it at 0x9000.',
                     'It stores the result at 0x9000.', 'A 13-entry jump table at 0x9000 decodes it.'):
            r = self.results(text)
            self.assertEqual([x[1] for x in r], ['ok'], text)

    def test_call_named_by_its_callee_is_exempt(self):
        self.assertEqual([x[1] for x in self.results('The body makes two computeMax calls at 0x9000, one per child.')], ['ok'])
        self.assertEqual([x[1] for x in self.results('The body makes two calls at 0x9000, one per child.')], ['mismatch'])

    def test_other_build_is_exempt_only_near_the_citation(self):
        self.assertEqual([x[1] for x in self.results('The N32 test is a plain `beq` at 0x9000.')], ['ok'])
        self.assertEqual([x[1] for x in self.results('The N32 test is plain. The `beq` at 0x9000 tests it.')], ['mismatch'])
        far = 'The N32 test is a plain branch, ' + 'and a long stretch of text follows ' * 2 + 'before the `beq` at 0x9000 is reached.'
        self.assertEqual([x[1] for x in self.results(far)], ['mismatch'])

    def test_exemption_does_not_leak_into_the_next_sentence(self):
        r = self.results('The caller passes a flag. The `lw` at 0x9000 loads the length.')
        self.assertEqual([x[1] for x in r], ['mismatch'])

    def test_low_32_bit_kernel_address_uses_routine_width(self):
        ctx = FakeCtx({0xc000000000001100: 'sw a0,0(s0)'})
        ctx.addr, ctx.end, ctx.size = 0xc000000000001100, 0xc000000000001200, 0x100
        e = types.SimpleNamespace(text='The `sw` at 0x1100 stores it.', table=None, binary=None, id='t', name='f', status='established')
        rep = []
        check_claims.Checker(e, ctx, rep, None, None).insn_address()
        self.assertEqual([x['verdict'] for x in rep if x['class'] == 'insn-outside'], [])
        self.assertEqual([x[1] for x in self.results('The `lw` at 0x9000 loads it.')], ['mismatch'])

    def test_comma_after_closed_address_citation_is_not_an_instruction_list(self):
        self.assertEqual(self.results('The `sw` at 0x1100), 0x1900 is the token value.'), [])
        self.assertEqual([x[1] for x in self.results('The `lw` at 0x9000 loads it.')], ['mismatch'])

    def test_small_values_and_parenthesized_encodings_are_not_addresses(self):
        self.assertEqual(self.results('The stores are at 0x1b0 and 0xd0; `jr ra` (0x03e00008) returns.'), [])
        self.assertEqual([x[1] for x in self.results('The `lw` at 0x9000 loads it.')], ['mismatch'])


    def high_routine(self, text):
        ctx = FakeCtx({0xc000000000001100: 'sw a0,0(s0)'})
        ctx.addr, ctx.end, ctx.size = 0xc000000000001100, 0xc000000000001200, 0x100
        e = types.SimpleNamespace(text=text, table=None, binary=None, id='t', name='f', status='established')
        rep = []
        check_claims.Checker(e, ctx, rep, None, None).insn_address()
        return [x['verdict'] for x in rep if x['class'] == 'insn-outside']

    def test_low_32_bit_form_is_still_bounded_by_the_routine_size(self):
        self.assertEqual(self.high_routine('The `sw` at 0x11f0 stores it.'), [])
        self.assertEqual(self.high_routine('The `sw` at 0x1200 stores it.'), ['mismatch'])
        self.assertEqual(self.high_routine('The `sw` at 0x10f0 stores it.'), ['mismatch'])
        self.assertEqual(self.high_routine('The `sw` at 0x2000000011f0 stores it.'), ['mismatch'])

    def test_wrong_address_after_a_parenthesised_citation_is_not_hidden_in_plain_lists(self):
        self.assertEqual([x[1] for x in self.results('The `sw` at 0x1100, 0x9000 and 0xa000 store it.')], ['mismatch', 'mismatch'])
        self.assertEqual([x[1] for x in self.results('The `sw` at 0x9000 (0x03e00008) stores it.')], ['mismatch'])

    def test_small_value_cutoff_is_exactly_the_first_page(self):
        self.assertEqual(self.high_routine('The `sw` at 0xfff stores it.'), [])
        self.assertEqual(self.high_routine('The `sw` at 0x1000 stores it.'), ['mismatch'])


class AliasForms(unittest.TestCase):
    """An entry may quote an instruction as its canonical encoding or as the assembler alias the facts print."""

    def same(self, a, b):
        self.assertIn(check_claims.norm_insn(a), {check_claims.norm_insn(f) for f in check_claims.canon(b)}, (a, b))
        self.assertIn(check_claims.norm_insn(b), {check_claims.norm_insn(f) for f in check_claims.canon(a)}, (b, a))

    def differ(self, a, b):
        self.assertNotIn(check_claims.norm_insn(a), {check_claims.norm_insn(f) for f in check_claims.canon(b)}, (a, b))

    def test_load_immediate_aliases(self):
        self.same('ori at,zero,0x80bc', 'dli at,0x80bc')
        self.same('ori at,zero,0x80bc', 'li at,0x80bc')
        self.same('addiu v0,zero,-1', 'li v0,-1')
        self.same('daddiu v0,zero,5', 'dli v0,5')

    def test_load_immediate_does_not_cross_encodings(self):
        self.differ('addiu at,zero,0x80bc', 'dli at,0x80bc')   # 0x80bc does not fit addiu's signed field
        self.differ('ori at,zero,-1', 'li at,-1')
        self.differ('ori at,zero,0x80bd', 'dli at,0x80bc')
        self.differ('ori v0,zero,0x80bc', 'dli at,0x80bc')

    def test_negate_move_not_aliases(self):
        self.same('subu v1,zero,s0', 'negu v1,s0')
        self.same('dsubu v1,zero,s0', 'dnegu v1,s0')
        self.same('sub v1,zero,s0', 'neg v1,s0')
        self.same('or v0,a0,zero', 'move v0,a0')
        self.same('daddu v0,a0,zero', 'move v0,a0')
        self.same('addu v0,a0,zero', 'move v0,a0')
        self.same('nor v0,a0,zero', 'not v0,a0')
        self.differ('subu v1,s0,zero', 'negu v1,s0')
        self.differ('dsubu v1,zero,s0', 'negu v1,s0')

    def test_branch_and_nop_aliases(self):
        self.same('beq zero,zero,0x40', 'b 0x40')
        self.same('bgezal zero,0x40', 'bal 0x40')
        self.same('bne a0,zero,0x40', 'bnez a0,0x40')
        self.same('beql a0,zero,0x40', 'beqzl a0,0x40')
        self.same('sll zero,zero,0x0', 'nop')
        self.same('sll zero,zero,0x1', 'ssnop')
        self.same('jalr ra,t9', 'jalr t9')
        self.differ('beq a0,a1,0x40', 'b 0x40')
        self.differ('bne a0,zero,0x40', 'beqz a0,0x40')


if __name__ == '__main__':
    unittest.main()


class BlockUnresolved(unittest.TestCase):
    """--block-unresolved refuses a graded entry the range adds or edits that cannot be tested; old ones pass."""

    OLD = ('# Doc\n\n'
           '| Option | Meaning |\n|---|---|\n| `--l2` | host |\n\n'
           '- `old` (`usr/sbin/nowhere`, `0x10`, 16 bytes). Established.\n'
           '- `fine` (`usr/sbin/l1cmd`, `0x10`, 16 bytes). Unverified.\n'
           '- Closing prose.\n')

    def git(self, td, *a):
        import subprocess
        subprocess.run(['git', '-C', td, '-c', 'user.name=t', '-c', 'user.email=t@t', *a], check=True,
                       capture_output=True)

    def run_range(self, new, *args):
        """Commit OLD, write NEW in the working tree, run main against the commit; returns (rc, stdout)."""
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, 'docs', 'inventory'))
            with open(os.path.join(td, 'docs', 'inventory', 'functions.tsv'), 'w') as f:
                f.write('binary\tname\nusr/sbin/l1cmd\tg\n')
            doc = os.path.join(td, 'docs', 't.md')
            with open(doc, 'w') as f:
                f.write(self.OLD)
            self.git(td, 'init', '-q')
            self.git(td, 'add', '.')
            self.git(td, 'commit', '-q', '-m', 'base')
            with open(doc, 'w') as f:
                f.write(new)
            old = check_claims.REPO
            check_claims.REPO = td
            out = io.StringIO()
            try:
                with contextlib.redirect_stdout(out):
                    rc = check_claims.main(['--status', 'all', '--quiet', '--list-unresolved', '--blocking',
                                            '--block-unresolved', '--changed', 'HEAD'] + list(args))
            finally:
                check_claims.REPO = old
        return rc, out.getvalue()

    def test_untouched_old_entry_is_not_refused(self):
        rc, out = self.run_range(self.OLD + '- Another closing line.\n')
        self.assertEqual(rc, 0, out)
        self.assertNotIn('REFUSED', out)

    def test_new_graded_entry_with_no_binary_is_refused(self):
        rc, out = self.run_range(self.OLD + '- `fresh` (`usr/sbin/missing`, `0x20`, 8 bytes). Inferred.\n')
        self.assertEqual(rc, 1, out)
        self.assertIn('REFUSED-UNTESTABLE\tdocs/t.md:10\tfresh', out)
        self.assertNotIn('docs/t.md:7', out)    # the old entry stays allowed
        self.assertIn('full build path', out)

    def test_editing_an_old_graded_entry_refuses_it(self):
        rc, out = self.run_range(self.OLD.replace('16 bytes). Established.', '16 bytes; reread. Established.', 1))
        self.assertEqual(rc, 1, out)
        self.assertIn('REFUSED-UNTESTABLE\tdocs/t.md:7\told', out)

    def test_entry_with_no_routine_is_refused(self):
        rc, out = self.run_range(self.OLD + '- The queue holds eight words. Established.\n')
        self.assertEqual(rc, 1, out)
        self.assertIn('no routine', out)

    def test_exempt_text_is_not_refused(self):
        rc, out = self.run_range(self.OLD + '- `a` (`usr/sbin/missing`, `0x20`, 8 bytes). Unverified.\n'
                                 '- Plain prose with no grade.\n'
                                 '\n| Option | Meaning |\n|---|---|\n| `--sc` | Established. |\n')
        self.assertEqual(rc, 0, out)

    def test_pure_deletion_does_not_touch_the_neighbour(self):
        rc, out = self.run_range(self.OLD.replace('- Closing prose.\n', ''))
        self.assertEqual(rc, 0, out)

    def test_needs_changed(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                check_claims.main(['--block-unresolved'])


class ChangedLines(unittest.TestCase):
    def test_deletion_adds_no_line(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, 'docs'))
            doc = os.path.join(td, 'docs', 'x.md')
            with open(doc, 'w') as f:
                f.write('a\nb\nc\nd\n')
            subprocess.run(['git', '-C', td, 'init', '-q'], check=True)
            subprocess.run(['git', '-C', td, 'add', '.'], check=True)
            subprocess.run(['git', '-C', td, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '-m', 'm'],
                           check=True)
            with open(doc, 'w') as f:
                f.write('a\nc\nd\nnew\n')
            old = check_claims.REPO
            check_claims.REPO = td
            try:
                self.assertEqual(dict(check_claims.changed_lines('HEAD')), {'docs/x.md': {4}})
            finally:
                check_claims.REPO = old


HEADING_DOC = ('# Readings\n\nEach entry was read from the member named below.\n\n'
               '## `fa` at `0x1008`\n\n'
               'Build: `builds/b1/usr/lib/x.a(a.o)`. Size: 64 bytes. **Established** from this disassembly.\n'
               'Its first memory write is `sd s2,8(sp)`. (instruction 0x1010)\n'
               'The routine returns with `jr ra`. (instruction 0x1020)\n\n'
               '### `fb` at `0x2000`\n\n'
               'Build: `builds/b1/usr/lib/x.a(b.o)`. Size: 8 bytes. **Inferred**.\n')


class HeadingEntries(unittest.TestCase):
    def test_heading_opens_an_entry_with_the_prose_below_it(self):
        ents, pre = entries_of(HEADING_DOC)
        self.assertEqual([(e.line, e.title) for e in ents], [(5, ('fa', 0x1008)), (11, ('fb', 0x2000))])
        self.assertEqual(ents[0].last, 10)
        self.assertIn('returns with `jr ra`', ents[0].text)
        self.assertNotIn('fb', ents[0].text)
        self.assertIn('member named below', pre)

    def test_other_headings_are_not_entries(self):
        ents, _ = entries_of('## Method\n\nSome prose.\n\n## `f` near `0x10`\n\nMore prose.\n')
        self.assertEqual(ents, [])

    def test_identify_takes_routine_address_size_and_grade_from_the_heading_entry(self):
        bins = binaries(['builds/b1/usr/lib/x.a(a.o)', 'builds/b1/usr/lib/x.a(b.o)'])
        ents, _ = entries_of(HEADING_DOC)
        check_claims.identify(ents[0], bins, [], None)
        self.assertEqual((ents[0].name, ents[0].address, ents[0].size, ents[0].status.lower()),
                         ('fa', 0x1008, 64, 'established'))
        self.assertEqual(ents[0].binary, 'builds/b1/usr/lib/x.a(a.o)')


class InsnLocator(unittest.TestCase):
    INSNS = {0x1000: 'addiu sp,sp,-16', 0x1004: 'sd s2,8(sp)', 0x1008: 'beq a0,zero,0x1010',
             0x100c: 'sll zero,zero,0x0', 0x1010: 'jr ra', 0x1014: 'sll zero,zero,0x0'}

    def run_check(self, text, insns=None):
        ctx = FakeCtx(insns or self.INSNS)
        ctx.addr, ctx.end = 0x1000, 0x1018
        e = types.SimpleNamespace(text=text, table=None, binary=None, id='t', name='f', status='established')
        rep = []
        check_claims.Checker(e, ctx, rep, None, None).insn_locator()
        return [(r['class'], r['verdict']) for r in rep]

    def test_return_at_the_cited_address_holds(self):
        self.assertEqual(self.run_check('The routine returns with `jr ra`. (instruction 0x1010)'),
                         [('insn-address', 'ok')])

    def test_return_one_word_off_mismatches(self):
        self.assertEqual(self.run_check('The routine returns with `jr ra`. (instruction 0x1014)'),
                         [('insn-address', 'mismatch')])

    def test_address_outside_the_routine_mismatches(self):
        self.assertEqual(self.run_check('The routine returns with `jr ra`. (instruction 0x2010)'),
                         [('insn-address', 'mismatch')])

    def test_first_memory_write_holds_and_an_earlier_store_refutes_it(self):
        text = 'Its first memory write is `sd s2,8(sp)`. (instruction 0x1004)'
        self.assertEqual(self.run_check(text), [('insn-address', 'ok')])
        later = dict(self.INSNS)
        later[0x1000] = 'sw a0,0(a1)'
        self.assertEqual(self.run_check(text, later), [('insn-address', 'ok'), ('insn-address', 'mismatch')])

    def test_range_with_no_conditional_transfer(self):
        text = 'No conditional transfer appears before the return. (instructions 0x1000–0x1004)'
        self.assertEqual(self.run_check(text), [('insn-address', 'ok')])
        text = 'No conditional transfer appears before the return. (instructions 0x1000–0x1010)'
        self.assertEqual(self.run_check(text), [('insn-address', 'mismatch')])

    def test_backwards_range_mismatches(self):
        self.assertEqual(self.run_check('It falls through to 0x1004. (instructions 0x1008–0x1004)'),
                         [('insn-address', 'mismatch')])


class ZeroEntries(unittest.TestCase):
    """A changed document with ## headings that parses to no entries is refused, not passed."""
    OLD = '# Doc\n\nIntro.\n'
    git = BlockUnresolved.git
    run_range = BlockUnresolved.run_range

    def test_headings_with_unreadable_entries_are_refused(self):
        rc, out = self.run_range('# Doc\n\n## `f` near `0x10`\n\nProse about f.\n')
        self.assertEqual(rc, 1, out)
        self.assertIn('REFUSED-NO-ENTRIES\tdocs/t.md', out)

    def test_heading_entries_are_read(self):
        rc, out = self.run_range('# Doc\n\n## `f` at `0x10`\n\nBuild: `usr/sbin/l1cmd`. Unverified.\n')
        self.assertEqual(rc, 0, out)
        self.assertNotIn('REFUSED', out)

    def test_prose_without_headings_still_passes(self):
        rc, out = self.run_range('# Doc\n\nOnly prose.\n')
        self.assertEqual(rc, 0, out)
