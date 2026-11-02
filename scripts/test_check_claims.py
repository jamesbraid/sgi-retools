"""Tests of how check_claims.py finds the routine and binary of an entry; they need no root/ and no toolchain."""
import contextlib
import io
import os
import sys
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
