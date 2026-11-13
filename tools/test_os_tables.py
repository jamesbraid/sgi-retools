#!/usr/bin/env python3
"""Tests of os_tables.py that need no kernel image: the guarded import, the coverage block and the --check
comparison against committed tables, on a throwaway repository with no kernels under root/.

Run from the repository root: python3 tools/test_os_tables.py (needs pyelftools, as the generator does)
"""
import importlib.util
import json
import os
import shutil
import tempfile
import unittest

try:
    import elftools  # noqa: F401
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location('os_tables', os.path.join(HERE, 'kudzu', 'os_tables.py'))
ot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ot)  # must not generate anything: main() runs only as a script

SCOPE = {'groups': [{'group': 'g1', 'scope': 'in', 'reason': 'r'}], 'structure_prefixes': ['x'], 'narrow_prefixes': ['y']}


# directory names of each layout: where the scope rules, the tables and the coverage page live
OLD = dict(config='scripts', inventory='docs/inventory', coverage='docs/coverage.md', pages='docs')
CURRENT = dict(config='tools/config', inventory='evidence/inventory', coverage='evidence/coverage.md',
               pages='software/kernel')


def fake_repo(root, L=OLD):
    inv = os.path.join(root, *L['inventory'].split('/'))
    os.makedirs(inv)
    os.makedirs(os.path.join(root, *L['config'].split('/')))
    os.makedirs(os.path.join(root, 'root'))
    json.dump(SCOPE, open(os.path.join(root, *L['config'].split('/'), 'scope.json'), 'w'))
    open(os.path.join(inv, 'binaries.tsv'), 'w').write('binary\tgroup\nb1\tg1\n')
    open(os.path.join(inv, 'functions.tsv'), 'w').write('binary\tname\tscope\nb1\tf\tin\n')
    open(os.path.join(root, *L['coverage'].split('/')), 'w').write('# Coverage\n')
    return inv


@unittest.skipUnless(HAVE_ELFTOOLS, 'pyelftools is not installed')
class Check(unittest.TestCase):
    L = OLD

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='test_os_tables-')
        self.addCleanup(shutil.rmtree, self.dir)
        self.inv = fake_repo(self.dir, self.L)
        self.saved = (ot.REPO, ot.RELEASE)
        ot.REPO, ot.RELEASE = self.dir, None
        self.addCleanup(lambda: setattr(ot, 'REPO', self.saved[0]) or setattr(ot, 'RELEASE', self.saved[1]))
        ot.generate(self.inv)

    def test_fresh_tables_match(self):
        ot.check(self.inv)

    def test_edited_table_is_stale(self):
        with open(os.path.join(self.inv, 'panics.tsv'), 'a') as f:
            f.write('extra\n')
        with self.assertRaises(SystemExit) as e:
            ot.check(self.inv)
        self.assertIn('panics.tsv', str(e.exception))

    def test_new_scope_group_makes_scope_table_stale(self):
        scope = dict(SCOPE, groups=SCOPE['groups'] + [{'group': 'g2', 'scope': 'out', 'reason': 'r'}])
        json.dump(scope, open(os.path.join(self.dir, *self.L['config'].split('/'), 'scope.json'), 'w'))
        with self.assertRaises(SystemExit) as e:
            ot.check(self.inv)
        self.assertIn('scope.tsv', str(e.exception))
        self.assertIn('coverage.md', str(e.exception))

    def test_check_leaves_the_repository_alone(self):
        before = open(os.path.join(self.dir, *self.L['coverage'].split('/'))).read()
        ot.check(self.inv)
        self.assertEqual(open(os.path.join(self.dir, *self.L['coverage'].split('/'))).read(), before)

    def test_missing_table_is_stale(self):
        os.remove(os.path.join(self.inv, 'formats.tsv'))
        with self.assertRaises(SystemExit) as e:
            ot.check(self.inv)
        self.assertIn('formats.tsv', str(e.exception))


@unittest.skipUnless(HAVE_ELFTOOLS, 'pyelftools is not installed')
class CheckCurrentLayout(Check):
    """The same checks on a workspace laid out as devices/, software/, evidence/ and tools/config/."""
    L = CURRENT

    def test_documented_names_come_from_the_pages_of_the_components(self):
        os.makedirs(os.path.join(self.dir, 'software', 'kernel'))
        with open(os.path.join(self.dir, 'software', 'kernel', 'page.md'), 'w') as f:
            f.write('The `f` routine.\n')
        self.assertIn('f', ot.doc_names())


class RequestLabels(unittest.TestCase):
    """A vendor driver-request name never reaches a generated table: the label is written in its place."""

    def test_panics_row_gets_the_label(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        ot.write(d, 'panics.tsv', ['binary', 'function', 'address', 'callee', 'sites', 'scope', 'status'],
                 [('6.5.30/unix.IP30', 'ODSY_SET_GC', '0xa800000020363f60', 'cmn_err', 1, 'out', 'undocumented')])
        with open(os.path.join(d, 'panics.tsv'), encoding='utf-8') as f:
            text = f.read()
        self.assertIn('the set graphics-context Odyssey driver request\t0xa800000020363f60', text)
        self.assertNotIn('ODSY_SET_GC', text)

    def test_name_inside_a_longer_word_is_left_alone(self):
        self.assertEqual(ot.inventory.scrub_request_names('ODSY_SET_GCX'), 'ODSY_SET_GCX')


if __name__ == '__main__':
    unittest.main()
