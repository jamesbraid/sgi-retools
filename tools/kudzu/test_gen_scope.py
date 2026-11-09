#!/usr/bin/env python3
"""Tests of the scope expansion in gen-scope.py: the narrow and out rules, and the `keep` entries that leave
a routine in scope in the binaries they name.

Run from the repository root: python3 tools/kudzu/test_gen_scope.py
"""
import importlib.util
import os
import re
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('gen_scope', os.path.join(HERE, 'gen-scope.py'))
gs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gs)

FILES = {'a': ['6.5.30/IP27boot/k.o', '6.5.30/IP35boot/k.o'], 'b': ['6.5.30/IP27boot/x.a']}


def expand(paths, claimed):
    out = [f for p in paths for f in FILES[p]]
    claimed.update(out)
    return out


def scope(keep=None):
    s = {'narrow_prefixes': ['hub', 'kl(?:_|hwg)'],
         'groups': [{'group': 'objs', 'role': 'shared-kernel', 'paths': ['a'], 'scope': 'narrow', 'reason': 'r1'},
                    {'group': 'fs', 'role': 'shared-kernel', 'paths': ['b'], 'scope': 'out', 'reason': 'r2'}]}
    if keep is not None:
        s['keep'] = keep
    return s


def excluded(rule, names):
    return sorted(n for n in names if any(re.fullmatch(p, n) for p in rule['patterns']))


class Build(unittest.TestCase):
    NAMES = ['hub_init', 'klhwg_add', 'timeout', 'tpu_open', 'bcopy']

    def test_without_keep_each_group_is_one_rule(self):
        groups, rules, claimed = gs.build(scope(), expand)
        self.assertEqual([g['group'] for g in groups], ['objs', 'fs'])
        self.assertEqual([r['binaries'] for r in rules], [FILES['a'], FILES['b']])
        self.assertEqual(excluded(rules[0], self.NAMES), ['bcopy', 'timeout', 'tpu_open'])
        self.assertEqual(rules[1]['patterns'], ['.+'])
        self.assertEqual(len(claimed), 3)

    def test_a_kept_name_is_left_in_scope_only_in_the_binaries_the_glob_names(self):
        keep = [{'binary': '*IP27boot/k.o', 'names': ['timeout'], 'why': 'reads a clock'}]
        _, rules, _ = gs.build(scope(keep), expand)
        self.assertEqual([r['binaries'] for r in rules], [['6.5.30/IP35boot/k.o'], FILES['b'],
                                                          ['6.5.30/IP27boot/k.o']])
        self.assertEqual(excluded(rules[0], self.NAMES), ['bcopy', 'timeout', 'tpu_open'])
        self.assertEqual(excluded(rules[2], self.NAMES), ['bcopy', 'tpu_open'])

    def test_a_kept_name_matches_exactly_not_as_a_prefix(self):
        keep = [{'binary': '*', 'names': ['timeout'], 'why': 'x'}]
        _, rules, _ = gs.build(scope(keep), expand)
        self.assertEqual(excluded(rules[0], ['timeout', 'timeout_poll', 'xtimeout']), ['timeout_poll', 'xtimeout'])

    def test_keep_in_an_out_group_excludes_the_rest(self):
        keep = [{'binary': '*x.a(x.o)', 'names': ['nfs_clock'], 'why': 'x'}]    # an archive member names its archive
        _, rules, _ = gs.build(scope(keep), expand)
        self.assertEqual(excluded(rules[-1], ['nfs_clock', 'nfs_read']), ['nfs_read'])
        self.assertEqual(rules[0]['binaries'], FILES['a'])    # the group without keeps keeps its number

    def test_a_byte_identical_copy_shares_the_keep_entry_of_its_twin(self):
        files = {'a': ['6.5.30/IP35boot/p.o'], 'b': ['6.5.30/IP35boot/p_part.o', '6.5.30/IP35boot/q.o']}
        content = {'6.5.30/IP35boot/p.o': (10, 'x'), '6.5.30/IP35boot/p_part.o': (10, 'x'),
                   '6.5.30/IP35boot/q.o': (10, 'y')}

        def ex(paths, claimed):
            out = [f for p in paths for f in files[p]]
            claimed.update(out)
            return out
        keep = [{'binary': '*IP35boot/p.o', 'names': ['part_init'], 'why': 'x'}]
        _, rules, _ = gs.build(scope(keep), ex, lambda f: content[f][0], lambda f: content[f][1])
        by_file = {f: r for r in rules for f in r['binaries']}
        self.assertEqual(excluded(by_file['6.5.30/IP35boot/p_part.o'], ['part_init', 'other']), ['other'])
        self.assertEqual(excluded(by_file['6.5.30/IP35boot/q.o'], ['part_init', 'other']), ['other', 'part_init'])

    def test_names_with_pattern_characters_are_escaped(self):
        keep = [{'binary': '*', 'names': ['a.b'], 'why': 'x'}]
        _, rules, _ = gs.build(scope(keep), expand)
        self.assertEqual(excluded(rules[0], ['a.b', 'axb']), ['axb'])


class CheckKeep(unittest.TestCase):
    def table(self, rows):
        f = tempfile.NamedTemporaryFile('w', suffix='.tsv', delete=False)
        f.write('binary\tname\n' + ''.join('%s\t%s\n' % r for r in rows))
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_a_current_entry_is_fine(self):
        tsv = self.table([('6.5.30/IP27boot/k.o', 'timeout')])
        keep = [{'binary': '*IP27boot/k.o', 'names': ['timeout'], 'why': 'x'}]
        self.assertEqual(gs.check_keep({'keep': keep}, tsv), [])

    def test_stale_entries_are_reported(self):
        tsv = self.table([('6.5.30/IP27boot/k.o', 'timeout')])
        keep = [{'binary': '*IP27boot/k.o', 'names': ['gone'], 'why': 'x'},
                {'binary': '*nowhere*', 'names': ['timeout'], 'why': 'x'},
                {'binary': '*IP27boot/k.o', 'names': ['timeout'], 'why': ' '}]
        problems = gs.check_keep({'keep': keep}, tsv)
        self.assertEqual(len(problems), 4)
        self.assertTrue(any('defines gone' in p for p in problems))
        self.assertTrue(any('matches no binary' in p for p in problems))
        self.assertTrue(any('no why' in p for p in problems))

    def test_without_a_table_nothing_is_checked(self):
        self.assertEqual(gs.check_keep({'keep': [{'binary': '*', 'names': ['x'], 'why': 'y'}]}, '/nonexistent'), [])


if __name__ == '__main__':
    unittest.main()
