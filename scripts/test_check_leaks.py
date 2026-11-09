"""Self-test for check-leaks.py: planted hits must be reported, clean text must pass."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
TOOL = os.path.join(HERE, 'check-leaks.py')


class CheckLeaks(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self.td.name, 'repo')
        self.cfg = os.path.join(self.td.name, 'cfg')
        os.makedirs(self.repo)
        os.makedirs(self.cfg)
        self.env = dict(os.environ, HOME=self.td.name, XDG_CONFIG_HOME=self.cfg,
                        GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid',
                        GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')
        self.env.pop('RE_LEAK_TERMS', None)
        self.env.pop('RE_LEAK_PATTERNS', None)
        self.git('init', '-q', '-b', 'main')
        self.write('doc.md', 'a clean first line\n')
        self.commit('start')
        self.base = self.git('rev-parse', 'HEAD').strip()

    def tearDown(self):
        self.td.cleanup()

    def git(self, *a):
        return subprocess.run(('git',) + a, cwd=self.repo, env=self.env, capture_output=True, text=True,
                              check=True).stdout

    def write(self, name, text, mode='w'):
        p = os.path.join(self.repo, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, mode) as f:
            f.write(text)

    def commit(self, msg):
        self.git('add', '-A')
        self.git('commit', '-q', '-m', msg)

    def check(self, *args, stdin=None):
        return subprocess.run([sys.executable, TOOL] + list(args), cwd=self.repo, env=self.env,
                              capture_output=True, text=True, input=stdin)

    def range(self):
        return self.check('--range', self.base + '..HEAD')

    def hit(self, text, term=None):
        self.write('doc.md', 'a clean first line\n' + text + '\n')
        self.commit('add')
        r = self.range()
        self.assertEqual(r.returncode, 1, (text, r.stdout, r.stderr))
        self.assertIn('doc.md:2', r.stdout)
        if term:
            self.assertIn(term, r.stdout.lower())

    def test_clean_text_passes(self):
        self.write('doc.md', 'a clean first line\nthe quick brown fox, address 0x1000, port 192.0.2.1\n')
        self.commit('describe the fox')
        r = self.range()
        self.assertEqual((r.returncode, r.stdout), (0, ''), r.stderr)

    def test_planted_hits(self):
        self.tearDown()
        for text, term in (('see /scratch/' + 'x/y', '/scratch/'), ('at /home/' + 'someone', '/home/'),
                           ('at /storage/' + 'nvme', '/storage/'), ('in /tmp/' + 'claude-1', '/tmp/claude'),
                           ('host 10.30.' + '20.5', '10.30.' + '20.5'), ('host 192.168.' + '1.1', '192.168.'),
                           ('Library ' + 'mail archive', 'library mail'), ('root techpubs' + ':x', 'techpubs:'),
                           ('cache/' + '0123abcd4567', 'cache/0123abcd4567'), ('ori' + 'gami build', 'origami'),
                           ('by Cla' + 'ude', 'claude')):
            with self.subTest(text=text):
                self.setUp()
                self.hit(text, term)
                self.tearDown()
        self.setUp()

    def test_existing_lines_are_not_rechecked_but_all_finds_them(self):
        self.write('old.md', 'at /home/' + 'someone\n')
        self.commit('old')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.write('new.md', 'clean\n')
        self.commit('new')
        self.assertEqual(self.range().returncode, 0)
        r = self.check('--all')
        self.assertEqual(r.returncode, 1)
        self.assertIn('old.md:1', r.stdout)

    def test_commit_message_and_trailer(self):
        self.write('doc.md', 'a clean first line\nmore\n')
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'say more', '-m', 'Co-Authored-By: someone <a@example.invalid>')
        r = self.range()
        self.assertEqual(r.returncode, 1)
        self.assertIn('trailer', r.stdout)
        self.write('doc.md', 'a clean first line\nmore\nand more\n')
        self.git('add', '-A')
        self.git('commit', '-q', '-m', 'notes from /scratch/' + 'x')
        r = self.range()
        self.assertIn('message line 1', r.stdout)

    def test_allow_is_exact_strings_with_a_reason(self):
        self.write('scripts/leak-allow.txt', 'public-' + 'qemu' + '-tree\tpublic third-party tree\n')
        self.write('doc.md', 'a clean first line\nthe public-' + 'qemu' + '-tree list\n')
        self.commit('mention')
        self.assertEqual(self.range().returncode, 0)
        self.write('doc.md', 'a clean first line\nthe public-' + 'qemu' + '-tree list at /home/' + 'x\n')
        self.commit('mention more')
        self.assertEqual(self.range().returncode, 1)
        self.write('scripts/leak-allow.txt', 'public-' + 'qemu' + '-tree\n')
        self.commit('no reason')
        self.assertEqual(self.range().returncode, 2)

    def test_terms_file_and_missing_terms_warning(self):
        r = self.range()
        self.assertEqual(r.returncode, 0)
        self.assertIn('warning: no term list', r.stderr)
        with open(os.path.join(self.cfg, 're-leak-terms'), 'w') as f:
            f.write('# host terms\nzebra-' + 'crossing\n')
        self.write('doc.md', 'a clean first line\na zebra-' + 'crossing here\n')
        self.commit('term')
        r = self.range()
        self.assertEqual(r.returncode, 1)
        self.assertNotIn('warning', r.stderr)
        self.assertIn('zebra-' + 'crossing', r.stdout)

    def test_push_mode_and_tool_errors(self):
        self.write('doc.md', 'a clean first line\nat /home/' + 'x\n')
        self.commit('leak')
        head = self.git('rev-parse', 'HEAD').strip()
        r = self.check('--push', stdin='refs/heads/x %s refs/heads/x %s\n' % (head, self.base))
        self.assertEqual(r.returncode, 1, r.stdout)
        r = self.check('--push', stdin='refs/heads/x %s refs/heads/x %s\n' % ('0' * 40, head))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.check('--range', 'nosuchrev..HEAD').returncode, 2)
        self.assertEqual(self.check('--bogus').returncode, 2)

    def test_source_file_names_in_docs_are_refused(self):
        # Built from parts so this file does not itself carry the tokens.
        src = 'kon_' + 'attrib.' + 'c'
        self.write('docs/a.md', 'a clean line\nthe routine lives in `%s` here\n' % src)
        self.commit('name a source')
        r = self.range()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn('docs/a.md:2', r.stdout)
        self.assertIn('source-file name', r.stdout)

    def test_source_names_outside_docs_and_in_published_sources_are_not_checked(self):
        src = 'kon_' + 'attrib.' + 'c'
        self.write('notes/a.md', 'see %s\n' % src)
        self.write('docs/sources/b.md', 'see %s\n' % src)
        self.commit('elsewhere')
        self.assertEqual(self.range().returncode, 0)

    def test_name_allow_list_directory_paths_and_float_mnemonics(self):
        pub = 's_' + 'tex.' + 'c'
        self.write('docs/a.md', 'a clean line\nsample %s and c.lt.s and cvt.s and x.s and 100.a.b.c\n' % pub)
        self.commit('mention')
        self.assertEqual(self.range().returncode, 1)
        self.write('scripts/source-names-allow.txt', '%s\tin the published sample implementation\n' % pub)
        self.commit('allow')
        self.assertEqual(self.check('--all').returncode, 0)
        self.write('listing/dump.s', 'x\n')
        self.write('docs/b.md', 'see [dump](../listing/dump.s) and listing/dump.s\n')
        self.commit('link own file')
        self.assertEqual(self.check('--all').returncode, 0)
        self.write('docs/c.md', 'see missing/dump2.s\n')
        self.commit('link missing file')
        self.assertEqual(self.check('--all').returncode, 1)

    def test_name_allow_needs_a_reason(self):
        self.write('scripts/source-names-allow.txt', 's_' + 'tex.' + 'c\n')
        self.commit('no reason')
        self.assertEqual(self.range().returncode, 2)

    def test_request_names_are_refused(self):
        for name in ('GFX_' + 'GETBOARDINFO', 'VENICE_' + 'SET_VIDEO', 'KONA_' + 'DMAWRITE', 'ODSY_' + 'SET_GC',
                     'RRM_' + 'SWAPBUF', 'CRIME_' + 'TEX_ALLOC'):
            with self.subTest(name=name):
                self.write('docs/r.md', 'a clean line\nthe %s request\n' % name)
                self.commit('request ' + name)
                r = self.range()
                self.assertEqual(r.returncode, 1, (name, r.stdout))
                self.assertIn('driver-request name', r.stdout)
                self.git('reset', '-q', '--hard', self.base)
        # A register constant that shares a prefix family but is not a request passes.
        self.write('docs/r.md', 'the CRIME_' + 'MEM_CONTROL register and KONA_' + 'HP_X_INIT token\n')
        self.commit('registers')
        self.assertEqual(self.range().returncode, 0)
        self.write('scripts/source-names-allow.txt', 'GFX_' + 'LABEL\tpublished in a Linux header\n')
        self.write('docs/r.md', 'the GFX_' + 'LABEL flag\n')
        self.commit('allowed request')
        self.assertEqual(self.range().returncode, 0)


if __name__ == '__main__':
    unittest.main()
