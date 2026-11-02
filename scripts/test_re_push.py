"""re-push refuses a planted leak, pushes clean work, and a plain git push is blocked."""
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
REPUSH = os.path.join(ROOT, 're-push')


class RePush(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        t = self.td.name
        self.env = dict(os.environ, HOME=t, XDG_CONFIG_HOME=os.path.join(t, 'cfg'),
                        GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid',
                        GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')
        for v in ('RE_LEAK_TERMS', 'RE_LEAK_PATTERNS', 'COPY_CHECK', 'CHECK_CLAIMS'):
            self.env.pop(v, None)
        self.remote = os.path.join(t, 'remote.git')
        self.ws = os.path.join(t, 'ws')
        self.git(t, 'init', '-q', '--bare', '-b', 'main', self.remote)
        self.git(t, 'clone', '-q', self.remote, self.ws)
        os.makedirs(os.path.join(self.ws, 'scripts'))
        for f in ('pre-push', 'check-leaks.sh'):
            os.symlink(os.path.join(HERE, f), os.path.join(self.ws, 'scripts', f))
        self.commit('notes.txt', 'start\n', 'start')
        self.git(self.ws, 'push', '-q', 'origin', 'HEAD:main')
        self.run_install()

    def tearDown(self):
        self.td.cleanup()

    def git(self, cwd, *a):
        return subprocess.run(('git',) + a, cwd=cwd, env=self.env, capture_output=True, text=True, check=True).stdout

    def commit(self, name, text, msg):
        with open(os.path.join(self.ws, name), 'w') as f:
            f.write(text)
        self.git(self.ws, 'add', '-A')
        self.git(self.ws, 'commit', '-q', '-m', msg)

    def run_install(self):
        subprocess.run([REPUSH, '--install', self.ws], env=self.env, capture_output=True, text=True, check=True)

    def repush(self, *a):
        return subprocess.run([REPUSH] + list(a), cwd=self.ws, env=self.env, capture_output=True, text=True)

    def remote_head(self):
        return self.git(self.remote, 'rev-parse', 'main').strip()

    def test_plain_push_is_blocked_even_without_verify(self):
        self.commit('notes.txt', 'start\nmore\n', 'more')
        for extra in ([], ['--no-verify']):
            p = subprocess.run(['git', 'push', 'origin', 'HEAD:main'] + extra, cwd=self.ws, env=self.env,
                               capture_output=True, text=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('re-push', p.stderr)
        self.git(self.ws, 'fetch', '-q', 'origin')   # fetching still works

    def test_clean_work_is_pushed(self):
        self.commit('notes.txt', 'start\nmore\n', 'add a line to the notes')
        r = self.repush()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.remote_head(), self.git(self.ws, 'rev-parse', 'HEAD').strip())

    def test_planted_leak_is_refused(self):
        before = self.remote_head()
        self.commit('notes.txt', 'start\nsee /home/' + 'someone/file\n', 'add a path')
        r = self.repush()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn('/home/', r.stdout + r.stderr)
        self.assertIn('not pushed', r.stderr)
        self.assertEqual(self.remote_head(), before)

    def test_leaking_message_is_refused_and_skips_are_ignored(self):
        before = self.remote_head()
        self.commit('notes.txt', 'start\nmore\n', 'add a line\n\nCo-Authored-By: someone <a@example.invalid>')
        self.env['CHECK_CLAIMS'] = 'off'
        self.env['COPY_CHECK'] = 'off'
        r = self.repush()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('ignoring', r.stderr)
        self.assertEqual(self.remote_head(), before)

    def test_unknown_option_and_non_fast_forward(self):
        self.assertEqual(self.repush('--skip-checks').returncode, 2)
        self.commit('notes.txt', 'start\nmine\n', 'mine')
        other = os.path.join(self.td.name, 'other')
        self.git(self.td.name, 'clone', '-q', self.remote, other)
        with open(os.path.join(other, 'x.txt'), 'w') as f:
            f.write('x\n')
        self.git(other, 'add', '-A')
        self.git(other, 'commit', '-q', '-m', 'theirs')
        self.git(other, 'push', '-q', 'origin', 'HEAD:main')
        r = self.repush()
        self.assertEqual(r.returncode, 1)
        self.assertIn('fast-forward', r.stderr)


if __name__ == '__main__':
    unittest.main()
