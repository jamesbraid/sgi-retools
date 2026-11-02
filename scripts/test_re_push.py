"""re-push refuses a planted leak, pushes clean work, a plain git push is blocked, and a copy check that cannot run refuses."""
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
REPUSH = os.path.join(ROOT, 're-push')

# A stand-in for the fingerprint tool. MOCK_MODE picks what it does; MOCK_STATE is a
# directory where it records its calls and whether a baseline exists.
MOCK_TOOL = '''#!/bin/sh
echo "$*" >> "$MOCK_STATE/calls"
case " $* " in
*" --build-symbol-baselines "*)
    [ "$MOCK_MODE" = buildfail ] && { echo "mock: build failed" >&2; exit 1; }
    touch "$MOCK_STATE/baseline"; exit 0 ;;
esac
case $MOCK_MODE in
    noimage) echo "fingerprint: not ready, nothing checked: missing container image the-tool-image" >&2; exit 3 ;;
    noindex) echo "fingerprint: not ready, nothing checked: missing /idx/reference.duckdb" >&2; exit 3 ;;
    leads) exit 4 ;;
    crash) echo "mock: boom" >&2; exit 1 ;;
    nobaseline|buildfail|stillnotready)
        [ "$MOCK_MODE" != stillnotready ] && [ -e "$MOCK_STATE/baseline" ] && exit 0
        echo "fingerprint: not ready, nothing checked: missing the symbol baseline for x at root manifest abc" >&2; exit 3 ;;
esac
exit 0
'''


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
        os.makedirs(os.path.join(self.ws, 'root'))
        with open(os.path.join(self.ws, 'root', 'file'), 'w') as f:
            f.write('x\n')
        self.state = os.path.join(t, 'state')
        os.makedirs(self.state)
        self.tool = os.path.join(t, 'copy-check')
        with open(self.tool, 'w') as f:
            f.write(MOCK_TOOL)
        os.chmod(self.tool, 0o755)
        self.env.update(COPY_CHECK=self.tool, MOCK_STATE=self.state, MOCK_MODE='ok')
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

    def calls(self):
        with open(os.path.join(self.state, 'calls')) as f:
            return f.read()

    def refused(self, mode, *needles, tool=None, root=True):
        before = self.remote_head()
        self.commit('notes.txt', 'start\nmore\n', 'add a line to the notes')
        self.env['MOCK_MODE'] = mode
        if tool is not None:
            self.env['COPY_CHECK'] = tool
        if not root:
            os.remove(os.path.join(self.ws, 'root', 'file'))
        r = self.repush()
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('REFUSED', r.stderr)
        self.assertIn('fix:', r.stderr)
        for n in needles:
            self.assertIn(n, r.stderr)
        self.assertEqual(self.remote_head(), before)

    def test_unavailable_image_refuses(self):
        self.refused('noimage', 'container image')
        self.assertNotIn('--build-symbol-baselines', self.calls())

    def test_missing_index_refuses(self):
        self.refused('noindex', 'not ready')

    def test_tool_error_refuses(self):
        self.refused('crash', 'exit 1')

    def test_no_tool_refuses(self):
        self.env['COPY_CHECK'] = ''
        self.refused('ok', 'no tool is configured')

    def test_missing_tool_refuses(self):
        self.refused('ok', 'missing or not executable', tool=os.path.join(self.td.name, 'nope'))

    def test_missing_root_refuses(self):
        self.refused('ok', 'root/ is missing', root=False)

    def test_lead_refuses(self):
        before = self.remote_head()
        self.commit('notes.txt', 'start\nmore\n', 'add a line to the notes')
        self.env['MOCK_MODE'] = 'leads'
        self.assertEqual(self.repush().returncode, 1)
        self.assertEqual(self.remote_head(), before)

    def test_missing_baseline_is_built_then_push_goes(self):
        self.commit('notes.txt', 'start\nmore\n', 'add a line to the notes')
        self.env['MOCK_MODE'] = 'nobaseline'
        r = self.repush()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        self.assertEqual(calls.count('--build-symbol-baselines'), 1)
        self.assertEqual(self.remote_head(), self.git(self.ws, 'rev-parse', 'HEAD').strip())

    def test_unbuildable_baseline_refuses(self):
        self.refused('buildfail', 'building it failed')

    def test_baseline_still_not_ready_after_build_refuses(self):
        self.refused('stillnotready', 'not ready')

    def test_hook_override_is_loud(self):
        # The hook run directly (not through re-push) keeps COPY_CHECK=off, with a warning.
        self.commit('notes.txt', 'start\nmore\n', 'add a line to the notes')
        self.env['COPY_CHECK'] = 'off'
        head = self.git(self.ws, 'rev-parse', 'HEAD').strip()
        r = subprocess.run([os.path.join(self.ws, 'scripts', 'pre-push')], cwd=self.ws, env=self.env, text=True,
                           input='refs/heads/main %s refs/heads/main %s\n' % (head, self.remote_head()),
                           capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('WARNING', r.stderr)
        self.assertIn('SKIPPED', r.stderr)

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
