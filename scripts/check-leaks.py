#!/usr/bin/env python3
"""Leak check for the reverse-engineering workspaces.

  check-leaks.sh --push            read pre-push ref lines from stdin; check what each push adds
  check-leaks.sh --range A..B      check what the commits A..B add (A empty: everything up to B)
  check-leaks.sh --all             audit every tracked file and every commit message
  check-leaks.sh                   same as --range origin/main..HEAD
  check-leaks.sh --self-test       run against planted hits and clean text

Checked: the lines the range adds (never the lines it leaves alone), and the commit messages of
the range. A message must also carry no Co-Authored-By or Signed-off-by trailer.

Patterns come from leak-patterns.txt beside this file (override: RE_LEAK_PATTERNS). Terms that
must not be written into a shared tool are read from the workspace's .re-leak-terms (or
scripts/leak-terms.txt) and from the host's ${XDG_CONFIG_HOME:-~/.config}/re-leak-terms
(override: RE_LEAK_TERMS); one extended regular expression per line, # for comments. With none of
those files the check warns and uses the base patterns only.

Exact strings that are fine despite matching go in the workspace's scripts/leak-allow.txt, one
per line as STRING<TAB>REASON; a line without a reason is an error. An allowed string is removed
from a line before it is matched, so the rest of that line is still checked. There are no
regular-expression allowances. The term and allow files are never themselves checked.

Exit status: 0 clean, 1 hit (each printed as file:line or commit, with the matched text), 2 tool error.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ZERO = '0' * 40
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
TRAILER = re.compile(r'^(Co-Authored-By|Signed-off-by):', re.I | re.M)
NEVER_CHECKED = ('scripts/leak-terms.txt', 'scripts/leak-allow.txt', '.re-leak-terms')


class ToolError(Exception):
    pass


def git(*args, check=True):
    p = subprocess.run(('git',) + args, capture_output=True)
    if check and p.returncode != 0:
        raise ToolError('git %s: %s' % (' '.join(args), p.stderr.decode('utf-8', 'replace').strip()))
    return p.stdout.decode('utf-8', 'replace')


def read_list(path):
    out = []
    with open(path, encoding='utf-8') as f:
        for ln in f:
            ln = ln.rstrip('\n')
            if ln.strip() and not ln.lstrip().startswith('#'):
                out.append(ln.strip())
    return out


def compile_all(pats, where):
    out = []
    for p in pats:
        try:
            out.append((p, re.compile(p, re.I)))
        except re.error as e:
            raise ToolError('%s: bad pattern %r: %s' % (where, p, e))
    return out


def load_patterns():
    path = os.environ.get('RE_LEAK_PATTERNS') or os.path.join(HERE, 'leak-patterns.txt')
    if not os.path.isfile(path):
        raise ToolError('no pattern file: %s' % path)
    pats = compile_all(read_list(path), path)
    if not pats:
        raise ToolError('%s holds no pattern' % path)
    return pats


def load_terms(top):
    env = os.environ.get('RE_LEAK_TERMS')
    cands = [env] if env else [os.path.join(top, '.re-leak-terms'), os.path.join(top, 'scripts', 'leak-terms.txt'),
                               os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config'),
                                            're-leak-terms')]
    found = [c for c in cands if os.path.isfile(c)]
    if not found:
        print('check-leaks: warning: no term list (.re-leak-terms, scripts/leak-terms.txt, '
              '~/.config/re-leak-terms or RE_LEAK_TERMS); checking the base patterns only', file=sys.stderr)
        return []
    pats = []
    for c in found:
        pats += compile_all(read_list(c), c)
    return pats


def load_allow(top):
    path = os.path.join(top, 'scripts', 'leak-allow.txt')
    out = []
    if os.path.isfile(path):
        with open(path, encoding='utf-8') as f:
            for n, ln in enumerate(f, 1):
                ln = ln.rstrip('\n')
                if not ln.strip() or ln.lstrip().startswith('#'):
                    continue
                s, _, reason = ln.partition('\t')
                if not s or not reason.strip():
                    raise ToolError('%s:%d: an allowed string needs a reason: STRING<TAB>REASON' % (path, n))
                out.append(s)
    return out


class Checker:
    def __init__(self, top):
        self.pats = load_patterns() + load_terms(top)
        self.allow = load_allow(top)
        self.hits = 0

    def match(self, text):
        for a in self.allow:
            text = text.replace(a, '')
        for _, rx in self.pats:
            m = rx.search(text)
            if m:
                return m.group(0)
        return None

    def line(self, where, text):
        m = self.match(text)
        if m is not None:
            self.hits += 1
            print('%s: matched %r: %s' % (where, m, text.strip()[:160]))

    def message(self, sha, body):
        for i, ln in enumerate(body.split('\n'), 1):
            self.line('commit %s message line %d' % (sha[:12], i), ln)
        if TRAILER.search(body):
            self.hits += 1
            print('commit %s: matched a Co-Authored-By or Signed-off-by trailer' % sha[:12])


def added_lines(base, head):
    """(path, line number, text) for every line a diff from base to head adds."""
    out = git('diff', '-U0', '--no-color', '--no-ext-diff', '--no-renames', '--diff-filter=AMT', base, head)
    path, n = None, 0
    for ln in out.split('\n'):
        if ln.startswith('+++ '):
            path = ln[6:] if ln.startswith('+++ b/') else None
        elif ln.startswith('@@'):
            m = re.match(r'@@ -\S+ \+(\d+)', ln)
            n = int(m.group(1)) if m else 0
        elif ln.startswith('+') and path is not None:
            yield path, n, ln[1:]
            n += 1


def messages(rng):
    out = git('log', '--format=%H%x00%B%x01', rng)
    for rec in out.split('\x01'):
        rec = rec.strip('\n')
        if rec:
            sha, _, body = rec.partition('\x00')
            yield sha, body


def check_range(chk, base, head):
    base_tree = base or EMPTY_TREE
    for path, n, text in added_lines(base_tree, head):
        if path not in NEVER_CHECKED:
            chk.line('%s:%d' % (path, n), text)
    for sha, body in messages('%s..%s' % (base, head) if base else head):
        chk.message(sha, body)


def push_base(rsha, lsha):
    if rsha != ZERO and git('rev-parse', '--verify', '-q', rsha + '^{commit}', check=False).strip():
        return rsha
    mb = git('merge-base', lsha, 'origin/main', check=False).strip()
    return mb or ''


def check_all(chk):
    files = git('ls-files', '-s', '-z').split('\0')
    for rec in files:
        if not rec:
            continue
        meta, path = rec.split('\t', 1)
        if meta.startswith(('120000', '160000')) or path in NEVER_CHECKED:
            continue
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError:
            continue
        if b'\0' in data[:8192]:
            continue
        for n, ln in enumerate(data.decode('utf-8', 'replace').split('\n'), 1):
            chk.line('%s:%d' % (path, n), ln)
    for sha, body in messages('HEAD'):
        chk.message(sha, body)


def run(argv):
    args = argv[1:]
    if args in (['-h'], ['--help']):
        print(__doc__)
        return 0
    if args == ['--self-test']:
        import unittest
        sys.path.insert(0, HERE)
        import test_check_leaks
        suite = unittest.defaultTestLoader.loadTestsFromModule(test_check_leaks)
        return 0 if unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful() else 1
    top = git('rev-parse', '--show-toplevel').strip()
    os.chdir(top)
    chk = Checker(top)
    if args == ['--all']:
        check_all(chk)
    elif args == ['--push']:
        seen = False
        for ln in sys.stdin.read().split('\n'):
            f = ln.split()
            if len(f) != 4 or f[1] == ZERO:
                continue
            seen = True
            check_range(chk, push_base(f[3], f[1]), f[1])
        if not seen:
            return 0
    elif len(args) == 2 and args[0] == '--range':
        a, sep, b = args[1].partition('..')
        if not sep or not b:
            raise ToolError('--range takes A..B')
        check_range(chk, a, b)
    elif not args:
        base = git('merge-base', 'HEAD', 'origin/main', check=False).strip()
        check_range(chk, base, 'HEAD')
    else:
        raise ToolError('unknown arguments: %s (see --help)' % ' '.join(args))
    return 1 if chk.hits else 0


if __name__ == '__main__':
    try:
        sys.exit(run(sys.argv))
    except ToolError as e:
        print('check-leaks: %s' % e, file=sys.stderr)
        sys.exit(2)
