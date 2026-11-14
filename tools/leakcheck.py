#!/usr/bin/env python3
"""Internal-host and internal-path check for the reverse-engineering workspaces.

  leakcheck.py                      every tracked text file and the HEAD commit message
  leakcheck.py --range A..B         what the commits A..B add (lines and messages)

Run it from the workspace root. Exit status: 0 clean, 1 hit (each printed as
file:line or commit with the matched text), 2 tool error.

The patterns that need no secret are built in and name no host: a link into a
forge repository (https://HOST/jamesb/REPO/src/..., /raw/, /commit/, /issues/
and so on, whatever HOST is), a /scratch/ or /storage/ path, and the home
directory of the account that works on these repositories. A workspace links
to its sibling repositories in plain words, never with a forge URL.

Patterns that would name the internal host itself are not stored in this
repository. They are read from, in turn:
  DENYLIST            the text of the homelab denylist (gitleaks TOML), as the
                      publication workflow receives it from the HOMELAB_DENYLIST
                      Actions variable
  RE_LEAK_DENYLIST    path of a denylist TOML file
  RE_LEAK_TERMS       path of a term file, else the workspace's ignored
                      .re-leak-terms and ~/.config/re-leak-terms
A term file holds one regular expression per line, matched case-insensitively, '#' for comments. A
denylist contributes every [[rules]] regex and honours its per-match
allowlists; its path and commit allowlists cannot apply here. With none of
these the check runs the built-in patterns and says so on stderr.

An exact string that is fine despite matching goes in the workspace's
leak-allow.txt (tools/config/, else scripts/) as STRING<TAB>REASON; a line
without a reason is an error. An allowed string is removed from a line before
it is matched, so the rest of the line is still checked. The term and allow
files are never themselves checked, and binary files are skipped.
"""
import os
import re
import subprocess
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _layout  # noqa: E402

# Built-in patterns: (label, regex). None names a host.
BUILTIN = [
    ('forge repository link',
     r'https?://[^/\s)>"\']+/jamesb/[A-Za-z0-9._-]+/(?:src|raw|commit|compare|pulls?|issues|releases|wiki|actions)\b'),
    ('internal storage path', r'(?<![\w.~-])/(?:scratch|storage)/'),
    ('home directory of the working account', r'(?<![\w.~-])/home/jamesb\b'),
    ('agent scratch path', r'(?<![\w.~-])/tmp/claude'),
]
NEVER_CHECKED = ('.re-leak-terms', 'tools/config/leak-allow.txt', 'scripts/leak-allow.txt')


class ToolError(Exception):
    pass


def git(*args, cwd='.', check=True):
    p = subprocess.run(('git',) + args, capture_output=True, cwd=cwd)
    if check and p.returncode != 0:
        raise ToolError('git %s: %s' % (' '.join(args), p.stderr.decode('utf-8', 'replace').strip()))
    return p.stdout


def compile_rx(rx, where):
    """Compile a Go-style pattern. Go accepts (?i) anywhere; Python wants it first, so hoist it."""
    flags = 0
    if '(?i)' in rx:
        rx, flags = rx.replace('(?i)', ''), re.I
    try:
        return re.compile(rx, flags)
    except re.error as e:
        raise ToolError('%s: bad pattern %r: %s' % (where, rx, e))


def denylist_rules(text, where):
    """(label, regex, allow regexes) per [[rules]] entry of a gitleaks denylist."""
    try:
        cfg = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ToolError('%s: not valid TOML: %s' % (where, e))
    out = []
    for r in cfg.get('rules', []):
        if not r.get('regex'):
            continue
        allow = []
        for a in r.get('allowlists', []):
            if a.get('regexTarget') == 'match':
                allow += [compile_rx(x, where) for x in a.get('regexes', [])]
        out.append(('denylist ' + r.get('id', '?'), compile_rx(r['regex'], where), allow))
    return out


def read_terms(path):
    out = []
    with open(path, encoding='utf-8') as f:
        for n, ln in enumerate(f, 1):
            ln = ln.strip()
            if ln and not ln.startswith('#'):
                out.append(('private term', compile_rx('(?i)' + ln, '%s:%d' % (path, n)), []))
    return out


def load_rules(top):
    rules = [(label, compile_rx(rx, 'built-in'), []) for label, rx in BUILTIN]
    external = False
    text = os.environ.get('DENYLIST')
    if text and text.strip():
        rules += denylist_rules(text, 'DENYLIST')
        external = True
    path = os.environ.get('RE_LEAK_DENYLIST')
    if path:
        with open(path, encoding='utf-8') as f:
            rules += denylist_rules(f.read(), path)
        external = True
    env = os.environ.get('RE_LEAK_TERMS')
    home = os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config'), 're-leak-terms')
    cands = [env] if env else [os.path.join(top, '.re-leak-terms'), home]
    for c in cands:
        if os.path.isfile(c):
            rules += read_terms(c)
            external = True
    if not external:
        print('leakcheck: no denylist or term list (DENYLIST, RE_LEAK_DENYLIST, .re-leak-terms); '
              'checking the built-in patterns only', file=sys.stderr)
    return rules


def load_allow(top):
    rel = _layout.of(top).config('leak-allow.txt')
    path = os.path.join(top, rel)
    out = []
    if os.path.isfile(path):
        with open(path, encoding='utf-8') as f:
            for n, ln in enumerate(f, 1):
                ln = ln.rstrip('\n')
                if not ln.strip() or ln.startswith('#'):
                    continue
                s, _, reason = ln.partition('\t')
                if not s or not reason.strip():
                    raise ToolError('%s:%d: an allowed string needs a reason: STRING<TAB>REASON' % (path, n))
                out.append(s)
    return out


def shown(label, match):
    """What a hit prints. Hosts and private terms stay out of CI logs: a private term shows only its
    length, and a URL shows no host."""
    if label.startswith(('denylist', 'private term')):
        return '<%d characters>' % len(match)
    return re.sub(r'(?i)(https?://)[^/\s)>"\']+', r'\1<host>', match)


# The denylist's domain rule starts with a character class that matches anywhere, so on a long run of
# letters or digits (a hash dump, a minified line) it is quadratic. Long lines are scanned in overlapping
# windows instead; a window is far longer than any hostname or path the rules look for.
WINDOW, STEP, LONG_LINE = 300, 150, 400


def windows(line):
    if len(line) <= LONG_LINE:
        yield line
        return
    for i in range(0, len(line), STEP):
        yield line[i:i + WINDOW]


def scan_line(rules, allow, line):
    for a in allow:
        line = line.replace(a, '')
    hits = []
    seen = set()
    for chunk in windows(line):
        for label, rx, okay in rules:
            for m in rx.finditer(chunk):
                key = (label, m.group(0))
                if key in seen or any(o.search(m.group(0)) for o in okay):
                    continue
                seen.add(key)
                hits.append((label, shown(label, m.group(0))))
    return hits


def report(hits, where, label_match):
    for label, match in label_match:
        hits.append('%s: %s: %s' % (where, label, match))


def check_tree(top, rules, allow):
    hits = []
    for rel in git('ls-files', '-z', cwd=top).decode('utf-8', 'surrogateescape').split('\0'):
        path = os.path.join(top, rel)
        if not rel or rel in NEVER_CHECKED or os.path.islink(path) or not os.path.isfile(path):
            continue
        with open(path, 'rb') as f:
            data = f.read()
        if b'\0' in data[:8192]:
            continue
        for n, line in enumerate(data.decode('utf-8', 'replace').split('\n'), 1):
            report(hits, '%s:%d' % (rel, n), scan_line(rules, allow, line))
    return hits


def check_messages(top, rules, allow, revs):
    hits = []
    raw = git('log', '--format=%H%x00%B%x01', *revs, cwd=top).decode('utf-8', 'replace')
    for rec in raw.split('\x01'):
        rec = rec.strip('\n')
        if not rec:
            continue
        sha, _, body = rec.partition('\0')
        for line in body.split('\n'):
            report(hits, 'commit %s message' % sha[:12], scan_line(rules, allow, line))
    return hits


def check_range(top, rules, allow, rng):
    hits = []
    raw = git('log', '-p', '-U0', '--no-color', '--no-renames', '--format=commit %H', rng,
              cwd=top).decode('utf-8', 'replace')
    sha = path = None
    for line in raw.split('\n'):
        if line.startswith('commit ') and re.fullmatch(r'commit [0-9a-f]{40}', line):
            sha, path = line[7:], None
        elif line.startswith('+++ '):
            path = line[6:] if line.startswith('+++ b/') else None
        elif line.startswith('+') and path and path not in NEVER_CHECKED:
            report(hits, '%s %s' % (sha[:12], path), scan_line(rules, allow, line[1:]))
    return hits + check_messages(top, rules, allow, [rng])


def main(argv):
    rng = None
    args = list(argv)
    if args and args[0] == '--range' and len(args) == 2:
        rng = args[1]
    elif args:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        top = git('rev-parse', '--show-toplevel').decode().strip()
        rules, allow = load_rules(top), load_allow(top)
        if rng:
            hits = check_range(top, rules, allow, rng)
        else:
            hits = check_tree(top, rules, allow) + check_messages(top, rules, allow, ['-1', 'HEAD'])
    except (ToolError, OSError) as e:
        print('leakcheck: %s' % e, file=sys.stderr)
        return 2
    for h in hits:
        print(h)
    if hits:
        print('leakcheck: %d hit(s). Describe the thing in words, or add an exact string with a '
              'reason to leak-allow.txt.' % len(hits), file=sys.stderr)
        return 1
    print('leakcheck: clean')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
