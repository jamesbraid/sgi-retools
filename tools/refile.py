#!/usr/bin/env python3
"""Move an RE workspace from the evidence/ grab-bag to the subject layout. Temporary: it goes with the
fallback to the old layout once every repository has moved.

    refile.py apply PLAN [--repo DIR]     do what PLAN says (see below), then rewrite links
    refile.py check PLAN [--repo DIR]     entry-preservation check of the splits in PLAN, against git HEAD
    refile.py leftovers [--repo DIR]      files and text that still name evidence/

PLAN is a TSV, one operation a line, `#` for comments:

    mv     OLD  NEW          git mv a file (or a directory) and keep history
    split  OLD               cut a batch reading file into <subject>/readings/<binary>.md by the rules in
                             tools/config/readings-subjects.json; entries move whole
    cov    OLD  [OLD...]     fold pages into COVERAGE.md (each under its own heading, headings pushed down)
    rm     OLD               git rm

A reading entry is a list item "- `name` in `binary` ..." with its indented lines, or a heading
"### `name` in `binary` at 0x..." with the text below it. Text between entries (batch prefaces, skip notes)
is not a finding and is not carried over; the run prints how many lines that is for each file. The run
fails unless every entry of the old files appears exactly once in the new ones, compared with link
targets blanked (links are rewritten for the new location).
"""
import argparse
import collections
import json
import os
import posixpath
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from _readings import ANY_HEADING, LINK_TARGET, REF_DEF, Subjects, normal, parse, reading_name  # noqa: E402


def git(repo, *args, check=True):
    return subprocess.run(('git', '-C', repo) + args, check=check, capture_output=True, text=True).stdout


# ---------------------------------------------------------------- operations
def do_split(repo, old, subj, done, stray_log):
    with open(os.path.join(repo, old), encoding='utf-8', errors='surrogateescape') as f:
        entries, stray = parse(f.read())
    stray_log[old] = len(stray)
    for binary, lines in entries:
        d = subj.dir_for(binary)
        rel = '%s/readings/%s' % (d, reading_name(binary))
        done[rel].append((binary, old, lines))


def address(lines):
    m = re.search(r' at (0x[0-9a-fA-F]+)', lines[0])
    return int(m.group(1), 16) if m else 0


def write_readings(repo, done):
    for rel, items in sorted(done.items()):
        binaries = {b for b, _, _ in items}
        path = os.path.join(repo, rel)
        if os.path.exists(path):
            sys.exit('refusing to overwrite %s' % rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if len(binaries) > 1:
            sys.exit('two binaries file to %s: %s' % (rel, sorted(binaries)))
        binary = items[0][0]
        with open(path, 'w', encoding='utf-8', errors='surrogateescape') as f:
            items.sort(key=lambda it: address(it[2]))
            f.write('# Readings: `%s`\n\n' % binary)
            f.write('One entry per routine, filed here from the reading batches by binary.\n')
            for _, _, lines in items:
                f.write('\n' + '\n'.join(lines) + '\n')


def demote(text, by):
    out, fence = [], False
    for line in text.split('\n'):
        if line.lstrip().startswith(('```', '~~~')):
            fence = not fence
        if not fence and re.match(r'#{1,6}\s', line):
            line = '#' * by + line
        out.append(line)
    return '\n'.join(out)


def do_cov(repo, olds):
    path = os.path.join(repo, 'COVERAGE.md')
    parts = []
    existing = os.path.exists(path)
    if existing:
        with open(path, encoding='utf-8') as f:
            parts.append(f.read().rstrip('\n'))
    for old in olds:
        with open(os.path.join(repo, old), encoding='utf-8') as f:
            body = f.read().strip('\n')
        parts.append(demote(body, 1) if parts else body)
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(parts) + '\n')


def read_plan(path):
    ops = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if line.strip() and not line.startswith('#'):
                ops.append(line.split('\t'))
    return ops


def tracked(repo, rel):
    return git(repo, 'ls-files', '--', rel).split('\n')[:-1]


def cmd_apply(args):
    repo = os.path.abspath(args.repo)
    ops = read_plan(args.plan)
    moves = {}           # old file -> new file (None when split or dropped)
    dirs = {}            # old directory -> new directory
    done = collections.defaultdict(list)
    stray_log = {}
    subj = None
    olds_split = []
    cov_olds = []
    for op in ops:
        if op[0] == 'split':
            subj = subj or Subjects(repo)
            do_split(repo, op[1], subj, done, stray_log)
            olds_split.append(op[1])
            moves[op[1]] = None
    write_readings(repo, done)
    for rel in sorted(done):
        git(repo, 'add', '--', rel)
    for op in ops:
        if op[0] == 'mv':
            old, new = op[1], op[2]
            os.makedirs(os.path.dirname(os.path.join(repo, new)) or '.', exist_ok=True)
            files = tracked(repo, old)
            git(repo, 'mv', old, new)
            if files != [old]:
                dirs[old.rstrip('/')] = new.rstrip('/')
            for f in files:
                moves[f] = new + f[len(old):] if f != old else new
        elif op[0] == 'cov':
            do_cov(repo, op[1:])
            for f in op[1:]:
                moves[f] = 'COVERAGE.md'
                cov_olds.append(f)
        elif op[0] == 'rm':
            for f in tracked(repo, op[1]):
                moves[f] = None
            git(repo, 'rm', '-rq', '--', op[1])
    git(repo, 'add', '--', 'COVERAGE.md') if cov_olds else None
    for f in cov_olds + olds_split:
        git(repo, 'rm', '-q', '--', f)
    for old, n in stray_log.items():
        print('%-60s dropped %d non-entry lines' % (old, n))
    relink(repo, moves, dirs, done)
    textfix(repo, moves, dirs, done)
    check(repo, olds_split, done)
    print('moved %d files, split %d files into %d reading files' % (
        sum(1 for v in moves.values() if v), len(olds_split), len(done)))


def check(repo, olds, done):
    """Every entry of the old files, read from git HEAD, appears once among the new reading files."""
    want = collections.Counter()
    for old in olds:
        entries, _ = parse(git(repo, 'show', 'HEAD:' + old))
        for _, lines in entries:
            want[normal(lines)] += 1
    have = collections.Counter()
    for rel in done:
        with open(os.path.join(repo, rel), encoding='utf-8', errors='surrogateescape') as f:
            entries, _ = parse(f.read())
        for _, lines in entries:
            have[normal(lines)] += 1
    if want != have:
        missing = sum((want - have).values())
        extra = sum((have - want).values())
        sys.exit('entry check failed: %d missing, %d extra (%d old entries, %d new)' % (
            missing, extra, sum(want.values()), sum(have.values())))
    print('entry check ok: %d entries in %d old files, all present once in %d new files' % (
        sum(want.values()), len(olds), len(done)))


def cmd_check(args):
    repo = os.path.abspath(args.repo)
    olds, news = [], set()
    for op in read_plan(args.plan):
        if op[0] == 'split':
            olds.append(op[1])
    news = set(tracked(repo, '*/readings/*.md'))
    check(repo, olds, news)


# ---------------------------------------------------------------- links
def is_external(t):
    return not t or t.startswith(('#', 'http:', 'https:', 'mailto:', '/', 'ssh:', 'git@')) or '://' in t


def relink(repo, moves, dirs, done):
    """Rewrite every relative link of the workspace to follow the moves. A link to a file with no single
    new home (a split batch) is left and printed."""
    inverse = {v: k for k, v in moves.items() if v}
    unresolved = []
    for rel in git(repo, 'ls-files').split('\n')[:-1]:
        if not rel.endswith('.md') or rel.startswith(('root/', 'references/code/', 'retools/')):
            continue
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        origin = inverse.get(rel, rel)
        if rel in done:
            origin = None
        with open(path, encoding='utf-8', errors='surrogateescape') as f:
            text = f.read()

        def fix(target, here_old):
            if is_external(target):
                return target
            tp, hash_, anchor = target.partition('#')
            if not tp:
                return target
            res = posixpath.normpath(posixpath.join(posixpath.dirname(here_old), tp))
            dest = res
            if res in moves:
                dest = moves[res]
                if dest is None:
                    unresolved.append((rel, target))
                    return target
            elif res in dirs:
                dest = dirs[res]
            new_t = posixpath.relpath(dest, posixpath.dirname(rel) or '.')
            if tp.endswith('/') and not new_t.endswith('/'):
                new_t += '/'
            return new_t + hash_ + anchor

        if origin is None:
            continue      # a new reading file: its entries hold no relative links worth keeping
        out = []
        for line in text.split('\n'):
            m = REF_DEF.match(line)
            if m:
                line = m.group(1) + fix(m.group(2), origin) + m.group(3)
            line = LINK_TARGET.sub(lambda m: m.group(1) + fix(m.group(2), origin) + m.group(3), line)
            out.append(line)
        new_text = '\n'.join(out)
        if new_text != text:
            with open(path, 'w', encoding='utf-8', errors='surrogateescape') as f:
                f.write(new_text)
    for rel, target in unresolved:
        print('LINK to a split file stays: %s -> %s' % (rel, target))


TEXT_FILES = ('.md', '.json', '.py', '.sh', '.toml', '.txt', '.yml', '.yaml', '.gitattributes', '.gitignore')


def textfix(repo, moves, dirs, done):
    """Rewrite plain mentions of a moved path (`evidence/coverage.md`, `evidence/inventory/`) in prose, config and
    scripts. Only repository-root paths are known here, so a mention written relative to another directory is
    left for `leftovers` to show."""
    pairs = {old: new for old, new in moves.items() if new}
    pairs.update({old + '/': new + '/' for old, new in dirs.items()})
    pairs = sorted(pairs.items(), key=lambda kv: -len(kv[0]))
    rx = re.compile('(?<![\\w./-])(' + '|'.join(re.escape(o) for o, _ in pairs) + ')') if pairs else None
    lookup = dict(pairs)
    for rel in git(repo, 'ls-files').split('\n')[:-1]:
        base = os.path.basename(rel)
        if rel in done or rel.startswith(('root/', 'retools/', 'references/code/')) or (
                rel.startswith('generated/') and not rel.startswith('generated/inventory/')):
            continue
        if not (rel.endswith(TEXT_FILES) or base in ('.gitattributes', '.gitignore')) or not rx:
            continue
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        with open(path, encoding='utf-8', errors='surrogateescape') as f:
            text = f.read()
        new = rx.sub(lambda m: lookup[m.group(1)], text)
        if new != text:
            with open(path, 'w', encoding='utf-8', errors='surrogateescape') as f:
                f.write(new)


def cmd_leftovers(args):
    repo = os.path.abspath(args.repo)
    if os.path.isdir(os.path.join(repo, 'evidence')):
        print('evidence/ still exists')
    out = subprocess.run(['git', '-C', repo, 'grep', '-n', '-I', 'evidence/', '--', '.', ':!root', ':!retools',
                          ':!references/code'], capture_output=True, text=True).stdout
    counts = collections.Counter(l.split(':', 1)[0] for l in out.split('\n') if l)
    for f, n in counts.most_common():
        print('%6d %s' % (n, f))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    for name, fn in (('apply', cmd_apply), ('check', cmd_check), ('leftovers', cmd_leftovers)):
        p = sub.add_parser(name)
        if name != 'leftovers':
            p.add_argument('plan')
        p.add_argument('--repo', default='.')
        p.set_defaults(fn=fn)
    args = ap.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
