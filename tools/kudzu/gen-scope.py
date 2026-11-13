#!/usr/bin/env python3
"""Write the binaries and scope sections of tools/config/inventory-config.json from tools/config/scope.json
(scripts/ on the old layout).

Usage: retools/tools/kudzu/gen-scope.py [--check]

scope.json is the one place that says which binary groups are in scope and why. This script expands
its path globs against root/ and writes, into the config, the groups for the inventory and one scope
rule per out-of-scope set of functions (a whole group, or the functions of a 'narrow' group whose
names start with none of the narrow prefixes). With --check it rewrites nothing and fails when the
config is out of date. Run it inside the toolchain container like the other scripts.

A routine that the inventory scan finds reaching a register window, a token or an ioctl cannot be
excluded: the run refuses. scope.json lists such routines under `keep`, as
{"binary": GLOB, "names": [...], "why": "..."}; every file the glob matches (relative to root/; the
glob of an archive member, `x.a(m.o)`, matches the whole archive) gets its own rule that leaves those
names in scope; these rules come after the group rules, so the rule numbers that the functions table
reports for the rest do not change when a keep entry is added. With the inventory functions table present, a kept name that no matching binary defines
fails the script, so a stale entry cannot hide.
"""
import collections
import csv
import fnmatch
import glob
import hashlib
import json
import os
import re
import sys

# The workspace comes from the current directory (tools/_workspace.py), not from this file's path.
TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, TOOLS)
from _workspace import find_workspace  # noqa: E402
from _layout import Layout  # noqa: E402
REPO = find_workspace()
LAYOUT = Layout(REPO)
ROOT = os.path.join(REPO, 'root')


def files_of(paths, claimed):
    out = []
    for pat in paths:
        for p in sorted(glob.glob(os.path.join(ROOT, pat))):
            cands = []
            if os.path.isdir(p):
                for dp, dn, fn in os.walk(p):
                    dn.sort()
                    cands += [os.path.join(dp, f) for f in sorted(fn)]
            elif os.path.isfile(p):
                cands.append(p)
            for c in cands:
                rel = os.path.relpath(c, ROOT)
                if rel not in claimed:
                    claimed.add(rel)
                    out.append(rel)
    return out


def applies(entry, path):
    """True when a keep entry's binary glob names this file: the file itself, or for the glob of an archive
    member (`x.a(m.o)`) the archive."""
    g = entry['binary']
    m = re.match(r'(.*)\([^()]*\)$', g)
    return fnmatch.fnmatch(path, g) or bool(m and fnmatch.fnmatch(path, m.group(1)))


def kept_names(keep, path):
    """The names that `keep` entries leave in scope in this file."""
    return tuple(sorted({n for k in keep if applies(k, path) for n in k.get('names', [])}))


def pattern(scope_kind, narrow, kept):
    """One regular expression for the functions a rule excludes: all of them ('out') or those starting with
    none of the narrow prefixes ('narrow'), except the kept names, which must match exactly."""
    alts = ([] if scope_kind == 'out' else list(narrow)) + [re.escape(n) + r'\Z' for n in kept]
    if scope_kind == 'out':
        return '(?!(?:%s)).+' % '|'.join(alts) if alts else '.+'
    return '(?!(?:%s)).+' % '|'.join(alts)


def build(scope, expand, size=None, digest=None):
    """(groups, rules, claimed) for the config; expand(paths, claimed) lists the files of a group.

    A byte-identical copy of a binary (a symlink, or two names for one object) is one image to the
    inventory, which checks every rule that names either name against it, so a keep entry for one copy
    applies to all of them: size(path) and digest(path) find the copies, and only files whose size is the
    size of a file a keep entry names are hashed."""
    claimed, groups, expanded = set(), [], []
    keep = scope.get('keep', [])
    for g in scope['groups']:
        groups.append({'group': g['group'], 'role': g['role'], 'paths': g['paths']})
        expanded.append((g, expand(g['paths'], claimed)))
    every = [f for _, files in expanded for f in files]
    copies = collections.defaultdict(set)       # file -> the files with the same bytes (itself included)
    if keep and size and digest:
        named = [f for f in every if any(applies(k, f) for k in keep)]
        sizes = {size(f) for f in named}
        by_digest = collections.defaultdict(set)
        for f in every:
            if size(f) in sizes:
                by_digest[digest(f)].add(f)
        for fs in by_digest.values():
            for f in fs:
                copies[f] = fs
    rules, variants = [], []        # a rule with kept names goes after all the others
    for g, files in expanded:
        if g['scope'] == 'in' or not files:
            continue
        reason = '%s: %s' % (g['group'], g['reason'])
        by_kept = collections.OrderedDict()
        for f in files:
            same = copies[f] | {f}
            kept = tuple(sorted({n for c in same for n in kept_names(keep, c)}))
            by_kept.setdefault(kept, []).append(f)
        for kept, fs in by_kept.items():
            (variants if kept else rules).append(
                {'binaries': fs, 'reason': reason,
                 'patterns': [pattern(g['scope'], scope.get('narrow_prefixes', []), kept)]})
    return groups, rules + variants, claimed


def check_keep(scope, functions_tsv):
    """Problems with `keep` entries against the functions table of the last inventory run."""
    problems = []
    keep = scope.get('keep', [])
    if not keep or not os.path.exists(functions_tsv):
        return problems
    defined = collections.defaultdict(set)
    with open(functions_tsv, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            defined[r['binary']].add(r['name'])
    for k in keep:
        if not str(k.get('why', '')).strip():
            problems.append('keep %s has no why' % k['binary'])
        labels = [b for b in defined if fnmatch.fnmatch(b, k['binary'])]
        if not labels:
            problems.append('keep %s matches no binary' % k['binary'])
        for n in k.get('names', []):
            if not any(n in defined[b] for b in labels):
                problems.append('keep %s: no matching binary defines %s' % (k['binary'], n))
    return problems


def main():
    scope = json.load(open(os.path.join(REPO, LAYOUT.scope_file)))
    cfgp = os.path.join(REPO, LAYOUT.inventory_config)
    cfg = json.load(open(cfgp))
    problems = check_keep(scope, os.path.join(REPO, LAYOUT.functions_table))
    if problems:
        sys.exit('%s: ' % LAYOUT.scope_file + '; '.join(problems))
    def sha(path):
        with open(os.path.join(ROOT, path), 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    groups, rules, claimed = build(scope, files_of, lambda p: os.path.getsize(os.path.join(ROOT, p)), sha)
    cfg['binaries'], cfg['scope'] = groups, rules
    text = json.dumps(cfg, indent=2) + '\n'
    if '--check' in sys.argv[1:]:
        if open(cfgp).read() != text:
            sys.exit('%s is out of date: run retools/tools/kudzu/gen-scope.py' % LAYOUT.inventory_config)
        print('config matches scope.json')
        return
    open(cfgp, 'w').write(text)
    print('%d groups, %d scope rules, %d files' % (len(groups), len(rules), len(claimed)))


if __name__ == '__main__':
    main()
