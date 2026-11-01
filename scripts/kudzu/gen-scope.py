#!/usr/bin/env python3
"""Write the binaries and scope sections of scripts/inventory-config.json from scripts/scope.json.

Usage: scripts/gen-scope.py [--check]

scope.json is the one place that says which binary groups are in scope and why. This script expands
its path globs against root/ and writes, into the config, the groups for the inventory and one scope
rule per out-of-scope set of functions (a whole group, or the functions of a 'narrow' group whose
names start with none of the narrow prefixes). With --check it rewrites nothing and fails when the
config is out of date. Run it inside the toolchain container like the other scripts.
"""
import glob
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


def main():
    scope = json.load(open(os.path.join(REPO, 'scripts', 'scope.json')))
    cfgp = os.path.join(REPO, 'scripts', 'inventory-config.json')
    cfg = json.load(open(cfgp))
    claimed, groups, rules = set(), [], []
    narrow = '(?!(?:%s)).+' % '|'.join(scope['narrow_prefixes'])
    for g in scope['groups']:
        paths = g['paths']
        groups.append({'group': g['group'], 'role': g['role'], 'paths': paths})
        files = files_of(paths, claimed)
        if g['scope'] == 'in' or not files:
            continue
        rule = {'binaries': files, 'reason': '%s: %s' % (g['group'], g['reason'])}
        rule['patterns'] = ['.+'] if g['scope'] == 'out' else [narrow]
        rules.append(rule)
    cfg['binaries'], cfg['scope'] = groups, rules
    text = json.dumps(cfg, indent=2) + '\n'
    if '--check' in sys.argv[1:]:
        if open(cfgp).read() != text:
            sys.exit('scripts/inventory-config.json is out of date: run scripts/gen-scope.py')
        print('config matches scope.json')
        return
    open(cfgp, 'w').write(text)
    print('%d groups, %d scope rules, %d files' % (len(groups), len(rules), len(claimed)))


main()
