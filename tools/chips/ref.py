#!/usr/bin/env python3
"""Stage 3: read the reference side of the census.

Usage: ref.py CONFIG.json [--repo DATASHEET_REPO] [--model model_SRC_DIR] [--out FILE]

For each variant named in the config's "reference" block this builds three
lists of register entries, each {lo, hi, stride, name, source, section, line, kind}:

  datasheet  rows of datasheet tables (and any prose list the config names)
  spec       rows of the published specification's register map, as transcribed
  model       registers the model handles, from the model source

Offsets are widget-local byte offsets of the eight-byte slot (the datasheet
convention); the scan stage folds the +4 data-half offsets onto them.

Datasheet and spec tables are read generically: any markdown table under a
heading the config lists, whose header has an Offset column. A cell that holds
`A` to `B` is a range, `A` + 8x*n* is a family (the count comes from "n = 0 to 7"
in the name cell), `A` and `B` are two registers. Read-only prose lists that a
table cannot hold go in the config's "supplement" with a source line, so every
non-table entry is visible in the config.

The model side has two adapters. "table" reads `#define NAME 0xOFF` constants
and designated-initialiser rows `[SLOT(NAME)] = { "name", ACCESS, reset, mask }`
(with the comment block above each row, where the model says it guessed).
"case-function" reads the `case A ... B:` labels and `addr >= A && addr < B`
tests of named functions, which is how a model without a register table says
what it defines and what it defers.
"""
import argparse
import json
import os
import re
import sys

FAMILY_DEFAULT = 8   # a '+ 8xn' family with no stated range: the eight PCI device slots
HEX = re.compile(r'0x[0-9a-fA-F_]+')
GUESS = re.compile(r"model'?s choice|not specified|no specified|unspecified|guess|assum|invent|"
                   r"approximat|placeholder|stand[s]? in|compatib|stub|deliberately|unobservable|"
                   r"storage[: ]|no power-up|nothing gave|own choice", re.I)


def h(tok):
    return int(tok.replace('_', ''), 16)


def split_row(line):
    cells = line.strip().strip('|').split('|')
    return [c.strip() for c in cells]


def offsets_of(cell, name_cell=''):
    """[(lo, hi, stride)] from one offset cell."""
    toks = [h(t) for t in HEX.findall(cell)]
    if not toks:
        return []
    c = cell.replace('`', '').replace('*', '')
    name_cell = name_cell.replace('*', '').replace('`', '')
    if len(toks) == 1 and re.search(r'\+\s*(\d+)\s*[x×*]', c):
        stride = int(re.search(r'\+\s*(\d+)\s*[x×*]', c).group(1))
        m = re.search(r'n\s*=\s*(\d+)\s*(?:to|through|–|-)\s*(\d+)', name_cell + ' ' + cell)
        count = int(m.group(2)) - int(m.group(1)) + 1 if m else FAMILY_DEFAULT
        return [(toks[0], toks[0] + stride * (count - 1), stride)]
    if len(toks) == 2 and re.search(r'\bto\b|through|–', c):
        return [(toks[0], toks[1], 8)]
    return [(t, t, 8) for t in toks]


def parse_size(cell):
    m = re.search(r'(\d+)\s*(KB|MB|GiB|bytes?)', cell)
    if not m:
        return None
    n = int(m.group(1))
    return n * {'KB': 1024, 'MB': 1 << 20, 'GiB': 1 << 30}.get(m.group(2), 1)


def prose_entries(para, head, label, line):
    """Register offsets named in running text: one clause, one name, an offset or a 'A to B' range."""
    out = []
    for clause in re.split(r'[;,]|\.\s|\sand\s(?=[A-Za-z])', para):
        if re.search(r'padding|undefined|unnamed|reserved|duplicate|not transcribed', clause, re.I):
            continue
        toks = [t for t in re.findall(r'0x[0-9A-Fa-f_]{4,12}', clause)]
        if not toks:
            continue
        vals = [h(t) for t in toks]
        if len(vals) >= 2 and re.search(r'\b(to|through)\b', clause):
            lo, hi = vals[0], vals[1]
        else:
            lo = hi = vals[0]
        if hi >= 0x1000 or lo > hi:
            continue
        name = re.sub(r'0x[0-9A-Fa-f_]+', '', clause)
        name = re.sub(r'\b(at|to|through|from)\b', '', name).strip(' :-')
        out.append({'lo': lo, 'hi': hi, 'stride': 8, 'name': ' '.join(name.split())[:70], 'access': '',
                    'source': label, 'section': head, 'line': line, 'kind': 'register'})
    return out


def parse_md(path, headings, label, prose=False):
    out = []
    head = ''
    cols = None
    para, para_line = [], 0
    rx = [re.compile(x, re.I) for x in headings]

    def flush():
        nonlocal para
        if para and prose:
            out.extend(prose_entries(' '.join(para), head, label, para_line))
        para = []

    for no, ln in enumerate(open(path, encoding='utf-8'), 1):
        ln = ln.rstrip('\n')
        m = re.match(r'^(#+)\s+(.*)', ln)
        if m:
            flush()
            head, cols = m.group(2).strip(), None
            continue
        ok = any(r.search(head) for r in rx)
        if not ok:
            continue
        if ln.startswith('|'):
            flush()
            cells = split_row(ln)
            if cols is None:
                cols = [c.lower() for c in cells]
                continue
            if re.fullmatch(r'[-: |]+', ln):
                continue
            oi = next((i for i, x in enumerate(cols) if x.startswith('offset')), None)
            if oi is None or oi >= len(cells):
                continue
            ni = next((i for i, x in enumerate(cols) if x in ('name', 'register', 'function', 'contents')
                       or x.startswith('register')), None)
            name = cells[ni] if ni is not None and ni < len(cells) else ''
            si = next((i for i, x in enumerate(cols) if x == 'size'), None)
            size = parse_size(cells[si]) if si is not None and si < len(cells) else None
            ai = next((i for i, x in enumerate(cols) if x == 'access'), None)
            access = cells[ai] if ai is not None and ai < len(cells) else ''
            for lo, hi, stride in offsets_of(cells[oi], name):
                kind = 'register'
                if size and size > 8 and lo == hi:
                    hi, kind = lo + size - 1, 'region'
                out.append({'lo': lo, 'hi': hi, 'stride': stride, 'name': re.sub(r'[`*]', '', name)[:80],
                            'access': re.sub(r'[`*]', '', access)[:30], 'source': label,
                            'section': head, 'line': no, 'kind': kind})
        elif not ln.strip():
            cols = None
            flush()
        else:
            if not para:
                para_line = no
            para.append(ln.strip())
    flush()
    return out


# ---- model adapters -------------------------------------------------------

def consts_of(text, extra):
    c = dict(extra)
    for m in re.finditer(r'^#define\s+(\w+)\s+\(?(0x[0-9a-fA-F]+)u?\)?\s*(?:/\*.*)?$', text, re.M):
        c[m.group(1)] = int(m.group(2), 16)
    return c


def families_of(text, consts):
    fam = {}
    for m in re.finditer(r'^#define\s+(\w+)\((\w)\)\s+\(?\s*(0x[0-9a-fA-F]+)\s*\+\s*(\w+)\s*\*\s*\(\w\)\s*\)?',
                         text, re.M):
        stride = consts.get(m.group(4))
        if stride:
            fam[m.group(1)] = (int(m.group(3), 16), stride)
    return fam


def adapter_table(cfg, src, label):
    text = open(src, encoding='utf-8').read()
    consts = consts_of(text, cfg.get('extra_consts', {}))
    fams = families_of(text, consts)
    out = []
    row_rx = re.compile(r'((?:/\*(?:(?!\*/).)*\*/\s*)*)\[' + cfg['row_slot'] +
                        r'\((\w+)(?:\((\d+)\))?\)\]\s*=\s*\{\s*"([^"]+)",\s*(\w+),\s*([^,]+),\s*([^}]+?)\s*\}',
                        re.S)
    seen_fam = {}
    lines_of = lambda pos: text.count('\n', 0, pos) + 1
    # one macro per family of rows; each use of it is one row of the family
    for m in re.finditer(r'((?:/\*(?:(?!\*/).)*\*/\s*)*)#define\s+(\w+)\((\w)\)[\s\\]*\[' + cfg['row_slot'] +
                         r'\((\w+)\(\w\)\)\]\s*=\s*\{[\s\\]*"([^"]+)",\s*(\w+),\s*([^,]+),\s*([^}\\]+?)[\s\\]*\}',
                         text, re.S):
        comment, macro, _, fam, name, access, reset, mask = m.groups()
        uses = len(re.findall(r'\b%s\(\d+\)' % macro, text))
        if fam in fams and uses:
            base, stride = fams[fam]
            storage = mask.strip() in ('0xffffffffu', '0xffffffff')
            out.append({'lo': base, 'hi': base + stride * (uses - 1), 'stride': stride,
                        'name': '%s x%d' % (name, uses), 'access': access.replace('SGI_BRIDGE_', ''),
                        'source': label, 'section': 'register table', 'line': lines_of(m.start()),
                        'kind': 'register', 'guessed': storage, 'note': 'whole-word storage' if storage else ''})
    for m in row_rx.finditer(text):
        comment, key, idx, name, access, reset, mask = m.groups()
        guess = bool(GUESS.search(comment))
        storage = mask.strip() in ('0xffffffffu', '0xffffffff')
        note = []
        if guess:
            note.append('comment says: ' + ' '.join(comment.replace('/*', '').replace('*/', '').split())[:90])
        if storage:
            note.append('whole-word storage, fields unmodelled')
        entry = {'name': name, 'access': access.replace('SGI_BRIDGE_', ''), 'source': label,
                 'section': 'register table', 'line': lines_of(m.start()), 'kind': 'register',
                 'guessed': guess or storage, 'note': '; '.join(note)}
        if key in consts and idx is None:
            off = consts[key]
            out.append(dict(entry, lo=off, hi=off, stride=8))
    # registers the model names and handles outside the table (NIC, reserved half, ...)
    for nm in cfg.get('extra_handled', []):
        if nm in consts:
            out.append({'lo': consts[nm], 'hi': consts[nm], 'stride': 8, 'name': nm, 'access': '',
                        'source': label, 'section': 'named constant', 'line': 0, 'kind': 'register',
                        'guessed': True, 'note': 'handled outside the table'})
    for r in cfg.get('regions', []):
        lo = consts.get(r['lo'], None) if isinstance(r['lo'], str) else r['lo']
        if lo is None:
            continue
        size = r['size'] if isinstance(r['size'], int) else (consts.get(r['size']) or
                                                           eval_size(r['size'], consts))
        out.append({'lo': lo, 'hi': lo + size - 1, 'stride': 1, 'name': r['name'], 'access': '',
                    'source': label, 'section': 'region', 'line': 0, 'kind': 'region',
                    'guessed': bool(r.get('guessed')), 'note': r.get('note', '')})
    return out


def eval_size(expr, consts):
    e = expr
    for k, v in sorted(consts.items(), key=lambda kv: -len(kv[0])):
        e = re.sub(r'\b%s\b' % k, str(v), e)
    e = e.replace('KiB', '*1024').replace('MiB', '*1048576')
    return int(eval(e, {'__builtins__': {}}))


def func_body(text, name):
    m = re.search(r'^[^\n;]*\b%s\s*\([^)]*\)\s*\n?\{' % re.escape(name), text, re.M)
    if not m:
        return None, 0
    i = m.end()
    depth = 1
    while i < len(text) and depth:
        depth += {'{': 1, '}': -1}.get(text[i], 0)
        i += 1
    return text[m.start():i], text.count('\n', 0, m.start()) + 1


def adapter_case(cfg, src, label):
    text = open(src, encoding='utf-8').read()
    out = []
    for fn in cfg.get('defined', []):
        body, line = func_body(text, fn)
        if body is None:
            continue
        for m in re.finditer(r'case\s+(0x[0-9a-fA-F]+)(?:\s*\.\.\.\s*(0x[0-9a-fA-F]+))?\s*:', body):
            lo = int(m.group(1), 16)
            hi = int(m.group(2), 16) if m.group(2) else lo
            out.append({'lo': lo, 'hi': hi, 'stride': 8, 'name': 'defined by ' + fn, 'access': '',
                        'source': label, 'section': fn, 'line': line, 'kind': 'register',
                        'guessed': False, 'note': ''})
    for fn in cfg.get('unimp', []):
        body, line = func_body(text, fn)
        if body is None:
            continue
        for m in re.finditer(r'addr\s*>=\s*(0x[0-9a-fA-F]+)\s*&&\s*addr\s*<\s*(0x[0-9a-fA-F]+)', body):
            lo, hi = int(m.group(1), 16), int(m.group(2), 16) - 1
            out.append({'lo': lo, 'hi': hi, 'stride': 8, 'name': 'deferred by ' + fn, 'access': '',
                        'source': label, 'section': fn, 'line': line, 'kind': 'register',
                        'guessed': True, 'unimp': True, 'note': 'LOG_UNIMP: deferred, reads give zero'})
        for m in re.finditer(r'addr\s*>=\s*(0x[0-9a-fA-F]+)\s*(?:\)|\|\||$)', body):
            out.append({'lo': int(m.group(1), 16), 'hi': 0xffffff, 'stride': 8, 'name': 'deferred by ' + fn,
                        'access': '', 'source': label, 'section': fn, 'line': line, 'kind': 'register',
                        'guessed': True, 'unimp': True, 'note': 'LOG_UNIMP: deferred'})
    for r in cfg.get('regions', []):
        out.append({'lo': r['lo'], 'hi': r['lo'] + r['size'] - 1, 'stride': 1, 'name': r['name'], 'access': '',
                    'source': label, 'section': 'region', 'line': 0, 'kind': 'region',
                    'guessed': bool(r.get('guessed')), 'note': r.get('note', '')})
    return out


def build(cfg, repo, model_dir, spec_dir=None):
    ref = {}
    for variant, v in cfg['reference'].items():
        r = {'datasheet': [], 'spec': [], 'model': [], 'spec_present': bool(v.get('spec'))}
        for d in v.get('datasheets', []):
            r['datasheet'] += parse_md(os.path.join(repo, d['file']), d['headings'], d['label'], d.get('prose', False))
        for d in v.get('spec', []):
            r['spec'] += parse_md(os.path.join(spec_dir, os.path.basename(d['file'])) if spec_dir else os.path.join(repo, d['file']), d['headings'], d['label'], d.get('prose', False))
        r['spec'] += [dict(s, source=s.get('source', 'supplement')) for s in v.get('spec_supplement', [])]
        r['datasheet'] += [dict(s, source=s.get('source', 'supplement')) for s in v.get('datasheet_supplement', [])]
        for q in v.get('model', []):
            src = os.path.join(model_dir, q['file'])
            fn = {'table': adapter_table, 'case-function': adapter_case}[q['adapter']]
            r['model'] += fn(q, src, q['file'])
        ref[variant] = r
    return ref


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('config')
    ap.add_argument('--repo', required=True)
    ap.add_argument('--model', required=True)
    ap.add_argument('--spec-dir', help='directory holding the register-map transcriptions the config names (by file name)')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    cfg = json.load(open(a.config))
    ref = build(cfg, a.repo, a.model, a.spec_dir)
    json.dump(ref, open(a.out, 'w'), indent=1)
    for v, r in ref.items():
        print(v, {k: len(x) for k, x in r.items() if isinstance(x, list)})


if __name__ == '__main__':
    main()
