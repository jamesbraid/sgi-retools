#!/usr/bin/env python3
"""Kernel tables the shared inventory does not measure: system calls, kernel structures and panic sites.

Usage: retools/tools/kudzu/os_tables.py [--out docs/inventory] [--release 6.5.30] [--check]

--release limits the tables to the kernels of one release under root/. Without it every root/<release>/unix.IP*
is read, so a release whose kernels are not yet documented adds rows the docs do not describe. The committed
tables cover every release under root/, so regenerate them without --release; a run with it rewrites them
with that release's rows alone.

--check generates the tables and the docs/coverage.md block into a scratch directory and compares them with the
committed files, exits 1 and names each file that differs, and changes nothing in the repository. The status
columns read docs/*.md and the scope columns read docs/inventory/functions.tsv and binaries.tsv, so a docs
change or a new scope group makes the committed tables stale until they are regenerated.

Run it from the repository root with root/ populated, inside the toolchain container
(retools/tools/re-run python3 retools/tools/kudzu/os_tables.py). It writes three tab-separated tables beside the output of
retools/tools/inventory.py. Nothing here is hand-edited, and the output is deterministic.

  syscalls.tsv  one row per entry of each system call table (`sysent` and `irix5_64_sysent`) per kernel
                image, from tools/syscall_table.py: the table, the entry index, the call number, the
                handler symbol the entry's function pointer resolves to, the argument-count byte and the
                raw flag bytes of the entry. The layout (three doublewords per entry: counts and flags,
                handler, argument-size table) is confirmed against the dispatcher's loads by the extractor.
  structs.tsv   one row per named structure in a kernel image's DWARF: byte size and member count. Only the
                kernel images (root/*/unix.*) are read. The DWARF also names the files that declare each
                structure; they are not written down, because the paths are the layout of a source tree.
                Status is `documented` when docs/structs/<name>.md exists: retools/tools/kudzu/struct_fields.py writes that
                page only after two kernels agree on the layout.
  panics.tsv    one row per calling function and callee in {panic, cmn_err, assfail, nopanicdebugger, printf, sync_printf,
                dri_printf, icmn_err, icmn_err_tag, cmn_err_tag} found
                in the linked kernels' text by decoding jal targets: the function, its address and the
                number of call sites. Message strings are not recovered here (retools/tools/kudzu/panic_sites.py reads them).

  selectors.tsv one row per `syssgi` selector that reaches code of its own, per kernel image, from
                tools/syssgi_selectors.py: the jump table or compare tree it came from, the selector, the
                code address it reaches and the first routine that code calls (`first_call`, a heuristic:
                blank when the block branches first). `shared` marks targets that several selectors reach.
                Other selector functions (`sysmp` and the like) are not generated yet.
  formats.tsv   the container and section kinds the kernel images use.

Each row has a `scope` column: `in` or `out`, from scripts/scope.json (a function row takes the scope
tools/inventory.py gave that function in docs/inventory/functions.tsv; a structure row takes it from the
structure_prefixes list). Status is `documented` when the name appears in backticks in a docs/*.md page, else
`undocumented`; a structure row uses its field-table page instead (see structs.tsv above).
"""
import glob
import io
import os
import re
import struct
import subprocess
import sys
import collections

os.environ['LC_ALL'] = os.environ['LANG'] = 'C'
# The workspace comes from the current directory (tools/_workspace.py), not from this file's path.
TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, TOOLS)
from _workspace import find_workspace  # noqa: E402
REPO = find_workspace()

import inventory  # noqa: E402  (the request-name labels live with it)

RELEASE = None
PANIC_CALLEES = ('panic', 'cmn_err', 'assfail', 'nopanicdebugger',
                 'printf', 'sync_printf', 'dri_printf', 'icmn_err', 'icmn_err_tag', 'cmn_err_tag')


def doc_names():
    names = set()
    for p in glob.glob(os.path.join(REPO, 'docs', '*.md')):
        for m in re.finditer(r'`([^`\n]+)`', open(p, encoding='utf-8').read()):
            names.add(m.group(1).strip())
    return names


def struct_pages():
    """Structure names with a field table page: docs/structs/<name>.md, titled with the name in backticks."""
    names = set()
    for p in glob.glob(os.path.join(REPO, 'docs', 'structs', '*.md')):
        m = re.fullmatch(r'# `([^`]+)`', open(p, encoding='utf-8').readline().strip())
        if m:
            names.add(m.group(1))
    return names


def kernels():
    return sorted(glob.glob(os.path.join(REPO, 'root', RELEASE or '*', 'unix.IP*')))


def label(p):
    return os.path.relpath(p, os.path.join(REPO, 'root'))


def syscalls(path, elf=None):
    import syscall_table
    rows, _how, _notes, _base = syscall_table.extract(path)
    return [(r[0], r[1], r[2], r[4], r[5], r[6], r[7]) for r in rows]


def selectors(path):
    import syssgi_selectors
    rows, _w, _resolved = syssgi_selectors.extract(path, 'syssgi')
    return [(g, sel, '0x%x' % t, call, shared) for g, sel, t, call, shared in rows]


def structs(path):
    out = subprocess.run(['dwarfdump', '-i', path], capture_output=True, text=True, errors='replace').stdout
    rows, cur = {}, None
    for ln in out.splitlines():
        if 'DW_TAG_' in ln:
            if cur and cur.get('name') and cur.get('size') is not None:
                key = (cur['name'], cur['size'])
                rows[key] = max(rows.get(key, 0), cur['members'])
            cur = {'members': 0, 'size': None} if 'DW_TAG_structure_type' in ln else (
                dict(cur, depth=1) if cur is not None and ln.lstrip().startswith('< 2>') and 'DW_TAG_member' in ln else None)
            if cur is not None and 'depth' in cur:
                cur.pop('depth')
                cur['members'] += 1
                cur['_member'] = True
            continue
        if cur is None:
            continue
        m = re.search(r'DW_AT_name\s+(\S+)', ln)
        if m and 'name' not in cur and not cur.get('_member'):
            cur['name'] = m.group(1)
        m = re.search(r'DW_AT_byte_size\s+(\d+)', ln)
        if m and cur['size'] is None:
            cur['size'] = int(m.group(1))
    if cur and cur.get('name') and cur.get('size') is not None:
        rows[(cur['name'], cur['size'])] = cur['members']
    return [(n, s, m) for (n, s), m in sorted(rows.items())]


def panics(path):
    objdump = 'mips64-linux-gnuabi64-objdump'
    out = subprocess.run([objdump, '-d', '--no-show-raw-insn', '-j', '.text', path], capture_output=True,
                         text=True, errors='replace').stdout
    nm = subprocess.run(['mips64-linux-gnuabi64-nm', path], capture_output=True, text=True).stdout
    targets = {}
    for ln in nm.splitlines():
        p = ln.split()
        if len(p) == 3 and p[1] in 'Tt' and p[2] in PANIC_CALLEES:
            targets[int(p[0], 16)] = p[2]
    fn_re = re.compile(r'^([0-9a-f]{16}) <([^>]+)>:')
    call_re = re.compile(r'\b(?:jal|bal)\s+([0-9a-f]+)\b')
    counts = collections.Counter()
    addr_of = {}
    cur = None
    for ln in out.splitlines():
        m = fn_re.match(ln)
        if m:
            cur = m.group(2)
            addr_of[cur] = '0x' + m.group(1)
            continue
        m = call_re.search(ln)
        if m and cur:
            t = targets.get(int(m.group(1), 16))
            if t:
                counts[(cur, t)] += 1
    return [(f, addr_of[f], c, n) for (f, c), n in sorted(counts.items())]


def write(out, name, header, rows):
    with open(os.path.join(out, name), 'w', encoding='utf-8') as f:
        f.write('\t'.join(header) + '\n')
        for r in rows:
            f.write('\t'.join(str(inventory.scrub_request_names(x)) for x in r) + '\n')
    print('%s: %d rows' % (name, len(rows)))


def function_scopes():
    """{(binary, name): 'in' | 'out'} from the shared inventory's functions table."""
    p = os.path.join(REPO, 'docs', 'inventory', 'functions.tsv')
    sc = {}
    if not os.path.exists(p):
        sys.exit('run retools/tools/inventory.py first: docs/inventory/functions.tsv is missing')
    with open(p, encoding='utf-8') as f:
        head = f.readline().rstrip('\n').split('\t')
        b, n, c = head.index('binary'), head.index('name'), head.index('scope')
        for ln in f:
            r = ln.rstrip('\n').split('\t')
            sc[(r[b], r[n])] = 'in' if r[c] == 'in' else 'out'
    return sc


def formats(paths):
    """Container and section kinds of the kernel images: (kind, name, detail, binaries)."""
    from elftools.elf.elffile import ELFFile
    seen = collections.defaultdict(list)
    for k in paths:
        with open(k, 'rb') as fh:
            e = ELFFile(io.BytesIO(fh.read()))
        seen[('container', 'ELF%d %s %s' % (e.elfclass, 'big-endian' if e.little_endian is False else 'little-endian',
                                           e.header['e_type']), 'machine %s, flags 0x%x' % (e.header['e_machine'], e.header['e_flags']))].append(label(k))
        for sec in e.iter_sections():
            seen[('section', sec.name, 'type %s' % sec['sh_type'])].append(label(k))
    return [(k, n, d, len(b), b[0]) for (k, n, d), b in sorted(seen.items()) if n]


def scope_report(out, scope):
    """scope.tsv: the in-scope rule of each binary group with its binary and function counts."""
    base = os.path.join(REPO, 'docs', 'inventory')
    group_of, nbin = {}, collections.Counter()
    with open(os.path.join(base, 'binaries.tsv'), encoding='utf-8') as f:
        head = f.readline().rstrip('\n').split('\t')
        b, g = head.index('binary'), head.index('group')
        for ln in f:
            r = ln.rstrip('\n').split('\t')
            group_of[r[b]] = r[g]
            nbin[r[g]] += 1
    fin, fout = collections.Counter(), collections.Counter()
    with open(os.path.join(base, 'functions.tsv'), encoding='utf-8') as f:
        head = f.readline().rstrip('\n').split('\t')
        b, c = head.index('binary'), head.index('scope')
        for ln in f:
            r = ln.rstrip('\n').split('\t')
            grp = group_of.get(r[b], group_of.get(r[b].split('(')[0], ''))
            (fin if r[c] == 'in' else fout)[grp] += 1
    rows = [(g['group'], g['scope'], nbin[g['group']], fin[g['group']], fout[g['group']], g['reason'])
            for g in scope['groups']]
    write(out, 'scope.tsv', ['group', 'scope', 'binaries', 'functions_in', 'functions_out', 'reason'], rows)
    return rows


def coverage_block(out, scope_rows, path=None):
    """Rewrite the os-inventory block of docs/coverage.md (or of a copy of it at path)."""
    def tsv(name):
        with open(os.path.join(out, name), encoding='utf-8') as f:
            return [ln.rstrip('\n').split('\t') for ln in f][1:]
    lines = ['<!-- os-inventory:begin -->', '## Kernel tables (generated by retools/tools/kudzu/os_tables.py)', '',
             'Rows in scope are the ones the finish line counts; rows out of scope are listed and not yet counted. Scope rules: [inventory/scope.tsv](inventory/scope.tsv).', '',
             '| Table | In scope | Out of scope | Documented | Undocumented |', '|---|---:|---:|---:|---:|']
    for r in tsv('summary-os.tsv'):
        lines.append('| [%s](inventory/%s.tsv) | %s | %s | %s | %s |' % (r[0], r[0], r[1], r[2], r[3], r[4]))
    lines += ['', '| Binary group | Scope | Binaries | Functions in | Functions out |', '|---|---|---:|---:|---:|']
    for g, sc, nb, fi, fo, _ in scope_rows:
        lines.append('| %s | %s | %d | %d | %d |' % (g, sc, nb, fi, fo))
    lines.append('<!-- os-inventory:end -->')
    p = path or os.path.join(REPO, 'docs', 'coverage.md')
    text = open(p, encoding='utf-8').read()
    block = '\n'.join(lines)
    if '<!-- os-inventory:begin -->' in text:
        text = re.sub(r'<!-- os-inventory:begin -->.*?<!-- os-inventory:end -->', lambda m: block, text, flags=re.S)
    else:
        text = text.rstrip('\n') + '\n\n' + block + '\n'
    open(p, 'w', encoding='utf-8').write(text)


def generate(out, coverage_path=None):
    import json
    from elftools.elf.elffile import ELFFile
    scope = json.load(open(os.path.join(REPO, 'scripts', 'scope.json')))
    spre = re.compile('(?:%s)' % '|'.join(scope['structure_prefixes']))
    sel_re = re.compile('(?:%s)' % '|'.join(scope['narrow_prefixes']))
    fscope = function_scopes()
    known = doc_names()
    pages = struct_pages()
    sc, st, pn, se = [], [], [], []
    for k in kernels():
        lab = label(k)
        with open(k, 'rb') as fh:
            elf = ELFFile(io.BytesIO(fh.read()))
            for table, i, number, name, nargs, flags, tbl in syscalls(k, elf):
                sc.append((lab, table, number, i, name, nargs, flags, tbl, fscope.get((lab, name), 'out'),
                           'documented' if name in known else 'undocumented'))
        for group, sel, target, call, shared in selectors(k):
            se.append((lab, group, sel, target, call, shared,
                       'in' if call and sel_re.match(call) else 'out',
                       'documented' if call and call in known else 'undocumented'))
        for n, size, members in structs(k):
            st.append((lab, n, size, members, 'in' if spre.match(n) else 'out', 'documented' if n in pages else 'undocumented'))
        for fn, addr, callee, n in panics(k):
            # functions.tsv carries the prose label of a request name, so look the row up under that label.
            pn.append((lab, fn, addr, callee, n, fscope.get((lab, inventory.scrub_request_names(fn)), 'out'),
                       'documented' if fn in known else 'undocumented'))
    write(out, 'syscalls.tsv', ['binary', 'table', 'number', 'index', 'handler', 'nargs', 'flags', 'arg_table',
                                'scope', 'status'], sc)
    write(out, 'structs.tsv', ['binary', 'name', 'bytes', 'members', 'scope', 'status'], st)
    write(out, 'panics.tsv', ['binary', 'function', 'address', 'callee', 'sites', 'scope', 'status'], pn)
    write(out, 'selectors.tsv', ['binary', 'group', 'selector', 'target', 'first_call', 'shared', 'scope', 'status'], se)
    fm = [(k, n, d, c, ex, 'in', 'documented' if n in known else 'undocumented') for k, n, d, c, ex in formats(kernels())]
    write(out, 'formats.tsv', ['kind', 'name', 'detail', 'binaries', 'example', 'scope', 'status'], fm)
    rows = []
    for t, hdr in (('syscalls', 'scope'), ('structs', 'scope'), ('panics', 'scope'), ('selectors', 'scope'), ('formats', 'scope')):
        with open(os.path.join(out, t + '.tsv'), encoding='utf-8') as f:
            heads = f.readline().rstrip('\n').split('\t')
            data = [ln.rstrip('\n').split('\t') for ln in f]
        si, ti = heads.index('scope'), heads.index('status')
        c = collections.Counter((r[si], r[ti]) for r in data)
        inn = [r for r in data if r[si] == 'in']
        rows.append((t, len(inn), len(data) - len(inn), sum(1 for r in inn if r[ti] == 'documented'),
                     sum(1 for r in inn if r[ti] == 'undocumented')))
    write(out, 'summary-os.tsv', ['table', 'in_scope', 'out_of_scope', 'documented', 'undocumented'], rows)
    coverage_block(out, scope_report(out, scope), coverage_path)


def check(out):
    """Regenerate into a scratch directory and compare with the committed tables and coverage block."""
    import filecmp
    import shutil
    import tempfile
    scratch = tempfile.mkdtemp(prefix='os_tables-')
    try:
        cov = os.path.join(scratch, 'coverage.md')
        shutil.copyfile(os.path.join(REPO, 'docs', 'coverage.md'), cov)
        tables = os.path.join(scratch, 'inventory')
        os.mkdir(tables)
        generate(tables, cov)
        stale = [os.path.relpath(os.path.join(out, n), REPO) for n in sorted(os.listdir(tables))
                 if not os.path.exists(os.path.join(out, n)) or not filecmp.cmp(os.path.join(tables, n), os.path.join(out, n), shallow=False)]
        if not filecmp.cmp(cov, os.path.join(REPO, 'docs', 'coverage.md'), shallow=False):
            stale.append('docs/coverage.md')
    finally:
        shutil.rmtree(scratch)
    if stale:
        sys.exit('stale, regenerate with retools/tools/kudzu/os_tables.py: ' + ', '.join(stale))
    print('os tables match the committed files')


def main():
    out = os.path.join(REPO, 'docs', 'inventory')
    if '--out' in sys.argv:
        out = sys.argv[sys.argv.index('--out') + 1]
    global RELEASE
    if '--release' in sys.argv:
        RELEASE = sys.argv[sys.argv.index('--release') + 1]
    if '--check' in sys.argv:
        check(out)
    else:
        generate(out)


if __name__ == '__main__':
    main()
