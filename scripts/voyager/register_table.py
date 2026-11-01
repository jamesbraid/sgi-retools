#!/usr/bin/env python3
"""Regenerate the access tables of docs/registers.md.

Usage: scripts/register_table.py [--public-root DIR] [--reuse DIR] [--check]

Run it from the repository root inside the toolchain environment, after
scripts/inventory.py has written docs/inventory/. The inventory merges the
register offsets of every binary into one row; this script runs the same
replay twice more (writing to a scratch directory), once with only the kernel
object's base rules and once with only the X module's, so that each offset is
listed per binary with its own access widths and routines. It then looks every
offset up in the public register tables and grades the match.

The public tables are read from the linux/ and mesa/ submodules at their pins
(--public-root says where they are checked out):

  linux/drivers/gpu/drm/radeon/reg_srcs/r300, r420, rv515   offset and name per line
  linux/drivers/gpu/drm/radeon/r100d.h, r300d.h             R_<offset>_<name> register definitions
  linux/drivers/gpu/drm/radeon/radeon_reg.h, r300_reg.h     column-0 #define lines whose value is an offset
  mesa/src/gallium/drivers/r300/r300_reg.h                  the same, from Mesa

Grades (see docs/registers.md):

  exact     one name at the offset in a table written for the R3xx: reg_srcs/r300,
            r300d.h, r100d.h or r300_reg.h, and no other table disagrees
  common    one name, but only in radeon_reg.h or Mesa's header (registers the earlier
            chips share; Linux uses them for the R3xx too)
  conflict  tables give different names at the offset; all are listed
  none      no public table has the offset

Only the text between the registers:begin and registers:end markers is
rewritten. Run with --check to exit non-zero when the file would change.
"""
import argparse
import collections
import csv
import json
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(REPO, 'docs', 'registers.md')
CONFIG = os.path.join(REPO, 'scripts', 'inventory-config.json')
FUNCS = os.path.join(REPO, 'docs', 'inventory', 'functions.tsv')
BINARIES = (('kernel', 'fglrx.o', 'usr/cpu/sysgen/IP35boot/fglrx.o'),
            ('xmod', 'fglrx_drv.so', 'usr/X11R6/lib/modules/drivers/fglrx_drv.so'))
R3XX = ('reg_srcs/r300', 'r300d.h', 'r100d.h', 'r300_reg.h')
RADEON = 'drivers/gpu/drm/radeon/'
# column-0 radeon_reg.h defines whose value is an offset in a different space or a field value
NOISE = re.compile(r'RADEON_CP_VC_|_PCI_CONFIG|VCLK_ECP_CNTL|SPLL_CNTL|XDLL_CNTL|RADEON_ADAPTER_ID|VSF_')
# the same register under two spellings in different tables
ALIASES = {'DISPLAY2_BASE_ADDR': 'CRTC2_DISPLAY_BASE_ADDR', 'MEM_SDRAM_MODE_REG': 'SDRAM_MODE_REG'}
MAX_ROUTINES = 1


def public_names(root):
    lin = os.path.join(root, 'linux', 'drivers', 'gpu', 'drm', 'radeon')
    mesa = os.path.join(root, 'mesa', 'src', 'gallium', 'drivers', 'r300', 'r300_reg.h')
    names = collections.defaultdict(list)

    def add(off, name, src):
        if (name, src) not in names[off]:
            names[off].append((name, src))

    for fn in ('r300', 'r420', 'rv515'):
        for line in open(os.path.join(lin, 'reg_srcs', fn), encoding='utf-8'):
            m = re.match(r'(0x[0-9A-Fa-f]+)\s+(\w+)', line)
            if m:
                add(int(m.group(1), 16), m.group(2), 'reg_srcs/' + fn)
    for fn in ('r100d.h', 'r300d.h'):
        for line in open(os.path.join(lin, fn), encoding='utf-8'):
            m = re.match(r'#define\s+R_([0-9A-F]{6})_(\w+)\s', line)
            if m:
                add(int(m.group(1), 16), m.group(2), fn)
    for path, prefix, tag in ((os.path.join(lin, 'radeon_reg.h'), 'RADEON_', 'radeon_reg.h'),
                              (os.path.join(lin, 'r300_reg.h'), 'R300_', 'r300_reg.h'),
                              (mesa, '', 'mesa r300_reg.h')):
        for line in open(path, encoding='utf-8'):
            m = re.match(r'#define\s+(%s\w+)\s+(0x[0-9A-Fa-f]+)\b' % prefix, line)
            if m and not NOISE.search(m.group(1)):
                v = int(m.group(2), 16)
                if v < 0x10000 and v % 4 == 0:
                    add(v, m.group(1), tag)
    return names


def norm(name):
    n = re.sub(r'^(RADEON_|R300_)', '', name).replace('MSK', 'MASK')
    return ALIASES.get(n, n)


def lookup(names, off):
    """(grade, names) for an offset. A byte or halfword access inside a dword is graded as a lane of
    the dword's register, not as a register of its own."""
    g, nm = grade(names.get(off & ~3, []))
    if off & 3:
        return ('lane of 0x%x' % (off & ~3) if nm else 'none'), nm
    return g, nm


def grade(cands):
    cands = [(n, s) for n, s in cands if not NOISE.search(n)]
    if not cands:
        return 'none', []
    by = collections.OrderedDict()
    for n, s in cands:
        by.setdefault(norm(n), set()).add(s)
    names = list(by)
    if len(names) > 1:
        return 'conflict', names
    srcs = by[names[0]]
    return ('exact' if srcs & set(R3XX) else 'common'), names


def run_inventory(label, key, scratch):
    cfg = json.load(open(CONFIG, encoding='utf-8'))
    cfg['bases'] = [b for b in cfg['bases'] if key in json.dumps(b['binaries'])]
    path = os.path.join(scratch, 'config-%s.json' % label)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(cfg, f)
    out = os.path.join(scratch, label)
    r = subprocess.run([sys.executable, os.path.join(REPO, 'scripts', 'inventory.py'), '--config', path,
                        '--out', out, '--no-coverage'], cwd=REPO, capture_output=True, text=True)
    if r.returncode:
        sys.exit('inventory run for %s failed:\n%s' % (label, r.stdout[-2000:] + r.stderr[-2000:]))
    return out


def read_rows(out):
    with open(os.path.join(out, 'mmio.tsv'), encoding='utf-8') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def function_addresses():
    addr = {}
    with open(FUNCS, encoding='utf-8') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            for label, _, path in BINARIES:
                if r['binary'] == path and r['rejected'] == '' and int(r['address'], 0):
                    addr[(label, r['name'])] = int(r['address'], 0)
    return addr


def routine_cell(funcs, label, addr):
    names = [f for f in funcs.split(';') if not f.startswith('+')]
    more = sum(int(re.match(r'\+(\d+)', f).group(1)) for f in funcs.split(';') if f.startswith('+'))
    more += max(0, len(names) - MAX_ROUTINES)
    shown = names[:MAX_ROUTINES]
    cells = []
    for n in shown:
        m = re.match(r'routine@(0x[0-9a-f]+)', n)
        if m:
            cells.append('static code at %s' % m.group(1))
        else:
            a = addr.get((label[0], re.sub(r'-0x[0-9a-f]+$', '', n)))
            cells.append('`%s`%s' % (n, ' at 0x%x' % a if a else ''))
    return ', '.join(cells), more


def read_in_full(text):
    """Offsets that the 'Registers read in full' entries of docs/registers.md start with."""
    sec = text.split('## Registers read in full', 1)[-1].split('\n## ', 1)[0]
    return {int(m, 16) for m in re.findall(r'^- \*\*(0x[0-9a-f]+)\*\*', sec, re.M)}


def table(label, rows, names, addr, READ):
    head = ['| Offset | Public name | Grade | Access | Sites | Routine | Further routines | Driver role |', '|---|---|---|---|---|---|---|---|']
    body = []
    for r in sorted(rows, key=lambda r: int(r['offset'], 16)):
        off = int(r['offset'], 16)
        g, nm = lookup(names, off)
        pn = ' or '.join('`%s`' % n for n in nm) if nm else 'none'
        acc = ' '.join(a for a in r['access'].split(',')).replace('r', 'read ').replace('w', 'write ').strip()
        acc = ', '.join(a.strip() for a in re.findall(r'(?:read|write) \d', acc))
        first, more = routine_cell(r['functions'], label, addr)
        body.append('| %s | %s | %s | %s | %s | %s | %d | %s |' % (r['offset'], pn, g, acc, r['sites'], first, more,
                                                                  'see below' if off in READ else 'unknown'))
    return '\n'.join(head + body)


def build(public_root, reuse, read):
    names = public_names(public_root)
    addr = function_addresses()
    scratch = reuse or tempfile.mkdtemp(prefix='regtable-', dir=os.environ.get('TMPDIR'))
    blocks, count = [], {}
    for label, key, _ in BINARIES:
        out = os.path.join(scratch, label) if reuse else run_inventory(label, key, scratch)
        rows = read_rows(out)
        cnt = collections.Counter(lookup(names, int(r['offset'], 16))[0].split(' of ')[0] for r in rows)
        count[label] = (len(rows), sum(int(r['sites']) for r in rows), cnt)
        blocks.append((label, key, rows))
    lines = []
    for label, key, rows in blocks:
        n, sites, cnt = count[label]
        lines.append('### `%s`\n' % key)
        lines.append('%d offsets, %d access sites. Public-name grades: %s.\n' % (
            n, sites, ', '.join('%d %s' % (cnt[g], g) for g in ('exact', 'common', 'conflict', 'lane', 'none'))))
        lines.append(table((label,), rows, names, addr, read))
        lines.append('')
    lines.append('### Offsets with no public name\n')
    lines.append('| Offset | Binary | Access | Routine | Further routines |')
    lines.append('|---|---|---|---|---|')
    unnamed = []
    for label, key, rows in blocks:
        for r in rows:
            off = int(r['offset'], 16)
            if lookup(names, off)[0] == 'none':
                unnamed.append((off, key, r))
    for off, key, r in sorted(unnamed, key=lambda x: (x[0], x[1])):
        acc = ', '.join(re.findall(r'[rw]\d', r['access']))
        label = 'kernel' if key == 'fglrx.o' else 'xmod'
        lines.append('| 0x%x | `%s` | %s | %s |' % (off, key, acc.replace('r', 'read ').replace('w', 'write '),
                                                  routine_cell(r['functions'], (label,), addr)))
    lines.append('')
    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--public-root', default=REPO)
    ap.add_argument('--reuse', help='directory holding kernel/ and xmod/ inventory outputs from an earlier run')
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args()
    text = open(DOC, encoding='utf-8').read()
    m = re.search(r'(<!-- registers:begin -->\n)(.*?)(<!-- registers:end -->)', text, re.S)
    if not m:
        sys.exit('docs/registers.md has no registers:begin / registers:end markers')
    new = text[:m.end(1)] + build(a.public_root, a.reuse, read_in_full(text)) + '\n' + text[m.start(3):]
    if a.check:
        sys.exit(0 if new == text else 1)
    open(DOC, 'w', encoding='utf-8').write(new)


if __name__ == '__main__':
    main()
