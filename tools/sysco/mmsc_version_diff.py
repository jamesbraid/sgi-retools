#!/usr/bin/env python3
"""Compare the MMSC firmware images routine by routine, by symbol name.

Usage: tools/re-run python3 scripts/mmsc_version_diff.py [--out docs/version-diffs]

The MMSC image is an unstripped a.out, so its routines are named. Each set is compared with
the one before it in release order (the series below), keyed by symbol name and kind:

  same-bytes         the routine's bytes are identical
  same-code-moved    the disassembly matches once in-image addresses are masked (counted
                     in mmsc-series.tsv only, not listed)
  changed            the names match and the code differs
  added, removed     the name is in one image only

A routine runs from its symbol to the next text symbol of the image. Symbols that the
compiler or assembler plants at object starts (markers) are not routines and are skipped.
Text is decoded with capstone in 32-bit mode. A hex operand inside the image's own address
range is masked as ADDR, so code that only moved still matches. Similarity is the sequence
match ratio of the normalised instruction lists; it is inferred, a ranking aid and no proof.

Writes, under docs/version-diffs/:

  mmsc-routines.tsv     one row per routine change between consecutive sets
  mmsc-data.tsv         data and bss symbols added or removed between consecutive sets
  mmsc-commands.tsv     help-table command names added or removed between consecutive sets
  mmsc-modules.tsv      objects (by basename) added, removed or changed between consecutive sets
  mmsc-series.tsv       counts per step

Run in the toolchain container (capstone is not on the host).
"""
import bisect
import collections
import difflib
import hashlib
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mmsc_aout as ma  # noqa: E402
import capstone  # noqa: E402

# The workspace comes from the current directory (tools/_workspace.py), not from this file's path.
TOOLS = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, TOOLS)
from _workspace import find_workspace  # noqa: E402
REPO = find_workspace()
OUT = os.path.join(REPO, 'docs', 'version-diffs')
if '--out' in sys.argv:
    OUT = os.path.abspath(sys.argv[sys.argv.index('--out') + 1])

# Release order by the image's own creation date (the _creationDate string), oldest first.
SERIES = [
    ('6.4-origin', 'root/6.4-origin/usr/cpu/firmware/mmscfw.bin'),
    ('6.4', 'root/6.4/usr/cpu/firmware/mmscfw.bin'),
    ('SG0002378', 'root/patches/SG0002378/usr/cpu/firmware/mmscfw.bin'),
    ('6.5.2', 'root/6.5.2/usr/cpu/firmware/mmscfw.bin'),
    ('6.5', 'root/6.5/usr/cpu/firmware/mmscfw.bin'),
    ('6.5.5', 'root/6.5.5/usr/cpu/firmware/mmscfw.bin'),
    ('6.5.6', 'root/6.5.6/usr/cpu/firmware/mmscfw.bin'),
    ('6.5.7', 'root/6.5.7/usr/cpu/firmware/mmscfw.bin'),
    ('6.5.30', 'root/6.5.30/usr/cpu/firmware/mmscfw.bin'),
]

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
# A help-table line is the command's syntax, spaces, a dash and its description. The
# older images align the dash with two spaces and the newer ones with one.
HELP_LINE = re.compile(rb'^([A-Z][A-Z_0-9]*(?: (?:<[^>]*>|[A-Z_0-9|]+))*)\s+- ')


class Build:
    def __init__(self, label, path):
        self.label = label
        with open(os.path.join(REPO, path), 'rb') as f:
            self.blob = f.read()
        self.img = ma.Image(self.blob)
        self.sha = hashlib.sha256(self.blob).hexdigest()
        self.lo = self.img.segment('text').addr
        self.hi = self.img.segment('bss').addr + self.img.segment('bss').size
        self._marks = []
        self.routines = self._routines()
        self.commands = self._commands()

    def _routines(self):
        text = [s for s in self.img.symbols if s.kind == 'text' and not s.marker]
        text.sort(key=lambda s: (s.value, s.index))
        out = collections.OrderedDict()
        seen = collections.Counter()
        for s in text:
            if s.size == 0:
                continue
            seen[s.name] += 1
            key = s.name if seen[s.name] == 1 else '%s#%d' % (s.name, seen[s.name])
            out[key] = (s.value, s.size, s.glob)
        return out

    def _commands(self):
        cmds = []
        for m in re.finditer(rb'[\x20-\x7e]{6,}', self.blob):
            hit = HELP_LINE.match(m.group(0))
            if hit:
                cmds.append(hit.group(1).decode())
        return sorted(set(cmds))

    def owner(self, addr):
        # The object a routine belongs to: the last object-start marker at or before it.
        # Each object's code is contiguous, so the nearest marker below names it. Object
        # names are compared by basename, since the build directory differs between releases.
        if not self._marks:
            marks = [(s.value, s.index, re.split(r'[\\/]', s.name)[-1].lower())
                     for s in self.img.symbols
                     if s.kind == 'text' and s.name.endswith('.o')]
            self._marks = sorted(marks)
        i = bisect.bisect_right(self._marks, (addr, 1 << 30, '')) - 1
        return self._marks[i][2] if i >= 0 else '?'

    def modules(self):
        return {m for _, _, m in self._marks_all()}

    def _marks_all(self):
        self.owner(0)
        return self._marks

    def code(self, addr, size):
        raw = self.img.read(addr, size)
        insns = []
        for i in MD.disasm(raw, addr):
            ops = re.sub(r'0x[0-9a-f]+', self._mask, i.op_str)
            insns.append('%s %s' % (i.mnemonic, ops))
        return raw, insns

    def _mask(self, m):
        return 'ADDR' if self.lo <= int(m.group(0), 16) < self.hi else m.group(0)


def compare(a, b):
    rows = []
    for name in a.routines:
        if name not in b.routines:
            addr, size, _ = a.routines[name]
            rows.append(('removed', name, addr, size, None, None, '', '', ''))
    for name in b.routines:
        if name not in a.routines:
            addr, size, _ = b.routines[name]
            rows.append(('added', name, None, None, addr, size, '', '', ''))
    for name in a.routines:
        if name not in b.routines:
            continue
        aa, asz, _ = a.routines[name]
        ba, bsz, _ = b.routines[name]
        ra, ia = a.code(aa, asz)
        rb, ib = b.code(ba, bsz)
        if ra == rb:
            status, sim, first = 'same-bytes', 1.0, ('', '')
        elif ia == ib:
            status, sim, first = 'same-code-moved', 1.0, ('', '')
        else:
            status = 'changed'
            sim = difflib.SequenceMatcher(None, ia, ib, autojunk=False).ratio()
            k = next((i for i, (x, y) in enumerate(zip(ia, ib)) if x != y), min(len(ia), len(ib)))
            first = (ia[k] if k < len(ia) else '', ib[k] if k < len(ib) else '')
        if status != 'same-bytes':
            rows.append((status, name, aa, asz, ba, bsz, '%.3f' % sim, first[0], first[1]))
    return rows


def symbol_rows(a, b):
    rows = []
    for kind in ('data', 'bss'):
        sa = {s.name: s for s in a.img.symbols if s.kind == kind and not s.marker and s.name}
        sb = {s.name: s for s in b.img.symbols if s.kind == kind and not s.marker and s.name}
        for n in sorted(set(sa) - set(sb)):
            rows.append((kind, 'removed', n, '%#x' % sa[n].value, '%d' % sa[n].size))
        for n in sorted(set(sb) - set(sa)):
            rows.append((kind, 'added', n, '%#x' % sb[n].value, '%d' % sb[n].size))
    return rows


def module_rows(step, a, b, rows, mods_a, mods_b):
    # One row per object that is added, removed, or holds a changed, added or removed routine.
    # Counts are routines of the object in the image it is in (the removed ones in a, the
    # added ones in b, the changed ones in b).
    per = collections.defaultdict(collections.Counter)
    for r in rows:
        if r[0] == 'same-code-moved':
            continue
        if r[0] == 'removed':
            per[a.owner(a.routines[r[1]][0])][r[0]] += 1
        elif r[0] == 'added':
            per[b.owner(b.routines[r[1]][0])][r[0]] += 1
        else:
            per[b.owner(b.routines[r[1]][0])][r[0]] += 1
    out = []
    for m in sorted(mods_a | mods_b):
        if m not in mods_a:
            status = 'added'
        elif m not in mods_b:
            status = 'removed'
        elif per.get(m) and sum(per[m].values()):
            status = 'changed'
        else:
            continue
        c = per.get(m, collections.Counter())
        out.append((step, m, status, c['changed'], c['added'], c['removed']))
    return out


def write(name, header, rows):
    path = os.path.join(OUT, name)
    with open(path, 'w') as f:
        f.write('\t'.join(header) + '\n')
        for r in rows:
            f.write('\t'.join(str(x) for x in r) + '\n')
    print('wrote', os.path.relpath(path, REPO), len(rows), 'rows')


def main():
    builds = [Build(label, path) for label, path in SERIES]
    routine_hdr = ['step', 'status', 'name', 'from_addr', 'from_len', 'to_addr', 'to_len',
                   'similarity', 'first_difference_from', 'first_difference_to']
    routines, data, cmds, mods, series = [], [], [], [], []
    # The adjacent pairs give each release its place in the series. The patch is also
    # compared directly with the earliest held 6.4 image, the baseline its notes are read from.
    pairs = list(zip(builds, builds[1:]))
    pairs.append((builds[0], builds[2]))
    for a, b in pairs:
        step = '%s -> %s' % (a.label, b.label)
        rows = compare(a, b)
        counts = collections.Counter(r[0] for r in rows)
        for r in rows:
            if r[0] == 'same-code-moved':
                continue
            fa = ('%#x' % r[2]) if r[2] is not None else ''
            ta = ('%#x' % r[4]) if r[4] is not None else ''
            routines.append((step, r[0], r[1], fa, r[3] if r[3] is not None else '',
                             ta, r[5] if r[5] is not None else '', r[6], r[7], r[8]))
        for kind, status, n, addr, size in symbol_rows(a, b):
            data.append((step, kind, status, n, addr, size))
        added = sorted(set(b.commands) - set(a.commands))
        removed = sorted(set(a.commands) - set(b.commands))
        cmds.extend((step, 'added', c) for c in added)
        cmds.extend((step, 'removed', c) for c in removed)
        mods_a, mods_b = a.modules(), b.modules()
        mods.extend(module_rows(step, a, b, rows, mods_a, mods_b))
        m_add = sum(1 for m in mods if m[0] == step and m[2] == 'added')
        m_rem = sum(1 for m in mods if m[0] == step and m[2] == 'removed')
        m_chg = sum(1 for m in mods if m[0] == step and m[2] == 'changed')
        series.append((step, len(a.routines), len(b.routines), counts['same-code-moved'],
                       counts['changed'], counts['removed'], counts['added'],
                       len(added), len(removed), m_add, m_rem, m_chg))
        print(step, dict(counts), 'commands +%d -%d' % (len(added), len(removed)),
              'modules +%d -%d ~%d' % (m_add, m_rem, m_chg))
    series_hdr = ['step', 'from_routines', 'to_routines', 'same_code_moved', 'changed',
                  'removed', 'added', 'commands_added', 'commands_removed',
                  'modules_added', 'modules_removed', 'modules_changed']
    os.makedirs(OUT, exist_ok=True)
    write('mmsc-routines.tsv', routine_hdr, routines)
    write('mmsc-data.tsv', ['step', 'kind', 'status', 'name', 'addr', 'size'], data)
    write('mmsc-commands.tsv', ['step', 'status', 'command'], cmds)
    write('mmsc-modules.tsv', ['step', 'object', 'status', 'routines_changed',
                               'routines_added', 'routines_removed'], mods)
    write('mmsc-series.tsv', series_hdr, series)


if __name__ == '__main__':
    main()
