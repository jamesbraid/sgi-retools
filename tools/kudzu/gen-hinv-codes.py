#!/usr/bin/env python3
"""Generate docs/hinv-codes.tsv: inventory class and type numbers.

Usage: scripts/gen-hinv-codes.py   (from the repository root, with root/ populated,
inside the toolchain container: tools/re-run python3 scripts/gen-hinv-codes.py)

Three sources, each read from a file in root/:

  root/6.5.30/sbin/hinv           the hinv command: its class-keyword table, its
                                  type-keyword table, and the code that reads them
  root/6.5.30/usr/include/sys/invent.h
                                  the installed header: the names of the class and type
                                  numbers (published, so the names are used as written)
  root/6.5.30/unix.IPnn           the linked kernels: every call to the routine that
                                  adds an inventory record, with the constant values
                                  the caller passes in the argument registers

A row is one class (kind "class") or one (class, type) pair (kind "type") that is
either a hinv type keyword or a value the kernel adds records with. The printed
strings hinv shows for each row are not mapped yet; that column is blank and listed
as left in the chapter.
"""
import bisect
import csv
import re
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile

sys.path.insert(0, 'scripts')
import toolchain  # noqa: E402

HINV = 'root/6.5.30/sbin/hinv'
HEADER = 'root/6.5.30/usr/include/sys/invent.h'
KERNELS = ['root/6.5.30/unix.IP27', 'root/6.5.30/unix.IP30', 'root/6.5.30/unix.IP35']
OUT = 'docs/hinv-codes.tsv'
CLASS_TABLE = 0x10011380   # hinv classes[]: name pointers, class = index + 1
TYPE_TABLE = 0x100113f0    # hinv type keywords: name pointer, class, type
CLASS_COUNT = 27
# (class scope, value) pairs whose header name is left out of the table: the copy
# check reports that name as present in a reference tree and absent from the
# baselines. The value stays in the table.
LEFT_OUT = {('GRAPHICS', 21)}

REGS = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 't0', 't1', 't2', 't3',
        't4', 't5', 't6', 't7', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1',
        'gp', 'sp', 's8', 'ra']


class Image:
    """Section-addressed view of a big-endian ELF."""

    def __init__(self, path):
        self.f = ELFFile(open(path, 'rb'))
        self.secs = [(s['sh_addr'], s['sh_size'], s.data() if s['sh_type'] != 'SHT_NOBITS' else None,
                      s.name) for s in self.f.iter_sections() if s['sh_addr'] and s['sh_size']]

    def bytes_at(self, addr, n):
        for base, size, data, _ in self.secs:
            if data is not None and base <= addr and addr + n <= base + size:
                o = addr - base
                return data[o:o + n]
        raise KeyError(hex(addr))

    def word(self, addr):
        return struct.unpack('>I', self.bytes_at(addr, 4))[0]

    def cstr(self, addr):
        for base, size, data, _ in self.secs:
            if data is not None and base <= addr < base + size:
                o = addr - base
                return data[o:data.index(b'\0', o)].decode('latin1')
        return None

    def symbols(self):
        out = []
        for s in self.f.get_section_by_name('.symtab').iter_symbols() if self.f.get_section_by_name('.symtab') else []:
            if s['st_info']['type'] == 'STT_FUNC' and s['st_value']:
                out.append((s['st_value'], s['st_size'], s.name))
        return sorted(out)


def hinv_tables():
    img = Image(HINV)
    classes = []
    for i in range(CLASS_COUNT):
        p = img.word(CLASS_TABLE + 4 * i)
        classes.append(img.cstr(p) or '')
    types = []
    a = TYPE_TABLE
    while True:
        p = img.word(a)
        if p == 0:
            break
        types.append((img.cstr(p), img.word(a + 4), img.word(a + 8), a))
        a += 12
    return classes, types


def header_names():
    """Macro name -> value, and macro name -> class name from the nearest "types for class X" comment."""
    names = {}
    scope = None
    scoped = {}
    for line in open(HEADER, encoding='latin1'):
        m = re.search(r'types? for class\s+(?:INV_)?(\w+)', line, re.I)
        if m:
            scope = m.group(1).upper()
        elif re.match(r'\s*/\*\s*(?:[\w ]+ )?(?:states?|bit definitions|sub types)\b', line, re.I):
            scope = None
        m = re.match(r'\s*#define\s+(INV_\w+)\s+(0x[0-9a-fA-F]+|\d+)', line)
        if m:
            name, val = m.group(1), int(m.group(2), 0)
            names.setdefault(name, val)
            scoped.setdefault(name, scope)
    return names, scoped


def disasm(path):
    return subprocess.run([toolchain.objdump(), '-d', path], capture_output=True, text=True,
                          check=True).stdout


INSN = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f]+\s+(\S+)\s*(.*)$')


def parse(text):
    ins = []
    for line in text.splitlines():
        m = INSN.match(line)
        if m:
            ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return ins


def const_write(mn, ops):
    parts = [p.strip() for p in ops.split(',')]
    if mn in ('li',) and len(parts) == 2:
        return parts[0], ('const', int(parts[1], 0))
    if mn == 'move' and len(parts) == 2:
        return parts[0], ('move', parts[1].lstrip('$'))
    if mn in ('addiu', 'daddiu') and len(parts) == 3:
        if parts[1] in ('zero', '$zero'):
            return parts[0], ('const', int(parts[2], 0))
        return parts[0], ('other', mn)
    if mn == 'lui' and len(parts) == 2:
        return parts[0], ('other', mn)
    if mn in ('jal', 'jalr', 'bal'):
        return 'CALL', None
    if parts and mn not in ('sd', 'sw', 'sh', 'sb', 'sdc1', 'swc1', 'beq', 'bne', 'beqz', 'bnez', 'b',
                            'j', 'jr', 'nop', 'bgez', 'bltz', 'blez', 'bgtz', 'beql', 'bnel', 'bgezl',
                            'bltzl', 'blezl', 'bgtzl', 'sync', 'cache', 'mtc0', 'dmtc0', 'mtc1', 'dmtc1',
                            'eret', 'syscall', 'break'):
        return parts[0], ('other', mn)
    return None, None


def trace(ins, idx, branch_targets, reg, depth=0):
    """Constant the register holds at ins[idx]: ('const', value, addr), or a status string."""
    site = ins[idx][0]
    # The instruction in a call's delay slot runs before the callee does, so a write to the
    # register there is the value the callee sees.
    if depth == 0 and idx + 1 < len(ins):
        dest, info = const_write(ins[idx + 1][1], ins[idx + 1][2])
        if dest and dest != 'CALL' and dest.lstrip('$') == reg:
            if info[0] == 'const':
                return ('const', info[1], ins[idx + 1][0])
            if info[0] == 'move' and info[1] == 'zero':
                return ('const', 0, ins[idx + 1][0])
            return 'variable'
    j = idx - 1
    while j >= 0 and idx - j < 120:
        a, mn, ops = ins[j]
        dest, info = const_write(mn, ops)
        if dest == 'CALL':
            return 'clobbered-by-call'
        if dest and dest.lstrip('$') == reg:
            if any(a < t <= site for t in branch_targets):
                return 'join'
            if info[0] == 'const':
                return ('const', info[1], a)
            if info[0] == 'move':
                if info[1] == 'zero':
                    return ('const', 0, a)
                if depth < 4:
                    return trace(ins, j, branch_targets, info[1], depth + 1)
                return 'variable'
            return 'variable'
        j -= 1
    return 'unknown'


def add_sites(path):
    img = Image(path)
    syms = img.symbols()
    starts = [s[0] for s in syms]
    target = [s[0] for s in syms if s[2] == 'add_to_inventory']
    if not target:
        return []
    target = target[0]
    ins = parse(disasm(path))
    targets = set()
    for a, mn, ops in ins:
        if mn.startswith('b') or mn in ('j',):
            m = re.search(r'\b(c?[0-9a-f]{8,16})\s*<', ops)
            if m:
                targets.add(int(m.group(1), 16))
    res = []
    index = {a: i for i, (a, _, _) in enumerate(ins)}
    for i, (a, mn, ops) in enumerate(ins):
        if mn in ('jal', 'bal') and ('<add_to_inventory>' in ops):
            fi = bisect.bisect_right(starts, a) - 1
            if fi < 0:
                fname = '?'
            elif a < syms[fi][0] + syms[fi][1]:
                fname = syms[fi][2]
            else:
                # a routine with no symbol: name the symbol before it and how far past its end
                fname = f'no symbol, {hex(a - syms[fi][0] - syms[fi][1])} past the end of {syms[fi][2]}'
            vals = {}
            for n, r in enumerate(['a0', 'a1', 'a2', 'a3', 'a4']):
                vals[r] = trace(ins, i, targets, r)
            res.append((a, fname, vals))
    return res


def fmt(v):
    if isinstance(v, tuple) and v[0] == 'const':
        return str(v[1])
    return v


def main():
    classes, types = hinv_tables()
    names, scoped = header_names()
    class_macro = {}
    for name, val in names.items():
        if 1 <= val <= CLASS_COUNT and scoped.get(name) is None:
            class_macro.setdefault(val, name)
    scope_of_class = {c: m[len('INV_'):] for c, m in class_macro.items()}
    sites = []
    for k in KERNELS:
        image = k.split('/')[-1]
        for a, fname, vals in add_sites(k):
            sites.append((image, a, fname, vals))
    print(f'{len(sites)} add_to_inventory call sites', file=sys.stderr)
    keyword_of = {}
    for kw, c, t, addr in types:
        keyword_of.setdefault((c, t), (kw, addr))
    pairs = {}
    for image, a, fname, vals in sites:
        c, t = vals['a0'], vals['a1']
        if isinstance(c, tuple) and c[0] == 'const' and isinstance(t, tuple) and t[0] == 'const':
            pairs.setdefault((c[1], t[1]), []).append((image, a, fname, vals))
    rows = []
    for c in range(1, CLASS_COUNT + 1):
        kw = classes[c - 1]
        rows.append(dict(
            kind='class', cls=c, typ='', class_macro=class_macro.get(c, ''), type_macro='',
            hinv_keyword=kw, hinv_entry=hex(CLASS_TABLE + 4 * (c - 1)),
            sites='; '.join(f'{img}@{hex(a)} ({fn})' for (img, a, fn, v) in sites
                            if isinstance(v['a0'], tuple) and v['a0'][0] == 'const' and v['a0'][1] == c and
                            isinstance(v['a1'], tuple) and v['a1'][0] == 'const') or '',
            grade='established' if kw else 'established (helper class, no keyword)',
        ))
    for image, a, fname, vals in sites:
        if not (isinstance(vals['a0'], tuple) and vals['a0'][0] == 'const' and
                isinstance(vals['a1'], tuple) and vals['a1'][0] == 'const'):
            rows.append(dict(
                kind='site-unresolved', cls='', typ='', class_macro='', type_macro='',
                hinv_keyword='', hinv_entry='',
                sites=f'{image}@{hex(a)} ({fname}): class {fmt(vals["a0"])}, type {fmt(vals["a1"])}',
                grade='unknown'))
    all_pairs = set(pairs) | {(c, t) for kw, c, t, _ in types}
    for c, t in sorted(all_pairs):
        scope = scope_of_class.get(c)
        mac = [n for n, v in names.items() if v == t and scope and scoped.get(n) == scope
               and (scope, t) not in LEFT_OUT]
        kw, addr = keyword_of.get((c, t), ('', None))
        site_list = pairs.get((c, t), [])
        rows.append(dict(
            kind='type', cls=c, typ=t, class_macro=class_macro.get(c, ''),
            type_macro=', '.join(sorted(mac)),
            hinv_keyword=kw, hinv_entry=hex(addr) if addr else '',
            sites='; '.join(f'{img}@{hex(a)} ({fn})' for (img, a, fn, v) in site_list),
            grade='established' if (kw or site_list) else '',
        ))
    return rows


FIELDS = ['kind', 'cls', 'typ', 'class_macro', 'type_macro', 'hinv_keyword', 'hinv_entry', 'sites',
          'printed_by_hinv', 'grade']


def write(rows):
    with open(OUT, 'w', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(FIELDS)
        for r in rows:
            w.writerow([r['kind'], r['cls'], r['typ'], r['class_macro'], r['type_macro'],
                        r['hinv_keyword'], r['hinv_entry'], r['sites'], 'not mapped', r['grade']])


if __name__ == '__main__':
    write(main())
