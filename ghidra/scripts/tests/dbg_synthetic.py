#!/usr/bin/env python3
"""A synthetic x86 PE image, its separate .dbg file, and what ReDbgImport.java must make of them.

  dbg_synthetic.py write DIR      write DIR/synthetic.dll and DIR/synthetic.dbg
  dbg_synthetic.py check SYMS LOG check DumpDbgSymbols.java's output and the headless log
  dbg_synthetic.py                build both and check them against a plain Python reading (no Ghidra)

No vendor bytes. The COFF symbols cover each case of the counting rule in ReDbgImport.java: an
auxiliary record, an alias of one address, a long (string table) name, a label in .text and in
.data, a ".text" section record and a label ahead of a function at that function's address (neither
may take the function's name), an undefined and an absolute symbol, a name Ghidra rejects, and an
address past the image. The NB09 file holds the same kinds of public.
"""
import os
import struct
import sys

BASE = 0x10000000
TEXT, DATA = 0x1000, 0x2000
SIZE_OF_IMAGE = 0x3000
# (name, value, section, type, aux records). Section 1 is .text, 2 is .data.
SYMBOLS = [
    ('func_a', TEXT, 1, 0x20, 1),
    ('.text', TEXT + 0x10, 1, 0, 1),
    ('func_b', TEXT + 0x10, 1, 0x20, 0),
    ('alias_of_b', TEXT + 0x10, 1, 0x20, 0),
    ('early_label', TEXT + 0x20, 1, 0, 0),
    ('a_function_with_a_long_name', TEXT + 0x20, 1, 0x20, 0),
    ('text_label', TEXT + 0x30, 1, 0, 0),
    ('table', DATA + 8, 2, 0, 0),
    ('\x7fBAD_NULL_THUNK_DATA', DATA + 0x10, 2, 0, 0),
    ('_undefined', 0, 0, 0, 0),
    ('_absolute', 0x1234, -1, 0, 0),
    ('past_the_image', TEXT + 0x5000, 1, 0x20, 0),
]
# What the summary line must say, and the symbols that must exist.
COUNTS = dict(records=len(SYMBOLS), auxiliary=2, functions=3, labels=4, sections=1, ignored=2, outside=1,
              rejected=1, uncreated=0)
# The loader names the entry point, at func_a's address, before the script runs and that name is kept.
EXPECT = [('function', TEXT, 'entry'), ('function', TEXT + 0x10, 'func_b'),
          ('function', TEXT + 0x20, 'a_function_with_a_long_name'),
          ('label', TEXT + 0x30, 'text_label'), ('label', DATA + 8, 'table')]


def pad(b, n):
    return b + bytes(-len(b) % n)


def sections():
    text = pad(b'\x55\x89\xe5\x5d\xc3' + b'\xc3' * 0x1f + b'\xc3' * 0x40, 0x200)
    return [(b'.text', TEXT, text, 0x60000020), (b'.data', DATA, bytes(0x200), 0xc0000040)]


def header_table(secs, file_off):
    out = b''
    for name, rva, data, ch in secs:
        out += struct.pack('<8sIIIIIIHHI', name, len(data), rva, len(data), file_off, 0, 0, 0, 0, ch)
        file_off += len(data)
    return out


def image():
    secs = sections()
    opt = struct.pack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', 0x10b, 6, 0, 0x200, 0x200, 0, TEXT, TEXT, DATA,
                      BASE, 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0, SIZE_OF_IMAGE, 0x200, 0, 2, 0,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    assert len(opt) == 96, len(opt)
    opt += bytes(16 * 8)
    coff = struct.pack('<HHIIIHH', 0x14c, len(secs), 0, 0, 0, len(opt), 0x230e)
    head = b'MZ' + bytes(0x3a) + struct.pack('<I', 0x40) + b'PE\0\0' + coff + opt
    head += header_table(secs, 0x200)
    return pad(head, 0x200) + b''.join(d for _, _, d, _ in secs)


def coff_symbols():
    table, strings = b'', b''
    for name, value, section, typ, aux in SYMBOLS:
        raw = name.encode('latin-1')
        if len(raw) <= 8:
            field = raw.ljust(8, b'\0')
        else:
            field = struct.pack('<II', 0, 4 + len(strings))
            strings += raw + b'\0'
        table += struct.pack('<8sIhHBB', field, value, section, typ, 2, aux) + bytes(18 * aux)
    return table + struct.pack('<I', 4 + len(strings)) + strings, len(table) // 18


def separate(debug_type, raw):
    secs = sections()
    first = 48 + 40 * len(secs) + 0 + 28
    entry = struct.pack('<IIHHIIII', 0, 0, 0, 0, debug_type, len(raw), 0, first)
    head = struct.pack('<HHHHIIIIIIII8s', 0x4944, 0, 0x14c, 0x230e, 0, 0, BASE, SIZE_OF_IMAGE,
                       len(secs), 0, 28, 0x1000, bytes(8))
    sec_table = header_table(secs, 0)
    return head + sec_table + entry + raw


def dbg():
    table, count = coff_symbols()
    coff_header = struct.pack('<8I', count, 32, 0, 0, TEXT, TEXT + 0x100, DATA, DATA + 0x200)
    return separate(1, coff_header + table)


def reference():
    """The counting rule read again from the bytes, without Ghidra."""
    d = dbg()
    nsec, = struct.unpack_from('<I', d, 24)
    entry = 48 + 40 * nsec
    raw, = struct.unpack_from('<I', d, entry + 24)
    count, first = struct.unpack_from('<II', d, raw)
    at, i = raw + first, 0
    seen = dict(records=0, auxiliary=0, functions=set(), ignored=0, sections=0)
    while i < count:
        name, value, section, typ, _, aux = struct.unpack_from('<8sIhHBB', d, at + 18 * i)
        seen['records'] += 1
        seen['auxiliary'] += aux
        i += 1 + aux
        if section <= 0:
            seen['ignored'] += 1
        elif name.startswith(b'.'):
            seen['sections'] += 1
        elif section == 1 and (typ >> 4) & 0xf == 2 and value < SIZE_OF_IMAGE:
            seen['functions'].add(value)
    seen['functions'] = len(seen['functions'])
    return seen


def check(syms, log):
    counts, expect = COUNTS, EXPECT
    seen = set()
    for line in open(syms):
        f = line.rstrip('\n').split('\t')
        if f[0] in ('function', 'label'):
            seen.add((f[0], int(f[1], 16), f[2]))
    bad = ['%s %#x %s missing' % e for e in expect if e not in seen]
    # Primary names: every function carries a symbol's name, never a placeholder or a section name.
    bad += ['function %#x is named %s' % (a, n) for k, a, n in sorted(seen)
            if k == 'function' and (n.startswith('FUN_') or n.startswith('.'))]
    functions = sorted(a for k, a, _ in seen if k == 'function')
    if len(functions) != counts['functions']:
        bad.append('%d functions, want %d: %s' % (len(functions), counts['functions'], functions))
    want = ('ReDbgImport: COFF: %d symbol records, %d auxiliary skipped, %d functions, '
            '%d other labels, %d section names skipped, %d without a section, %d outside the image, '
            '%d names Ghidra rejects, %d functions not created'
            % (tuple(counts[k] for k in ('records', 'auxiliary', 'functions', 'labels', 'sections',
                                                   'ignored', 'outside', 'rejected', 'uncreated'))))
    if want not in open(log).read():
        bad.append('summary line is not: ' + want)
    for b in bad:
        print('FAIL dbg: ' + b)
    print('%s: .dbg symbols applied, %d functions at distinct addresses' %
          ('ok' if not bad else 'FAIL', len(functions)))
    return 1 if bad else 0


def main():
    if len(sys.argv) == 1:
        ref = reference()
        for key in ('records', 'auxiliary', 'functions', 'ignored', 'sections'):
            assert ref[key] == COUNTS[key], (key, ref[key], COUNTS[key])
        assert image()[:2] == b'MZ'
        print('ok: dbg and pe build, %d records, %d auxiliary, %d functions by the counting rule'
              % (ref['records'], ref['auxiliary'], ref['functions']))
        return 0
    if sys.argv[1] == 'write':
        os.makedirs(sys.argv[2], exist_ok=True)
        for name, data in (('synthetic.dll', image()), ('synthetic.dbg', dbg())):
            with open(os.path.join(sys.argv[2], name), 'wb') as f:
                f.write(data)
        return 0
    if sys.argv[1] == 'check':
        return check(sys.argv[2], sys.argv[3])
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main())
