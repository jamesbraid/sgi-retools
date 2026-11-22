#!/usr/bin/env python3
"""A synthetic x86 PE image, its separate .dbg files, and what ReDbgImport.java must make of them.

  dbg_synthetic.py write DIR             write DIR/synthetic.dll, synthetic.dbg (COFF),
                                         synthetic-va.dbg (COFF, values are virtual addresses),
                                         synthetic-nb09.dbg (CodeView publics), and the same image
                                         at a low base as synthetic-low.dll and synthetic-low.dbg
  dbg_synthetic.py check CASE SYMS LOG   check DumpDbgSymbols.java's output and the headless log;
                                         CASE is coff, coff-va, coff-low or nb09
  dbg_synthetic.py check-types OUT LOG   check ReFunctionTypesCheck.java's output and the headless log
  dbg_synthetic.py check-returning BEFORE AFTER LOG
                                         check DumpFunctionBodies.java's output before and after
                                         ReReturning.java, and the headless log
  dbg_synthetic.py                       build all and check them against a plain Python reading
                                         (no Ghidra)

No vendor bytes. The COFF symbols cover each case of the counting rule in ReDbgImport.java: an
auxiliary record, an alias of one address, a long (string table) name, a label in .text and in
.data, a ".text" section record and a label ahead of a function at that function's address (neither
may take the function's name), an undefined and an absolute symbol, a name Ghidra rejects, and an
address past the image. The NB09 file holds the same kinds of public. The low-base image puts
its RVAs above its ImageBase (0x10000, as an NT4 display driver does), where reading a value at or
above the ImageBase as a virtual address would move every function by the base.

synthetic-returning.dll is for ReReturning.java: a routine that returns, and three callers of it
(one call, two calls, and a call with a branch around it). The test marks the routine non-returning
before disassembling the callers, as analysis does when it is wrong, so each caller is cut at its call.
"""
import os
import struct
import sys

BASE = 0x10000000
TEXT, DATA = 0x1000, 0x2000
SIZE_OF_IMAGE = 0x3000
LOW = dict(base=0x10000, text=0x11000, data=0x12000, size=0x13000)
# (name, value, section, type, aux records). Section 1 is .text, 2 is .data. A value is an RVA, as an
# offset from the start of .text or .data (section 1 or 2) unless it has no section.
SYMBOLS = [
    ('func_a', 0, 1, 0x20, 1),
    ('.text', 0x10, 1, 0, 1),
    ('func_b', 0x10, 1, 0x20, 0),
    ('alias_of_b', 0x10, 1, 0x20, 0),
    ('early_label', 0x20, 1, 0, 0),
    ('a_function_with_a_long_name', 0x20, 1, 0x20, 0),
    ('text_label', 0x30, 1, 0, 0),
    ('table', 8, 2, 0, 0),
    ('\x7fBAD_NULL_THUNK_DATA', 0x10, 2, 0, 0),
    ('_undefined', 0, 0, 0, 0),
    ('_absolute', 0x1234, -1, 0, 0),
    ('past_the_image', 0x5000, 1, 0x20, 0),
]
# What the summary line must say, and the symbols that must exist.
COUNTS = dict(records=len(SYMBOLS), auxiliary=2, functions=3, labels=4, sections=1, ignored=2, outside=1,
              rejected=1, uncreated=0)
# The loader names the entry point, at func_a's address, before the script runs and that name is kept.
EXPECT = [('function', 'T', 0, 'entry'), ('function', 'T', 0x10, 'func_b'),
          ('function', 'T', 0x20, 'a_function_with_a_long_name'),
          ('label', 'T', 0x30, 'text_label'), ('label', 'D', 8, 'table')]


# CodeView publics: (name, offset in the segment, segment, is a function). Segment 1 is .text, 2 .data.
PUBLICS = [
    ('_pub_func', 0, 1, True),
    ('_pub_alias', 0, 1, True),
    ('_pub_second@8', 0x10, 1, True),
    ('_pub_table', 8, 2, False),
    ('??_C@_0M@EKBA@user?5buffer?$AA@', 0x40, 1, False),
    ('__IMPORT_DESCRIPTOR_FOO', 0x50, 1, False),
    ('__NULL_IMPORT_DESCRIPTOR', 0x64, 1, False),
    ('_pub_nosection', 0, 0, False),
    ('_pub_past_the_image', 0x5000, 1, True),
    ('.text', 0x30, 1, False),
]
NB09_COUNTS = dict(records=len(PUBLICS), auxiliary=0, functions=2, labels=4, sections=1, ignored=1,
                   outside=1, rejected=0, uncreated=0)
NB09_EXPECT = [('function', 'T', 0, 'entry'), ('function', 'T', 0x10, '_pub_second@8'),
               ('label', 'D', 8, '_pub_table'),
               ('label', 'T', 0x40, '??_C@_0M@EKBA@user?5buffer?$AA@'),
               ('label', 'T', 0x50, '__IMPORT_DESCRIPTOR_FOO'), ('label', 'T', 0x64, '__NULL_IMPORT_DESCRIPTOR')]
KINDS = {'coff': ('COFF', COUNTS, EXPECT, {}), 'nb09': ('CodeView NB09 publics', NB09_COUNTS, NB09_EXPECT, {}),
         'coff-va': ('COFF', COUNTS, EXPECT, {}), 'coff-low': ('COFF', COUNTS, EXPECT, LOW)}


STD = dict(base=BASE, text=TEXT, data=DATA, size=SIZE_OF_IMAGE)


def pad(b, n):
    return b + bytes(-len(b) % n)


def returning_text():
    """.text of the ReReturning image: a callee at 0, then callers at 0x10, 0x20 and 0x40."""
    t = bytearray(b'\xcc' * 0x200)

    def call(at):
        return b'\xe8' + struct.pack('<i', -(at + 5))
    t[0:3] = b'\x31\xc0\xc3'                                                  # xor eax,eax; ret
    t[0x10:0x18] = call(0x10) + b'\x40\x40\xc3'                               # call; inc; inc; ret
    t[0x20:0x2d] = call(0x20) + b'\x90' + call(0x26) + b'\x90\xc3'            # call; nop; call; nop; ret
    t[0x40:0x4d] = b'\x85\xc0\x74\x07' + call(0x44) + b'\x40\xc3\x48\xc3'   # test; jz; call; inc; ret; dec; ret
    return bytes(t)


# caller offset: (last byte of its whole body, instructions in it), and the same cut at the call.
CALLERS = {0x10: (0x17, 4, 0x14, 1), 0x20: (0x2c, 5, 0x24, 1), 0x40: (0x4c, 7, 0x4c, 5)}


def sections(lay=STD, text=None):
    text = pad(text or b'\x55\x89\xe5\x5d\xc3' + b'\xc3' * 0x1f + b'\xc3' * 0x40, 0x200)
    return [(b'.text', lay['text'], text, 0x60000020), (b'.data', lay['data'], bytes(0x200), 0xc0000040)]


def header_table(secs, file_off):
    out = b''
    for name, rva, data, ch in secs:
        out += struct.pack('<8sIIIIIIHHI', name, len(data), rva, len(data), file_off, 0, 0, 0, 0, ch)
        file_off += len(data)
    return out


def image(lay=STD, text=None):
    secs = sections(lay, text)
    opt = struct.pack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', 0x10b, 6, 0, 0x200, 0x200, 0, lay['text'],
                      lay['text'], lay['data'], lay['base'], 0x1000, 0x200, 4, 0, 0, 0, 4, 0, 0,
                      lay['size'], 0x200, 0, 2, 0,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    assert len(opt) == 96, len(opt)
    opt += bytes(16 * 8)
    coff = struct.pack('<HHIIIHH', 0x14c, len(secs), 0, 0, 0, len(opt), 0x230e)
    head = b'MZ' + bytes(0x3a) + struct.pack('<I', 0x40) + b'PE\0\0' + coff + opt
    head += header_table(secs, 0x200)
    return pad(head, 0x200) + b''.join(d for _, _, d, _ in secs)


def coff_symbols(lay=STD, va=False):
    table, strings = b'', b''
    for name, value, section, typ, aux in SYMBOLS:
        if section > 0:
            value += lay['text' if section == 1 else 'data'] + (lay['base'] if va else 0)
        raw = name.encode('latin-1')
        if len(raw) <= 8:
            field = raw.ljust(8, b'\0')
        else:
            field = struct.pack('<II', 0, 4 + len(strings))
            strings += raw + b'\0'
        table += struct.pack('<8sIhHBB', field, value, section, typ, 2, aux) + bytes(18 * aux)
    return table + struct.pack('<I', 4 + len(strings)) + strings, len(table) // 18


def separate(debug_type, raw, lay=STD):
    secs = sections(lay)
    first = 48 + 40 * len(secs) + 0 + 28
    entry = struct.pack('<IIHHIIII', 0, 0, 0, 0, debug_type, len(raw), 0, first)
    head = struct.pack('<HHHHIIIIIIII8s', 0x4944, 0, 0x14c, 0x230e, 0, 0, lay['base'], lay['size'],
                       len(secs), 0, 28, 0x1000, bytes(8))
    sec_table = header_table(secs, 0)
    return head + sec_table + entry + raw


def dbg(lay=STD, va=False):
    table, count = coff_symbols(lay, va)
    coff_header = struct.pack('<8I', count, 32, 0, 0, lay['text'], lay['text'] + 0x100, lay['data'],
                              lay['data'] + 0x200)
    return separate(1, coff_header + table, lay)


def publics():
    """An sstGlobalPub subsection: its 16-byte header, then S_PUB32 records (4-byte offset, segment,
    2-byte type index, length-prefixed name) and one record of another kind that must be skipped."""
    records = b''
    for name, off, seg, _ in PUBLICS:
        body = struct.pack('<HIHH', 0x203, off, seg, 0) + bytes([len(name)]) + name.encode()
        records += struct.pack('<H', len(body)) + body
    records += struct.pack('<HHII', 10, 0x402, 1, 2)
    return struct.pack('<HHIII', 0, 0, len(records), 0, 0) + records


def dbg_nb09():
    """NB09: the signature and the offset of a directory of three subsections, one of them sstGlobalPub."""
    pub = publics()
    dir_at = 8
    entries = [(0x120, 1, 0, 0), (0x12a, 0xffff, 0, len(pub)), (0x12d, 0xffff, 0, 4)]
    body_at = dir_at + 16 + 12 * len(entries)
    out, at = b'', body_at
    for sst, mod, _, size in entries:
        out += struct.pack('<HHII', sst, mod, at, size)
        at += size
    header = struct.pack('<HHIII', 16, 12, len(entries), 0, 0)
    return separate(2, b'NB09' + struct.pack('<I', dir_at) + header + out + pub + bytes(4))


def reference():
    """The counting rule read again from the bytes, without Ghidra: (COFF, NB09) counts."""
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


def reference_nb09():
    d = dbg_nb09()
    nsec, = struct.unpack_from('<I', d, 24)
    raw, = struct.unpack_from('<I', d, 48 + 40 * nsec + 24)
    assert d[raw:raw + 4] == b'NB09'
    seen = dict(records=0, functions=set(), ignored=0, sections=0)
    for name, off, seg, function in PUBLICS:
        seen['records'] += 1
        if seg == 0:
            seen['ignored'] += 1
        elif name.startswith('.'):
            seen['sections'] += 1
        elif function and TEXT + off < SIZE_OF_IMAGE:
            seen['functions'].add(TEXT + off)
    seen['functions'] = len(seen['functions'])
    return seen


def check(case, syms, log):
    kind, counts, expect, override = KINDS[case]
    lay = dict(STD, **override)
    expect = [(k, lay['text' if r == 'T' else 'data'] + off, n) for k, r, off, n in expect]
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
    want = ('ReDbgImport: %s: %d symbol records, %d auxiliary skipped, %d functions, '
            '%d other labels, %d section names skipped, %d without a section, %d outside the image, '
            '%d names Ghidra rejects, %d functions not created'
            % ((kind,) + tuple(counts[k] for k in ('records', 'auxiliary', 'functions', 'labels', 'sections',
                                                   'ignored', 'outside', 'rejected', 'uncreated'))))
    if want not in open(log).read():
        bad.append('summary line is not: ' + want)
    for b in bad:
        print('FAIL dbg %s: %s' % (case, b))
    print('%s: %s symbols applied (%s), %d functions at distinct addresses' %
          ('ok' if not bad else 'FAIL', case, kind, len(functions)))
    return 1 if bad else 0


def check_returning(before, after, log):
    """Each caller is cut at its call before ReReturning and whole after it."""
    def bodies(path):
        out = {}
        for line in open(path):
            f = line.rstrip('\n').split('\t')
            out[int(f[1], 16) - TEXT] = (int(f[2], 16) - TEXT, int(f[3]), f[4] == 'true')
        return out
    was, now = bodies(before), bodies(after)
    bad = []
    if not was.get(0, (0, 0, False))[2]:
        bad.append('the callee is not marked no-return before the repair: the test models nothing')
    if now.get(0, (0, 0, True))[2]:
        bad.append('the callee is still marked no-return')
    for at, (end, count, cut_end, cut_count) in sorted(CALLERS.items()):
        if was.get(at, (0, 0))[:2] != (cut_end, cut_count):
            bad.append('caller %#x before: %s, want it cut at %#x with %d instructions' %
                       (at, was.get(at), cut_end, cut_count))
        if now.get(at, (0, 0))[:2] != (end, count):
            bad.append('caller %#x after: %s, want %#x with %d instructions' % (at, now.get(at), end, count))
    # The second call of the middle caller is found only once the first is repaired: 3 sites, not 4.
    want = ('ReReturning: @0x%x at %x was no-return, 3 call sites, 3 callers rebuilt, '
            '0 sites with no code after the call' % (BASE + TEXT, BASE + TEXT))
    if want not in open(log).read():
        bad.append('summary line is not: ' + want)
    for b in bad:
        print('FAIL returning: ' + b)
    print('%s: returning, %d callers whole after the repair' % ('ok' if not bad else 'FAIL', len(CALLERS)))
    return 1 if bad else 0


TYPE_RULES = ['callconv\tfastcall\talpha*', 'param\talpha_one\t0\tCtx *', 'param\talpha_one\t3\tint',
              'param\tnosuch\t0\tint', 'callconv\tnosuchconv\talpha*', 'param\talpha_one\t0\tNoSuchType *']


def check_types(out, log):
    """ReFunctionTypes.java applies what it can and reports each rule it cannot."""
    bad = []
    if open(out).read().rstrip('\n') != 'alpha_one\t__fastcall\tCtx *':
        bad.append('alpha_one has %r, want __fastcall and a Ctx * parameter' % open(out).read())
    text = open(log).read()
    for want in ('FAILED no function matches param nosuch 0 int', 'FAILED no calling convention nosuchconv',
                 'FAILED alpha_one has no parameter 3', 'FAILED type NoSuchType *',
                 'ReFunctionTypes: 6 rules, 1 calling conventions changed, 1 parameters typed, 4 failed'):
        if want not in text:
            bad.append('no line with: ' + want)
    for b in bad:
        print('FAIL types: ' + b)
    print('%s: types, a calling convention and a parameter type applied, 4 bad rules reported' %
          ('ok' if not bad else 'FAIL'))
    return 1 if bad else 0


def main():
    if len(sys.argv) == 1:
        ref = reference()
        for key in ('records', 'auxiliary', 'functions', 'ignored', 'sections'):
            assert ref[key] == COUNTS[key], (key, ref[key], COUNTS[key])
        pub = reference_nb09()
        for key in ('records', 'functions', 'ignored', 'sections'):
            assert pub[key] == NB09_COUNTS[key], (key, pub[key], NB09_COUNTS[key])
        assert image()[:2] == b'MZ'
        print('ok: dbg and pe build, %d COFF records, %d auxiliary, %d functions by the counting rule; '
              '%d NB09 publics, %d functions' % (ref['records'], ref['auxiliary'], ref['functions'],
                                                 pub['records'], pub['functions']))
        return 0
    if sys.argv[1] == 'write':
        os.makedirs(sys.argv[2], exist_ok=True)
        for name, data in (('synthetic.dll', image()), ('synthetic.dbg', dbg()),
                           ('synthetic-va.dbg', dbg(va=True)), ('synthetic-nb09.dbg', dbg_nb09()),
                           ('synthetic-low.dll', image(LOW)), ('synthetic-low.dbg', dbg(LOW)),
                           ('synthetic-returning.dll', image(text=returning_text()))):
            with open(os.path.join(sys.argv[2], name), 'wb') as f:
                f.write(data)
        with open(os.path.join(sys.argv[2], 'types.tsv'), 'w') as f:
            f.write('\n'.join(TYPE_RULES) + '\n')
        return 0
    if sys.argv[1] == 'check-types':
        return check_types(*sys.argv[2:4])
    if sys.argv[1] == 'check-returning':
        return check_returning(*sys.argv[2:5])
    if sys.argv[1] == 'check':
        return check(sys.argv[2], sys.argv[3], sys.argv[4])
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main())
