#!/usr/bin/env python3
"""Extract the system call dispatch table from an IRIX kernel image.

    python3 scripts/syscall_table.py KERNEL [KERNEL...] [--out FILE.tsv]
            [--cross-check DIR] [--report FILE.tsv]

KERNEL is a linked kernel (unix.IPnn), a 64-bit big-endian ELF file. Every output row comes from
the image. Three steps:

1. Find the tables. A system call table is a run of 24-byte entries whose second doubleword is a
   code address inside the text section and whose third is zero or a data address. Maximal runs
   of at least 64 such entries are taken; a table found by shape is then tied to the dispatcher
   by a pointer-and-count pair somewhere in data (the per-ABI switch), whose count must equal the
   run length.
2. Confirm the entry layout in the dispatcher. The routine that loads the entry computes
   `index * 24`, then loads one byte at +0 (the argument count), one byte at +1 (flags), a
   doubleword at +8 (the handler) and calls through it. The script looks for that sequence on a
   single base register in the function that contains the most such loads, and for the
   subtraction of the call-number base (`addiu r, r, -N` ahead of the bound compare). If it
   cannot find them, the layout column says so and the rows are kept as shape-only.
3. Emit one row per entry. Names come from the image's own symbol table; nothing is taken from
   outside the file.

Columns: binary, table (symbol of the table or its address), number (index plus the number
base the dispatcher subtracts), index, handler_address, handler (symbol or empty), nargs (high
byte of the first doubleword), flags (the remaining seven bytes, hex), arg_table (third
doubleword), layout (how the layout was confirmed).

--cross-check DIR compares the numbering with public lists, if DIR holds copies of them:
  linux-irix5sys.S   the old Linux IRIX emulation table (number, handler name, argument count)
  netbsd-irix-syscalls.master
                     NetBSD's IRIX compatibility list (index from 0)
  qi-linux-user_irix_syscall_nr.h
                     qemu-irix's TARGET_NR_ list (1000-based)
Those are used only to check numbering; they never contribute a row. --report writes every
disagreement to a TSV. Needs pyelftools and capstone (the toolchain image has both).
"""
import argparse
import collections
import os
import re
import struct
import sys

ENTRY = 24
MIN_RUN = 64


def load(path):
    from elftools.elf.elffile import ELFFile
    data = open(path, 'rb').read()
    elf = ELFFile(open(path, 'rb'))
    if elf.elfclass != 64 or elf.little_endian:
        sys.exit('syscall_table: %s is not a 64-bit big-endian ELF kernel' % path)
    secs = []
    for s in elf.iter_sections():
        if s['sh_addr'] and s['sh_type'] in ('SHT_PROGBITS',):
            secs.append((s['sh_addr'], s['sh_size'], s['sh_offset'], s.name, s['sh_flags']))
    syms = {}
    funcs = {}
    st = elf.get_section_by_name('.symtab')
    if st is not None:
        for s in st.iter_symbols():
            if not s.name:
                continue
            syms.setdefault(s.name, s)
            if s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(s['st_value'], s.name)
    return data, elf, secs, syms, funcs


def read(data, secs, addr, n):
    for sa, sz, so, _nm, _fl in secs:
        if sa <= addr and addr + n <= sa + sz:
            return data[so + addr - sa:so + addr - sa + n]
    return None


def find_tables(data, secs):
    text = [(sa, sa + sz) for sa, sz, _so, nm, fl in secs if fl & 4]
    def in_text(a):
        return a & 3 == 0 and any(lo <= a < hi for lo, hi in text)
    def in_data(a):
        return any(sa <= a < sa + sz for sa, sz, _so, _nm, fl in secs if not fl & 4)
    out = []
    seen = set()
    for sa, sz, so, nm, fl in secs:
        if fl & 4 or nm.startswith('.debug'):
            continue
        off = 0
        while off + ENTRY <= sz:
            n = 0
            while off + (n + 1) * ENTRY <= sz:
                w0, w1, w2 = struct.unpack('>3Q', data[so + off + n * ENTRY:so + off + (n + 1) * ENTRY])
                if not (in_text(w1) and (w2 == 0 or in_data(w2)) and (w0 >> 56) <= 15):
                    break
                n += 1
            if n >= MIN_RUN and (sa + off) not in seen:
                seen.add(sa + off)
                out.append((sa + off, n))
                off += n * ENTRY
            else:
                off += 8
    return out


def abi_switches(data, secs, tables):
    """(address of the pair, table address, count) for each pointer-and-count pair naming a table."""
    by = {a + i * ENTRY: n for a, n in tables for i in range(n)}
    found = []
    for sa, sz, so, nm, fl in secs:
        if fl & 4 or nm.startswith('.debug'):
            continue
        for off in range(0, sz - 15, 8):
            ptr, nxt = struct.unpack('>QQ', data[so + off:so + off + 16])
            if ptr in by and nxt & 0xffffffff == 0 and 0 < nxt >> 32 <= 4096:
                found.append((sa + off, ptr, nxt >> 32, nxt & 0xffffffff))
    return found


def number_base(order):
    """The call-number base: `addiu r, r, -N` shortly before an unsigned compare against a count."""
    for k, ins in enumerate(order):
        m = re.match(r'(\$\w+), (\$\w+), -(0x[0-9a-f]+|\d+)$', ins.op_str)
        if ins.mnemonic in ('addiu', 'daddiu') and m and m.group(1) == m.group(2):
            n = int(m.group(3), 0)
            if 100 <= n <= 4000 and any(x.mnemonic in ('sltu', 'sltiu') for x in order[k + 1:k + 5]):
                return n
    return None


def confirm_layout(data, elf, secs, funcs):
    """Look for the dispatcher's entry loads. Returns (description, function name, number base)."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = True
    text = [s for s in secs if s[4] & 4]
    starts = sorted(funcs)
    best = None
    import bisect
    for sa, sz, so, nm, fl in text:
        # Walk functions; score each by the entry-load pattern.
        for i, f in enumerate(starts):
            if not sa <= f < sa + sz:
                continue
            end = starts[i + 1] if i + 1 < len(starts) else sa + sz
            end = min(end, f + 0x1000)   # a dispatcher is short; bound the work
            code = data[so + f - sa:so + end - sa]
            loads = collections.defaultdict(dict)
            jalr = set()
            order = []
            for ins in md.disasm(code, f):
                m, ops = ins.mnemonic, ins.op_str
                mm = re.match(r'(\$\w+), (-?(?:0x)?[0-9a-f]*)\((\$\w+)\)$', ops)
                if m in ('lbu', 'ld', 'lw') and mm:
                    off = int(mm.group(2) or '0', 0) if mm.group(2) not in ('', '-') else 0
                    loads[mm.group(3)].setdefault((m, off), (mm.group(1), ins.address))
                elif m == 'jalr':
                    jalr.add(ops.split(',')[-1].strip())
                order.append(ins)
            nb = number_base(order)
            for base, d in loads.items():
                need = [('lbu', 0), ('lbu', 1), ('ld', 8)]
                if all(k in d for k in need) and d[('ld', 8)][0] in jalr:
                    score = 3 + (('ld', 16) in d) + (10 if nb else 0)
                    if best is None or score > best[0]:
                        best = (score, f, base, d, order)
    if best is None:
        return None
    score, f, base, d, order = best
    nbase = number_base(order)
    score &= 7
    desc = ('dispatcher %s: byte +0, byte +1 and doubleword +8 of the entry loaded through %s, '
            'call through the doubleword%s' % (funcs.get(f, '0x%x' % f), base,
                                               ', doubleword +16 also loaded' if score == 4 else ''))
    return desc, funcs.get(f, '0x%x' % f), nbase


def extract(path):
    data, elf, secs, syms, funcs = load(path)
    tables = find_tables(data, secs)
    switches = abi_switches(data, secs, tables)
    layout = confirm_layout(data, elf, secs, funcs)
    rows = []
    notes = []
    sw = {ptr: (at, cnt) for at, ptr, cnt, _ in switches}
    names = {}
    for n, s in syms.items():
        if s['st_info']['type'] == 'STT_OBJECT':
            names.setdefault(s['st_value'], n)
    nbase = layout[2] if layout and layout[2] is not None else None
    starts = []
    for addr, n in tables:
        tied = [a for a in sw if addr <= a < addr + n * ENTRY]
        if not tied:
            notes.append('%s: run at %#x (%d entries) has no pointer-and-count pair; shape only' % (path, addr, n))
            starts.append((addr, n))
        for a in sorted(tied):
            starts.append((a, sw[a][1]))
    for addr, count in starts:
        label = names.get(addr, '0x%x' % addr)
        use = count
        if addr in sw and sw[addr][1] != count:
            use = sw[addr][1]
        for i in range(use):
            w0, w1, w2 = struct.unpack('>3Q', read(data, secs, addr + i * ENTRY, ENTRY))
            rows.append((label, i, (i + nbase) if nbase is not None else '', w1, funcs.get(w1, ''),
                         w0 >> 56, '%014x' % (w0 & ((1 << 56) - 1)), '0x%x' % w2))
    how = layout[0] if layout else 'not confirmed: no dispatcher with the entry loads was found'
    return rows, how, notes, nbase


def linux_table(path):
    out = {}
    for ln in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'\s*sys\s+(\S+)\s+(\d+)\s*/\*\s*(\d+)\s+(\S*?)\(', ln)
        if m:
            out[int(m.group(3))] = (m.group(4), int(m.group(2)))
    return out


def netbsd_table(path):
    out = {}
    text = open(path, encoding='utf-8', errors='replace').read().replace('\\\n', ' ')
    for ln in text.splitlines():
        m = re.match(r'(\d+)\s+(?:STD|NOARGS|OBSOL|UNIMPL|NODEF)\s+(.*)$', ln)
        if not m:
            continue
        body = m.group(2)
        pm = re.search(r'\{\s*[^()]*?\b(\w+)\s*\((.*?)\)\s*;?\s*\}(?:\s*(\w+))?', body)
        if pm:
            name = pm.group(3) or pm.group(1)
            args = pm.group(2).strip()
            n = 0 if args in ('', 'void') else args.count(',') + 1
            out[int(m.group(1))] = (name, n)
        else:
            out[int(m.group(1))] = (body.split()[0] if body.split() else '', None)
    return out


def qirix_table(path):
    out = {}
    for ln in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'#define\s+TARGET_NR_(\w+)\s+\((\d+)\+TARGET_NR_Linux\)', ln)
        if m:
            out.setdefault(int(m.group(2)), m.group(1))
    return out


def norm(name):
    name = name.lower()
    for pre in ('sys_', 'irix_sys_', 'irix_', 'svr4_sys_', 'sgi_'):
        if name.startswith(pre):
            name = name[len(pre):]
    return {'rexit': 'exit', 'exec': 'execv', 'syscall': 'sysindir'}.get(name, name)


def cross_check(rows_by_kernel, directory, report):
    lin = os.path.join(directory, 'linux-irix5sys.S')
    nb = os.path.join(directory, 'netbsd-irix-syscalls.master')
    qi = os.path.join(directory, 'qi-linux-user_irix_syscall_nr.h')
    pubs = {}
    if os.path.exists(lin):
        pubs['linux'] = linux_table(lin)
    if os.path.exists(nb):
        pubs['netbsd'] = netbsd_table(nb)
    if os.path.exists(qi):
        pubs['qemu-irix'] = qirix_table(qi)
    lines = []
    summary = []
    for kern, rows in rows_by_kernel.items():
        first = {}
        for r in rows:
            first.setdefault(r[1], r)           # the first table (native ABI) per index
        for src, tbl in pubs.items():
            same_name = diff_name = same_n = diff_n = nosys = missing = 0
            for idx, r in sorted(first.items()):
                number = r[2] if r[2] != '' else idx
                # qemu-irix and Linux number from 1000; NetBSD from 0
                key = number if src == 'linux' else idx
                pub = tbl.get(key)
                ours = r[4]
                if ours == 'nosys' or ours == '':
                    nosys += 1
                    continue
                if pub is None:
                    missing += 1
                    continue
                pname = pub[0] if isinstance(pub, tuple) else pub
                if norm(ours) == norm(pname) or norm(pname) in norm(ours) or norm(ours) in norm(pname) and len(norm(pname)) > 3:
                    same_name += 1
                else:
                    diff_name += 1
                    lines.append((kern, src, key, 'name', ours, pname))
                if isinstance(pub, tuple) and pub[1] is not None:
                    if pub[1] == r[5]:
                        same_n += 1
                    else:
                        diff_n += 1
                        lines.append((kern, src, key, 'nargs', r[5], pub[1]))
            summary.append((kern, src, same_name, diff_name, same_n, diff_n, nosys, missing))
    if report:
        with open(report, 'w', encoding='utf-8') as f:
            f.write('binary\tsource\tnumber\tfield\tkernel\tpublic\n')
            for l in lines:
                f.write('\t'.join(str(x) for x in l) + '\n')
    return summary


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('kernels', nargs='+')
    ap.add_argument('--out')
    ap.add_argument('--cross-check', metavar='DIR')
    ap.add_argument('--report')
    a = ap.parse_args(argv)
    out = open(a.out, 'w', encoding='utf-8') if a.out else sys.stdout
    out.write('binary\ttable\tnumber\tindex\thandler_address\thandler\tnargs\tflags\targ_table\tlayout\n')
    per = {}
    for k in a.kernels:
        rows, how, notes, nbase = extract(k)
        label = os.path.relpath(k) if not os.path.isabs(k) else k
        for n in notes:
            print('syscall_table: ' + n, file=sys.stderr)
        counts = collections.Counter(r[0] for r in rows)
        print('syscall_table: %s: %s; number base %s; layout: %s' % (
            label, ', '.join('%s %d entries' % kv for kv in counts.items()), nbase, how), file=sys.stderr)
        for r in rows:
            out.write('\t'.join([label, str(r[0]), str(r[2]), str(r[1]), '0x%x' % r[3], r[4], str(r[5]), r[6],
                                 r[7], how]) + '\n')
        per[label] = rows
    if a.cross_check:
        for s in cross_check(per, a.cross_check, a.report):
            print('syscall_table: cross-check %s vs %s: names agree %d, differ %d; argument counts agree %d, '
                  'differ %d; skipped %d unimplemented in the kernel, %d absent from the public list' % s,
                  file=sys.stderr)


if __name__ == '__main__':
    main(sys.argv[1:])
