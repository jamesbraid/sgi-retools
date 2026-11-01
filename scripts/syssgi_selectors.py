#!/usr/bin/env python3
"""Extract the syssgi() selector dispatch from an IRIX kernel image.

    python3 scripts/syssgi_selectors.py KERNEL [KERNEL...] [--out FILE.tsv]
            [--cross-check DIR] [--report FILE.tsv] [--function NAME]

KERNEL is a linked kernel (unix.IPnn), a 64-bit big-endian ELF file. The script finds the `syssgi`
function in the image's symbol table, disassembles it and explores its control flow with the
selector (the first word of the argument block, loaded through the first argument) as the one
symbolic value. Every conditional branch that tests the selector, directly or through a set-on-less-than
flag, narrows the set of selector values the path can carry, and every indirect jump through a
table indexed by the selector is read from the image. Whenever the set narrows to one value the
address control reaches is that selector's handler code. Two shapes are handled, and a kernel
can have both in one function:

  jumptable  `base + selector*8` loaded and jumped through; the base comes from a global-pointer
             relative load, which is read out of the image. The entries are code addresses.
  compare    a tree of `slti`/`sltiu`/`beq`/`bne` tests on the selector.

Output columns: binary, group (the jump table address with its entry count, or `compare`), selector
(decimal), selector_hex, target (code address control reaches for that selector), first_call (the
first routine called by the target block before it branches, by the image's symbol table, as a name for the handler
when the case calls one), default_shared (yes when more than one selector reaches that target:
the fill of a table for unused numbers, or the shared error path of a compare tree).

Selectors that never narrow to a single value, such as ranges that share one error path, are not
listed; the count of selector values left unresolved is printed. Selectors are taken from 0 to
2^32-1.

--cross-check DIR compares with public lists, if DIR holds copies of them:
  netbsd-irix_syssgi.h  the `IRIX_SGI_*` constants NetBSD's IRIX compatibility layer defines
  linux-sysirix.c       the old Linux IRIX emulation; its `case SGI_*:` names are looked up in the list above
Public lists are used only to check numbering; they never contribute a row. --report writes the
disagreements as a TSV. Needs pyelftools and capstone (the toolchain image has both).
"""
import argparse
import collections
import os
import re
import struct
import sys

DOMAIN = (0, 0xffffffff)
CALLER_SAVED = {'$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3', '$t0', '$t1', '$t2', '$t3', '$t4', '$t5',
                '$t6', '$t7', '$t8', '$t9'}
LIKELY = {'beql', 'bnel', 'beqzl', 'bnezl', 'blezl', 'bgtzl', 'bltzl', 'bgezl'}
COND = {'beq', 'bne', 'beqz', 'bnez', 'blez', 'bgtz', 'bltz', 'bgez'} | LIKELY


def u64(v):
    return v & 0xffffffffffffffff


def num(s):
    return int(s, 0)


# -- sets of selector values: sorted tuples of inclusive (lo, hi) pairs --------------------------
def meet(iv, lo, hi):
    out = []
    for a, b in iv:
        a2, b2 = max(a, lo), min(b, hi)
        if a2 <= b2:
            out.append((a2, b2))
    return tuple(out)


def minus(iv, lo, hi):
    out = []
    for a, b in iv:
        if b < lo or a > hi:
            out.append((a, b))
            continue
        if a < lo:
            out.append((a, lo - 1))
        if b > hi:
            out.append((hi + 1, b))
    return tuple(out)


def size(iv):
    return sum(b - a + 1 for a, b in iv)


class Image:
    def __init__(self, path):
        from elftools.elf.elffile import ELFFile
        self.path = path
        self.data = open(path, 'rb').read()
        self.elf = ELFFile(open(path, 'rb'))
        if self.elf.elfclass != 64 or self.elf.little_endian:
            sys.exit('syssgi_selectors: %s is not a 64-bit big-endian ELF kernel' % path)
        self.secs = [(s['sh_addr'], s['sh_size'], s['sh_offset'], s.name, s['sh_flags'])
                     for s in self.elf.iter_sections()
                     if s['sh_addr'] and s['sh_type'] == 'SHT_PROGBITS']
        self.syms = {}
        self.funcs = {}
        st = self.elf.get_section_by_name('.symtab')
        if st is None:
            sys.exit('syssgi_selectors: %s has no symbol table' % path)
        for s in st.iter_symbols():
            if s.name:
                self.syms.setdefault(s.name, s)
                if s['st_info']['type'] == 'STT_FUNC':
                    self.funcs.setdefault(s['st_value'], s.name)
        opt = self.elf.get_section_by_name('.MIPS.options')
        self.gp = None
        if opt is not None:
            d, o = opt.data(), 0
            while o + 8 <= len(d):
                kind, sz = d[o], d[o + 1]
                if kind == 1 and sz >= 40:      # ODK_REGINFO: gp value is the last doubleword
                    self.gp = struct.unpack('>Q', d[o + 32:o + 40])[0]
                if sz == 0:
                    break
                o += sz
        if self.gp is None and '_gp' in self.syms:
            self.gp = self.syms['_gp']['st_value']

    def read(self, addr, n):
        for sa, sz, so, _nm, _fl in self.secs:
            if sa <= addr and addr + n <= sa + sz:
                return self.data[so + addr - sa:so + addr - sa + n]
        return None

    def code(self, name):
        s = self.syms.get(name)
        if s is None or s['st_info']['type'] != 'STT_FUNC':
            return None
        a, n = s['st_value'], s['st_size']
        return a, self.read(a, n)


def disassemble(addr, code):
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN)
    out = {}
    for ins in md.disasm(code, addr):
        ops = [x.strip() for x in ins.op_str.split(',')] if ins.op_str else []
        out[ins.address] = (ins.mnemonic, ops)
    return out


def mem_operand(op):
    m = re.match(r'^(-?(?:0x[0-9a-f]+|\d+))?\((\$\w+)\)$', op)
    if not m:
        return None
    return (num(m.group(1)) if m.group(1) else 0), m.group(2)


class Walker:
    def __init__(self, img, name):
        found = img.code(name)
        if found is None:
            raise SystemExit('syssgi_selectors: %s has no function %s' % (img.path, name))
        self.img = img
        self.base, blob = found
        self.end = self.base + len(blob)
        self.ins = disassemble(self.base, blob)
        self.hits = collections.defaultdict(set)    # selector -> {(target, group)}
        self.tables = {}
        self.sel_reg = None
        self.visited = set()
        self.unresolved = 0

    # the selector: the first doubleword or word loaded through a register that copied $a0
    def find_selector(self):
        copies = set()
        for a in sorted(self.ins):
            m, ops = self.ins[a]
            if m == 'move' and ops[1] == '$a0':
                copies.add(ops[0])
            if m in ('ld', 'lw', 'lwu') and len(ops) == 2:
                mo = mem_operand(ops[1])
                if mo and mo[0] == 0 and mo[1] in copies:
                    return a, ops[0]
        return None

    def run(self):
        sel = self.find_selector()
        if sel is None:
            raise SystemExit('syssgi_selectors: no load of the selector found in the function')
        sel_at, reg = sel
        self.sel_at = sel_at
        # Start at the function entry; registers learn the selector when its load executes.
        self.walk(self.base, {}, (DOMAIN,), sel_at, reg)
        return self

    # value domain: ('c', n) | ('s', mul, add) | ('f', lo, hi) flag true iff selector in [lo, hi] | ('e', base)
    def val(self, regs, r):
        if r == '$zero':
            return ('c', 0)
        return regs.get(r)

    def exec(self, regs, a, sel_at, sel_reg):
        m, ops = self.ins[a]
        if a == sel_at:
            regs[ops[0]] = ('s', 1, 0)
            return
        if m == 'nop' or not ops:
            return
        d = ops[0]
        if m in ('move', 'or') and (m == 'move' or ops[2] == '$zero'):
            v = self.val(regs, ops[1])
            self.setr(regs, d, v)
        elif m in ('addiu', 'daddiu', 'addi', 'daddi') and len(ops) == 3:
            v = self.val(regs, ops[1])
            k = num(ops[2])
            if v and v[0] == 'c':
                self.setr(regs, d, ('c', v[1] + k))
            elif v and v[0] == 's':
                self.setr(regs, d, ('s', v[1], v[2] + k))
            else:
                self.setr(regs, d, None)
        elif m == 'lui':
            self.setr(regs, d, ('c', num(ops[1]) << 16))
        elif m in ('ori', 'xori') and len(ops) == 3:
            v = self.val(regs, ops[1])
            if v and v[0] == 'c':
                k = num(ops[2])
                self.setr(regs, d, ('c', v[1] | k if m == 'ori' else v[1] ^ k))
            else:
                self.setr(regs, d, None)
        elif m in ('addu', 'daddu') and len(ops) == 3:
            x, y = self.val(regs, ops[1]), self.val(regs, ops[2])
            if x and y and x[0] == 'c' and y[0] == 'c':
                self.setr(regs, d, ('c', x[1] + y[1]))
            elif x and y and {x[0], y[0]} == {'c', 's'}:
                c, s = (x, y) if x[0] == 'c' else (y, x)
                self.setr(regs, d, ('s', s[1], s[2] + c[1]))
            else:
                self.setr(regs, d, None)
        elif m in ('sll', 'dsll') and len(ops) == 3:
            v = self.val(regs, ops[1])
            k = num(ops[2])
            if v and v[0] == 's':
                self.setr(regs, d, ('s', v[1] << k, v[2] << k))
            elif v and v[0] == 'c':
                self.setr(regs, d, ('c', v[1] << k))
            else:
                self.setr(regs, d, None)
        elif m in ('slti', 'sltiu') and len(ops) == 3:
            v = self.val(regs, ops[1])
            k = num(ops[2])
            if v and v[0] == 's' and v[1] == 1:
                if m == 'sltiu':
                    k = k & 0xffffffffffffffff if k < 0 else k
                    lo, hi = -v[2], k - 1 - v[2]
                else:
                    lo, hi = DOMAIN[0] - v[2] if False else -(1 << 62), k - 1 - v[2]
                self.setr(regs, d, ('f', lo, hi))
            else:
                self.setr(regs, d, None)
        elif m in ('slt', 'sltu') and len(ops) == 3:
            x, y = self.val(regs, ops[1]), self.val(regs, ops[2])
            if x and y and x[0] == 's' and x[1] == 1 and y[0] == 'c':
                self.setr(regs, d, ('f', -(1 << 62), y[1] - 1 - x[2]))
            elif x and y and x[0] == 'c' and y[0] == 's' and y[1] == 1:
                self.setr(regs, d, ('f', x[1] + 1 - y[2], 1 << 62))
            else:
                self.setr(regs, d, None)
        elif m in ('ld', 'lw', 'lwu', 'lb', 'lbu', 'lh', 'lhu') and len(ops) == 2:
            mo = mem_operand(ops[1])
            v = None
            if mo:
                base = self.val(regs, mo[1]) if mo[1] != '$gp' else ('c', self.img.gp) if self.img.gp else None
                if base and base[0] == 'c' and m == 'ld':
                    raw = self.img.read(u64(base[1] + mo[0]), 8)
                    if raw:
                        v = ('c', struct.unpack('>Q', raw)[0])
                elif base and base[0] == 's' and m == 'ld' and mo[0] == 0 and base[1] == 8:
                    v = ('e', base[2])
            self.setr(regs, d, v)
        elif m in ('jal', 'jalr', 'bal'):
            for r in CALLER_SAVED:
                regs.pop(r, None)
        elif m in ('sd', 'sw', 'sb', 'sh', 'sync') or m.startswith(('b', 'j')):
            pass
        else:
            self.setr(regs, d, None)

    @staticmethod
    def setr(regs, d, v):
        if d == '$zero':
            return
        if v is None:
            regs.pop(d, None)
        else:
            regs[d] = v

    def target(self, ops):
        return u64(num(ops[-1]))

    def walk(self, pc, regs, iv, sel_at, sel_reg):
        stack = [(pc, dict(regs), iv)]
        while stack:
            pc, regs, iv = stack.pop()
            steps = 0
            while True:
                if not iv or not (self.base <= pc < self.end) or pc not in self.ins:
                    break
                key = (pc, iv)
                if key in self.visited:
                    break
                self.visited.add(key)
                steps += 1
                m, ops = self.ins[pc]
                if m in COND:
                    delay = pc + 4
                    taken_regs, fall_regs = dict(regs), dict(regs)
                    if delay in self.ins:
                        self.exec(taken_regs, delay, sel_at, sel_reg)
                        if m not in LIKELY:
                            self.exec(fall_regs, delay, sel_at, sel_reg)
                    tgt = self.target(ops)
                    t_iv, f_iv = self.split(m, ops, regs, iv)
                    for iv2, r2, to in ((t_iv, taken_regs, tgt), (f_iv, fall_regs, pc + 8)):
                        if not iv2:
                            continue
                        if size(iv2) == 1 and iv2 != iv:
                            self.hits[iv2[0][0]].add((to, 'compare'))
                        else:
                            stack.append((to, r2, iv2))
                    break
                if m in ('b', 'j'):
                    delay = pc + 4
                    if delay in self.ins:
                        self.exec(regs, delay, sel_at, sel_reg)
                    pc = self.target(ops)
                    continue
                if m == 'jr':
                    if ops[0] == '$ra':
                        break
                    v = regs.get(ops[0])
                    if v and v[0] == 'e':
                        self.table(v[1], iv)
                    break
                self.exec(regs, pc, sel_at, sel_reg)
                pc += 4

    def split(self, m, ops, regs, iv):
        base = m[:-1] if m in LIKELY else m
        if base in ('beq', 'bne'):
            x, y = self.val(regs, ops[0]), self.val(regs, ops[1])
            if base == 'beq' and ops[0] == ops[1]:
                return iv, ()
            flag = None
            if x and y:
                if x[0] == 's' and x[1] == 1 and y[0] == 'c':
                    flag = (y[1] - x[2], y[1] - x[2])
                elif y[0] == 's' and y[1] == 1 and x[0] == 'c':
                    flag = (x[1] - y[2], x[1] - y[2])
                elif x[0] == 'f' and y[0] == 'c' and y[1] == 0:
                    flag = (x[1], x[2])
                elif y[0] == 'f' and x[0] == 'c' and x[1] == 0:
                    flag = (y[1], y[2])
            elif x and x[0] == 'f' and ops[1] == '$zero':
                flag = (x[1], x[2])
            elif y and y[0] == 'f' and ops[0] == '$zero':
                flag = (y[1], y[2])
            elif x and x[0] == 's' and x[1] == 1 and ops[1] == '$zero':
                flag = (-x[2], -x[2])
            if flag is None:
                return iv, iv
            inside, outside = meet(iv, *flag), minus(iv, *flag)
            return (inside, outside) if base == 'beq' else (outside, inside)
        if base in ('beqz', 'bnez'):
            x = self.val(regs, ops[0])
            flag = None
            if x and x[0] == 'f':
                flag = (x[1], x[2])
            elif x and x[0] == 's' and x[1] == 1:
                flag = (-x[2], -x[2])
            if flag is None:
                return iv, iv
            inside, outside = meet(iv, *flag), minus(iv, *flag)
            # bnez flag: taken when the flag is set (selector inside); beqz: taken when it is clear
            if x[0] == 'f':
                return (inside, outside) if base == 'bnez' else (outside, inside)
            return (outside, inside) if base == 'bnez' else (inside, outside)
        x = self.val(regs, ops[0])
        if x and x[0] == 's' and x[1] == 1:
            k = -x[2]
            cut = {'blez': (-(1 << 62), k), 'bltz': (-(1 << 62), k - 1), 'bgtz': (k + 1, 1 << 62),
                   'bgez': (k, 1 << 62)}.get(base)
            if cut:
                return meet(iv, *cut), minus(iv, *cut)
        return iv, iv

    def table(self, base, iv):
        sels = [v for a, b in iv for v in range(a, b + 1)]
        if len(sels) > 1 << 16:
            return
        group = 'jumptable 0x%x' % base
        entries = {}
        for v in sels:
            raw = self.img.read(base + 8 * v, 8)
            if raw is None:
                continue
            t = struct.unpack('>Q', raw)[0]
            entries[v] = t
        self.tables[base] = entries
        for v, t in entries.items():
            self.hits[v].add((t, group))


def first_call(w, target):
    """Name of the first routine the block at `target` calls, within its straight-line start."""
    pc = target
    for _ in range(40):
        if pc not in w.ins:
            return ''
        m, ops = w.ins[pc]
        if m in ('jal', 'bal'):
            t = u64(num(ops[-1]))
            return w.img.funcs.get(t, '0x%x' % t)
        if m in ('jalr', 'jr', 'j', 'b') or m in COND:
            return ''           # the block ends before it calls anything
        pc += 4
    return ''


def extract(path, fn):
    img = Image(path)
    w = Walker(img, fn).run()
    rows = []
    shared = collections.Counter()
    for sel, hits in w.hits.items():
        for t in {t for t, _g in hits}:
            shared[t] += 1
    for sel in sorted(w.hits):
        for t, g in sorted(w.hits[sel]):
            rows.append((g, sel, t, first_call(w, t), 'yes' if shared[t] > 1 else ''))
    resolved = {r[1] for r in rows}
    return rows, w, resolved


def parse_netbsd(path):
    out = {}
    for ln in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'#define\s+IRIX_SGI_(\w+)\s+(0x[0-9a-fA-F]+|\d+)\b', ln)
        if m:
            out.setdefault(m.group(1), int(m.group(2), 0))
    return out


def parse_linux_cases(path):
    names = []
    for ln in open(path, encoding='utf-8', errors='replace'):
        m = re.match(r'\s*case\s+SGI_(\w+)\s*:', ln)
        if m:
            names.append(m.group(1))
    return names


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('kernels', nargs='+')
    ap.add_argument('--out')
    ap.add_argument('--cross-check', metavar='DIR')
    ap.add_argument('--report')
    ap.add_argument('--function', default='syssgi')
    a = ap.parse_args(argv)
    out = open(a.out, 'w', encoding='utf-8') if a.out else sys.stdout
    out.write('binary\tgroup\tselector\tselector_hex\ttarget\tfirst_call\tdefault_shared\n')
    pubs = {}
    if a.cross_check:
        p = os.path.join(a.cross_check, 'netbsd-irix_syssgi.h')
        if os.path.exists(p):
            pubs['netbsd'] = parse_netbsd(p)
        p = os.path.join(a.cross_check, 'linux-sysirix.c')
        if os.path.exists(p):
            pubs['linux-cases'] = parse_linux_cases(p)
    lines = []
    for k in a.kernels:
        rows, w, resolved = extract(k, a.function)
        label = os.path.relpath(k) if not os.path.isabs(k) else k
        groups = collections.Counter(r[0] for r in rows)
        # rows in a jump table whose target many selectors share are that table's fill: keep them
        # in the output, but count the distinct, unshared ones as the real cases
        distinct = {r[1] for r in rows if not r[4]}
        for g, sel, t, call, sh in rows:
            out.write('\t'.join([label, g, str(sel), '0x%x' % sel, '0x%x' % t, call, sh]) + '\n')
        print('syssgi_selectors: %s: %d selector rows (%s); %d selectors have a target that is not shared fill; '
              'max selector %d' % (label, len(rows), ', '.join('%s %d' % kv for kv in groups.items()),
                                   len(distinct), max(resolved) if resolved else -1), file=sys.stderr)
        if 'netbsd' in pubs:
            names = pubs['netbsd']
            by_val = collections.defaultdict(list)
            for n, v in names.items():
                by_val[v].append(n)
            real = {r[1] for r in rows if not r[4]}
            have = [v for v in by_val if v in real]
            absent = [v for v in by_val if v not in real]
            extra = sorted(real - set(by_val))
            print('syssgi_selectors: cross-check %s vs netbsd constants: %d public selector values; %d have a '
                  'case in the kernel, %d have none (default or unresolved); %d kernel cases have no public '
                  'constant' % (label, len(by_val), len(have), len(absent), len(extra)), file=sys.stderr)
            for v in sorted(absent):
                lines.append((label, 'netbsd', v, 'public selector %s has no resolved case in the kernel' % ','.join(by_val[v])))
            for v in extra:
                lines.append((label, 'netbsd', v, 'kernel case with no public constant'))
            if 'linux-cases' in pubs:
                lin = [n for n in pubs['linux-cases'] if n in names]
                ok = [n for n in lin if names[n] in real]
                bad = [n for n in lin if names[n] not in real]
                print('syssgi_selectors: cross-check %s vs linux case names: %d named cases, %d known to the '
                      'netbsd list; %d of those have a case in the kernel, %d do not' % (
                          label, len(pubs['linux-cases']), len(lin), len(ok), len(bad)), file=sys.stderr)
                for n in bad:
                    lines.append((label, 'linux', names[n], 'Linux implements SGI_%s; the kernel has no resolved case' % n))
    if a.report:
        with open(a.report, 'w', encoding='utf-8') as f:
            f.write('binary\tsource\tselector\tfinding\n')
            for l in lines:
                f.write('\t'.join(str(x) for x in l) + '\n')


if __name__ == '__main__':
    main(sys.argv[1:])
