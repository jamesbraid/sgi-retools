#!/usr/bin/env python3
"""Mechanical fact sheet for one MIPS routine in one build.

Usage: scripts/facts.py BINARY[:MEMBER] ROUTINE [--size N] [--flat --load ADDR [--isa mips3|mips4]]
                        [--error-routine REGEX ...] [--no-insns] [--out FILE]

BINARY is a shared object, an executable (a linked kernel), a relocatable object or an archive
(name the member after a colon: kona.a:kona_fifo.o). ROUTINE is a symbol name or an address
(0x...). With --flat, BINARY is a raw big-endian image loaded at --load and ROUTINE must be an
address; give --size, or the routine is scanned up to the last reachable return.

Run it from the repository root inside the toolchain environment (MIPS objdump and pyelftools,
as for scripts/inventory.py). The output is JSON with sorted keys, so the same inputs give the
same bytes. It states what the instructions do, nothing about what they mean:

  routine      name, address, size, words, frame size, ABI, ISA, where the address came from
  calls        every call: jal/bal targets, GOT-slot loads (slot, dynsym index, name) and calls
               through a register whose value is known; tail jumps are marked
  got_loads    every load from the GOT: gp offset, slot, local or global, dynsym index, name
  accesses     loads and stores in address order: base register, its origin, offset, the
               offset from that origin, width, kind; an absolute address where it resolves
  addresses    addresses formed with addiu/daddiu/addu (an address is not "the word at")
  immediates   every immediate operand, and each constant a register holds after it is formed
  literals     constants loaded from read-only sections (.rodata, .lit4, .lit8)
  branches     every branch with its delay-slot instruction; branch-likely sites; branches that
               can never be taken; loops with bytes stored and pointer steps per pass
  exits        the value in v0 (and f0) on every path into each return
  jump_tables  tables read from a data section, with every target
  errors       the first argument at each call to an error routine (default: names ending
               in SetError)
  mmio         accesses whose address is a constant outside the file's sections, and
               accesses through a base whose origin is a loaded or computed pointer
  args         which argument registers the routine reads before writing, and how
  sections     the file's section headers

Values are symbolic: a0 is the first argument as it arrived, [X+16] the word loaded from X+16,
ret(f) what f returned, sp+N the stack at entry plus N, sym(S)+N the address of symbol S.
"""
import argparse
import bisect
import collections
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

os.environ['LC_ALL'] = os.environ['LANG'] = 'C'
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import inventory  # noqa: E402  the same file in every workspace

M64 = (1 << 64) - 1
NAMES_O32 = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
             's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']
NAMES_N = NAMES_O32[:8] + ['a4', 'a5', 'a6', 'a7', 't0', 't1', 't2', 't3'] + NAMES_O32[16:]
LOADS = inventory.LOADS
STORES = inventory.STORES
LIKELY = {'beql', 'bnel', 'blezl', 'bgtzl', 'bltzl', 'bgezl', 'bc1tl', 'bc1fl', 'bc0tl', 'bc0fl', 'bc2tl',
          'bc2fl', 'bgezall', 'bltzall'}
CALLS = {'jal', 'jalr', 'bal', 'bgezal', 'bltzal', 'bgezall', 'bltzall', 'jalx'}
UNSIGNED = {'lbu', 'lhu', 'lwu'}
RO_SECTIONS = {'.rodata', '.lit4', '.lit8', '.srdata', '.rdata', '.lita'}
PHI_MAX = 4
DEFAULT_ERRORS = [r'(.*_)?_?gl[A-Za-z]*SetError']


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


def sx32(v):
    v &= 0xffffffff
    return s64(v | (0xffffffff00000000 if v >> 31 else 0))


def num(s):
    s = s.strip()
    neg = s.startswith('-')
    s = s.lstrip('-')
    v = int(s, 16) if s.lower().startswith('0x') else int(s)
    return -v if neg else v


# ===================================================================== images

class Image:
    """One file: ELF (shared object, executable, relocatable, archive member) or a flat payload."""

    def __init__(self, path, member=None, flat=False, load=0, isa='mips4'):
        self.path, self.member, self.flat, self.load = path, member, flat, load
        data = open(path, 'rb').read()
        if member:
            mem = dict(inventory.unpack_ar(data))
            if member not in mem:
                raise SystemExit('facts: %s has no member %s' % (path, member))
            data = mem[member]
        self.data = data
        self.elf = None
        self.tmpdir = None
        self.isa = isa
        self.syms = []          # (address, size, name, section) sorted
        self.byname = collections.defaultdict(list)
        self.sections = []
        self.relmaps = None
        self.gp0 = 0
        self.gp = None
        self.got = None         # (address, size, local_gotno, gotsym, gsz, data)
        self.dynsym = []
        self.kind = 'flat'
        self.abi = 'o32' if isa == 'mips3_32' else 'n64'
        if flat:
            self.abi = 'flat'
            self.sections = [{'name': '(flat payload)', 'type': 'binary', 'address': '0x%x' % load,
                              'offset': '0x0', 'size': len(data), 'flags': 'AX'}]
            return
        self.elf = inventory.elf_of(data)
        self.abi = inventory.abi_of(self.elf)
        self.kind = inventory.kind_of(data, self.elf)
        flags = self.elf.header['e_flags']
        arch = (flags >> 28) & 0xf
        self.isa = {0: 'mips1', 1: 'mips2', 2: 'mips3', 3: 'mips4', 4: 'mips5', 5: 'mips32', 6: 'mips64'}.get(
            arch, 'arch%d' % arch)
        self.read_sections()
        self.read_symbols()
        self.read_dynamic()
        if self.kind == 'object':
            self.gp0 = inventory.ImageInfo(self.elf).gp0

    @property
    def regnames(self):
        return NAMES_O32 if self.abi in ('o32',) else NAMES_N

    @property
    def gsz(self):
        return 8 if (self.elf is not None and self.elf.elfclass == 64) else 4

    def read_sections(self):
        fl = {1: 'W', 2: 'A', 4: 'X', 0x10000000: 'G'}
        for s in self.elf.iter_sections():
            if not s.name:
                continue
            self.sections.append({
                'name': s.name, 'type': s['sh_type'].replace('SHT_', '') if isinstance(s['sh_type'], str)
                else '0x%x' % s['sh_type'], 'address': '0x%x' % s['sh_addr'], 'offset': '0x%x' % s['sh_offset'],
                'size': s['sh_size'], 'flags': ''.join(v for k, v in sorted(fl.items()) if s['sh_flags'] & k)})

    def read_symbols(self):
        e = self.elf
        execsec = {i for i, s in enumerate(e.iter_sections()) if s['sh_flags'] & 4}
        seen = set()
        for sn in ('.symtab', '.dynsym'):
            sec = e.get_section_by_name(sn)
            if sec is None or not hasattr(sec, 'iter_symbols'):
                continue
            for s in sec.iter_symbols():
                if not s.name or s['st_shndx'] in ('SHN_UNDEF', 'SHN_ABS', 'SHN_COMMON'):
                    continue
                t = s['st_info']['type']
                if t in ('STT_SECTION', 'STT_FILE'):
                    continue
                shn = s['st_shndx']
                secname = e.get_section(shn).name if isinstance(shn, int) and shn < e.num_sections() else ''
                key = (s['st_value'], s.name)
                if key in seen:
                    continue
                seen.add(key)
                func = t == 'STT_FUNC' or (shn in execsec and t == 'STT_NOTYPE')
                self.syms.append((s['st_value'], s['st_size'], s.name, secname, func, sn[1:]))
        for name, addr in inventory.mdebug_procs(e, self.data):
            if (addr, name) not in seen:
                seen.add((addr, name))
                self.syms.append((addr, 0, name, '.text', True, 'mdebug'))
        self.inventory_names(seen)
        self.syms.sort()
        for x in self.syms:
            self.byname[x[2]].append(x)
        self.addrs = [x[0] for x in self.syms]
        self.func_addrs = sorted({x[0] for x in self.syms if x[4]})

    def table_key(self):
        p = self.path.replace(os.sep, '/')
        i = p.rfind('/root/')
        rel = p[i + 6:] if i >= 0 else p[5:] if p.startswith('root/') else None
        if rel is None:
            return None
        return rel + ('(%s)' % self.member if self.member else '')

    def inventory_names(self, seen):
        """Names the workspace inventory gives this file (DWARF and .mdebug names of static routines
        the symbol tables lack), from docs/inventory/functions.tsv."""
        key = self.table_key()
        tsv = os.path.join(os.path.dirname(HERE), 'docs', 'inventory', 'functions.tsv')
        if key is None or not os.path.exists(tsv):
            return
        rows = _TSV.get(tsv)
        if rows is None:
            rows = collections.defaultdict(list)
            with open(tsv, encoding='utf-8') as f:
                head = f.readline().rstrip('\n').split('\t')
                ix = {h: i for i, h in enumerate(head)}
                for ln in f:
                    c = ln.rstrip('\n').split('\t')
                    try:
                        a = int(c[ix['address']], 16)
                    except (ValueError, IndexError):
                        continue
                    if a:
                        rows[c[ix['binary']]].append((a, int(c[ix['size']] or 0), c[ix['name']],
                                                      c[ix['elf_section']]))
            _TSV[tsv] = rows
        have = {x[0] for x in self.syms if x[4]}
        for a, sz, name, sec in rows.get(key, []):
            if (a, name) in seen:
                continue
            seen.add((a, name))
            self.syms.append((a, sz, name, sec or '.text', True, 'inventory' if a not in have else 'inventory-alias'))

    def read_dynamic(self):
        e = self.elf
        dyn = e.get_section_by_name('.dynamic')
        dsym = e.get_section_by_name('.dynsym')
        if dsym is not None and hasattr(dsym, 'iter_symbols'):
            self.dynsym = [s.name for s in dsym.iter_symbols()]
        if dyn is not None:
            tags = {t.entry.d_tag: t.entry.d_val for t in dyn.iter_tags()}
            if 'DT_PLTGOT' in tags and 'DT_MIPS_LOCAL_GOTNO' in tags and 'DT_MIPS_GOTSYM' in tags:
                ga = tags['DT_PLTGOT']
                for s in e.iter_sections():
                    if s['sh_addr'] == ga and s['sh_type'] == 'SHT_PROGBITS':
                        self.got = (ga, s['sh_size'], tags['DT_MIPS_LOCAL_GOTNO'], tags['DT_MIPS_GOTSYM'],
                                    self.gsz, s.data())
                self.gp = ga + 0x7ff0
        if self.gp is None:
            for x in self.byname.get('_gp', []):
                self.gp = x[0]
        if self.gp is None and self.kind != 'object':
            ri = e.get_section_by_name('.reginfo')
            if ri is not None and len(ri.data()) >= 24:
                self.gp = struct.unpack('>i', ri.data()[20:24])[0] & 0xffffffff
            op = e.get_section_by_name('.MIPS.options')
            if op is not None:
                d, p = op.data(), 0
                while p + 8 <= len(d):
                    kind, size = d[p], d[p + 1]
                    if size == 0:
                        break
                    if kind == 1 and size >= 40 and e.elfclass == 64:
                        self.gp = struct.unpack('>Q', d[p + 32:p + 40])[0]
                    elif kind == 1 and size >= 32:
                        self.gp = struct.unpack('>I', d[p + 28:p + 32])[0]
                    p += size
            if self.gp == 0:
                self.gp = None

    # ---------------------------------------------------------- lookups

    def find(self, routine, size=None):
        """(name, address, size, section, source)"""
        if re.fullmatch(r'0x[0-9a-fA-F]+', routine):
            a = int(routine, 16)
            names = [x for x in self.syms if x[0] == a and x[4]]
            if self.flat:
                return ('', a, size or 0, '', 'given')
            if not names:
                if size:
                    return ('', a, size, self.section_of(a) or '', 'given')
                raise SystemExit('facts: no function symbol at 0x%x; give --size to read it anyway' % a)
            x = sorted(names, key=lambda x: (x[5] != 'symtab', -x[1], x[2]))[0]
        else:
            cands = [x for x in self.byname.get(routine, []) if x[4]] or self.byname.get(routine, [])
            if not cands:
                raise SystemExit('facts: %s not found in %s' % (routine, self.path))
            if len({x[0] for x in cands}) > 1:
                # same-named static routines: guessing would document the wrong one
                seen = {}
                for x in sorted(cands, key=lambda x: (x[0], -x[1])):
                    seen.setdefault(x[0], x[1])
                raise SystemExit('facts: %s matches %d routines in %s:\n%s\npass 0xADDR --size N to choose one' % (
                    routine, len(seen), self.path,
                    '\n'.join('  0x%x  size %s' % (a, '0x%x' % n if n else 'unknown') for a, n in seen.items())))
            x = sorted(cands, key=lambda x: (x[0], -x[1]))[0]
        a, sz = x[0], size or x[1]
        self.size_source = 'given' if size else 'symbol' if x[1] and x[5] in ('symtab', 'dynsym') else \
            'debug information' if x[1] else 'next symbol'
        if not sz:
            i = bisect.bisect_right(self.func_addrs, a)
            nxt = self.func_addrs[i] if i < len(self.func_addrs) else None
            sec = self.section_bounds(x[3]) if x[3] else None
            if sec and (nxt is None or nxt > sec[1]):
                nxt = sec[1]
            sz = (nxt - a) if nxt else 0
        return (x[2], a, sz, x[3], x[5])

    def sec_reloc(self, sec, off):
        """The symbol address a relocated word at sec+off holds, in a relocatable object."""
        if self.relmaps is None:
            self.relmaps = {}
        if sec not in self.relmaps:
            m = {}
            e = self.elf
            for rn in ('.rel' + sec, '.rela' + sec):
                rs = e.get_section_by_name(rn)
                if rs is None or not hasattr(rs, 'iter_relocations'):
                    continue
                symtab = e.get_section(rs['sh_link'])
                for r in rs.iter_relocations():
                    t = r['r_info_type']
                    if t not in (2, 18):        # R_MIPS_32, R_MIPS_64
                        continue
                    sy = symtab.get_symbol(r['r_info_sym'])
                    nm = sy.name
                    if sy['st_info']['type'] == 'STT_SECTION':
                        nm = e.get_section(sy['st_shndx']).name
                    w = 8 if t == 18 else 4
                    if 'r_addend' in r.entry:
                        a = r['r_addend']
                    else:
                        raw = self.read_section(sec, r['r_offset'], w)
                        a = int.from_bytes(raw, 'big', signed=True) if raw else 0
                    m[r['r_offset']] = ('sym', nm, a)
            self.relmaps[sec] = m
        return self.relmaps[sec].get(off)

    def symbolize_sec(self, sec, off):
        """name+k for an offset into a section of a relocatable object."""
        best = None
        for a, sz, name, s, func, src in self.syms:
            if s == sec and a <= off and (off < a + sz or (not sz and a == off)):
                if best is None or a > best[0]:
                    best = (a, name)
        if best is None:
            return None
        return best[1] + ('+%d' % (off - best[0]) if off != best[0] else '')

    def section_bounds(self, name):
        for s in self.sections:
            if s['name'] == name:
                a = int(s['address'], 16)
                return (a, a + s['size'])
        return None

    def section_of(self, addr):
        if self.kind == 'object':
            return None
        for s in self.sections:
            a = int(s['address'], 16)
            if a and 'A' in s['flags'] and a <= addr < a + s['size']:
                return s['name']
        return None

    def read(self, addr, width):
        """Big-endian bytes at a linked address from a section with file contents, or None."""
        if self.flat:
            o = addr - self.load
            if 0 <= o and o + width <= len(self.data):
                return self.data[o:o + width]
            return None
        if self.kind == 'object':
            return None
        for s in self.sections:
            a = int(s['address'], 16)
            if a and s['type'] not in ('NOBITS',) and a <= addr and addr + width <= a + s['size']:
                o = int(s['offset'], 16) + addr - a
                return self.data[o:o + width]
        return None

    def read_section(self, name, off, width):
        for s in self.sections:
            if s['name'] == name and s['type'] != 'NOBITS' and 0 <= off and off + width <= s['size']:
                o = int(s['offset'], 16) + off
                return self.data[o:o + width]
        return None

    def symbolize(self, addr, funcs_only=False):
        if self.flat or not self.syms:
            return None
        i = bisect.bisect_right(self.addrs, addr) - 1
        while i >= 0:
            a, sz, name, sec, func, src = self.syms[i]
            if funcs_only and not func:
                i -= 1
                continue
            if a == addr:
                return name
            if sz and a <= addr < a + sz:
                return '%s+%d' % (name, addr - a)
            return None
        return None

    def func_name_at(self, addr):
        best = [x for x in self.syms if x[0] == addr and x[4]] if self.syms else []
        if not best:
            return None
        return sorted(best, key=lambda x: (x[5] != 'symtab', x[2]))[0][2]

    # ---------------------------------------------------------- disassembly

    def objdump(self):
        import toolchain
        return toolchain.objdump()

    def disassemble(self, addr, size, section):
        args = [self.objdump(), '-d', '-w', '-M', 'no-aliases,gpr-names=numeric', '--no-show-raw-insn',
                '--start-address=0x%x' % addr, '--stop-address=0x%x' % (addr + size)]
        path = self.path
        if self.flat:
            args += ['-b', 'binary', '-m', 'mips:4000' if self.isa == 'mips3' else 'mips:8000', '-EB',
                     '--adjust-vma=0x%x' % self.load, '-D']
        else:
            args += ['-r']
            if section:
                args += ['-j', section]
        if self.member or self.flat:
            if self.member:
                self.tmpdir = self.tmpdir or tempfile.TemporaryDirectory(prefix='facts-')
                path = os.path.join(self.tmpdir.name, os.path.basename(self.member))
                with open(path, 'wb') as f:
                    f.write(self.data)
        out = subprocess.run(args + [path], capture_output=True, text=True, encoding='utf-8',
                             errors='replace').stdout
        insns, last = [], None
        for ln in out.split('\n'):
            m = re.match(r'^\s*([0-9a-f]+):\s+(R_MIPS\S*)\s+(\S+)\s*$', ln)
            if m:
                if last is not None and int(m.group(1), 16) == last['addr']:
                    t = m.group(2).split('/')[0]
                    if t != 'R_MIPS_NONE' and last['reloc'] is None:
                        last['reloc'] = parse_reloc(t, m.group(3))
                continue
            m = re.match(r'^\s*([0-9a-f]+):\t(\S+)\t?(.*)$', ln)
            if not m:
                continue
            rest = m.group(3).split('\t')
            opstr = re.sub(r'\s*<[^>]*>', '', rest[0]).split('#')[0].strip()
            ops = [o.strip() for o in opstr.split(',')] if opstr else []
            last = {'addr': int(m.group(1), 16), 'mn': m.group(2), 'ops': ops, 'reloc': None}
            if len(rest) >= 3:
                r = re.match(r'\s*[0-9a-f]+: (R_MIPS\S*)$', rest[1])
                if r and r.group(1).split('/')[0] != 'R_MIPS_NONE':
                    last['reloc'] = parse_reloc(r.group(1).split('/')[0], rest[2].strip())
            insns.append(last)
        return insns


def parse_reloc(t, target):
    m = re.match(r'^(.*?)(?:([+-])0x([0-9a-f]+))?$', target)
    add = int(m.group(3), 16) * (-1 if m.group(2) == '-' else 1) if m.group(3) else 0
    return (t, m.group(1), add)


# ===================================================================== values

def C(v):
    return ('c', s64(v))


def is_c(v):
    return v is not None and v[0] == 'c'


def add(v, k):
    if v is None:
        return None
    if k == 0:
        return v
    if v[0] == 'c':
        return C(v[1] + k)
    if v[0] == 'add':
        return add(v[1], v[2] + k) if v[2] + k else v[1]
    if v[0] == 'sym':
        return ('sym', v[1], v[2] + k)
    if v[0] == 'tbl' and not isinstance(v[1], tuple):
        return ('tbl', v[1] + k)
    if v[0] == 'phi':
        u = frozenset(C(x[1] + k) for x in v[1])
        return ('phi', u)
    if v[0] == 'op' and v[1] == '+' and v[3] is not None and v[3][0] in ('c', 'phi'):
        return ('op', '+', v[2], add(v[3], k))
    return ('add', v, k)


def split(v):
    """(root, offset) of a value."""
    if v is None:
        return None, 0
    if v[0] == 'add':
        return v[1], v[2]
    if v[0] == 'sym':
        return ('sym', v[1], 0), v[2]
    return v, 0


def depth(v):
    if not isinstance(v, tuple):
        return 0
    return 1 + max([depth(x) for x in v[1:] if isinstance(x, tuple)] or [0])


def cap(v):
    return None if v is not None and depth(v) > 10 else v


def meet(a, b):
    if a == b:
        return a
    if a is None or b is None:
        return None
    if a[0] == 'add' and b[0] == 'op' and b[1] == '+':
        a = ('op', '+', a[1], C(a[2]))
    elif b[0] == 'add' and a[0] == 'op' and a[1] == '+':
        b = ('op', '+', b[1], C(b[2]))
    if a[0] == b[0] and len(a) == len(b) and a[0] in ('op', 'add', 'ld', 'sym') and depth(a) < 10:
        # same shape: keep the shape, and let the parts that differ become a choice
        if a[0] == 'add':
            x = meet(a[1], b[1])
            k = meet(C(a[2]), C(b[2]))
            return cap(('op', '+', x, k)) if x is not None and k is not None else None
        if a[0] == 'sym':
            return None
        parts = [a[0]]
        for x, y in zip(a[1:], b[1:]):
            if isinstance(x, tuple) or isinstance(y, tuple):
                z = meet(x, y) if isinstance(x, tuple) and isinstance(y, tuple) else None
                if z is None:
                    return None
                parts.append(z)
            elif x == y:
                parts.append(x)
            else:
                return None
        return tuple(parts)
    sa = a[1] if a[0] == 'phi' else frozenset([a]) if a[0] == 'c' else None
    sb = b[1] if b[0] == 'phi' else frozenset([b]) if b[0] == 'c' else None
    if sa is None or sb is None:
        return None
    u = sa | sb
    return ('phi', u) if len(u) <= PHI_MAX else None


def terms(v):
    """(possible constant sums, symbolic terms) of an address value."""
    if v is None:
        return None
    k = v[0]
    if k == 'c':
        return {v[1]}, []
    if k == 'phi':
        return {x[1] for x in v[1]}, []
    if k == 'add':
        t = terms(v[1])
        return ({c + v[2] for c in t[0]}, t[1]) if t else None
    if k == 'op' and v[1] == '+':
        a, b = terms(v[2]), terms(v[3])
        if a is None or b is None:
            return None
        cs = {x + y for x in a[0] for y in b[0]}
        if len(cs) > PHI_MAX:
            return None
        return cs, a[1] + b[1]
    if k == 'op' and v[1] == '|':
        a, b = terms(v[2]), terms(v[3])
        if a is not None and b is not None and not b[1] and len(b[0]) == 1:
            return {x | next(iter(b[0])) for x in a[0]}, a[1]
        return {0}, [v]
    return {0}, [v]


def io_constant(c):
    """A constant that only an I/O or kernel-segment address has (not a small structure offset)."""
    c &= M64
    return c >= 0x80000000 and (c >> 62 == 2 or c >> 32 in (0, 0xffffffff))


class Render:
    def __init__(self, img):
        self.img = img

    def __call__(self, v):
        if v is None:
            return '?'
        k = v[0]
        if k == 'c':
            return hexs(v[1])
        if k == 'phi':
            return 'one of ' + ', '.join(hexs(x[1]) for x in sorted(v[1], key=lambda x: x[1]))
        if k == 'in':
            return v[1]
        if k == 'sp0':
            return 'sp%+d' % v[1] if v[1] else 'sp'
        if k == 'sym':
            if v[1].startswith('.') and self.img.kind == 'object':
                nm = self.img.symbolize_sec(v[1], v[2])
                if nm:
                    return 'sym(%s)' % nm
            return 'sym(%s)%s' % (v[1], ('%+d' % v[2]) if v[2] else '')
        if k == 'add':
            return '%s%s' % (self(v[1]), ('%+d' % v[2]) if abs(v[2]) < 0x100000 else '+' + hexs(v[2]))
        if k == 'ld':
            return '[%s%s]%s' % (self(v[1]), ('%+d' % v[2]) if v[2] else '', '' if v[3] == 4 else ':%d' % v[3])
        if k == 'ret':
            return 'ret(%s)' % v[1]
        if k == 'tbl':
            return 'table(%s)' % (self(v[1]) if isinstance(v[1], tuple) else hexs(v[1]))
        if k == 'tent':
            return 'entry(%s)' % (self(v[1]) if isinstance(v[1], tuple) else hexs(v[1]))
        if k == 'op':
            return '(%s %s %s)' % (self(v[2]), v[1], self(v[3]))
        return repr(v)


def hexs(x):
    if x < -0xffff:
        return '0x%x' % (x & M64)
    return ('-0x%x' % -x) if x < 0 else '0x%x' % x


# ===================================================================== analysis

REG = re.compile(r'^\$(\d+)$')
FREG = re.compile(r'^\$f(\d+)$')
MEM = re.compile(r'^(-?(?:0x)?[0-9a-fA-F]+)?\(\$(\d+)\)$')


def reg(op):
    m = REG.match(op)
    return int(m.group(1)) if m else None


def imm(op):
    try:
        return num(op)
    except ValueError:
        return None


def is_branch(mn):
    return mn in ('j', 'jr', 'jal', 'jalr', 'jalx', 'jr.hb', 'jalr.hb') or (mn.startswith('b') and mn != 'break')


def branch_target(ins):
    try:
        return int(ins['ops'][-1], 16)
    except (ValueError, IndexError):
        return None


class State:
    __slots__ = ('r', 'f', 'm')

    def __init__(self, r=None, f=None, m=None):
        self.r = r if r is not None else {}
        self.f = f if f is not None else {}
        self.m = m if m is not None else {}

    def copy(self):
        return State(dict(self.r), dict(self.f), dict(self.m))

    def get(self, n):
        if n == 0:
            return C(0)
        return self.r.get(n)

    def set(self, n, v):
        if n == 0:
            return
        v = cap(v)
        if v is None:
            self.r.pop(n, None)
        else:
            self.r[n] = v

    def key(self):
        return (tuple(sorted(self.r.items(), key=lambda kv: kv[0])), tuple(sorted(self.f.items())),
                tuple(sorted(self.m.items())))


def meet_state(a, b):
    out = State()
    for k in set(a.r) & set(b.r):
        v = meet(a.r[k], b.r[k])
        if v is not None:
            out.r[k] = v
    for k in set(a.f) & set(b.f):
        v = meet(a.f[k], b.f[k])
        if v is not None:
            out.f[k] = v
    for k in set(a.m) & set(b.m):
        v = meet(a.m[k], b.m[k])
        if v is not None:
            out.m[k] = v
    return out


class Routine:
    def __init__(self, img, name, addr, size, section, source, errors):
        self.img, self.name, self.addr, self.size, self.section = img, name, addr, size, section
        self.source = source
        self.errors = [re.compile(e) for e in errors]
        self.R = Render(img)
        self.insns = img.disassemble(addr, size, section) if size else []
        self.at = {ins['addr']: i for i, ins in enumerate(self.insns)}
        self.w64 = img.abi in ('n64', 'n32', 'flat') or img.isa in ('mips3', 'mips4')
        self.nargs = 4 if img.abi == 'o32' else 8
        self.rel = img.kind == 'object'

    # ---------------------------------------------------------- semantics

    def entry_state(self):
        st = State()
        for r in range(1, 32):
            if r in (2, 3, 1, 26, 27):
                continue
            st.r[r] = ('in', self.img.regnames[r])
        st.r[29] = ('sp0', 0)
        if not self.rel and not self.img.flat:
            st.r[25] = C(self.addr)
            if self.img.gp is not None:
                st.r[28] = C(self.img.gp)
        for f in list(range(12, 20 if self.img.abi != 'o32' else 16)) + list(range(20, 32)):
            st.f[f] = ('in', 'f%d' % f)
        return st

    def resolve_reloc(self, ins):
        r = ins['reloc']
        if not r:
            return None
        t, s, a = r
        if s.startswith('.') and not s.startswith('.L'):
            return ('sym', s, a)
        return ('sym', s, a)

    def eff(self, st, ins):
        """(base register, base value, offset, effective value) of a memory operand."""
        m = MEM.match(ins['ops'][-1])
        if not m:
            return None
        off = num(m.group(1)) if m.group(1) else 0
        b = int(m.group(2))
        bv = st.get(b)
        if self.rel and ins['reloc'] and ins['reloc'][0] in ('R_MIPS_LO16', 'R_MIPS_GPREL16', 'R_MIPS_GOT16',
                                                              'R_MIPS_CALL16', 'R_MIPS_GOT_DISP', 'R_MIPS_GOT_PAGE',
                                                              'R_MIPS_GOT_OFST'):
            t, s, a = ins['reloc']
            if t in ('R_MIPS_LO16',):
                if bv is not None and bv[0] == 'sym' and bv[1] == s:
                    return b, bv, off, ('sym', s, bv[2] + off)
                return b, bv, off, ('sym', s, a + off)
            if t == 'R_MIPS_GPREL16':
                # REL addend in the instruction; a local (section) symbol also adds the object's gp0
                return b, bv, off, ('sym', s, a + off + (self.img.gp0 if s.startswith('.') else 0))
            return b, bv, off, ('gotref', s, a, t)
        return b, bv, off, add(bv, off) if bv is not None else None

    def got_info(self, ev):
        """GOT slot facts for a load from the effective address ev (linked images)."""
        g = self.img.got
        if g is None or not is_c(ev):
            return None
        ga, gs, local, gotsym, gsz, gdata = g
        a = ev[1] & M64 if self.img.gsz == 8 else ev[1] & 0xffffffff
        if not (ga <= a < ga + gs) or (a - ga) % gsz:
            return None
        i = (a - ga) // gsz
        word = int.from_bytes(gdata[i * gsz:(i + 1) * gsz], 'big')
        info = {'gp_offset': a - self.img.gp, 'slot': i, 'slot_address': '0x%x' % a}
        if i >= local:
            k = gotsym + i - local
            info.update(kind='global', dynsym_index=k, name=self.img.dynsym[k] if k < len(self.img.dynsym) else '',
                        formula='PLTGOT 0x%x + %d*(local_gotno %d + dynsym %d - gotsym %d)' % (
                            ga, gsz, local, k, gotsym))
        else:
            info.update(kind='local', local_entry=i, value='0x%x' % word,
                        formula='PLTGOT 0x%x + %d*local entry %d' % (ga, gsz, i))
            nm = self.img.func_name_at(word) or self.img.symbolize(word)
            if nm:
                info['value_symbol'] = nm
        return info, word

    def load_value(self, st, ins, ev, width):
        mn = ins['mn']
        if ev is None:
            return None
        if ev[0] == 'gotref':
            return ('sym', ev[1], ev[2])
        if ev[0] == 'sp0':
            return st.m.get(ev[1])
        if ev[0] == 'add' and ev[1][0] == 'sp0':
            return st.m.get(ev[1][1] + ev[2])
        if is_c(ev):
            gi = self.got_info(ev)
            if gi:
                info, word = gi
                if info['kind'] == 'global':
                    return ('sym', info['name'], 0)
                return C(word)
            b = self.img.read(ev[1] & (M64 if self.w64 else 0xffffffff), width)
            if b is not None and self.ro_addr(ev[1]):
                return C(int.from_bytes(b, 'big', signed=mn not in UNSIGNED))
            return ('ld', ev, 0, width)
        if ev[0] == 'tbl':
            return ('tent', ev[1], width)
        if ev[0] == 'sym' and self.rel:
            tgt = self.img.sec_reloc(ev[1], ev[2])
            if tgt is not None:
                return tgt
            if ev[1] in RO_SECTIONS:
                raw = self.img.read_section(ev[1], ev[2], width)
                if raw is not None:
                    return C(int.from_bytes(raw, 'big', signed=mn not in UNSIGNED))
            return ('ld', ev, 0, width)
        root, off = split(ev)
        return ('ld', root, off, width)

    def ro_addr(self, a):
        s = self.img.section_of(a & (M64 if self.w64 else 0xffffffff))
        if not s:
            return False
        for x in self.img.sections:
            if x['name'] == s:
                return 'W' not in x['flags'] or s in ('.got', '.lit4', '.lit8', '.rodata', '.sdata.rodata')
        return False

    def step(self, st, ins, rec=None):
        """Apply one instruction to st (in place). rec collects facts when given."""
        mn, ops = ins['mn'], ins['ops']
        R = [reg(o) for o in ops]
        g = st.get
        rel = self.resolve_reloc(ins) if self.rel else None
        if mn in LOADS:
            e = self.eff(st, ins)
            if e is None:
                return
            b, bv, off, ev = e
            w = LOADS[mn]
            v = self.load_value(st, ins, ev, w)
            if mn in ('lwc1', 'ldc1', 'lwc2', 'ldc2'):
                fm = FREG.match(ops[0])
                if fm:
                    if v is None:
                        st.f.pop(int(fm.group(1)), None)
                    else:
                        st.f[int(fm.group(1))] = v
                        if mn == 'ldc1' and self.img.abi == 'o32':
                            st.f.pop(int(fm.group(1)) + 1, None)
            elif mn in ('lwl', 'lwr', 'ldl', 'ldr'):
                st.set(R[0], None)
            else:
                st.set(R[0], v)
            if rec is not None:
                rec.access(ins, 'load', b, bv, off, ev, w, v)
            return
        if mn in STORES:
            e = self.eff(st, ins)
            if e is None:
                return
            b, bv, off, ev = e
            w = STORES[mn]
            if mn in ('swc1', 'sdc1', 'swc2', 'sdc2'):
                fm = FREG.match(ops[0])
                val = st.f.get(int(fm.group(1))) if fm else None
                src = ops[0]
            else:
                val = g(R[0]) if R[0] is not None else None
                src = ops[0]
            slot = None
            if ev is not None and ev[0] == 'sp0':
                slot = ev[1]
            elif ev is not None and ev[0] == 'add' and ev[1][0] == 'sp0':
                slot = ev[1][1] + ev[2]
            if slot is not None:
                if val is None or mn in ('swl', 'swr', 'sdl', 'sdr', 'sb', 'sh'):
                    st.m.pop(slot, None)
                else:
                    st.m[slot] = val
            if rec is not None:
                rec.access(ins, 'store', b, bv, off, ev, w, val, src)
            return
        if is_branch(mn) or mn in ('break', 'syscall', 'sync', 'cache', 'pref', 'nop', 'ssnop', 'eret', 'wait'):
            if mn in ('jalr', 'jalr.hb') and len(ops) == 2 and R[0] is not None:
                st.set(R[0], C(ins['addr'] + 8))
            return
        if not ops:
            return
        d = R[0]
        if d is None:
            fm = FREG.match(ops[0])
            if fm:
                fd = int(fm.group(1))
                if mn in ('mov.s', 'mov.d') and FREG.match(ops[1]):
                    v = st.f.get(int(FREG.match(ops[1]).group(1)))
                    if v is None:
                        st.f.pop(fd, None)
                    else:
                        st.f[fd] = v
                elif mn in ('mtc1', 'dmtc1'):
                    pass  # mtc1 rt, fs: destination is the second operand
                else:
                    st.f.pop(fd, None)
            if mn in ('mtc1', 'dmtc1') and len(ops) == 2:
                fm = FREG.match(ops[1])
                if fm:
                    v = g(reg(ops[0]))
                    if v is None:
                        st.f.pop(int(fm.group(1)), None)
                    else:
                        st.f[int(fm.group(1))] = ('bits', v) if is_c(v) else v
            return
        if mn.startswith('c.') or mn in ('mult', 'multu', 'dmult', 'dmultu', 'div', 'divu', 'ddiv', 'ddivu',
                                          'mthi', 'mtlo', 'teq', 'tne', 'tlt', 'tltu', 'tge', 'tgeu', 'teqi',
                                          'tnei', 'mtc0', 'dmtc0', 'ctc1', 'mtc2', 'dmtc2', 'ctc2', 'madd',
                                          'maddu', 'msub', 'msubu'):
            return
        if mn in ('mtc1', 'dmtc1'):
            return
        a = g(R[1]) if len(R) > 1 and R[1] is not None else None
        bv = g(R[2]) if len(R) > 2 and R[2] is not None else None
        k = imm(ops[2]) if len(ops) > 2 and R[2] is None else None
        if len(ops) == 2 and mn == 'lui':
            k = imm(ops[1])
        v = None
        if rel is not None and mn in ('lui', 'addiu', 'daddiu', 'ori'):
            t = ins['reloc'][0]
            if mn == 'lui' and t == 'R_MIPS_HI16':
                v = ('sym', rel[1], rel[2] + (sx32(k << 16) if k is not None else 0))
            elif t == 'R_MIPS_LO16' and a is not None and a[0] == 'sym' and a[1] == rel[1]:
                v = ('sym', rel[1], a[2] + (k or 0))
            elif t == 'R_MIPS_GPREL16':
                v = ('sym', rel[1], rel[2] + (k or 0) + (self.img.gp0 if rel[1].startswith('.') else 0))
            else:
                v = ('sym', rel[1], rel[2] + (k or 0 if t == 'R_MIPS_LO16' else 0))
        elif mn == 'lui':
            v = C(sx32(k << 16))
        elif mn in ('addiu', 'daddiu', 'addi', 'daddi'):
            v = add(a, k) if a is not None else None
            if mn in ('addiu', 'addi') and is_c(v):
                v = C(sx32(v[1]))
            if a is not None and a[0] == 'sym' and self.rel:
                v = a
        elif mn in ('addu', 'daddu', 'add', 'dadd'):
            ta = is_c(a) and not is_c(bv) and bv is not None and bv[0] not in ('tent', 'tbl') and self.table_base(a[1])
            tb = is_c(bv) and not is_c(a) and a is not None and a[0] not in ('tent', 'tbl') and self.table_base(bv[1])
            if a is not None and a[0] == 'tent' and is_c(bv):
                v = ('tent_gp', a[1], a[2], bv[1])
            elif bv is not None and bv[0] == 'tent' and is_c(a):
                v = ('tent_gp', bv[1], bv[2], a[1])
            elif ta or tb:
                v = ('tbl', (a if ta else bv)[1])
            elif is_c(a) and is_c(bv):
                v = C(a[1] + bv[1])
                if mn in ('addu', 'add'):
                    v = C(sx32(v[1]))
            elif is_c(bv) and a is not None:
                v = add(a, bv[1])
            elif is_c(a) and bv is not None:
                v = add(bv, a[1])
            elif a is not None and a[0] == 'sym' and bv is not None and bv[0] == 'sym' and a[1] == bv[1]:
                v = a
            elif a is not None and bv is not None and a[0] == 'tent' and is_c(bv):
                v = ('tent_gp', a[1], a[2], bv[1])
            elif bv is not None and a is not None and bv[0] == 'tent' and is_c(a):
                v = ('tent_gp', bv[1], bv[2], a[1])
            elif is_c(a) and bv is None:
                v = ('tbl', a[1])
            elif is_c(bv) and a is None:
                v = ('tbl', bv[1])
            elif a is not None and a[0] == 'sym' and self.rel and bv is None:
                v = ('tbl', a)
            elif a is not None and bv is not None:
                v = ('op', '+', bv, a) if a[0] == 'phi' else ('op', '+', a, bv)
        elif mn in ('subu', 'dsubu', 'sub', 'dsub'):
            if is_c(a) and is_c(bv):
                v = C(a[1] - bv[1])
                if mn in ('subu', 'sub'):
                    v = C(sx32(v[1]))
            elif is_c(bv) and a is not None:
                v = add(a, -bv[1])
        elif mn in ('or', 'xor', 'and', 'nor'):
            if mn == 'or' and is_c(bv) and bv[1] == 0:
                v = a
            elif mn == 'or' and is_c(a) and a[1] == 0:
                v = bv
            elif is_c(a) and is_c(bv):
                v = C({'or': a[1] | bv[1], 'xor': a[1] ^ bv[1], 'and': a[1] & bv[1],
                       'nor': ~(a[1] | bv[1])}[mn])
            elif a is not None and bv is not None and mn == 'or':
                v = ('op', '|', a, bv)
            elif a is not None and a[0] == 'sym' and bv is not None and bv[0] == 'sym' and a[1] == bv[1]:
                v = a
        elif mn in ('ori', 'xori', 'andi'):
            if is_c(a):
                v = C({'ori': a[1] | k, 'xori': a[1] ^ k, 'andi': a[1] & k}[mn])
            elif a is not None and mn == 'ori':
                v = ('op', '|', a, C(k))
        elif mn in ('sll', 'srl', 'sra', 'dsll', 'dsrl', 'dsra', 'dsll32', 'dsrl32', 'dsra32'):
            if is_c(a):
                x, sh = a[1], k
                if mn == 'sll':
                    v = C(sx32(x << sh))
                elif mn == 'srl':
                    v = C(sx32((x & 0xffffffff) >> sh))
                elif mn == 'sra':
                    v = C(sx32(sx32(x) >> sh))
                else:
                    sh += 32 if mn.endswith('32') else 0
                    if mn.startswith('dsll'):
                        v = C(x << sh)
                    elif mn.startswith('dsrl'):
                        v = C((x & M64) >> sh)
                    else:
                        v = C(s64(x) >> sh)
            elif a is not None and a[0] == 'sym' and self.rel and mn.startswith('dsll'):
                v = a
            elif a is not None and mn in ('dsll', 'dsll32', 'sll'):
                v = ('op', '<<', a, C(k + (32 if mn.endswith('32') else 0)))
        elif mn in ('slt', 'sltu', 'slti', 'sltiu'):
            y = bv if mn in ('slt', 'sltu') else (C(k) if k is not None else None)
            if is_c(a) and is_c(y):
                if mn.endswith('u'):
                    v = C(int((a[1] & M64) < (y[1] & M64)))
                else:
                    v = C(int(a[1] < y[1]))
        elif mn in ('movn', 'movz'):
            old = g(d)
            cond = g(R[2])
            if is_c(cond):
                v = a if (cond[1] != 0) == (mn == 'movn') else old
            else:
                v = meet(old, a) if old is not None and a is not None else None
        if mn in ('mfc1', 'dmfc1') and len(ops) == 2:
            fm = FREG.match(ops[1])
            fv = st.f.get(int(fm.group(1))) if fm else None
            v = fv[1] if fv is not None and fv[0] == 'bits' else None
        st.set(d, v)
        if rec is not None:
            rec.alu(ins, mn, d, a, k, v)

    def table_base(self, c):
        """Whether a constant added to a computed index can be a table in a data section (it, or a page
        base a 16-bit offset away from one)."""
        c &= M64 if self.w64 else 0xffffffff
        if c < 0x100000 or self.img.flat:
            return False
        for d in (0, 0x8000, -0x8000, 0x10000, -0x10000):
            sec = self.img.section_of(c + d)
            if sec and not any(x['name'] == sec and 'X' in x['flags'] for x in self.img.sections):
                return True
        return False

    def clobber(self, st, callee):
        for r in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 31]:
            st.r.pop(r, None)
        if self.img.abi == 'o32':
            st.r.pop(28, None)
        for f in list(st.f):
            if f < 20 or (self.img.abi == 'o32' and f < 20):
                st.f.pop(f, None)
        st.r[2] = ('ret', callee)
        st.f[0] = ('ret', callee)
        # The callee may write any stack slot whose address the routine handed out (a reply buffer, an
        # out-parameter), so a slot keeps its value only when it saved an incoming register or gp.
        for k in list(st.m):
            v = st.m[k]
            if not (v[0] == 'in' or (is_c(v) and self.img.gp is not None and v[1] == self.img.gp)):
                del st.m[k]

    # ---------------------------------------------------------- control flow

    def callee_of(self, st, ins, deep=True):
        """(kind, name, address, extra) for a call or jump through a register."""
        mn, ops = ins['mn'], ins['ops']
        if mn in ('jal', 'jalx') or (mn in ('bal', 'bgezal', 'bgezall', 'bltzal', 'bltzall', 'j')):
            if self.rel and ins['reloc'] and ins['reloc'][0] in ('R_MIPS_26', 'R_MIPS_PC16'):
                t, s, a = ins['reloc']
                if s.startswith('.'):
                    # a call to a local routine, relocated against its section: the target is in the field
                    tg = branch_target(ins)
                    nm = self.img.func_name_at(tg + a) if tg is not None else None
                    if nm:
                        return ('direct', nm, tg + a, {})
                return ('direct', s + (('%+d' % a) if a else ''), None, {})
            t = branch_target(ins)
            if t is None:
                return ('direct', '?', None, {})
            nm = self.img.func_name_at(t) or self.img.symbolize(t, funcs_only=True)
            return ('direct', nm or '', t, {})
        r = reg(ops[-1]) if mn in ('jalr', 'jalr.hb') else reg(ops[0])
        v = st.get(r)
        name = self.img.regnames[r] if r is not None else ops[-1]
        if v is None:
            return ('register', '', None, {'register': name, 'origin': '?'})
        if v[0] == 'sym':
            return ('got' if not self.rel else 'reloc', v[1] + (('%+d' % v[2]) if v[2] else ''), None,
                    {'register': name})
        if is_c(v):
            t = v[1] & (M64 if self.w64 else 0xffffffff)
            return ('register-constant', self.img.func_name_at(t) or self.img.symbolize(t, True) or '', t,
                    {'register': name})
        return ('register', '', None, {'register': name, 'origin': self.R(v)})

    def run(self):
        n = len(self.insns)
        if not n:
            return
        self.in_states = {0: self.entry_state()}
        self.edges = {}     # (from index, to index) -> state on that edge
        work = [0]
        visits = collections.Counter()
        while work:
            i = work.pop()
            visits[i] += 1
            if visits[i] > 400:
                continue
            st = self.in_states[i].copy()
            for j, out in self.successors(i, st):
                if j is None or j >= n or j < 0:
                    continue
                self.edges[(i, j)] = out
                old = self.in_states.get(j)
                new = out if old is None else meet_state(old, out)
                if old is None or new.key() != old.key():
                    self.in_states[j] = new
                    work.append(j)

    def successors(self, i, st):
        ins = self.insns[i]
        mn = ins['mn']
        n = len(self.insns)
        if not is_branch(mn):
            self.step(st, ins)
            return [(i + 1, st)]
        self.step(st, ins)
        delay = self.insns[i + 1] if i + 1 < n else None
        taken = st.copy()
        callee = None
        if mn in CALLS:
            callee = self.callee_of(st, ins)
        if delay is not None:
            self.step(taken, delay)
        if mn in CALLS:
            self.clobber(taken, callee[1] or (hexs(callee[2]) if callee[2] is not None else '?'))
            cond = mn in ('bgezal', 'bltzal', 'bgezall', 'bltzall') and ins['ops'][0] != '$0'
            out = [(i + 2, taken)]
            if cond:
                nt = st.copy()
                if mn not in LIKELY and delay is not None:
                    self.step(nt, delay)
                out.append((i + 2, nt))
            return out
        if mn in ('jr', 'jr.hb'):
            r = reg(ins['ops'][0])
            v = taken.get(r) if r is not None else None
            if v is not None and v[0] in ('tent', 'tent_gp'):
                return [(self.at.get(t), taken.copy()) for t in self.table_targets(i, v)]
            return []
        if mn == 'j':
            t = branch_target(ins)
            if self.rel and ins['reloc']:
                return []
            return [(self.at.get(t), taken)]
        t = branch_target(ins)
        never, always = self.static_cond(st, ins)
        out = []
        if not never:
            out.append((self.at.get(t) if t is not None else None, taken))
        if not always:
            nt = st.copy()
            if mn not in LIKELY and delay is not None:
                self.step(nt, delay)
            out.append((i + 2, nt))
        return out

    def static_cond(self, st, ins):
        mn, ops = ins['mn'], ins['ops']
        if mn in ('beq', 'beql', 'bne', 'bnel') and len(ops) == 3:
            a, b = reg(ops[0]), reg(ops[1])
            same = a == b
            va, vb = st.get(a), st.get(b)
            if not same and is_c(va) and is_c(vb):
                eq = va[1] == vb[1]
            elif same:
                eq = True
            else:
                return False, False
            if mn.startswith('beq'):
                return (not eq), eq
            return eq, (not eq)
        if mn in ('bgez', 'bgezl', 'blez', 'blezl') and reg(ops[0]) == 0:
            return False, True
        if mn in ('bltz', 'bltzl', 'bgtz', 'bgtzl') and reg(ops[0]) == 0:
            return True, False
        return False, False

    def table_targets(self, i, v):
        """Targets of a jump table read at v; the bound comes from the nearest sltiu before i."""
        tab = v[1]
        width = v[2]
        bound = None
        for j in range(i, max(-1, i - 40), -1):
            if self.insns[j]['mn'] == 'sltiu':
                bound = imm(self.insns[j]['ops'][2])
                break
        if bound is None or bound <= 0 or bound > 4096 or not is_c(('c', tab) if not isinstance(tab, tuple)
                                                                     else tab):
            return []
        tab = tab if not isinstance(tab, tuple) else tab[1]
        gpadd = v[3] if v[0] == 'tent_gp' else 0
        out = []
        for k in range(bound):
            b = self.img.read((tab + k * width) & M64, width)
            if b is None:
                return []
            w = int.from_bytes(b, 'big', signed=True) + gpadd
            w &= M64 if self.w64 else 0xffffffff
            if self.img.gsz == 4:
                w &= 0xffffffff
            out.append(w)
        self.tables.append({'jump': '0x%x' % self.insns[i]['addr'], 'table': '0x%x' % (tab & M64),
                            'section': self.img.section_of(tab & M64) or '', 'entries': bound,
                            'entry_width': width, 'gp_relative': bool(gpadd),
                            'targets': ['0x%x' % t for t in out],
                            'outside_routine': sorted({'0x%x' % t for t in out if t not in self.at})})
        return out

    # ---------------------------------------------------------- facts

    def facts(self, with_insns=True):
        self.tables = []
        self.run()
        tables = self.tables
        self.tables = []
        rec = Recorder(self)
        visited = set(self.in_states)
        delay_of = {}
        for i in sorted(visited):
            ins = self.insns[i]
            if is_branch(ins['mn']) and i + 1 < len(self.insns):
                delay_of[i + 1] = i
        for i in sorted(visited):
            ins = self.insns[i]
            st = self.in_states[i].copy()
            rec.cur = i
            if i in delay_of and delay_of[i] in visited and i not in self.branch_targets():
                continue    # recorded with its branch
            self.step(st, ins, rec)
            if is_branch(ins['mn']):
                rec.branch(i, ins, st, self.in_states[i])
                if i + 1 < len(self.insns):
                    rec.cur = i + 1
                    self.step(st, self.insns[i + 1], rec)
                    rec.cur = i
                    rec.after_delay(i, ins, st)
        self.tables = tables
        unreached = [self.insns[i]['addr'] for i in range(len(self.insns))
                     if i not in visited and not (i in delay_of and delay_of[i] in visited)]
        out = rec.finish(unreached, with_insns)
        # GOT slots that only unreachable code loads (a call the routine never makes)
        dead = []
        for i in range(len(self.insns)):
            ins = self.insns[i]
            if ins['addr'] in unreached and ins['mn'] in LOADS and self.img.gp is not None:
                m = MEM.match(ins['ops'][-1]) if ins['ops'] else None
                if m and int(m.group(2)) == 28:
                    gi = self.got_info(C(self.img.gp + (num(m.group(1)) if m.group(1) else 0)))
                    if gi:
                        nm = gi[0].get('name') or gi[0].get('value_symbol')
                        if nm:
                            dead.append({'address': '0x%x' % ins['addr'], 'name': nm, 'slot': gi[0]['slot']})
        out['unreached_got'] = dead
        return out

    def branch_targets(self):
        if not hasattr(self, '_bt'):
            self._bt = {self.at.get(branch_target(x)) for x in self.insns if is_branch(x['mn'])} - {None}
        return self._bt


class Recorder:
    def __init__(self, r):
        self.r = r
        self.R = r.R
        self.cur = 0
        self.accesses, self.addresses, self.immediates, self.consts = [], [], [], []
        self.literals, self.calls, self.got, self.branches, self.exits = [], [], [], [], []
        self.errors, self.mmio = [], []
        self.frame = None
        self.argread = collections.OrderedDict()
        self.last_got = {}

    def where(self):
        ins = self.r.insns[self.cur]
        return {'address': '0x%x' % ins['addr'], 'index': self.cur}

    def text(self, ins):
        if ins['mn'] in ('mfc0', 'mtc0', 'dmfc0', 'dmtc0', 'cfc1', 'ctc1') and len(ins['ops']) == 2:
            return '%s %s,%s' % (ins['mn'], self.r.img.regnames[reg(ins['ops'][0])] if reg(ins['ops'][0])
                                 is not None else ins['ops'][0], ins['ops'][1])
        return '%s %s' % (ins['mn'], ','.join(self.r.img.regnames[int(o[1:])] if REG.match(o) else
                                              re.sub(r'\(\$(\d+)\)', lambda m: '(%s)' % self.r.img.regnames[
                                                  int(m.group(1))], o) for o in ins['ops']))

    def note_args(self, ins, state):
        pass

    def access(self, ins, kind, b, bv, off, ev, w, val, src=None):
        img = self.r.img
        root, roff = split(ev) if ev is not None and ev[0] not in ('gotref',) else (None, 0)
        d = dict(self.where(), kind=kind, mnemonic=ins['mn'], width=w, base=img.regnames[b],
                 base_origin=self.R(bv), offset=off, text=self.text(ins))
        if ins['mn'] in ('lwc1', 'ldc1', 'swc1', 'sdc1'):
            d['register_file'] = 'fp'
        if ins['mn'] in UNSIGNED:
            d['unsigned'] = True
        if ev is not None and ev[0] == 'gotref':
            d['reloc'] = '%s %s%s' % (ev[3], ev[1], ('%+d' % ev[2]) if ev[2] else '')
        elif root is not None:
            d['origin'] = self.R(root)
            d['origin_offset'] = roff
            if is_c(ev):
                a = ev[1] & (M64 if self.r.w64 else 0xffffffff)
                d['absolute'] = '0x%x' % a
                nm = img.symbolize(a)
                if nm:
                    d['symbol'] = nm
                sec = img.section_of(a)
                if sec:
                    d['section'] = sec
        if self.r.w64 and ev is not None and ev[0] == 'sp0' or (root is not None and root[0] == 'sp0'):
            d['stack'] = True
        if kind == 'store':
            d['source'] = img.regnames[reg(src)] if reg(src) is not None else src.lstrip('$')
            d['value'] = self.R(val)
        else:
            d['value'] = self.R(val)
        broot = split(bv)[0] if bv is not None else None
        if broot is not None and broot[0] == 'in' and broot[1] in img.regnames[4:4 + self.r.nargs]:
            self.argread.setdefault(broot[1], collections.Counter())[kind] += 1
        if ev is not None and is_c(ev) and kind == 'load':
            gi = self.r.got_info(ev)
            if gi:
                info, word = gi
                self.got.append(dict(self.where(), register=img.regnames[reg(ins['ops'][0])]
                                     if reg(ins['ops'][0]) is not None else ins['ops'][0], **info))
                self.last_got[ins['ops'][0]] = self.got[-1]
                d['got_slot'] = info['slot']
            elif self.r.ro_addr(ev[1]) and img.read(ev[1] & M64, w) is not None:
                raw = img.read(ev[1] & M64, w)
                lit = dict(self.where(), address='0x%x' % (ev[1] & M64), section=img.section_of(ev[1] & M64),
                           width=w, word='0x%s' % raw.hex())
                if w == 4:
                    lit['float'] = struct.unpack('>f', raw)[0]
                elif w == 8:
                    lit['double'] = struct.unpack('>d', raw)[0]
                lit['instruction'] = '0x%x' % ins['addr']
                del lit['address']
                lit['data_address'] = '0x%x' % (ev[1] & M64)
                lit['address'] = '0x%x' % ins['addr']
                self.literals.append(lit)
        # memory-mapped I/O: a constant address outside every section of the file, or a base
        # pointer the routine loaded or computed (not the stack, not an argument)
        if not d.get('stack'):
            if is_c(ev) and not img.section_of(ev[1] & M64) and not (img.got and self.r.got_info(ev)):
                a = ev[1] & M64
                m = dict(d, absolute='0x%x' % a, resolved=True)
                m['physical'] = '0x%x' % inventory.translate({'translate': True}, a)
                self.mmio.append(m)
            elif ev is not None and not is_c(ev):
                t = terms(ev)
                if t is not None and t[1] and all(io_constant(c) for c in t[0]):
                    m = dict(d, resolved=False, constant_part=['0x%x' % (c & M64) for c in sorted(t[0])],
                             variable_terms=[self.R(x) for x in t[1]],
                             physical_constant_part=['0x%x' % inventory.translate({'translate': True}, c)
                                                     for c in sorted(t[0])])
                    self.mmio.append(m)
        self.accesses.append(d)

    def alu(self, ins, mn, dst, a, k, v):
        img = self.r.img
        if dst == 29 and mn in ('addiu', 'daddiu') and k is not None and k < 0 and self.frame is None:
            self.frame = -k
        ops = ins['ops']
        for o in ops[1:]:
            if reg(o) is None and not FREG.match(o):
                x = imm(o)
                if x is not None:
                    self.immediates.append(dict(self.where(), mnemonic=mn, immediate=x, hex=hexs(x),
                                                text=self.text(ins)))
        if is_c(v) and mn in ('lui', 'ori', 'addiu', 'daddiu', 'xori', 'andi', 'dsll', 'dsll32', 'daddu', 'addu',
                              'or', 'dsrl', 'dsrl32', 'sll', 'srl') and dst not in (28, 29):
            x = v[1]
            c = dict(self.where(), register=img.regnames[dst], value=hexs(x), unsigned32='0x%x' % (x & 0xffffffff))
            sec = img.section_of(x & M64)
            if sec:
                c['section'] = sec
                nm = img.symbolize(x & M64)
                if nm:
                    c['symbol'] = nm
            self.consts.append(c)
        if mn in ('addiu', 'daddiu', 'addu', 'daddu', 'addi', 'daddi') and dst not in (29,) and v is not None \
                and v[0] in ('add', 'sym') and dst != 28:
            root, off = split(v)
            if root is not None and root[0] != 'sp0' and (off or v[0] == 'sym'):
                self.addresses.append(dict(self.where(), register=img.regnames[dst], origin=self.R(root),
                                           offset=off, value=self.R(v), text=self.text(ins)))
            elif root is not None and root[0] == 'sp0':
                self.addresses.append(dict(self.where(), register=img.regnames[dst], origin='sp', offset=off,
                                           value=self.R(v), text=self.text(ins), stack=True))

    def branch(self, i, ins, st_after, st_in):
        r = self.r
        mn = ins['mn']
        delay = r.insns[i + 1] if i + 1 < len(r.insns) else None
        b = dict(self.where(), mnemonic=mn, text=self.text(ins),
                 delay_slot=self.text(delay) if delay else None,
                 delay_address='0x%x' % delay['addr'] if delay else None)
        if mn in LIKELY:
            b['likely'] = True
        t = branch_target(ins)
        if t is not None and mn not in ('jr', 'jalr', 'jr.hb', 'jalr.hb'):
            b['target'] = '0x%x' % t
            if t not in r.at:
                b['target_outside'] = True
        never, always = r.static_cond(st_in, ins) if mn not in CALLS and mn not in ('j', 'jr') else (False, False)
        if never:
            b['never_taken'] = True
        if always and mn not in ('j',):
            b['always_taken'] = True
        self.branches.append(b)
        self._pending = (i, ins, st_in)

    def after_delay(self, i, ins, st):
        r, img = self.r, self.r.img
        mn = ins['mn']
        st0 = self._pending[2].copy()
        r.step(st0, ins)
        if mn in CALLS or mn in ('jr', 'jr.hb', 'j'):
            callee = r.callee_of(st0, ins)
            if mn in ('jr', 'jr.hb') and reg(ins['ops'][0]) == 31:
                self.exit(i, ins, st)
                return
            if mn in ('jr', 'jr.hb'):
                v = st0.get(reg(ins['ops'][0]))
                if v is not None and v[0] in ('tent', 'tent_gp'):
                    return
            if mn == 'j' and not (r.rel and ins['reloc']):
                t = branch_target(ins)
                if t in r.at:
                    return
            c = dict(self.where(), mnemonic=mn, kind=callee[0], callee=callee[1])
            if callee[2] is not None:
                c['target'] = '0x%x' % callee[2]
            c.update(callee[3])
            if mn in ('jr', 'jr.hb', 'j'):
                c['tail'] = True
            if r.insns[i + 1:i + 2]:
                c['delay_slot'] = self.text(r.insns[i + 1])
            # the argument registers as the callee sees them (after the delay slot)
            args = {}
            for k in range(r.nargs):
                v = st.get(4 + k)
                if v is not None and v != ('in', img.regnames[4 + k]):
                    args[img.regnames[4 + k]] = self.R(v)
            c['args'] = args
            for k in range(r.nargs):
                fv = st.f.get(12 + k)
                if fv is not None and fv != ('in', 'f%d' % (12 + k)):
                    c.setdefault('fp_args', {})['f%d' % (12 + k)] = self.R(fv)
            rops = ins['ops'][-1] if mn in ('jalr', 'jalr.hb') else ins['ops'][0] if ins['ops'] else ''
            gl = self.last_got.get(rops) if mn not in ('jal', 'bal', 'j', 'bgezal', 'bgezall') else None
            if gl is not None and (gl.get('name') == callee[1] or gl.get('value_symbol') == callee[1]
                                   or gl.get('value') == c.get('target')):
                c['got'] = {k: gl[k] for k in ('gp_offset', 'slot', 'kind', 'dynsym_index', 'local_entry',
                                               'formula', 'slot_address') if k in gl}
            self.calls.append(c)
            nm = callee[1]
            if any(e.fullmatch(nm) for e in r.errors):
                a0 = st.get(4)
                self.errors.append(dict(self.where(), callee=nm, argument=self.R(a0),
                                        code=a0[1] if is_c(a0) else None,
                                        codes=sorted(x[1] for x in a0[1]) if a0 is not None and a0[0] == 'phi'
                                        else None))

    def exit(self, i, ins, st):
        r = self.r
        # walk back over straight code to the block start, then report each incoming edge
        j = i
        starts = r.branch_targets()
        while j > 0:
            prev = r.insns[j - 1]
            if j in starts or (j - 2 >= 0 and is_branch(r.insns[j - 2]['mn'])) or is_branch(prev['mn']):
                break
            j -= 1
        paths = []
        preds = sorted(k for k in r.edges if k[1] == j)
        for (p, q) in preds:
            s = r.edges[(p, q)].copy()
            for k in range(j, i + 2):
                if k < len(r.insns) and k in r.at.values():
                    if k == i:
                        continue
                    r.step(s, r.insns[k])
            paths.append({'from': '0x%x' % r.insns[p]['addr'], 'v0': self.R(s.get(2)),
                          'f0': self.R(s.f.get(0)) if s.f.get(0) is not None else None})
        e = dict(self.where(), v0=self.R(st.get(2)), f0=self.R(st.f.get(0)) if st.f.get(0) is not None else None,
                 delay_slot=self.text(r.insns[i + 1]) if i + 1 < len(r.insns) else None, paths=paths)
        self.exits.append(e)

    def finish(self, unreached, with_insns):
        r, img = self.r, self.r.img
        loops = []
        for b in self.branches:
            t = b.get('target')
            if t and int(t, 16) <= int(b['address'], 16) and int(t, 16) in r.at:
                lo, hi = int(t, 16), int(b['address'], 16) + 4
                st = [a for a in self.accesses if a['kind'] == 'store' and lo <= int(a['address'], 16) <= hi
                      and not a.get('stack')]
                ld = [a for a in self.accesses if a['kind'] == 'load' and lo <= int(a['address'], 16) <= hi
                      and not a.get('stack')]
                steps = collections.defaultdict(int)
                for ins in r.insns[r.at[lo]:r.at.get(hi, len(r.insns) - 1) + 1]:
                    if ins['mn'] in ('addiu', 'daddiu') and len(ins['ops']) == 3 and ins['ops'][0] == ins['ops'][1]:
                        k = imm(ins['ops'][2])
                        rr = reg(ins['ops'][0])
                        if k is not None and rr not in (29,):
                            steps[img.regnames[rr]] += k
                bases = collections.defaultdict(int)
                for a in st:
                    bases[a['base']] += a['width']
                lb = collections.defaultdict(int)
                for a in ld:
                    lb[a['base']] += a['width']
                loops.append({'head': t, 'back_branch': b['address'], 'stores': len(st), 'bytes_stored': sum(
                    a['width'] for a in st), 'bytes_stored_by_base': dict(sorted(bases.items())),
                    'bytes_loaded_by_base': dict(sorted(lb.items())), 'pointer_steps': dict(sorted(steps.items())),
                    'likely': bool(b.get('likely'))})
        args_read = {}
        for k in range(r.nargs):
            nm = img.regnames[4 + k]
            if nm in self.argread:
                args_read[nm] = dict(sorted(self.argread[nm].items()))
        used = self.used_args()
        out = {
            'routine': {'name': r.name, 'address': '0x%x' % r.addr, 'size': r.size, 'words': r.size // 4,
                        'end': '0x%x' % (r.addr + r.size), 'frame_size': self.frame or 0, 'abi': img.abi,
                        'isa': img.isa, 'kind': img.kind, 'section': r.section, 'address_source': r.source,
                        'size_source': getattr(img, 'size_source', 'given'),
                        'file': img.path + (':' + img.member if img.member else ''),
                        'gp': '0x%x' % img.gp if img.gp is not None else None},
            'calls': self.calls,
            'got_loads': self.got,
            'accesses': self.accesses,
            'addresses': self.addresses,
            'immediates': self.immediates,
            'constants': self.consts,
            'literals': self.literals,
            'branches': self.branches,
            'branch_likely': [b['address'] for b in self.branches if b.get('likely') and b['mnemonic'] not in CALLS],
            'likely_calls': [b['address'] for b in self.branches if b.get('likely') and b['mnemonic'] in CALLS],
            'never_taken': [b['address'] for b in self.branches if b.get('never_taken')],
            'loops': loops,
            'exits': self.exits,
            'jump_tables': r.tables,
            'errors': self.errors,
            'mmio': self.mmio,
            'args': {'read_before_write': used, 'accessed_through': args_read},
            'unreached': ['0x%x' % a for a in unreached],
            'sections': img.sections,
        }
        if with_insns:
            out['insns'] = [['0x%x' % x['addr'], self.text(x)] for x in r.insns]
        return out

    def used_args(self):
        """Argument registers read before the routine writes them, in program order of first read."""
        r = self.r
        img = r.img
        written, read = set(), []
        args = {4 + k for k in range(r.nargs)}
        fargs = set(range(12, 12 + (r.nargs if img.abi != 'o32' else 4)))
        for ins in r.insns:
            mn, ops = ins['mn'], ins['ops']
            regs_read, dst = [], None
            if mn in STORES:
                regs_read = [reg(ops[0])] + [int(m.group(2)) for m in [MEM.match(ops[-1])] if m]
                if FREG.match(ops[0]):
                    f = int(FREG.match(ops[0]).group(1))
                    if f in fargs and ('f%d' % f) not in written and ('f%d' % f) not in read:
                        read.append('f%d' % f)
            elif mn in LOADS:
                regs_read = [int(m.group(2)) for m in [MEM.match(ops[-1])] if m]
                dst = reg(ops[0])
            elif is_branch(mn):
                regs_read = [reg(o) for o in ops if reg(o) is not None]
                if mn in CALLS:
                    break
            else:
                if ops:
                    dst = reg(ops[0])
                    regs_read = [reg(o) for o in ops[1:]]
                    for o in ops[1:]:
                        fm = FREG.match(o)
                        if fm and int(fm.group(1)) in fargs and ('f%d' % int(fm.group(1))) not in written \
                                and ('f%d' % int(fm.group(1))) not in read:
                            read.append('f%d' % int(fm.group(1)))
                    fm = FREG.match(ops[0])
                    if fm and mn not in ('mtc1', 'dmtc1') and not mn.startswith('c.'):
                        written.add('f%d' % int(fm.group(1)))
            for x in regs_read:
                if x in args and x not in written and img.regnames[x] not in read:
                    read.append(img.regnames[x])
            if dst is not None:
                written.add(dst)
        return read


# ===================================================================== entry points

_CACHE = {}
_TSV = {}


def image(path, member=None, flat=False, load=0, isa='mips4'):
    key = (os.path.realpath(path), member, flat, load, isa)
    if key not in _CACHE:
        _CACHE[key] = Image(path, member, flat, load, isa)
    return _CACHE[key]


def fact_sheet(path, routine, member=None, size=None, flat=False, load=0, isa='mips4', errors=None,
               with_insns=True):
    img = image(path, member, flat, load, isa)
    name, addr, sz, sec, src = img.find(routine, size)
    if flat and not sz:
        sz = scan_size(img, addr)
        src = 'scanned to the last reachable return'
    r = Routine(img, name, addr, sz, sec if not flat else None, src, errors or DEFAULT_ERRORS)
    return r.facts(with_insns)


def scan_size(img, addr, limit=0x4000):
    """Bytes from addr to the delay slot of the last return reachable without crossing it."""
    insns = img.disassemble(addr, limit, None)
    far = addr
    for k, ins in enumerate(insns):
        t = branch_target(ins) if is_branch(ins['mn']) and ins['mn'] not in CALLS else None
        if t is not None and t > far and t < addr + limit:
            far = t
        if ins['mn'] == 'jr' and ins['ops'] == ['$31'] and ins['addr'] >= far:
            return ins['addr'] + 8 - addr
    return limit


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('binary', help='file, or archive:member')
    ap.add_argument('routine', help='symbol name or 0xADDRESS')
    ap.add_argument('--size', type=lambda s: int(s, 0))
    ap.add_argument('--flat', action='store_true', help='raw big-endian payload (PROM image)')
    ap.add_argument('--load', type=lambda s: int(s, 0), default=0, help='load address of a flat payload')
    ap.add_argument('--offset', type=lambda s: int(s, 0), default=0,
                    help='byte offset of the payload inside the flat file')
    ap.add_argument('--isa', default='mips4', choices=('mips3', 'mips4'))
    ap.add_argument('--error-routine', action='append', help='regex of error routines (repeatable)')
    ap.add_argument('--no-insns', action='store_true', help='leave out the instruction listing')
    ap.add_argument('--out')
    a = ap.parse_args(argv)
    path, member = a.binary, None
    m = re.fullmatch(r'(.+)\((.+)\)', path)
    if m and not os.path.exists(path):
        path, member = m.groups()
    elif ':' in path and not os.path.exists(path):
        path, member = path.split(':', 1)
    if a.flat and a.offset:
        data = open(path, 'rb').read()[a.offset:]
        td = tempfile.TemporaryDirectory(prefix='facts-')
        p2 = os.path.join(td.name, os.path.basename(path))
        with open(p2, 'wb') as f:
            f.write(data)
        path = p2
    fs = fact_sheet(path, a.routine, member, a.size, a.flat, a.load, a.isa, a.error_routine, not a.no_insns)
    fs['routine']['file'] = a.binary
    text = json.dumps(fs, indent=1, sort_keys=True) + '\n'
    if a.out:
        with open(a.out, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
