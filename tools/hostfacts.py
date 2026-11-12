#!/usr/bin/env python3
"""Mechanical facts for one routine, readable as text, with no container.

Usage: retools/tools/hostfacts.py BINARY[:MEMBER] ROUTINE [--size N] [--flat --load ADDR [--isa mips3|mips4]]
                            [--arch mips|m68k|coldfire|arm|thumb|ppc32|x86-16|x86-32]
                            [--offset N] [--abi NAME] [--elf] [--json]

  uv run --with capstone --with pyelftools \\
      python -I retools/tools/hostfacts.py root/usr/lib32/libGLcore.so CISendFc

For MIPS, the same inputs and arguments as tools/facts.py, and the same analysis: this script replaces
only the disassembler. It decodes the routine with Capstone instead of the MIPS objdump that
facts.py runs in the toolchain container, builds the instruction list facts.py builds, and lets
facts.py's Routine track registers (lui/addiu/daddiu/ori/or/move/addu/shifts, stack slots, GOT
loads, relocations, meeting the values of every path into a block). What it adds is the text
form and a control-flow graph with each condition stated in words. A hostfacts run and a
facts.py run of one routine agree on every access, call and constant; the disassembly is the
only difference, and tools/test_hostfacts.py checks the decoder against hand-assembled words.

Sections of the output:
  routine   range, size, ELF class, ABI, ISA, where the address and size came from
  accesses  every load and store: width, base register and what it held, the displacement as
            written, and the resolved target: `abs 0xADDR`, or `ORIGIN +/-0xOFF` where ORIGIN is
            an argument as it arrived (a0), a value loaded from memory ([a0+16] is the word at
            a0+16), a stack slot (sp-32), a symbol or a call's return value. A displacement from
            a lui-built base is shown with its sign; the resolved offset is the sum.
  calls     every call with its callee and the argument registers as the callee sees them,
            after the call's delay slot; `?` is a register the routine did not set to anything
            it could follow
  blocks    basic blocks with the instruction range, predecessors and exit. Each conditional
            branch says in words when it is taken and when it falls through, which instruction
            sits in its delay slot and whether a branch-likely annuls it
  returns   each return, the blocks that reach it and v0 on the way in
  constants every constant a register holds after it is built, immediates, literal-pool loads

Non-MIPS flat firmware requires an explicit --load and --size. MMSC a.out images use
tools/sysco/mmsc_aout.py for their mapped segments and symbols; their size can come from
the next symbol (inferred). With --elf, ARM ELF32 executables and shared objects use linked virtual
coordinates: --load must equal the lowest mapped PT_LOAD virtual address, not a guessed runtime
base. ELF magic alone does not select this mode: extracted load images can begin with
an ELF header and still use the historical flat contract. --offset is unavailable for
mapped files. Defined function symbols supply sizes; zero-sized symbols need --size.
Relocations are not applied; reads
overlapping them and writable literals remain unknown. A reached instruction overlapping
a relocation or a conflicting mapping symbol stops analysis with an error. Architecture adapters share the symbolic value representation,
worklist, path merging and output format inside this module. Calling conventions are assumed
and argument counts are unknown. Unsupported effects are invalidated and reported.

A value this tool cannot follow is shown as `?` or `(unknown)`; it never guesses one.
"""
import argparse
import collections
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import facts  # noqa: E402  the same file in every workspace

M64 = facts.M64
GPR = {n: i for i, n in enumerate(facts.NAMES_O32)}
GPR.update({'fp': 30, 'a4': 8, 'a5': 9, 'a6': 10, 'a7': 11})
RTYPE = {0x20: 'add', 0x21: 'addu', 0x22: 'sub', 0x23: 'subu', 0x24: 'and', 0x25: 'or', 0x26: 'xor',
         0x27: 'nor', 0x2c: 'dadd', 0x2d: 'daddu', 0x2e: 'dsub', 0x2f: 'dsubu'}
SHIFTS = {'sll', 'srl', 'sra', 'dsll', 'dsrl', 'dsra', 'dsll32', 'dsrl32', 'dsra32'}
ZERO_IMM = {'andi', 'ori', 'xori', 'lui'}
FP_COND = ['f', 'un', 'eq', 'ueq', 'olt', 'ult', 'ole', 'ule', 'sf', 'ngle', 'seq', 'ngl', 'lt', 'nge', 'le', 'ngt']
FP_WORDS = {'f': 'never (always false)', 'sf': 'never (always false)', 'un': 'unordered (a NaN)',
            'ngle': 'unordered', 'eq': '==', 'seq': '==', 'ueq': '== or unordered', 'ngl': '== or unordered',
            'olt': '<', 'lt': '<', 'ult': '< or unordered', 'nge': '< or unordered', 'ole': '<=', 'le': '<=',
            'ule': '<= or unordered', 'ngt': '<= or unordered'}
ARG_ORDINAL = {'a%d' % k: k for k in range(8)}


def is_stack_or_global_access(access):
    """Whether an access is routine frame or global-pointer traffic."""
    return bool(access.get('stack') or access.get('base') in ('sp', 'gp'))


def split_top_level(value, separator=','):
    """Split a string at separators outside balanced parentheses and brackets.

    A bracketed term is one loaded word: "[one of 0x1, 0x2]" is a single value read from
    one of two addresses, not a choice between two values.
    """
    parts = []
    depth = 0
    start = 0
    for index, char in enumerate(value):
        if char in '([':
            depth += 1
        elif char in ')]':
            depth = max(0, depth - 1)
        elif char == separator and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def sc(x, bits=16):
    return x - (1 << bits) if x >> (bits - 1) else x


# ===================================================================== decoding

_MD = None


def capstone_md():
    global _MD
    if _MD is None:
        try:
            import capstone
        except ImportError:
            raise SystemExit('hostfacts: needs capstone and pyelftools; run it as\n  '
                             'uv run --with capstone --with pyelftools python -I %s ...' % sys.argv[0])
        _MD = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN)
        _MD.detail = True
    return _MD


def regnum(md, rid):
    name = md.reg_name(rid)
    if name in GPR:
        return '$%d' % GPR[name]
    if re.fullmatch(r'f\d+', name):
        return '$' + name
    return '$' + name


def decode(w, addr):
    """(mnemonic, operands) in the form facts.py reads from objdump -M no-aliases,gpr-names=numeric."""
    md = capstone_md()
    op, rs, rt, rd = w >> 26, (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
    R = lambda n: '$%d' % n  # noqa: E731
    simm = sc(w & 0xffff)
    if w == 0:
        return 'sll', ['$0', '$0', '0x0']
    if op in (4, 5, 0x14, 0x15):
        mn = {4: 'beq', 5: 'bne', 0x14: 'beql', 0x15: 'bnel'}[op]
        return mn, [R(rs), R(rt), '%x' % ((addr + 4 + (simm << 2)) & M64)]
    if op in (2, 3):
        return ('j' if op == 2 else 'jal'), ['%x' % (((addr + 4) & ~0xfffffff & M64) | ((w & 0x3ffffff) << 2))]
    if op == 0x13:
        fn = w & 0x3f
        fr, ft, fs, fd = rs, rt, rd, (w >> 6) & 31
        fmadd = {0x20: 'madd.s', 0x21: 'madd.d', 0x28: 'msub.s', 0x29: 'msub.d',
                 0x30: 'nmadd.s', 0x31: 'nmadd.d', 0x38: 'nmsub.s', 0x39: 'nmsub.d'}
        if fn in fmadd:
            return fmadd[fn], ['$f%d' % fd, '$f%d' % fr, '$f%d' % fs, '$f%d' % ft]
        indexed = {0x00: ('lwxc1', True), 0x01: ('ldxc1', True),
                   0x08: ('swxc1', True), 0x09: ('sdxc1', True),
                   0x0f: ('prefx', False)}
        if fn in indexed:
            mn, floating = indexed[fn]
            reg = '$f%d' % fs if floating else '$%d' % fs
            return mn, [reg, R(rs), R(ft)]
    ins = next(iter(md.disasm(struct.pack('>I', w), addr)), None)
    if ins is None:
        return '.word', ['0x%08x' % w]
    mn = ins.mnemonic
    if mn in ('move', 'negu', 'neg', 'not') and op == 0 and (w & 0x3f) in RTYPE:
        return RTYPE[w & 0x3f], [R(rd), R(rs), R(rt)]
    ops = []
    for o in ins.operands:
        if o.type == 1:
            ops.append(regnum(md, o.reg))
        elif o.type == 2:
            v = o.imm
            if mn in ZERO_IMM:
                v &= 0xffff
                ops.append('0x%x' % v)
                continue
            elif mn.startswith('b') or mn in ('j', 'jal') or mn == 'bal':
                ops.append('%x' % (v & M64))
                continue
            ops.append('0x%x' % v if mn in SHIFTS else str(v))
        elif o.type == 3:
            ops.append('%d(%s)' % (o.mem.disp, regnum(md, o.mem.base)))
    return mn, ops


def object_relocs(elf, secname):
    """r_offset -> (type, symbol, addend) as objdump -r shows it (the addend only for RELA)."""
    from elftools.elf.descriptions import describe_reloc_type
    out = {}
    for rn in ('.rel' + secname, '.rela' + secname):
        rs = elf.get_section_by_name(rn)
        if rs is None or not hasattr(rs, 'iter_relocations'):
            continue
        symtab = elf.get_section(rs['sh_link'])
        for r in rs.iter_relocations():
            t = describe_reloc_type(r['r_info_type'] & 0xff, elf)
            if t in ('R_MIPS_NONE', 'unknown'):
                continue
            sy = symtab.get_symbol(r['r_info_sym'])
            nm = sy.name
            if sy['st_info']['type'] == 'STT_SECTION':
                nm = elf.get_section(sy['st_shndx']).name
            out.setdefault(r['r_offset'], (t, nm, r['r_addend'] if 'r_addend' in r.entry else 0))
    return out


class HostImage(facts.Image):
    """facts.Image with a Capstone disassembler in place of the container's objdump."""

    def disassemble(self, addr, size, section):
        if self.flat:
            o = addr - self.load
            raw = self.data[max(o, 0):o + size]
            rel = {}
        elif self.kind == 'object':
            sec = self.elf.get_section_by_name(section) if section else None
            if sec is None:
                return []
            raw = sec.data()[addr:addr + size]
            rel = object_relocs(self.elf, section)
        else:
            raw = self.read(addr, size) or b''
            rel = {}
        out = []
        for k in range(0, len(raw) - 3, 4):
            a = addr + k
            w = struct.unpack('>I', raw[k:k + 4])[0]
            mn, ops = decode(w, a)
            out.append({'addr': a, 'mn': mn, 'ops': ops, 'reloc': rel.get(a), 'word': w})
        return out


def host_image(path, member=None, flat=False, load=0, isa='mips4'):
    return HostImage(path, member, flat, load, isa)


def routine_for(path, routine, member=None, size=None, flat=False, load=0, isa='mips4', errors=None,
                arch='mips', offset=0, abi=None, elf=False, data=None):
    if elf and (flat or arch not in ('arm', 'thumb')):
        raise ValueError('--elf requires ARM/Thumb and cannot be combined with --flat')
    if arch != 'mips':
        if member:
            raise ValueError('non-MIPS firmware does not support archive members')
        img = FirmwareImage(path, arch, load, offset, abi, elf=elf, data=data)
        name, addr, size, source = img.find(routine, size)
        return FirmwareRoutine(img, name, addr, size, source)
    img = host_image(path, member, flat, load, isa)
    name, addr, sz, sec, src = img.find(routine, size)
    if flat and not sz:
        sz = facts.scan_size(img, addr)
        src = 'scanned to the last reachable return'
    return facts.Routine(img, name, addr, sz, sec if not flat else None, src, errors or facts.DEFAULT_ERRORS)


# ===================================================================== non-MIPS firmware

class FirmwareImage:
    """Flat firmware, mapped ARM ELF, or the MMSC a.out reader's segments."""

    def __init__(self, path, arch, load, offset=0, abi=None, elf=False, data=None):
        import capstone as cs
        self.path, self.arch, self.load = path, arch, load
        if data is None:
            with open(path, 'rb') as stream:
                data = stream.read()
        # `data` is a segment cut out of a container; path then only names it
        self.data = data
        self.kind, self.elf, self.flat = 'flat', None, True
        self.offset, self.symbols, self.aout = offset, {}, None
        self.elf_segments, self.relocations, self.mapping_regions = [], [], []
        self._consumed_elf_relocations = {}
        self.symbol_modes = {}
        self.bits = 16 if arch == 'x86-16' else 32
        self.endian = 'big' if arch in ('m68k', 'coldfire', 'ppc32') else 'little'
        self.abi = abi or {'m68k': 'm68k-sysv', 'coldfire': 'm68k-sysv', 'arm': 'arm-aapcs',
                           'thumb': 'arm-aapcs', 'ppc32': 'ppc-sysv', 'x86-32': 'cdecl32', 'x86-16': 'unknown'}[arch]
        expected = 'm68k-sysv' if arch in ('m68k','coldfire') else 'arm-aapcs' if arch in ('arm','thumb') else 'ppc-sysv' if arch == 'ppc32' else 'cdecl16' if arch=='x86-16' else 'cdecl32'
        if self.abi not in ('unknown',expected):
            raise ValueError('ABI %s is incompatible with %s' % (self.abi,arch))
        if offset < 0 or offset > len(self.data):
            raise ValueError('--offset is outside the file')
        modes = {'m68k': (cs.CS_ARCH_M68K, cs.CS_MODE_BIG_ENDIAN | cs.CS_MODE_M68K_040),
                 'coldfire': (cs.CS_ARCH_M68K, cs.CS_MODE_BIG_ENDIAN | cs.CS_MODE_M68K_040),
                 'arm': (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | cs.CS_MODE_LITTLE_ENDIAN),
                 'thumb': (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | cs.CS_MODE_LITTLE_ENDIAN),
                 'ppc32': (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN),
                 'x86-16': (cs.CS_ARCH_X86, cs.CS_MODE_16), 'x86-32': (cs.CS_ARCH_X86, cs.CS_MODE_32)}
        self.md = cs.Cs(*modes[arch])
        self.md.detail = True
        self.sections = [{'name': 'flat', 'address': hex(load), 'offset': hex(offset),
                          'size': len(self.data) - offset, 'flags': 'AX'}]
        if elf:
            if not self.data.startswith(b'\x7fELF'):
                raise ValueError('--elf input has no ELF header')
            if arch not in ('arm', 'thumb'):
                raise ValueError('non-MIPS ELF input currently requires ARM or Thumb mode')
            if offset:
                raise ValueError('--offset cannot be combined with an ARM ELF image')
            try:
                self.read_arm_elf()
            except ValueError:
                raise
            except (IndexError, KeyError, TypeError, struct.error) as error:
                raise ValueError('invalid ARM ELF metadata: %s' % error) from error
            except __import__('elftools.common.exceptions', fromlist=['ELFError']).ELFError as error:
                raise ValueError('invalid ARM ELF metadata: %s' % error) from error
        # The header and nlist are not mapped into the controller's address space.
        if arch.startswith('x86') and len(self.data) >= 32 and self.data[:4] == b'\x07\x01\x00\x00':
            from sysco import mmsc_aout
            self.aout = mmsc_aout.Image(self.data)
            if offset:
                raise ValueError('--offset cannot be combined with an MMSC a.out image')
            if load != self.aout.entry:
                raise ValueError('--load must match the MMSC a.out entry address')
            self.kind = 'a.out'
            self.sections = [{'name': s.name, 'address': hex(s.addr), 'offset': hex(s.fileoff),
                              'size': s.size, 'flags': 'AX' if s.name == 'text' else 'AW'}
                             for s in self.aout.segments]
            for s in self.aout.symbols:
                if s.kind == 'text' and not s.marker:
                    self.symbols.setdefault(s.name, []).append((s.value, s.size))

    def read_arm_elf(self):
        from elftools.elf.sections import SymbolTableSection
        from elftools.elf.relocation import RelocationSection
        self.elf = facts.inventory.elf_of(self.data)
        elf = self.elf
        if (elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_ARM'
                or elf['e_type'] not in ('ET_EXEC', 'ET_DYN')):
            raise ValueError('expected a little-endian ARM ELF32 executable or shared object')
        self.kind, self.flat = 'elf', False
        for segment in elf.iter_segments():
            if segment['p_type'] != 'PT_LOAD':
                continue
            a, off, size, mem, flags = (segment[k] for k in ('p_vaddr', 'p_offset', 'p_filesz', 'p_memsz', 'p_flags'))
            align = segment['p_align']
            if (size > mem or off + size > len(self.data) or a + mem > 1 << 32
                    or align > 1 and (align & (align-1) or a % align != off % align)):
                raise ValueError('invalid ARM ELF PT_LOAD bounds or alignment')
            if mem:
                self.elf_segments.append(dict(address=a, offset=off, size=size, memory_size=mem, flags=flags))
        self.elf_segments.sort(key=lambda s:s['address'])
        if not self.elf_segments or self.load != self.elf_segments[0]['address']:
            raise ValueError('--load must equal the lowest mapped linked ELF PT_LOAD address')
        for left, right in zip(self.elf_segments, self.elf_segments[1:]):
            if left['address'] + left['memory_size'] > right['address']:
                raise ValueError('overlapping ARM ELF PT_LOAD mappings')
        sections = list(elf.iter_sections())
        if not sections:
            raise ValueError('ARM ELF mapped analysis requires section and symbol metadata')
        self.sections = []
        for section in sections:
            if section['sh_flags'] & 2 and (isinstance(section['sh_type'], int) or section['sh_type'] == 'SHT_RELR'):
                raise ValueError('unsupported allocated ARM ELF section type')
            if section['sh_type'] != 'SHT_NOBITS' and section['sh_offset'] + section['sh_size'] > len(self.data):
                raise ValueError('ARM ELF section extends beyond file')
            if section['sh_flags'] & 2:
                self.sections.append(dict(name=section.name, address=hex(section['sh_addr']),
                                          offset=hex(section['sh_offset']), size=section['sh_size'],
                                          flags=''.join(c for mask,c in ((2,'A'),(1,'W'),(4,'X')) if section['sh_flags'] & mask)))
        maps = collections.defaultdict(list)
        for table in sections:
            if not isinstance(table, SymbolTableSection):
                continue
            if table['sh_entsize'] != 16 or table['sh_size'] % 16:
                raise ValueError('invalid ARM ELF symbol table entry size')
            for symbol in table.iter_symbols():
                index = symbol['st_shndx']
                if not isinstance(index, int) or not 0 < index < len(sections):
                    continue
                section = sections[index]
                value, size = symbol['st_value'], symbol['st_size']
                mapping = re.fullmatch(r'\$([atd])(?:\..*)?', symbol.name)
                if mapping:
                    if not section['sh_flags'] & 2:
                        continue
                    if (symbol['st_info']['type'] != 'STT_NOTYPE'
                            or symbol['st_info']['bind'] != 'STB_LOCAL' or size):
                        raise ValueError('invalid ARM ELF mapping symbol attributes')
                    if not section['sh_addr'] <= value < section['sh_addr'] + section['sh_size']:
                        raise ValueError('ARM ELF mapping symbol outside its section')
                    maps[index].append((value, mapping[1]))
                    continue
                if (symbol['st_info']['type'] != 'STT_FUNC' or not symbol.name
                        or section['sh_flags'] & 6 != 6 or section['sh_type']=='SHT_NOBITS'):
                    continue
                address = value & ~1
                mode = 'thumb' if value & 1 else 'arm'
                if not section['sh_addr'] <= address < section['sh_addr'] + section['sh_size'] or address + size > section['sh_addr'] + section['sh_size']:
                    raise ValueError('ARM ELF function symbol outside its executable section')
                if address % (2 if mode == 'thumb' else 4):
                    raise ValueError('misaligned ARM ELF function symbol')
                if not any(s['flags'] & 1 and s['address'] <= address
                           and address+max(1,size) <= s['address']+s['size'] for s in self.elf_segments):
                    continue
                if address in self.symbol_modes and self.symbol_modes[address] != mode:
                    raise ValueError('conflicting ARM ELF function modes')
                self.symbol_modes[address] = mode
                hit = (address, size)
                if hit not in self.symbols.setdefault(symbol.name, []):
                    self.symbols[symbol.name].append(hit)
        for index, values in maps.items():
            values = sorted(set(values)); section = sections[index]
            for n, (start, mode) in enumerate(values):
                if n and start == values[n-1][0]:
                    raise ValueError('conflicting ARM ELF mapping symbols')
                end = values[n+1][0] if n+1 < len(values) else section['sh_addr'] + section['sh_size']
                self.mapping_regions.append((start, end, {'a':'arm', 't':'thumb', 'd':'data'}[mode]))
        # AAELF32 defines data and instruction places independently. No relocation
        # is applied here: known extents only identify bytes that are not constants.
        widths = {1:4, 2:4, 3:4, 4:4, 5:2, 6:4, 7:2, 8:1, 9:4, 10:4, 11:2,
                  17:4, 18:4, 19:4, 21:4, 22:4, 23:4, 28:4, 29:4, 30:4,
                  38:4, 40:4, 43:4, 44:4, 45:4, 46:4}
        for section_index, section in enumerate(sections):
            if not isinstance(section, RelocationSection):
                continue
            target = section['sh_info']
            if target and (target >= len(sections) or not sections[target]['sh_flags'] & 2):
                if target >= len(sections):
                    raise ValueError('invalid ARM ELF relocation target section')
                continue
            expected = 12 if section.is_RELA() else 8
            if section['sh_entsize'] != expected or section['sh_size'] % expected:
                raise ValueError('invalid ARM ELF relocation entry size')
            table = elf.get_section(section['sh_link'])
            if not isinstance(table, SymbolTableSection):
                raise ValueError('ARM ELF relocation has no symbol table')
            for relocation_index, relocation in enumerate(section.iter_relocations()):
                kind, address, symbol_index = (relocation[k] for k in ('r_info_type','r_offset','r_info_sym'))
                if symbol_index >= table.num_symbols():
                    raise ValueError('ARM ELF relocation symbol index outside table')
                if kind == 0:
                    continue
                symbol = table.get_symbol(symbol_index)
                if kind == 20:
                    if elf['e_type'] != 'ET_EXEC' or not symbol['st_size']:
                        raise ValueError('ARM ELF COPY relocation has unknown extent')
                    width = symbol['st_size']
                else:
                    width = widths.get(kind)
                    if width is None:
                        raise ValueError('ARM ELF relocation type %d has unknown extent' % kind)
                if not any(s['address'] <= address and address + width <= s['address'] + s['memory_size'] for s in self.elf_segments):
                    raise ValueError('ARM ELF relocation place outside mapped memory')
                taint = dict(address=address, size=width, type=kind, symbol=symbol.name,
                             addend=relocation['r_addend'] if section.is_RELA() else None,
                             section=section.name)
                self.relocations.append(taint)
                self._consumed_elf_relocations[(section_index,relocation_index)] = taint
        self.check_dynamic_relocations(sections)

    def check_dynamic_relocations(self, sections):
        """Refuse dynamic tables whose bytes or symbol metadata were not parsed."""
        from elftools.elf.sections import SymbolTableSection
        from elftools.elf.relocation import RelocationSection
        critical = {'DT_REL','DT_RELSZ','DT_RELENT','DT_RELA','DT_RELASZ','DT_RELAENT',
                    'DT_JMPREL','DT_PLTRELSZ','DT_PLTREL','DT_SYMTAB','DT_SYMENT','DT_STRTAB','DT_STRSZ',
                    'DT_RELCOUNT','DT_RELACOUNT'}
        # Generic ABI tags locate the handled tables or describe binding,
        # initialization and names. AAELF32 adds symbol-version metadata;
        # RELCOUNT/RELACOUNT describe prefixes of the already parsed tables.
        # Unreviewed extensions can introduce additional relocation places.
        allowed = critical | {'DT_NEEDED','DT_PLTGOT','DT_HASH','DT_INIT','DT_FINI',
                    'DT_SONAME','DT_RPATH','DT_SYMBOLIC','DT_DEBUG','DT_TEXTREL','DT_BIND_NOW',
                    'DT_INIT_ARRAY','DT_FINI_ARRAY','DT_INIT_ARRAYSZ','DT_FINI_ARRAYSZ',
                    'DT_RUNPATH','DT_FLAGS','DT_PREINIT_ARRAY','DT_PREINIT_ARRAYSZ',
                    'DT_SYMTAB_SHNDX','DT_SYMTABSZ','DT_VERSYM','DT_VERDEF','DT_VERDEFNUM',
                    'DT_VERNEED','DT_VERNEEDNUM','DT_RELCOUNT','DT_RELACOUNT'}
        for segment in self.elf.iter_segments():
            if segment['p_type'] != 'PT_DYNAMIC':
                continue
            size = segment['p_filesz']
            if size % 8 or self.read(segment['p_vaddr'], size) != segment.data():
                raise ValueError('ARM ELF dynamic metadata is not completely mapped')
            tags = {}; terminated = False
            for n, tag in enumerate(segment.iter_tags()):
                if n >= size // 8:
                    break
                key, value = tag['d_tag'], tag['d_val']
                if key == 'DT_NULL':
                    terminated = True; break
                if key not in allowed:
                    raise ValueError('unsupported ARM ELF dynamic tag %s' % (hex(key)if isinstance(key,int)else key))
                if key in critical and key in tags and tags[key] != value:
                    raise ValueError('conflicting ARM ELF dynamic metadata')
                tags[key] = value
            if not terminated:
                raise ValueError('unterminated ARM ELF dynamic metadata')
            symbol_tables = []
            if 'DT_SYMTAB' in tags:
                if tags.get('DT_SYMENT') != 16 or 'DT_STRTAB' not in tags or 'DT_STRSZ' not in tags:
                    raise ValueError('incomplete ARM ELF dynamic symbol metadata')
                for index, table in enumerate(sections):
                    if not isinstance(table, SymbolTableSection) or table['sh_addr'] != tags['DT_SYMTAB']:
                        continue
                    if self.read(table['sh_addr'],table['sh_size']) != table.data():
                        continue
                    strings = self.elf.get_section(table['sh_link']); string_size = tags['DT_STRSZ']
                    if (strings['sh_addr'] != tags['DT_STRTAB'] or string_size > strings['sh_size']
                            or self.read(tags['DT_STRTAB'],string_size) != strings.data()[:string_size]):
                        continue
                    data = strings.data()[:string_size]
                    if any(s['st_name'] >= string_size or b'\0' not in data[s['st_name']:] for s in table.iter_symbols()):
                        continue
                    symbol_tables.append(index)
                if not symbol_tables:
                    raise ValueError('ARM ELF dynamic symbol/string tables disagree with sections')
            tables = []
            for kind in ('REL','RELA'):
                prefix = 'DT_'+kind
                count = tags.get(prefix+'COUNT',0)
                if prefix in tags or tags.get(prefix+'SZ',0):
                    entry = 8 if kind=='REL' else 12
                    if prefix not in tags or prefix+'SZ' not in tags or tags.get(prefix+'ENT') != entry:
                        raise ValueError('incomplete ARM ELF dynamic relocation table')
                    tables.append((tags[prefix],tags[prefix+'SZ'],entry,count))
                if count and (prefix not in tags or count > tags.get(prefix+'SZ',0)//(8 if kind=='REL'else 12)):
                    raise ValueError('invalid ARM ELF relative relocation count')
            if 'DT_JMPREL' in tags or tags.get('DT_PLTRELSZ',0):
                if 'DT_JMPREL' not in tags or 'DT_PLTRELSZ' not in tags or tags.get('DT_PLTREL') not in (7,17):
                    raise ValueError('incomplete ARM ELF PLT relocation table')
                tables.append((tags['DT_JMPREL'],tags['DT_PLTRELSZ'],12 if tags['DT_PLTREL']==7 else 8,0))
            for address, length, entry, relative_count in tables:
                if length % entry:
                    raise ValueError('invalid ARM ELF dynamic relocation table bounds')
                if not length:
                    continue
                if self.read(address,length) is None:
                    raise ValueError('invalid ARM ELF dynamic relocation table bounds')
                for place in range(address,address+length,entry):
                    matching = [(i,s) for i,s in enumerate(sections) if isinstance(s,RelocationSection)
                                and (12 if s.is_RELA()else 8)==entry
                                and s['sh_addr'] <= place and place+entry <= s['sh_addr']+s['sh_size']
                                and (place-s['sh_addr'])%entry==0]
                    if not matching:
                        raise ValueError('ARM ELF dynamic relocation table has unparsed records')
                    for section_index, section in matching:
                        off = place-section['sh_addr']
                        if self.read(place,entry) != section.data()[off:off+entry]:
                            raise ValueError('ARM ELF dynamic relocation bytes disagree with sections')
                        if section['sh_link'] not in symbol_tables:
                            raise ValueError('ARM ELF dynamic relocation symbol table disagrees with sections')
                        relocation_index = off // entry
                        relocation = section.get_relocation(relocation_index)
                        kind = relocation['r_info_type']
                        if (place-address)//entry < relative_count and kind != 23:
                            raise ValueError('ARM ELF relative relocation count prefix is not RELATIVE')
                        # Matching bytes do not prove the earlier section pass
                        # consumed them: sh_info may have filtered that section.
                        if kind:
                            taint = self._consumed_elf_relocations.get((section_index,relocation_index))
                            if (taint is None or taint not in self.relocations
                                    or taint['address'] != relocation['r_offset'] or taint['type'] != kind):
                                raise ValueError('active ARM ELF relocation record was not consumed into taint')

    def relocation_overlap(self, addr, size):
        return any(r['address'] < addr + size and addr < r['address'] + r['size'] for r in self.relocations)

    def code_value(self, address):
        # Instruction coordinates do not establish where an ELF image was loaded.
        return facts.add(('in','ELF load bias (unknown)'),address & 0xffffffff) if self.elf else facts.C(address)

    def linked_address(self, value):
        root, offset = facts.split(value)
        if self.elf and root == ('in','ELF load bias (unknown)'):
            return offset & 0xffffffff
        return None

    def read_constant(self, addr, size):
        if self.elf:
            if self.relocation_overlap(addr, size):
                return None
            if not any(s['address'] <= addr and addr + size <= s['address'] + s['size'] and not s['flags'] & 2 for s in self.elf_segments):
                return None
            if any('W' in s['flags'] and int(s['address'],16) < addr + size and addr < int(s['address'],16) + s['size'] for s in self.sections):
                return None
        return self.read(addr, size)

    def check_instruction(self, addr, size):
        if self.elf:
            if self.relocation_overlap(addr, size):
                raise ValueError('relocation-dependent instruction at 0x%x; no fact sheet emitted' % addr)
            if self.symbol_modes.get(addr,self.arch) != self.arch:
                raise ValueError('ARM ELF instruction mode differs from selected architecture at 0x%x' % addr)
            for hits in self.symbols.values():
                if any(a < addr+size and addr < a+z and self.symbol_modes[a] != self.arch for a,z in hits):
                    raise ValueError('ARM ELF instruction mode differs from containing function at 0x%x' % addr)
            for start, end, mode in self.mapping_regions:
                if start < addr + size and addr < end and mode != self.arch:
                    raise ValueError('ARM ELF instruction mode/data mismatch at 0x%x' % addr)

    def read(self, addr, size):
        if size < 0:
            return None
        if self.elf:
            for s in self.elf_segments:
                if s['address'] <= addr and addr + size <= s['address'] + s['size']:
                    off = s['offset'] + addr - s['address']
                    return self.data[off:off+size]
            return None
        if self.aout:
            for s in self.aout.segments:
                if s.fileoff >= 0 and s.addr <= addr and addr + size <= s.addr + s.size:
                    off = s.fileoff + addr - s.addr
                    return self.data[off:off + size]
            return None
        off = addr - self.load + self.offset
        if self.offset <= off and off + size <= len(self.data):
            return self.data[off:off + size]
        return None

    def find(self, routine, size):
        if routine.startswith('0x'):
            addr = int(routine, 16)
            names = [(n, z) for n, hits in self.symbols.items() for a, z in hits if a == addr]
            name, inferred = names[0] if names else ('', None)
        else:
            hits = self.symbols.get(routine, [])
            if len({a for a, _ in hits}) != 1:
                raise ValueError('routine is absent or ambiguous; use 0xADDR --size N')
            name, (addr, inferred) = routine, hits[0]
        if self.elf:
            if self.arch == 'thumb':
                addr &= ~1
            if addr % (2 if self.arch == 'thumb' else 4) or self.symbol_modes.get(addr, self.arch) != self.arch:
                raise ValueError('ARM ELF symbol mode differs from selected architecture')
            for hits in self.symbols.values():
                if any(a <= addr < a+z and self.symbol_modes[a] != self.arch for a,z in hits):
                    raise ValueError('ARM ELF containing function mode differs from selected architecture')
            inferred_sizes = {z for a,z in self.symbols.get(name, []) if a == addr and z}
            if len(inferred_sizes) > 1 and size is None:
                raise ValueError('ARM ELF symbol size is ambiguous; use --size')
            inferred = next(iter(inferred_sizes)) if len(inferred_sizes) == 1 else None
        size = size if size is not None else inferred
        if not size or size < 0:
            if self.elf:
                raise ValueError('ARM ELF function requires --size; no boundary is guessed')
            raise ValueError('flat firmware requires --size; no routine boundary is guessed')
        if self.read(addr, size) is None:
            raise ValueError('routine range lies outside the mapped image')
        if self.elf and not any('X' in s['flags'] and int(s['address'],16) <= addr and addr + size <= int(s['address'],16) + s['size'] for s in self.sections):
            raise ValueError('routine range lies outside an ELF executable section')
        if self.elf and not any(s['flags'] & 1 and s['address'] <= addr and addr + size <= s['address'] + s['size'] for s in self.elf_segments):
            raise ValueError('routine range lies outside an executable ELF PT_LOAD')
        source = ('ELF symbol size' if self.elf else 'next a.out symbol (inferred)') if inferred and size == inferred else 'given'
        return name, addr, size, source

    def name_at(self, addr):
        names = sorted(n for n, hits in self.symbols.items() if any(a == addr for a, _ in hits))
        return names[0] if len(names) == 1 else None


class FirmwareState:
    def __init__(self, regs=None, memory=None, flags=None, direction=None):
        self.regs, self.memory, self.flags = regs or {}, memory or {}, flags
        self.direction = direction

    def copy(self):
        return FirmwareState(dict(self.regs), dict(self.memory), self.flags, self.direction)

    def merged(self, other):
        # A disagreement is unknown. Do not pick whichever predecessor ran last.
        regs = {k: v for k, v in self.regs.items() if v == other.regs.get(k)}
        memory = {k: v for k, v in self.memory.items() if v == other.memory.get(k)}
        return FirmwareState(regs, memory, self.flags if self.flags == other.flags else None,
                             self.direction if self.direction == other.direction else None)

    def key(self):
        return self.regs, self.memory, self.flags, self.direction


PPC_MEMORY = {'lwz': False, 'lhz': False, 'lha': False, 'lbz': False, 'lfs': False, 'lfd': False,
              'stw': True, 'sth': True, 'stb': True, 'stfs': True, 'stfd': True, 'ld': False, 'std': True}
# Indexed forms, rA + rB: the D-form mnemonic with the width and direction it shares. A `u` form (lwzux)
# also writes the address back to rA; the byte-reversed forms move the same widths.
PPC_INDEXED = {'lwzx': 'lwz', 'lhzx': 'lhz', 'lhax': 'lha', 'lbzx': 'lbz', 'lfsx': 'lfs', 'lfdx': 'lfd',
               'stwx': 'stw', 'sthx': 'sth', 'stbx': 'stb', 'stfsx': 'stfs', 'stfdx': 'stfd',
               'lwbrx': 'lwz', 'lhbrx': 'lhz', 'stwbrx': 'stw', 'sthbrx': 'sth',
               # Load-reserved and store-conditional have no displacement, only rA|0 + rB.
               'lwarx': 'lwz', 'stwcx.': 'stw', 'ldarx': 'ld', 'stdcx.': 'std'}
PPC_CONDITIONS = {'eq', 'ne', 'lt', 'le', 'gt', 'ge', 'ns', 'so', 'dnz', 'dz', 'dnzt', 'dnzf', 'dzt', 'dzf'}


# m68k and ColdFire mnemonics (size suffix removed) whose last operand is the only thing they write.
M68K_WRITES_LAST = {
    'move', 'movea', 'moveq', 'mov3q', 'mvs', 'mvz', 'movec', 'lea', 'add', 'adda', 'addi', 'addq', 'addx',
    'sub', 'suba', 'subi', 'subq', 'subx', 'and', 'andi', 'or', 'ori', 'eor', 'eori', 'asl', 'asr', 'lsl',
    'lsr', 'rol', 'ror', 'roxl', 'roxr', 'neg', 'negx', 'not', 'clr', 'ext', 'extb', 'swap', 'bset', 'bclr',
    'bchg', 'bitrev', 'byterev', 'ff1', 'mulu', 'muls', 'divu', 'divs', 'remu', 'rems', 'tas', 'sats', 'abs',
    'st', 'sf', 'shi', 'sls', 'scc', 'scs', 'sne', 'seq', 'svc', 'svs', 'spl', 'smi', 'sge', 'slt', 'sgt',
    'sle', 'shs', 'slo'}
# Instructions that change no register, except through a postincrement or predecrement operand.
M68K_WRITES_NONE = {'cmp', 'cmpa', 'cmpi', 'cmpm', 'tst', 'btst', 'pea', 'nop', 'cpushl', 'cpusha', 'cinvl',
                    'cinva', 'wddata', 'wdebug', 'pulse'}


def ppc_width(mnemonic):
    """Bytes moved by a PowerPC load or store mnemonic; 4 for anything else."""
    plain = mnemonic[:-1] if mnemonic.endswith('u') and mnemonic[:-1] in PPC_MEMORY else mnemonic
    if plain in ('lbz', 'stb'):
        return 1
    if plain in ('lhz', 'lha', 'sth'):
        return 2
    if plain in ('lfd', 'stfd', 'ld', 'std'):
        return 8
    return 4


def ppc_branch(mnemonic):
    """(kind, via, condition) for a PowerPC branch mnemonic, or None for any other instruction.

    via is None for a direct branch, else 'lr' or 'ctr'.
    """
    simple = {'b': ('jump', None), 'ba': ('jump', None), 'bl': ('call', None), 'bla': ('call', None),
              'blr': ('return', 'lr'), 'bctr': ('jump', 'ctr'), 'blrl': ('call', 'lr'),
              'bctrl': ('call', 'ctr')}
    if mnemonic in simple:
        kind, via = simple[mnemonic]
        return kind, via, None
    if not mnemonic.startswith('b'):
        return None
    rest, via = mnemonic[1:], None
    for suffix in ('lrl', 'ctrl', 'lr', 'ctr'):
        if rest.endswith(suffix) and rest[:-len(suffix)] in PPC_CONDITIONS:
            via, rest = suffix, rest[:-len(suffix)]
            break
    link = via in ('lrl', 'ctrl')
    if via is None:
        if rest.endswith('a') and rest[:-1] in PPC_CONDITIONS:
            rest = rest[:-1]
        if rest.endswith('l') and rest[:-1] in PPC_CONDITIONS:
            rest, link = rest[:-1], True
    if rest not in PPC_CONDITIONS:
        return None
    if via in ('lr', 'lrl'):
        return ('conditional-call' if link else 'conditional-return'), 'lr', rest
    if via in ('ctr', 'ctrl'):
        return ('conditional-call' if link else 'conditional'), 'ctr', rest
    return ('conditional-call' if link else 'conditional'), None, rest


class FirmwareRoutine:
    """Architecture adapters share one worklist, symbolic values and fact-sheet format.

    Only modelled instructions preserve their results. Other instructions invalidate their
    written registers and flags; undecodable bytes end a path rather than bridging a gap.
    """

    def __init__(self, img, name, addr, size, source):
        self.img, self.name, self.addr, self.size, self.source = img, name, addr, size, source
        self.R = facts.Render(img)
        self.arch = img.arch
        self.m68k = self.arch in ('m68k', 'coldfire')
        self.arm = self.arch in ('arm', 'thumb')
        self.x86 = self.arch.startswith('x86')
        self.ppc = self.arch == 'ppc32'
        self.word = 2 if img.bits == 16 else 4
        self.sp = 'a7' if self.m68k else 'sp' if self.arm else 'r1' if self.ppc else 'sp' if img.bits == 16 else 'esp'
        self.retreg = 'd0' if self.m68k else 'r0' if self.arm else 'r3' if self.ppc else 'ax' if img.bits == 16 else 'eax'
        self.insns = []
        self.warnings = set()
        self._index_base = None
        raw = img.read(addr, size)
        if self.arch == 'arm':
            # ARM words have fixed boundaries. A literal can be undecodable even
            # when a direct branch reaches valid code later in the same span.
            decoded = []
            gaps = []
            for off in range(0, size, 4):
                word = raw[off:off + 4]
                ins = next(img.md.disasm(word, addr + off), None) if len(word) == 4 else None
                if ins is not None:
                    decoded.append(ins)
                elif gaps and gaps[-1][1] == addr + off:
                    gaps[-1][1] += len(word)
                else:
                    gaps.append([addr + off, addr + off + len(word)])
            for first, end in gaps:
                self.warnings.add('undecodable bytes at 0x%x-0x%x; fall-through stops at this range' % (first, end))
        else:
            # M68K can report a truncated instruction with a clipped size and
            # invented extension operands. Lookahead gives its full length;
            # the range check below keeps all added bytes out of the facts.
            decoded = img.md.disasm(raw + bytes(32) if self.m68k else raw, addr)
        # Linear decoding supplies instruction boundaries only; reachability is computed below.
        for i in decoded:
            if i.address + i.size > addr + size:
                break
            self.insns.append({'addr': i.address, 'size': i.size, 'mn': i.mnemonic,
                               'ops': i.op_str, 'bytes': i.bytes.hex(), '_cs': i})
        self.at = {i['addr']: n for n, i in enumerate(self.insns)}
        self.in_states = {}
        self.out_states = {}
        self.edges = {}
        self.conditions = {}
        end = self.insns[-1]['addr'] + self.insns[-1]['size'] if self.insns else addr
        if self.arch != 'arm' and end != addr + size:
            self.warnings.add('decoder stopped at 0x%x; remaining bytes are not instructions' % end)
        if self.arch == 'coldfire':
            self.warnings.add('ColdFire uses the 68040 decoder for the common ISA subset; unsupported opcodes are unknown')
        if self.img.bits == 16:
            self.warnings.add('16-bit addresses are segment offsets; segment bases are unknown')
        self.initial_warnings = set(self.warnings)

    def reg(self, ins, rid):
        name = ins.reg_name(rid)
        if self.arm:
            return {'fp': 'r11', 'ip': 'r12', 'sb': 'r9', 'sl': 'r10'}.get(name, name)
        if self.m68k:
            return 'a7' if name == 'sp' else name
        return name

    def fullreg(self, name):
        if not self.x86:
            return name
        for family in ('a', 'b', 'c', 'd'):
            if name in (family + 'l', family + 'h', family + 'x', 'e' + family + 'x'):
                return 'e' + family + 'x'
        for family in ('si', 'di', 'bp', 'sp'):
            if name in (family, 'e' + family):
                return 'e' + family
        return name

    def getreg(self, st, name):
        if name in st.regs:
            return st.regs[name]
        full = self.fullreg(name)
        v = st.regs.get(full)
        if name == full:
            return v
        bits = 8 if name.endswith(('h', 'l')) else 16
        shift = 8 if name.endswith('h') else 0
        if v is None and bits == 8:
            v = st.regs.get(full[1:])
        if facts.is_c(v):
            return facts.C((v[1] >> shift) & ((1 << bits) - 1))
        return None

    def setreg(self, st, name, value, width=None):
        full = self.fullreg(name)
        alias_value = value
        if self.x86:
            old = st.regs.get(full)
            for alias in list(st.regs):
                if self.fullreg(alias) == full:
                    del st.regs[alias]
            if name != full:
                bits = 8 if name.endswith(('h', 'l')) else 16
                shift = 8 if name.endswith('h') else 0
                if facts.is_c(alias_value):
                    alias_value = facts.C(alias_value[1] & ((1 << bits) - 1))
                if facts.is_c(old) and facts.is_c(alias_value):
                    mask = ((1 << bits) - 1) << shift
                    value = facts.C((old[1] & ~mask) | ((alias_value[1] << shift) & mask))
                else:
                    value = None
                if alias_value is not None:
                    st.regs[name] = facts.cap(alias_value)
        elif self.m68k and name.startswith('d') and width and width < 4:
            old = st.regs.get(full)
            if facts.is_c(old) and facts.is_c(value):
                mask = (1 << (width * 8)) - 1
                value = facts.C((old[1] & ~mask) | (value[1] & mask))
            else:
                value = None
        if facts.is_c(value):
            value = facts.C(value[1] & 0xffffffff)
        value = facts.cap(self.normalize_value(value))
        if value is None:
            st.regs.pop(full, None)
        else:
            st.regs[full] = value

    def plus(self, a, b):
        if a is None or b is None:
            return None
        if facts.is_c(b):
            value = facts.add(a, b[1])
        elif facts.is_c(a):
            value = facts.add(b, a[1])
        else:
            value = facts.cap(('op', '+', a, b))
        return self.normalize_value(value)

    def normalize_value(self, value):
        if self.arm and value is not None and value[0] == 'add':
            # ARM register indices, folded sums and writeback wrap at 32 bits.
            # Keep equivalent symbolic addresses identical for stack aliasing.
            root, offset = facts.split(value)
            return facts.add(root, sc(offset & 0xffffffff, 32))
        return value

    def width(self, ins, op=None):
        if self.x86:
            if (op is not None and op.type == 3 and ins.opcode[0] == 0xff
                    and (ins.modrm >> 3) & 7 in (3, 5)):
                # Indirect far CALL/JMP reads an offset plus a 16-bit selector.
                # Capstone's memory size varies between the offset and the
                # whole pointer, and can ignore the operand-size override.
                offset_width = 4 if (self.word == 4) != (0x66 in ins.prefix) else 2
                return offset_width + 2
            return op.size if op is not None and op.size else self.word
        if self.m68k:
            if ins.mnemonic.split('.')[0] == 'btst' and len(ins.operands) == 2:
                # Dynamic memory forms may decode with .l; only data-register
                # destinations use a longword, memory always uses a byte.
                return 4 if ins.operands[1].type == 1 else 1
            return {'.b': 1, '.w': 2, '.l': 4, '.s': 4, '.d': 8}.get(ins.mnemonic[-2:], 4)
        mn = ins.mnemonic
        if self.ppc:
            return ppc_width(mn)
        if mn.startswith(('ldrb', 'ldrsb', 'strb')):
            return 1
        if mn.startswith(('ldrh', 'ldrsh', 'strh')):
            return 2
        if mn.startswith(('ldrd', 'strd')):
            return 8
        return 4

    def effective(self, st, ins, op):
        """Return effective address, base name, displacement; no implicit updates here."""
        self._index_base = None
        if self.m68k:
            from capstone import m68k_const as c
            mode = op.address_mode
            if mode in (c.M68K_AM_ABSOLUTE_DATA_SHORT, c.M68K_AM_ABSOLUTE_DATA_LONG):
                a = op.imm
                if mode == c.M68K_AM_ABSOLUTE_DATA_SHORT:
                    a = sc(a & 0xffff)
                return facts.C(a & 0xffffffff), 'absolute', 0
            rid = op.mem.base_reg
            if not rid and mode in (c.M68K_AM_REGI_ADDR, c.M68K_AM_REGI_ADDR_POST_INC, c.M68K_AM_REGI_ADDR_PRE_DEC):
                rid = op.reg
            base = self.reg(ins, rid) if rid else ''
            disp = op.mem.disp
            if mode in (c.M68K_AM_PCI_DISP, c.M68K_AM_PCI_INDEX_8_BIT_DISP):
                v, base = facts.C(ins.address + 2), 'pc'
            else:
                v = self.getreg(st, base)
            if mode == c.M68K_AM_REGI_ADDR_PRE_DEC:
                step = 2 if base == 'a7' and self.width(ins, op) == 1 else self.width(ins, op)
                v = facts.add(v, -step)
            pre = facts.add(v, disp) if facts.is_c(v) else None
            if op.mem.index_reg:
                idx = self.getreg(st, self.reg(ins, op.mem.index_reg))
                if op.mem.index_size == 0:
                    idx = facts.C(sc(idx[1] & 0xffff)) if facts.is_c(idx) else None
                scale = op.mem.scale or 1
                idx = facts.C(idx[1] * scale) if facts.is_c(idx) else idx if scale == 1 else None
                v = self.plus(v, idx)
                # a known base with an index that is not known: the access is base + something
                self._index_base = None if facts.is_c(idx) else pre
            # Full 68020 memory-indirect modes need an extra memory read; never flatten them.
            supported = {c.M68K_AM_REGI_ADDR, c.M68K_AM_REGI_ADDR_POST_INC, c.M68K_AM_REGI_ADDR_PRE_DEC,
                         c.M68K_AM_REGI_ADDR_DISP, c.M68K_AM_AREGI_INDEX_8_BIT_DISP,
                         c.M68K_AM_PCI_DISP, c.M68K_AM_PCI_INDEX_8_BIT_DISP}
            if mode not in supported:
                return None, base, disp
            return facts.add(v, disp), base, disp
        mem = op.mem
        base = self.reg(ins, mem.base) if mem.base else ''
        if self.ppc:
            # D-form only; a zero base register field means the constant zero.
            return facts.add(self.getreg(st, base) if base else facts.C(0), mem.disp), base, mem.disp
        idx = self.reg(ins, mem.index) if mem.index else ''
        if self.arm and base == 'pc':
            v = self.img.code_value((ins.address + (4 if self.arch == 'thumb' else 8)) & ~3)
        elif base:
            v = self.getreg(st, base)
        else:
            v = facts.C(0)
        if self.x86 and mem.segment:
            # FS/GS and explicit real-mode segment overrides have no known base.
            return None, base, mem.disp
        if idx:
            iv = self.getreg(st, idx)
            scale = mem.scale or 1
            if self.arm:
                shift = getattr(op, 'shift', None)
                if shift and shift.type:
                    # ARM shift ids are not x86 scale factors.
                    from capstone.arm_const import ARM_SFT_LSL
                    iv = facts.C(iv[1] << shift.value) if shift.type == ARM_SFT_LSL and facts.is_c(iv) else None
                if getattr(op, 'subtracted', False):
                    iv = facts.C(-iv[1]) if facts.is_c(iv) else None
            elif scale != 1:
                iv = facts.C(iv[1] * scale) if facts.is_c(iv) else None
            v = self.plus(v, iv)
        return facts.add(v, mem.disp), base, mem.disp

    def access(self, events, ins, kind, width, address, base, disp, value=None, implicit=False):
        address = self.normalize_value(address)
        a = {'address': hex(ins.address), 'mnemonic': ins.mnemonic, 'text': ins.mnemonic + ' ' + ins.op_str,
             'kind': kind, 'width': width, 'base': base, 'offset': disp, 'value': self.R(value),
             'implicit': implicit}
        index_base, self._index_base = self._index_base, None
        if facts.is_c(address):
            bits = ins.addr_size * 8 if self.x86 else self.img.bits
            a['absolute'] = hex(address[1] & ((1 << bits) - 1))
        elif index_base is not None and not implicit:
            # base + index with a base that is a known constant and an index that is not: the base is the
            # one part of the address the code fixes
            a['indexed'], a['index_base'] = True, hex(index_base[1] & 0xffffffff)
            if address is not None:
                origin, off = facts.split(address)
                a['origin'], a['origin_offset'] = self.R(origin), off
        elif address is not None:
            origin, off = facts.split(address)
            a['origin'], a['origin_offset'] = self.R(origin), off
        if self.img.elf:
            linked = self.img.linked_address(address)
            if linked is not None:
                a.update(linked_address=hex(linked),coordinate_basis='ELF load-bias-relative')
            elif facts.is_c(address):
                a['coordinate_basis']='runtime constant'
        events['accesses'].append(a)

    def memory(self, st, ins, address, width, events, store=False, value=None, base='', disp=0, implicit=False):
        address = self.normalize_value(address)
        if store and facts.is_c(value):
            value = facts.C(value[1] & ((1 << (width * 8)) - 1))
        self.access(events, ins, 'store' if store else 'load', width, address, base, disp, value, implicit)
        root, off = facts.split(address)
        stack = root is not None and root[0] == 'sp0'
        key = (address, width)
        if store:
            # An arbitrary store can alias earlier stack saves. Unknown addresses discard them.
            if not stack:
                st.memory.clear()
            else:
                for (a, n) in list(st.memory):
                    ar, ao = facts.split(a)
                    if ar == root and off < ao + n and ao < off + width:
                        del st.memory[(a, n)]
                if value is not None:
                    st.memory[key] = value
            return value
        if stack and key in st.memory:
            return st.memory[key]
        literal = self.img.linked_address(address) if self.img.elf else address[1] if facts.is_c(address) else None
        if base == 'pc' and literal is not None:
            raw = self.img.read_constant(literal, width)
            if raw is not None:
                return facts.C(int.from_bytes(raw, self.img.endian))
            if self.img.elf:
                self.warnings.add('0x%x ELF literal at linked 0x%x has relocation, writable or unmapped bytes; value unknown' % (ins.address, literal))
                return None
        if address is None:
            return None
        return facts.cap(('ld', root, off, width))

    def operand(self, st, ins, op, events, address_only=False, store=False, value=None):
        typ = op.type
        if typ == 1:
            name = self.reg(ins, op.reg)
            if store:
                self.setreg(st, name, value, self.width(ins, op))
                return value
            v = self.getreg(st, name)
            if self.arm and self.img.elf and name=='pc':
                v = self.img.code_value(ins.address+(4 if self.arch=='thumb'else 8))
            if self.arm and op.shift.type:
                from capstone import arm_const as ac
                if not facts.is_c(v) or op.shift.type != ac.ARM_SFT_LSL or not 0 <= op.shift.value < 32:
                    return None
                v = facts.C((v[1] << op.shift.value) & 0xffffffff)
            if self.arm and op.subtracted:
                v = facts.C(-v[1]) if facts.is_c(v) else None
            return v
        if typ == 2:
            return facts.C(-op.imm if self.arm and op.subtracted else op.imm)
        if typ == 3:
            a, base, disp = self.effective(st, ins, op)
            if address_only:
                return a
            v = self.memory(st, ins, a, self.width(ins, op), events, store, value, base, disp)
            if self.m68k:
                from capstone import m68k_const as c
                if op.address_mode in (c.M68K_AM_REGI_ADDR_POST_INC, c.M68K_AM_REGI_ADDR_PRE_DEC):
                    step = 2 if base == 'a7' and self.width(ins, op) == 1 else self.width(ins, op)
                    self.setreg(st, base, facts.add(a, step) if op.address_mode == c.M68K_AM_REGI_ADDR_POST_INC else a)
            return v
        return None

    def control(self, ins):
        self.img.check_instruction(ins.address, ins.size)
        """kind, direct target, condition code. Architectures here have no delay slots."""
        mn, op = ins.mnemonic, ins.operands
        if self.m68k:
            shortmn = mn.split('.')[0]
            target = None
            if op:
                if op[0].type == 8:
                    target = (ins.address + 2 + op[0].br_disp.disp) & 0xffffffff
                elif op[0].type == 3 and op[0].address_mode in (16, 17):
                    target = (sc(op[0].imm & 0xffff) if op[0].address_mode == 16 else op[0].imm) & 0xffffffff
            if shortmn in ('rts', 'rte', 'rtr', 'rtd'):
                return 'return', None, None
            if shortmn in ('jsr', 'bsr'):
                return 'call', target, None
            if shortmn in ('jmp', 'bra'):
                return 'jump', target, None
            if shortmn.startswith('db'):
                branch = next((o for o in op if o.type == 8), None)
                target = (ins.address + 2 + branch.br_disp.disp) & 0xffffffff if branch else None
                return 'conditional', target, 'unknown decrement-and-branch condition'
            if shortmn.startswith('b') and shortmn not in ('bset', 'bclr', 'bchg', 'btst', 'bfextu', 'bfexts'):
                return 'conditional', target, shortmn[1:]
        elif self.ppc:
            parsed = ppc_branch(mn)
            if parsed:
                kind, via, cc = parsed
                target = op[-1].imm & 0xffffffff if via is None and op and op[-1].type == 2 else None
                # An explicit CR field other than cr0 is not tracked; the condition stays symbolic.
                if cc and op and op[0].type == 1 and self.reg(ins, op[0].reg).startswith('cr') \
                        and self.reg(ins, op[0].reg) != 'cr0':
                    cc = 'cr-field:' + cc
                return kind, target, cc
        elif self.arm:
            from capstone.arm_const import ARM_CC_AL, ARM_CC_INVALID
            cc = ins.cc
            conditional = cc not in (ARM_CC_AL, ARM_CC_INVALID)
            cond = {1: 'eq', 2: 'ne', 3: 'hs', 4: 'lo', 5: 'mi', 6: 'pl', 7: 'vs', 8: 'vc',
                    9: 'hi', 10: 'ls', 11: 'ge', 12: 'lt', 13: 'gt', 14: 'le'}.get(cc)
            if ins.id in (__import__('capstone').arm_const.ARM_INS_BL, __import__('capstone').arm_const.ARM_INS_BLX):
                return 'conditional-call' if conditional else 'call', op[0].imm if op[0].type == 2 else None, cond
            if mn.startswith('bx') or (ins.insn_name() == 'mov' and not ins.update_flags
                    and len(op) == 2 and op[0].type == 1 and self.reg(ins, op[0].reg) == 'pc'
                    and not op[-1].shift.type):
                reg = self.reg(ins, op[-1].reg) if op[-1].type == 1 else ''
                return ('conditional-return' if conditional else 'return') if reg == 'lr' else ('conditional' if conditional else 'jump'), None, cond
            if mn.startswith(('pop', 'ldm')) and any(o.type == 1 and self.reg(ins, o.reg) == 'pc' for o in op):
                return 'conditional-return' if conditional else 'return', None, cond
            from capstone import arm_const as ac
            if ins.id in (ac.ARM_INS_LDR, ac.ARM_INS_LDRB, ac.ARM_INS_LDRH) and op[0].type == 1 and self.reg(ins,op[0].reg) == 'pc':
                return 'conditional' if conditional else 'jump', None, cond
            if ins.id == ac.ARM_INS_B:
                return 'conditional' if conditional else 'jump', op[0].imm, cond
            if ins.id in (ac.ARM_INS_CBZ, ac.ARM_INS_CBNZ):
                return 'conditional', op[-1].imm, 'cbz' if ins.id == ac.ARM_INS_CBZ else 'cbnz'
            if self.arm_computed_pc_write(ins):
                return 'conditional' if conditional else 'jump', None, cond
        else:
            if mn.startswith(('ret', 'iret')):
                return 'return', None, None
            if mn in ('call', 'lcall'):
                return 'call', op[0].imm if op and op[0].type == 2 else None, None
            if mn in ('jmp', 'ljmp'):
                return 'jump', op[0].imm if op and op[0].type == 2 else None, None
            if mn.startswith('loop') or mn in ('jcxz', 'jecxz'):
                return 'conditional', op[0].imm if op and op[0].type == 2 else None, mn
            if mn.startswith('j'):
                return 'conditional', op[0].imm if op and op[0].type == 2 else None, mn[1:]
        return 'normal', None, None

    def arm_computed_pc_write(self, ins):
        """Explicit destination writes, excluding status-only and modeled transfers."""
        if not self.arm or not ins.operands or ins.operands[0].type != 1:
            return False
        if self.reg(ins,ins.operands[0].reg) != 'pc':
            return False
        operation=ins.insn_name()
        if operation in ('cmp','tst','teq','cmn','mrc','mrc2','vmrs','ldr','ldrb','ldrh','bx','bl','blx','pop') or operation.startswith(('ldm','stm')):
            return False
        if operation=='mov' and not ins.update_flags and len(ins.operands)==2 and not ins.operands[-1].shift.type:
            return False
        if ins.operands[0].access & 2:
            return True
        return any(self.reg(ins,r)=='pc' for r in ins.regs_access()[1])

    def arm_computed_pc_target(self, st, ins):
        # S-bit writes can restore CPSR from an untracked SPSR. Other ALU
        # operations, carry inputs and unsupported shifts remain unresolved.
        operation=ins.insn_name();op=ins.operands
        if ins.update_flags or operation not in ('add','sub'):
            return None
        def value(operand):
            if operand.type==1 and self.reg(ins,operand.reg)=='pc':
                if operand.shift.type or operand.subtracted:
                    return None
                return self.img.code_value(ins.address+(4 if self.arch=='thumb'else 8))
            return self.operand(st,ins,operand,{'accesses':[],'calls':[]})
        if len(op)==3:
            left,right=value(op[1]),value(op[2])
        elif self.arch=='thumb' and operation=='add' and len(op)==2:
            left=self.img.code_value(ins.address+4);right=value(op[1])
        else:
            return None
        if operation=='sub':
            if not facts.is_c(right):
                return None
            right=facts.C(-right[1])
        result=self.plus(left,right)
        target=self.img.linked_address(result) if self.img.elf else result[1]&0xffffffff if facts.is_c(result) else None
        if target is None:
            return None
        if self.arch=='thumb':
            return target & ~1
        return target if target & 3 == 0 else None

    def ppc_transfer(self, st, old, ins, events):
        """Model the PowerPC instructions that move addresses and constants; False for the rest."""
        mn, op = ins.mnemonic, ins.operands
        reg = lambda o: self.reg(ins, o.reg)
        val = lambda o: facts.C(0) if o.type == 1 and not o.reg else (
            self.getreg(st, reg(o)) if o.type == 1 else facts.C(o.imm) if o.type == 2 else None)
        if mn in ('li', 'lis') and len(op) == 2 and op[1].type == 2:
            imm = sc(op[1].imm & 0xffff) if mn == 'li' else (op[1].imm & 0xffff) << 16
            self.setreg(st, reg(op[0]), facts.C(imm & 0xffffffff))
            return True
        if mn == 'mr' and len(op) == 2:
            self.setreg(st, reg(op[0]), val(op[1]))
            return True
        if mn in ('addi', 'addis', 'subi') and len(op) == 3 and op[2].type == 2:
            imm = sc(op[2].imm & 0xffff)
            imm = imm << 16 if mn == 'addis' else -imm if mn == 'subi' else imm
            self.setreg(st, reg(op[0]), self.plus(val(op[1]), facts.C(imm)))
            return True
        if mn in ('ori', 'oris') and len(op) == 3 and op[2].type == 2:
            base = val(op[1])
            imm = op[2].imm & 0xffff
            self.setreg(st, reg(op[0]), facts.C(base[1] | (imm << 16 if mn == 'oris' else imm)) if facts.is_c(base) else None)
            return True
        if mn in ('cmpwi', 'cmpw') and len(op) in (2, 3):
            if len(op) == 3:
                st.flags = None if reg(op[0]) != 'cr0' else ('cmp', val(op[1]), val(op[2]), 4)
            else:
                st.flags = ('cmp', val(op[0]), val(op[1]), 4)
            return True
        if mn in ('cmplwi', 'cmplw'):
            st.flags = None
            return True
        if mn == 'mflr' and len(op) == 1:
            self.setreg(st, reg(op[0]), self.getreg(st, 'lr'))
            return True
        if mn == 'mtlr' and len(op) == 1:
            self.setreg(st, 'lr', self.getreg(st, reg(op[0])))
            return True
        if mn == 'mtctr' and len(op) == 1:
            self.setreg(st, 'ctr', self.getreg(st, reg(op[0])))
            return True
        if mn == 'nop' or mn == 'sync' or mn == 'isync' or mn == 'eieio':
            return True
        indexed = PPC_INDEXED.get(mn.replace('ux', 'x') if mn.endswith('ux') else mn)
        if indexed and len(op) == 3 and op[1].type == 1 and op[2].type == 1:
            if mn.endswith('cx.'):
                st.flags = None  # the store-conditional sets cr0
            return self.ppc_indexed(st, old, ins, events, indexed, mn.endswith('ux'), val)
        update = mn.endswith('u') and mn[:-1] in PPC_MEMORY
        plain = mn[:-1] if update else mn
        if plain in PPC_MEMORY and len(op) == 2 and op[1].type == 3:
            store = PPC_MEMORY[plain]
            address, base, disp = self.effective(old, ins, op[1])
            width = self.width(ins)
            if store:
                self.memory(st, ins, address, width, events, True, val(op[0]), base, disp)
            else:
                value = self.memory(st, ins, address, width, events, base=base, disp=disp)
                if plain in ('lha',):
                    value = facts.C(sc(value[1] & 0xffff)) if facts.is_c(value) else None
                if width < 4 and facts.is_c(value):
                    value = facts.C(value[1] & ((1 << (8 * width)) - 1)) if plain != 'lha' else value
                self.setreg(st, reg(op[0]), value if width <= 4 and not plain.startswith('lf') else None)
            if update and base:
                self.setreg(st, base, address)
            return True
        return False

    def ppc_indexed(self, st, old, ins, events, plain, update, val):
        """A load or store at rA + rB (rA field 0 reads as zero). Both registers known gives an absolute
        address; one known and one not gives the known one as the base of an indexed access."""
        self._index_base = None
        op = ins.operands
        first, second = val(op[1]), val(op[2])
        address = self.plus(first, second)
        if not facts.is_c(address):
            known = [v for v in (first, second) if facts.is_c(v)]
            self._index_base = known[0] if len(known) == 1 else None
        width = ppc_width(plain)
        base = self.reg(ins, op[1].reg) if op[1].reg else ''
        if PPC_MEMORY[plain]:
            self.memory(st, ins, address, width, events, True, val(op[0]), base, 0)
        else:
            value = self.memory(st, ins, address, width, events, base=base, disp=0)
            if plain == 'lha':
                value = facts.C(sc(value[1] & 0xffff)) if facts.is_c(value) else None
            if width < 4 and facts.is_c(value) and plain != 'lha':
                value = facts.C(value[1] & ((1 << (8 * width)) - 1))
            reverses = ins.mnemonic.endswith('brx')
            self.setreg(st, self.reg(ins, op[0].reg), value if width <= 4 and not plain.startswith('lf')
                        and not reverses else None)
        if update and base:
            self.setreg(st, base, address)
        return True

    def branch_words(self, st, ins, code):
        if self.x86 and code in ('loop', 'loope', 'loopne', 'jcxz', 'jecxz'):
            bits = ins.addr_size * 8
            reg = 'cx' if bits == 16 else 'ecx'
            count = self.x86_low_register(st, reg)
            if code.startswith('loop'):
                count = self.x86_mask(facts.add(count, -1), bits)
            value = self.R(count)
            if count is None:
                value += ' (%s%s)' % (reg, ' after decrement, %d-bit wrap' % bits if code.startswith('loop') else '')
            zero, nonzero = value + ' == 0x0', value + ' != 0x0'
            if code in ('jcxz', 'jecxz'):
                return zero, nonzero
            if code == 'loop':
                return nonzero, zero
            # LOOPcc leaves flags unchanged and tests Z after decrementing
            # the address-size-selected counter. Either failed test exits.
            taken, fall = self.branch_words(st, ins, 'e' if code == 'loope' else 'ne')
            return nonzero + ' and (' + taken + ')', zero + ' or (' + fall + ')'
        if code in ('cbz', 'cbnz'):
            lhs = self.R(self.getreg(st, self.reg(ins, ins.operands[0].reg)))
            return (lhs + ' == 0x0', lhs + ' != 0x0') if code == 'cbz' else (lhs + ' != 0x0', lhs + ' == 0x0')
        pairs = {'eq': ('==', '!='), 'e': ('==', '!='), 'z': ('==', '!='), 'ne': ('!=', '=='),
                 'nz': ('!=', '=='), 'lt': ('<', '>='), 'l': ('<', '>='), 'ge': ('>=', '<'),
                 'gt': ('>', '<='), 'g': ('>', '<='), 'le': ('<=', '>'), 'hi': ('>', '<='),
                 'a': ('>', '<='), 'ls': ('<=', '>'), 'be': ('<=', '>'), 'hs': ('>=', '<'),
                 'cc': ('>=', '<'), 'ae': ('>=', '<'), 'lo': ('<', '>='), 'cs': ('<', '>='), 'b': ('<', '>=')}
        if st.flags and code in pairs:
            kind, lhs, rhs, width = st.flags
            if kind == 'cmp' or kind == 'test' and code in ('eq','e','z','ne','nz'):
                a, b = pairs[code]
                left = self.R(lhs) if kind == 'cmp' else '(%s & %s)' % (self.R(lhs), self.R(rhs))
                right = self.R(rhs) if kind == 'cmp' else '0x0'
                signed = 'unsigned' if code in ('hi', 'a', 'ls', 'be', 'hs', 'cc', 'ae', 'lo', 'cs', 'b') else 'signed'
                suffix = '' if a in ('==', '!=') else ' (%s, %d-bit)' % (signed, width * 8)
                return '%s %s %s%s' % (left, a, right, suffix), '%s %s %s%s' % (left, b, right, suffix)
        flags = {'eq': 'Z == 1', 'e': 'Z == 1', 'z': 'Z == 1', 'ne': 'Z == 0', 'nz': 'Z == 0',
                 'cs': 'C == 1', 'lo': 'C == 1', 'b': 'C == 1', 'cc': 'C == 0', 'hs': 'C == 0',
                 'ae': 'C == 0', 'mi': 'N == 1', 's': 'N == 1', 'pl': 'N == 0', 'ns': 'N == 0',
                 'vs': 'V == 1', 'o': 'V == 1', 'vc': 'V == 0', 'no': 'V == 0'}
        if self.arm:
            flags.update({'hs': 'C == 1', 'lo': 'C == 0'})
        condition = flags.get(code, '%s flags condition (operands unknown)' % code)
        return condition, 'not (%s)' % condition

    def call_args(self, st):
        args = []
        if self.img.abi == 'arm-aapcs':
            for n in range(4):
                args.append({'location': 'r%d' % n, 'value': self.R(self.getreg(st, 'r%d' % n))})
        elif self.img.abi == 'ppc-sysv':
            for n in range(3, 11):
                args.append({'location': 'r%d' % n, 'value': self.R(self.getreg(st, 'r%d' % n))})
        elif self.img.abi in ('cdecl16', 'cdecl32', 'm68k-sysv'):
            sp = self.getreg(st, self.sp)
            for n in range(6):
                at = facts.add(sp, n * self.word)
                args.append({'location': 'stack arg%d' % n, 'value': self.R(st.memory.get((at, self.word)))})
        else:
            args.append({'location': 'calling convention', 'value': '(unknown)'})
        return args

    def control_at(self, st, ins):
        kind, target, cc = self.control(ins)
        if self.arm_computed_pc_write(ins):
            if ins.address in getattr(self,'_unresolved_pc_writers',set()):
                target=None
            elif getattr(self,'_fixed_pc_targets',None) is not None:
                target=self._fixed_pc_targets.get(ins.address)
            else:
                target=self.arm_computed_pc_target(st,ins)
            if ins.update_flags:
                self.warnings.add('0x%x PC-destination instruction has untracked exception-return state' % ins.address)
            elif target is None:
                self.warnings.add('0x%x computed PC destination is unresolved; no normal taken-path continuation' % ins.address)
        # Before BLX, ARM code supplied the return address in lr explicitly.
        # A merged or unrelated link value must not turn a jump into a call.
        if (self.arch == 'arm' and kind in ('jump', 'conditional')
                and ins.insn_name() == 'mov' and not ins.update_flags
                and len(ins.operands) == 2 and ins.operands[1].type == 1
                and not ins.operands[1].shift.type
                and (ins.address in self._fixed_calls if getattr(self, '_fixed_calls', None) is not None
                     else self.getreg(st, 'lr') == self.img.code_value(ins.address + ins.size))):
            return 'conditional-call' if kind == 'conditional' else 'call', target, cc
        return kind, target, cc

    def ppc_writes(self, ins):
        """Registers a PowerPC instruction may change. Capstone's PowerPC backend has no usable
        regs_access, so the effect comes from the operand layout. Treating an instruction it does not
        know as writing everything also makes a live base register unknown, and every later access
        through it then renders "to ?". A store writes no register (an update form writes back its
        base), lmw writes rD..r31, lswi a run of ceil(n/4) registers from rD, and a compare, a move to
        a special register or a cache, sync or TLB operation writes no general register. The rest write
        rD (the first operand), plus the base for an update-form load. System calls, returns from
        interrupt and anything unrecognised still invalidate everything."""
        mn, op = ins.mnemonic, ins.operands
        everything = ['r%d' % n for n in range(32)] + ['lr', 'ctr']
        update = mn.endswith(('u', 'ux'))
        if mn.startswith('st'):
            if update and len(op) >= 2:
                base = op[1].mem.base_reg if op[1].type == 3 else op[1].reg
                return [self.reg(ins, base)] if base else []
            return []
        if mn in ('sc', 'rfi', 'rfid') or mn.startswith(('tw', 'td')):
            return everything
        if mn == 'mtspr' or mn.startswith('mtlr') or mn.startswith('mtctr'):
            return ['lr', 'ctr']
        if mn != 'cmpb' and mn.startswith(('cmp', 'fcmp', 'mt', 'cr', 'dcb', 'icb', 'tlb', 'sync', 'isync', 'eieio',
                                          'lwsync', 'mbar', 'ptesync')):
            return []
        if not op or op[0].type != 1:
            return everything
        first = self.reg(ins, op[0].reg)
        if mn == 'lmw':
            return ['r%d' % n for n in range(int(first[1:]), 32)]
        if mn == 'lswi' and len(op) == 3 and op[2].type == 2:
            # NB of 0 means 32 bytes, and the run wraps from r31 to r0.
            return ['r%d' % ((int(first[1:]) + n) % 32) for n in range(((op[2].imm & 31 or 32) + 3) // 4)]
        if mn == 'lswx':
            return everything
        writes = [first]
        if mn.startswith('l') and update and len(op) >= 2:
            base = op[1].mem.base_reg if op[1].type == 3 else op[1].reg
            if base:
                writes.append(self.reg(ins, base))
        return writes

    def m68k_writes(self, ins):
        """Registers an m68k or ColdFire instruction may change. Capstone's M68K backend has no
        regs_access, and treating every instruction as writing d0-d7 and a0-a7 loses every pointer held
        across an addq, and, lsl or lea. A listed instruction writes its destination operand (the last
        one) when that is a register, and writes back the base of a postincrement or predecrement
        operand. exg writes both operands. Anything unlisted, or with an operand shape that is not
        understood, still invalidates everything. Calls never come here: they clobber d0, d1, a0 and a1
        by convention."""
        from capstone import m68k_const as c
        mn, op = ins.mnemonic.split('.')[0], ins.operands
        everything = ['d%d' % n for n in range(8)] + ['a%d' % n for n in range(8)]
        writes = []
        for o in op:
            if o.type == 3 and o.address_mode in (c.M68K_AM_REGI_ADDR_POST_INC, c.M68K_AM_REGI_ADDR_PRE_DEC):
                rid = o.mem.base_reg or o.reg
                if not rid:
                    return everything
                writes.append(self.reg(ins, rid))
        if mn in M68K_WRITES_NONE:
            return writes
        if mn == 'exg' and len(op) == 2 and all(o.type == 1 for o in op):
            return writes + [self.reg(ins, o.reg) for o in op]
        if mn in M68K_WRITES_LAST and op:
            if op[-1].type == 1:
                writes.append(self.reg(ins, op[-1].reg))
            elif op[-1].type != 3:
                return everything
            return writes
        return everything

    def invalidate(self, st, ins):
        try:
            writes = [self.reg(ins, n) for n in ins.regs_access()[1]]
        except Exception:
            # Capstone's M68K backend has no regs_access implementation, and its PowerPC backend raises
            # for some instructions: assume every register may change.
            if self.ppc:
                writes = self.ppc_writes(ins)
            elif self.m68k:
                writes = self.m68k_writes(ins)
            else:
                writes = ['d%d' % n for n in range(8)] + ['a%d' % n for n in range(8)]
        if self.arm and ins.insn_name() in ('mrc', 'mrc2'):
            # Capstone omits the destination write for coprocessor reads.
            writes.extend(self.reg(ins, o.reg) for o in ins.operands if o.type == 1)
        for name in writes:
            self.setreg(st, name, None)
        st.flags = None
        st.direction = None
        st.memory.clear()
        self.warnings.add('0x%x %s: unsupported effects invalidated' % (ins.address, ins.mnemonic))

    def x86_mask(self, value, bits):
        if value is None:
            return None
        mask = (1 << bits) - 1
        return facts.C(value[1] & mask) if facts.is_c(value) else facts.cap(('op', '&', value, facts.C(mask)))

    def x86_low_register(self, st, name):
        value = self.getreg(st, name)
        # Partial register reads otherwise keep only constants. String I/O
        # also needs the low DX/CX/SI/DI expression when its parent is known.
        if value is None and name != self.fullreg(name):
            value = self.x86_mask(self.getreg(st, self.fullreg(name)), 16)
        return value

    def string_io(self, st, ins, events):
        incoming = ins.insn_name().startswith('ins')
        mem = ins.operands[0 if incoming else 1]
        bits = ins.addr_size * 8
        index_name = ('edi' if incoming else 'esi') if bits == 32 else ('di' if incoming else 'si')
        count_name = ('ecx' if bits == 32 else 'cx') if 0xf3 in ins.prefix else None
        count = self.x86_low_register(st, count_name) if count_name else facts.C(1)
        if facts.is_c(count) and count[1] == 0:
            return
        index = self.x86_low_register(st, index_name)
        port = self.x86_low_register(st, 'dx')
        width = self.width(ins, mem)
        stride = width * st.direction if st.direction is not None else None
        segment = self.reg(ins, mem.mem.segment) if mem.mem.segment else 'ds'
        common = dict(iterations=self.R(count), count_register=count_name, completion='normal')
        if count_name and not facts.is_c(count):
            common['condition'] = (self.R(count) if count is not None else count_name) + ' != 0x0'
        first = len(events['accesses'])
        # A segment selector does not supply its base. Keep the known offset
        # separately instead of presenting it as a linear effective address.
        if incoming:
            self.access(events, ins, 'load', width, port, 'port', 0)
            self.access(events, ins, 'store', width, None, index_name, 0)
        else:
            self.access(events, ins, 'load', width, None, index_name, 0)
            self.access(events, ins, 'store', width, port, 'port', 0)
        accesses = events['accesses'][first:]
        memory, io = (accesses[1], accesses[0]) if incoming else accesses
        memory.update(common, stride=stride, address_bits=bits, segment=segment,
                      segment_offset=self.R(index), segment_base='unknown')
        io.update(common, stride=0, address_bits=16, space='io')
        # Aggregate repeated input can overwrite saved stack values too.
        if incoming:
            st.memory.clear()
        updated = None
        if stride is not None and count is not None:
            step = facts.C(count[1] * stride) if facts.is_c(count) else facts.cap(('op', '*', count, facts.C(stride)))
            updated = self.x86_mask(self.plus(index, step), bits)
        self.setreg(st, index_name, updated)
        if count_name:
            self.setreg(st, count_name, facts.C(0))

    def transfer(self, old, record, events):
        st = old.copy()
        ins = record['_cs']
        mn, op = ins.mnemonic, ins.operands
        kind, target, cc = self.control_at(old, ins)
        conditional = kind.startswith('conditional')
        if self.arm:
            from capstone.arm_const import ARM_CC_AL, ARM_CC_INVALID
            predicated = ins.cc not in (ARM_CC_AL, ARM_CC_INVALID)
        else:
            predicated = False
        if kind in ('call', 'conditional-call'):
            linked_target = target is not None
            direct_target = linked_target
            if target is None and op:
                callee_op = op[-1] if self.arch == 'arm' and ins.insn_name() == 'mov' else op[0]
                value = self.operand(st, ins, callee_op, events, address_only=self.m68k)
                target = value[1] if facts.is_c(value) else self.img.linked_address(value)
                linked_target = target is not None and not facts.is_c(value)
            lookup, target_arch = target, None
            if self.img.elf and target is not None:
                operation=ins.insn_name()
                if direct_target:
                    target_arch=('thumb'if self.arch=='arm'else'arm')if operation=='blx'else self.arch
                elif operation=='blx':
                    target_arch='thumb'if target & 1 else'arm';lookup=target & ~1
            name = self.img.name_at(lookup) if lookup is not None and (not self.img.elf or linked_target) else None
            if self.img.elf and name and self.img.symbol_modes.get(lookup) != target_arch:
                name=None
            call = {'address': hex(ins.address), 'mnemonic': mn, 'target': hex(target) if target is not None else None,
                    'callee': name, 'args': self.call_args(st), 'conditional': conditional}
            if self.img.elf:
                call['target_coordinate_basis']='unknown'if target is None else'linked ELF virtual address'if linked_target else'runtime constant'
                call['target_arch']=target_arch or'unknown'
                call['instruction_target']=hex(lookup)if target_arch and lookup is not None else None
            if conditional:
                call['taken_when'], call['falls_through_when'] = self.branch_words(old, ins, cc)
            events['calls'].append(call)
            clobber = ['d0', 'd1', 'a0', 'a1'] if self.m68k else ['r0', 'r1', 'r2', 'r3', 'r12', 'lr'] if self.arm else ['r0'] + ['r%d' % n for n in range(3, 13)] + ['lr', 'ctr'] if self.ppc else ['eax', 'ecx', 'edx'] if self.word == 4 else ['ax', 'cx', 'dx']
            for reg in clobber:
                self.setreg(st, reg, None)
            result = name or hex(target) if target is not None else 'unknown'
            if self.img.elf and target is not None and name is None:
                result = ('linked ELF 'if linked_target else'runtime ')+hex(target)
            self.setreg(st, self.retreg, ('ret', result))
            st.flags = None
            st.direction = None
            st.memory.clear()
            return old.merged(st) if conditional else st
        if self.x86 and kind == 'jump' and op and op[0].type == 3:
            self.operand(st,ins,op[0],events)
        if kind in ('conditional', 'jump', 'return', 'conditional-return') and not (self.arm and (mn.startswith('pop') or mn.startswith('ldr') or mn.startswith('ldm'))):
            if self.x86 and mn.startswith('loop'):
                self.setreg(st, 'cx' if ins.addr_size==2 else 'ecx', None)
            if self.m68k and mn.startswith('db') and op and op[0].type == 1:
                self.setreg(st, self.reg(ins, op[0].reg), None)
            if conditional:
                self.conditions[ins.address] = self.branch_words(old, ins, cc)
            return st
        read = lambda o: self.operand(st, ins, o, events)
        write = lambda o, v: self.operand(st, ins, o, events, store=True, value=v)
        modeled = False
        # Stack saves use the same memory model as explicit loads/stores.
        if self.ppc:
            modeled = self.ppc_transfer(st, old, ins, events)
        elif self.m68k and mn.startswith('movem'):
            from capstone import m68k_const as mc
            saving = op[0].type == 6
            reglist, mem = (op[0], op[1]) if saving else (op[1], op[0])
            names = ['d%d' % n for n in range(8)] + ['a%d' % n for n in range(8)]
            names = [name for n, name in enumerate(names) if reglist.register_bits & (1 << n)]
            width = self.width(ins)
            a, base, disp = self.effective(st, ins, mem)
            if mem.address_mode == mc.M68K_AM_REGI_ADDR_PRE_DEC:
                a = facts.add(a, -width * (len(names)-1))
            for n, name in enumerate(names):
                at = facts.add(a, width*n)
                if saving:
                    self.memory(st, ins, at, width, events, True, self.getreg(old, name), base, disp+width*n)
                else:
                    v = self.memory(st, ins, at, width, events, base=base, disp=disp+width*n)
                    if width == 2:
                        v = facts.C(sc(v[1] & 0xffff)) if facts.is_c(v) else None
                    self.setreg(st, name, v)
            if mem.address_mode in (mc.M68K_AM_REGI_ADDR_PRE_DEC, mc.M68K_AM_REGI_ADDR_POST_INC):
                self.setreg(st, base, a if saving else facts.add(a,width*len(names)))
            modeled = True
        elif self.m68k and mn.startswith('pea'):
            value = self.operand(st,ins,op[0],events,address_only=True)
            address = facts.add(self.getreg(st,self.sp),-4)
            self.memory(st,ins,address,4,events,True,value,self.sp,-4,True)
            self.setreg(st,self.sp,address)
            modeled = True
        # Capstone drops repeat prefixes from CLD/STD metadata. Their raw
        # encodings must remain unsupported rather than establish known DF.
        elif (self.x86 and mn in ('cld', 'std')
              and not any(b in (0xf2, 0xf3) for b in ins.bytes[:-1])):
            st.direction = 1 if mn == 'cld' else -1
            modeled = True
        elif (self.x86 and ins.insn_name() in ('insb', 'insw', 'insd', 'outsb', 'outsw', 'outsd')
              and 0xf2 not in ins.prefix):
            self.string_io(st, ins, events)
            modeled = True
        elif self.x86 and mn in ('in', 'out'):
            data, port = (op[0],op[1]) if mn == 'in' else (op[1],op[0])
            pv = read(port)
            self.access(events, ins, 'load' if mn == 'in' else 'store', self.width(ins,data),
                        pv, 'port', 0, read(data) if mn == 'out' else None)
            events['accesses'][-1]['space'] = 'io'
            if mn == 'in':
                write(data, None)
            modeled = True
        elif self.x86 and mn in ('push', 'pop') and op:
            width = self.width(ins, op[0])
            sp = self.getreg(st, self.sp)
            if mn == 'push':
                v = read(op[0]); sp = facts.add(sp, -width)
                self.memory(st, ins, sp, width, events, True, v, self.sp, -width, True)
                self.setreg(st, self.sp, sp)
            else:
                v = self.memory(st, ins, sp, width, events, base=self.sp, implicit=True)
                self.setreg(st, self.sp, facts.add(sp, width)); write(op[0], v)
            modeled = True
        elif self.x86 and mn == 'leave':
            bp = 'bp' if self.word == 2 else 'ebp'
            sp = self.getreg(st, bp)
            v = self.memory(st, ins, sp, self.word, events, base=bp, implicit=True)
            self.setreg(st, self.sp, facts.add(sp, self.word)); self.setreg(st, bp, v)
            modeled = True
        elif self.m68k and mn.startswith('link') and len(op) == 2:
            reg = self.reg(ins, op[0].reg)
            v = self.getreg(st, reg); sp = facts.add(self.getreg(st, self.sp), -4)
            self.memory(st, ins, sp, 4, events, True, v, self.sp, -4, True)
            frame = sc(op[1].imm & 0xffff) if mn.endswith('.w') else sc(op[1].imm & 0xffffffff, 32)
            self.setreg(st, reg, sp); self.setreg(st, self.sp, facts.add(sp, frame))
            modeled = True
        elif self.m68k and mn == 'unlk':
            reg = self.reg(ins, op[0].reg); sp = self.getreg(st, reg)
            v = self.memory(st, ins, sp, 4, events, base=reg, implicit=True)
            self.setreg(st, self.sp, facts.add(sp, 4)); self.setreg(st, reg, v)
            modeled = True
        elif self.arm and ins.insn_name() in ('ldm','ldmda','ldmdb','ldmib','stm','stmda','stmdb','stmib'):
            loading = ins.insn_name().startswith('ldm')
            base = self.reg(ins,op[0].reg)
            names = [self.reg(ins,o.reg) for o in op[1:]]
            bv = self.getreg(old,base)
            mode = ins.insn_name()[3:] or 'ia'
            first = {'ia':0,'ib':4,'da':-4*(len(names)-1),'db':-4*len(names)}[mode]
            for n,name in enumerate(names):
                a = facts.add(bv,first+4*n)
                if loading:
                    value = self.memory(st,ins,a,4,events,base=base,disp=first+4*n)
                    self.setreg(st,name,value)
                else:
                    self.memory(st,ins,a,4,events,True,self.getreg(old,name),base,first+4*n)
            if ins.writeback:
                self.setreg(st,base,None if base in names else facts.add(bv,(-4 if mode.startswith('d') else 4)*len(names)))
            modeled = True
        elif self.arm and mn in ('push', 'pop'):
            regs = [self.reg(ins, o.reg) for o in op]
            sp = self.getreg(st, self.sp)
            start = facts.add(sp, -4 * len(regs)) if mn == 'push' else sp
            for n, reg in enumerate(regs):
                a = facts.add(start, 4 * n)
                if mn == 'push':
                    self.memory(st, ins, a, 4, events, True, self.getreg(st, reg), self.sp, 4 * n, True)
                else:
                    self.setreg(st, reg, self.memory(st, ins, a, 4, events, base=self.sp, disp=4 * n, implicit=True))
            self.setreg(st, self.sp, start if mn == 'push' else facts.add(sp, 4 * len(regs)))
            modeled = True
        elif self.m68k and mn.split('.')[0] == 'btst' and len(op) == 2:
            bit, value = read(op[0]), read(op[1])
            width = self.width(ins, op[1])
            # BTST changes only Z. The test tuple supplies equality conditions only;
            # it must not imply the carry or signed-comparison flags of CMP.
            st.flags = ('test', value, facts.C(1 << (bit[1] % (width * 8))), width) if facts.is_c(bit) else None
            modeled = True
        elif (self.x86 and mn in ('cmp', 'test')) or (self.m68k and mn.split('.')[0] in ('cmp','cmpi','cmpa','tst')) or (self.arm and ins.insn_name() in ('cmp','tst')):
            if len(op) == 2:
                lhs, rhs = (read(op[1]), read(op[0])) if self.m68k else (read(op[0]), read(op[1]))
            else:
                lhs, rhs = read(op[0]), facts.C(0)
            width = self.width(ins, op[0])
            if self.m68k and mn.startswith('cmpa'):
                rhs = facts.C(sc(rhs[1] & 0xffff) & 0xffffffff) if width == 2 and facts.is_c(rhs) else rhs if width == 4 else None
                width = 4
            mask = (1 << (width * 8)) - 1
            if facts.is_c(lhs): lhs = facts.C(lhs[1] & mask)
            if facts.is_c(rhs): rhs = facts.C(rhs[1] & mask)
            if width < self.word:
                mask = (1 << (width * 8)) - 1
                lhs = facts.C(lhs[1] & mask) if facts.is_c(lhs) else facts.cap(('op','&',lhs,facts.C(mask))) if lhs is not None else None
                rhs = facts.C(rhs[1] & mask) if facts.is_c(rhs) else facts.cap(('op','&',rhs,facts.C(mask))) if rhs is not None else None
            st.flags = ('test' if mn.startswith(('test', 'tst')) and len(op) == 2 else 'cmp', lhs, rhs, width)
            modeled = True
        elif len(op) >= 2 and (self.x86 and mn in ('mov', 'movzx', 'movsx', 'lea') or self.m68k and mn.split('.')[0] in ('move','movea','moveq','lea') or self.arm and ins.insn_name() in ('mov','movw','movt','ldr','ldrb','ldrh','ldrsb','ldrsh','str','strb','strh')):
            if self.m68k:
                v = self.operand(st, ins, op[0], events, address_only=mn.startswith('lea'))
                if mn.startswith('moveq'):
                    v = facts.C(sc(op[0].imm & 0xff, 8))
                elif mn.startswith('movea') and self.width(ins) == 2:
                    v = facts.C(sc(v[1] & 0xffff)) if facts.is_c(v) else None
                if not mn.startswith(('movea','lea')) and self.width(ins) < 4:
                    mask = (1 << (8*self.width(ins)))-1
                    v = facts.C(v[1] & mask) if facts.is_c(v) else facts.cap(('op','&',v,facts.C(mask))) if v is not None else None
                write(op[1], v)
                if not mn.startswith(('movea', 'lea')):
                    st.flags = ('cmp', v, facts.C(0), self.width(ins))
            elif self.x86:
                v = self.operand(st, ins, op[1], events, address_only=mn == 'lea')
                if mn == 'movsx':
                    v = facts.C(sc(v[1] & ((1 << (op[1].size * 8)) - 1), op[1].size * 8)) if facts.is_c(v) else None
                write(op[0], v)
            elif mn.startswith('str'):
                v = read(op[0])
                width = self.width(ins, op[1])
                if width < self.word and v is not None:
                    mask = (1 << (width * 8)) - 1
                    v = facts.C(v[1] & mask) if facts.is_c(v) else facts.cap(('op', '&', v, facts.C(mask)))
                write(op[1], v)
            else:
                if (self.arch == 'arm' and ins.insn_name() == 'mov'
                        and not ins.update_flags and op[0].type == op[1].type == 1
                        and self.reg(ins, op[0].reg) == 'lr'
                        and self.reg(ins, op[1].reg) == 'pc' and not op[1].shift.type):
                    v = self.img.code_value(ins.address + 8)
                else:
                    v = read(op[1])
                if ins.insn_name() == 'movt':
                    previous = read(op[0])
                    v = facts.C((previous[1] & 0xffff) | ((v[1] & 0xffff) << 16)) if facts.is_c(previous) and facts.is_c(v) else None
                if ins.insn_name() in ('ldrsb','ldrsh'):
                    width = self.width(ins,op[1])
                    v = facts.C(sc(v[1] & ((1 << (8*width))-1), 8*width)) if facts.is_c(v) else None
                write(op[0], v)
            if self.arm and ins.update_flags:
                st.flags = None
            if self.arm and ins.writeback:
                mem = next((o for o in op if o.type == 3), None)
                if mem:
                    base = self.reg(ins, mem.mem.base)
                    # Post-index has a third operand; pre-index uses the effective address.
                    v = self.effective(old, ins, mem)[0]
                    if len(op) > 2:
                        v = self.plus(self.getreg(old, base), read(op[2]))
                    self.setreg(st, base, v)
            modeled = True
        elif self.arm and mn in ('lsl','lsr','asr','ror') and len(op) == 2:
            # Capstone represents the immediate in the source operand's shift field.
            write(op[0], read(op[1])); modeled = True
            if ins.update_flags:
                st.flags = None
        elif self.m68k and mn.startswith('clr') and op:
            write(op[0], facts.C(0)); st.flags = ('cmp', facts.C(0), facts.C(0), self.width(ins)); modeled = True
        elif len(op) >= 2 and mn.split('.')[0].rstrip('s') in ('add', 'sub', 'and', 'or', 'orr', 'eor', 'xor', 'bic', 'addq', 'subq', 'adda', 'suba', 'lsl', 'lsr', 'shl', 'shr', 'sal', 'sar'):
            if self.m68k:
                dest = op[1]; a, b = read(op[1]), read(op[0])
            elif self.arm and len(op) >= 3:
                dest = op[0]; a, b = read(op[1]), read(op[2])
            else:
                dest = op[0]; a, b = read(op[0]), read(op[1])
            base = mn.split('.')[0].rstrip('s')
            if self.m68k:
                width = self.width(ins)
                mask = (1 << (8*width))-1
                if base in ('adda','suba') and width == 2:
                    b = facts.C(sc(b[1] & 0xffff)) if facts.is_c(b) else None
                elif width < 4:
                    a = facts.C(a[1] & mask) if facts.is_c(a) else None
                    if not base.startswith(('lsl','lsr','shl','shr','sal','sar')):
                        b = facts.C(b[1] & mask) if facts.is_c(b) else None
            v = None
            if base.startswith(('add', 'sub')):
                if self.x86 and op[-1].type == 2 and facts.is_c(b):
                    bits = self.width(ins,dest) * 8
                    b = facts.C(sc(b[1] & ((1 << bits)-1),bits))
                if base.startswith('sub'):
                    b = facts.C(-b[1]) if facts.is_c(b) else None
                v = self.plus(a, b)
            elif base in ('xor', 'eor') and op[-1].type == 1 and dest.type == 1 and op[-1].reg == dest.reg and (not self.arm or len(op) > 2 and op[1].reg == dest.reg):
                v = facts.C(0)
            elif facts.is_c(a) and facts.is_c(b):
                funcs = {'and': lambda x,y:x & y, 'or': lambda x,y:x | y, 'orr': lambda x,y:x | y,
                         'xor': lambda x,y:x ^ y, 'eor': lambda x,y:x ^ y, 'bic': lambda x,y:x & ~y,
                         'lsl': lambda x,y:x << y, 'shl': lambda x,y:x << y, 'sal': lambda x,y:x << y,
                         'lsr': lambda x,y:(x & 0xffffffff) >> y, 'shr': lambda x,y:(x & 0xffffffff) >> y}
                if base in funcs and (base not in ('lsl','shl','sal','lsr','shr') or 0 <= b[1] < 32):
                    v = facts.C(funcs[base](a[1], b[1]))
            write(dest, v)
            if self.x86 or self.m68k and not mn.startswith(('adda', 'suba')) or self.arm and ins.update_flags:
                st.flags = None
            modeled = True
        elif mn in ('nop',):
            modeled = True
        if not modeled:
            # Preserve observable memory operands even when the value transfer is unsupported.
            for operand in op:
                if operand.type != 3:
                    continue
                address, base, disp = self.effective(old, ins, operand)
                access = getattr(operand, 'access', 0)
                kinds = (['load'] if access & 1 else []) + (['store'] if access & 2 else [])
                # Capstone marks several x87 memory stores as reads.
                # The floating-point value is still unknown, but the access
                # direction must not depend on those incorrect flags.
                if self.x86 and mn in ('fst', 'fstp', 'fist', 'fistp', 'fisttp',
                                       'fbstp', 'fnstcw', 'fnstsw'):
                    kinds = ['store']
                if self.arm and ins.insn_name() in ('ldrd','strd'):
                    kinds = ['load' if ins.insn_name() == 'ldrd' else 'store']
                width = self.width(ins, operand)
                if self.ppc and mn in ('stmw', 'lmw') and operand is op[-1] and op[0].type == 1:
                    # Capstone leaves the access flags empty. The transfer runs from rS/rD through r31.
                    kinds = ['store' if mn == 'stmw' else 'load']
                    width = 4 * (32 - int(self.reg(ins, op[0].reg)[1:]))
                if self.arm and ins.insn_name().startswith(('stc', 'ldc')):
                    # Capstone marks STC memory operands as reads. The
                    # coprocessor decides the transfer length, including
                    # the long forms, so the ARM word size is not evidence.
                    kinds = ['store' if ins.insn_name().startswith('stc') else 'load']
                    width = 'unknown'
                    self.warnings.add('0x%x coprocessor transfer width is unknown' % ins.address)
                if self.m68k and mn.split('.')[0] in ('btst','bset','bclr','bchg'):
                    kinds = ['load'] if mn.startswith('btst') else ['load','store']
                for access_kind in kinds or ['unknown']:
                    self.access(events, ins, access_kind, width, address, base, disp)
            self.invalidate(st, ins)
        if predicated:
            self.warnings.add('0x%x predicated effects are merged with the unexecuted path' % ins.address)
            # Conditional stores must not be presented as unconditional writes.
            tw, fw = self.branch_words(old, ins, {1:'eq',2:'ne',3:'hs',4:'lo',9:'hi',10:'ls',11:'ge',12:'lt',13:'gt',14:'le'}.get(ins.cc))
            for access in events['accesses']:
                access['condition'] = tw
            return old.merged(st)
        return st

    def analyze(self):
        if not self.insns or self.insns[0]['addr'] != self.addr:
            return
        regs = {}
        if self.m68k:
            names = ['d%d' % n for n in range(8)] + ['a%d' % n for n in range(8)]
        elif self.arm:
            names = ['r%d' % n for n in range(13)] + ['sp','lr']
        elif self.ppc:
            names = ['r%d' % n for n in range(32)] + ['lr', 'ctr']
        else:
            names = ['eax','ebx','ecx','edx','esi','edi','ebp','esp'] if self.word == 4 else ['ax','bx','cx','dx','si','di','bp','sp']
        for name in names:
            regs[name] = ('in', name)
        regs[self.sp] = ('sp0', 0)
        call_sites, seen = set(), set()
        pc_targets={};self._unresolved_pc_writers=set()
        # Keep control-flow edges fixed during each register-tracking pass.
        # Recompute from entry when link evidence changes the call sites, so
        # removed continuations cannot leave stale values in a live join.
        while True:
            signature = (frozenset(call_sites),tuple(sorted(pc_targets.items())),frozenset(self._unresolved_pc_writers))
            if signature in seen or len(seen) > max(10, len(self.insns)*4):
                raise ValueError('control-flow tracking did not converge; no partial fact sheet emitted')
            seen.add(signature)
            self._fixed_calls = call_sites
            self._fixed_pc_targets=pc_targets
            self.warnings = set(self.initial_warnings)
            self.in_states = {0: FirmwareState(dict(regs))}
            self.out_states, self.edges, self.conditions = {}, {}, {}
            work = collections.deque([0])
            count = 0
            while work:
                count += 1
                if count > max(1000, len(self.insns) * 100):
                    raise ValueError('register tracking did not converge; no partial fact sheet emitted')
                n = work.popleft(); record = self.insns[n]; ins = record['_cs']
                st = self.transfer(self.in_states[n], record, {'accesses': [], 'calls': []})
                self.out_states[n] = st
                kind, target, cc = self.control_at(self.in_states[n], ins)
                nextaddr = ins.address + ins.size
                successors = []
                if kind not in ('jump','return') and nextaddr in self.at:
                    successors.append(('falls through', self.at[nextaddr]))
                if kind in ('jump','conditional') and target in self.at:
                    successors.append(('taken', self.at[target]))
                self.edges[n] = successors
                for _, successor in successors:
                    merged = self.in_states[successor].merged(st) if successor in self.in_states else st.copy()
                    if successor not in self.in_states or self.in_states[successor].key() != merged.key():
                        self.in_states[successor] = merged; work.append(successor)
            self._fixed_calls = None
            resolved = {self.insns[n]['addr'] for n, st in self.in_states.items()
                        if self.control(self.insns[n]['_cs'])[0] in ('jump', 'conditional')
                        and self.control_at(st, self.insns[n]['_cs'])[0] in ('call', 'conditional-call')}
            proposed=dict(pc_targets)
            for n,st in self.in_states.items():
                ins=self.insns[n]['_cs']
                if not self.arm_computed_pc_write(ins):
                    continue
                target=self.arm_computed_pc_target(st,ins)
                if ins.address in self._unresolved_pc_writers:
                    target=None
                elif ins.address in pc_targets and pc_targets[ins.address] is not None and target!=pc_targets[ins.address]:
                    # A changed join cannot leave states from the previous edge.
                    # Widen this writer permanently to avoid known/unknown cycles.
                    self._unresolved_pc_writers.add(ins.address);target=None
                proposed[ins.address]=target
            if resolved == call_sites and proposed==pc_targets:
                self._fixed_calls = resolved
                self._fixed_pc_targets=proposed
                return
            call_sites = resolved
            pc_targets=proposed

    def facts(self, _unused=False):
        self.analyze()
        fs = {'routine': {'file': self.img.path, 'name': self.name, 'address': hex(self.addr),
                          'size': self.size, 'arch': self.arch, 'abi': self.img.abi,
                          'kind': self.img.kind, 'load': hex(self.img.load), 'size_source': self.source},
              'accesses': [], 'calls': [], 'blocks': [], 'exits': [], 'constants': [],
              'instructions': [], 'immediates': [], 'unreached': [], 'warnings': [], 'sections': self.img.sections,
              'coverage': {'unresolved_transfers': []}}
        if self.img.elf:
            fs['routine'].update(coordinate_basis='linked ELF virtual addresses', runtime_load_base='unknown')
        predecessors = collections.defaultdict(list)
        for n, edges in self.edges.items():
            for label, successor in edges:
                predecessors[successor].append((n, label))
        for n, record in enumerate(self.insns):
            ins = record['_cs']
            fs['instructions'].append({k:v for k,v in record.items() if k != '_cs'})
            if n not in self.in_states:
                fs['unreached'].append(hex(ins.address)); continue
            events = {'accesses': [], 'calls': []}
            out = self.transfer(self.in_states[n], record, events)
            fs['accesses'].extend(events['accesses']); fs['calls'].extend(events['calls'])
            kind, target, cc = self.control_at(self.in_states[n], ins)
            block = {'id': 'B%d' % n, 'first': hex(ins.address), 'last': hex(ins.address),
                     'kind': kind, 'target': hex(target) if target is not None else None,
                     'preds': ['B%d' % p for p, _ in predecessors[n]],
                     'successors': [{'kind': k, 'block': 'B%d' % s} for k,s in self.edges.get(n,[])]}
            if self.arm_computed_pc_write(ins):
                block['computed_pc_write']=True
                block['target_coordinate_basis']='unknown'if target is None else'linked ELF virtual address'if self.img.elf else'flat analysis coordinates'
                block['target_arch']=self.arch if target is not None else'unknown'
            if kind.startswith('conditional'):
                block['taken_when'], block['falls_through_when'] = self.branch_words(self.in_states[n], ins, cc)
            fs['blocks'].append(block)
            if kind in ('jump','conditional') and target is None:
                fs['coverage']['unresolved_transfers'].append(hex(ins.address))
            if kind in ('return','conditional-return'):
                fs['exits'].append({'address': hex(ins.address), 'register': self.retreg,
                                    'value': self.R(self.getreg(out, self.retreg)),
                                    'from': block['preds'], 'condition': block.get('taken_when')})
            for name, v in out.regs.items():
                if facts.is_c(v) and v != self.in_states[n].regs.get(name):
                    fs['constants'].append({'address': hex(ins.address), 'register': name, 'value': self.R(v)})
            for op in ins.operands:
                if op.type == 2:
                    fs['immediates'].append({'address': hex(ins.address), 'value': hex(op.imm & ((1 << self.img.bits)-1))})
        if fs['coverage']['unresolved_transfers']:
            self.warnings.add('unresolved indirect transfers: access, call and return lists cover known edges only')
        fs['warnings'] = sorted(self.warnings)
        if self.img.elf:
            used = [(self.addr, self.size)] + [(int(a['linked_address'],16), a['width'])
                    for a in fs['accesses'] if a['kind']=='load' and 'linked_address' in a and isinstance(a['width'],int)]
            fs['relocations'] = [dict(r, address=hex(r['address'])) for r in self.img.relocations
                                 if any(r['address'] < a+size and a < r['address']+r['size'] for a,size in used)]
        return fs

    def render(self, fs):
        lines = ['routine %s  %s-0x%x  size 0x%x (%d bytes)' % (self.name or '(unnamed)', hex(self.addr), self.addr+self.size, self.size, self.size),
                 '  file %s  %s  ISA %s  ABI %s  load %s; size from %s' % (self.img.path,self.img.kind,self.arch,self.img.abi,hex(self.img.load),self.source),
                 '  calling convention: assumed %s; argument count unknown; printed arguments are candidate locations; ? means unknown' % self.img.abi,
                 '  legend: sp is the stack pointer at entry; [X+N] is a loaded value; ret(F) is a call result']
        if self.img.elf:
            lines.append('  coordinates: instructions/direct targets are linked ELF virtual addresses; runtime load base unknown')
            lines.append('  data: PC-derived image references retain unknown ELF load bias; unrelocated scalar constants retain runtime values; relocations are not applied')
        for warning in fs['warnings']:
            lines.append('  warning: '+warning)
        if self.img.elf:
            lines += ['', 'ELF relocation-dependent places (%d)' % len(fs['relocations'])]
            for relocation in fs['relocations']:
                lines.append('  %s size %d type %d symbol %s; value unknown (not applied)' % (
                    relocation['address'],relocation['size'],relocation['type'],relocation['symbol'] or '(none)'))
        lines += ['', 'accesses (%d)' % len(fs['accesses'])]
        for a in fs['accesses']:
            target = 'abs '+a['absolute'] if 'absolute' in a else a['origin']+' '+sgn(a['origin_offset']) if 'origin' in a else '? (unknown effective address)'
            string = ''
            if 'iterations' in a:
                string = ' iterations=%s%s stride=%s address_bits=%d (per transfer; normal completion)' % (
                    a['iterations'], ' counter='+a['count_register'] if a['count_register'] else '',
                    a['stride'] if a['stride'] is not None else '?', a['address_bits'])
                if a.get('segment'):
                    string += ' segment=%s offset=%s base unknown' % (a['segment'], a['segment_offset'])
            if self.img.elf and a.get('coordinate_basis'):
                string += ' coordinate_basis='+a['coordinate_basis']
                if a.get('linked_address'):
                    string += ' linked_address='+a['linked_address']
            lines.append('  %s %s w%s %s base=%s disp %s => %s%s%s' % (a['address'],a['kind'],a['width'],a['mnemonic'],a['base'] or '?',sgn(a['offset']),target,
                         ' value '+a['value'] if a['kind']=='store' else '', (' space='+a['space'] if a.get('space') else '')+string+(' when '+a['condition'] if a.get('condition') else '')))
        lines += ['', 'calls (%d)' % len(fs['calls'])]
        for c in fs['calls']:
            lines.append('  %s %s %s [%s]' % (c['address'],c['mnemonic'],c['callee'] or '(unknown callee)',c['target'] or 'unknown target'))
            if self.img.elf:
                lines.append('      target coordinate basis: '+c['target_coordinate_basis'])
                lines.append('      target execution state: %s; instruction target: %s' % (c['target_arch'],c['instruction_target']or'unknown'))
            lines.append('      args: '+', '.join(a['location']+'='+a['value'] for a in c['args']))
            if c.get('conditional'):
                lines.append('      taken when '+c['taken_when']+'; falls through when '+c['falls_through_when'])
        lines += ['', 'blocks (%d)' % len(fs['blocks'])]
        for b in fs['blocks']:
            lines.append('  %s %s-%s preds: %s' % (b['id'],b['first'],b['last'],', '.join(b['preds']) or ('entry' if b['first']==hex(self.addr) else 'none')))
            if 'taken_when' in b:
                lines.append('      taken when %s -> %s' % (b['taken_when'], b['target'] or b['kind']))
                nexts = [s['block'] for s in b['successors'] if s['kind']=='falls through']
                lines.append('      falls through when %s -> %s' % (b['falls_through_when'], ', '.join(nexts) or 'outside'))
            else:
                lines.append('      %s%s' % (b['kind'], ' -> '+b['target'] if b['target'] else ' -> '+', '.join(s['block'] for s in b['successors']) if b['successors'] else ''))
            if b.get('computed_pc_write'):
                lines.append('      computed PC write; target coordinate basis: %s; execution state: %s' % (b['target_coordinate_basis'],b['target_arch']))
        lines += ['', 'returns (%d)' % len(fs['exits'])]
        for e in fs['exits']:
            lines.append('  %s: %s = %s; reached from %s%s' % (e['address'],e['register'],e['value'],', '.join(e['from']) or 'entry',' when '+e['condition'] if e.get('condition') else ''))
        lines += ['', 'constants']
        lines += ['  %s %s = %s' % (c['address'],c['register'],c['value']) for c in fs['constants']]
        lines += ['immediates']
        lines += ['  %s at %s' % (c['value'],c['address']) for c in fs['immediates']]
        lines += ['instructions']
        lines += ['  %s %s %s %s%s' % (hex(i['addr']),i['bytes'],i['mn'],i['ops'],' (not reached by known edges)' if hex(i['addr']) in fs['unreached'] else '') for i in fs['instructions']]
        return '\n'.join(lines)+'\n'


# ===================================================================== control flow

class Block:
    def __init__(self, bid, first, last):
        self.id, self.first, self.last = bid, first, last   # instruction indexes, last inclusive
        self.succ = []      # (kind, block id or None)
        self.preds = []


def build_blocks(r):
    n = len(r.insns)
    leaders = {0}
    branch_idx = [i for i in range(n) if facts.is_branch(r.insns[i]['mn'])]
    delay = {i + 1 for i in branch_idx}
    for i in branch_idx:
        ins = r.insns[i]
        mn = ins['mn']
        if mn in facts.CALLS:
            continue
        t = facts.branch_target(ins) if mn not in ('jr', 'jr.hb') else None
        if t in r.at and r.at[t] not in delay:
            leaders.add(r.at[t])
        if i + 2 < n:
            leaders.add(i + 2)
    for tab in getattr(r, 'tables', []):
        for tv in tab['targets']:
            if int(tv, 16) in r.at:
                leaders.add(r.at[int(tv, 16)])
    order = sorted(leaders)
    blocks, by_first = [], {}
    for k, f in enumerate(order):
        end = (order[k + 1] - 1) if k + 1 < len(order) else n - 1
        b = Block('B%d' % k, f, end)
        blocks.append(b)
        by_first[f] = b
    return blocks, by_first


def reg_note(r, st, n):
    names = r.img.regnames
    if n == 0:
        return '0'
    nm = names[n]
    v = st.get(n)
    if v is None:
        return '%s (unknown)' % nm
    if v[0] == 'in':
        if v[1] == nm:
            return '%s (arg%d at entry)' % (nm, ARG_ORDINAL[nm]) if nm in ARG_ORDINAL and \
                ARG_ORDINAL[nm] < r.nargs else '%s (at entry)' % nm
        o = ARG_ORDINAL.get(v[1])
        return '%s (= %s%s)' % (nm, v[1], ', arg%d at entry' % o if o is not None and o < r.nargs else ' at entry')
    return '%s (= %s)' % (nm, r.R(v))


def short(r, st, n):
    if n == 0:
        return '0'
    v = st.get(n)
    nm = r.img.regnames[n]
    if v is None:
        return '%s(?)' % nm
    if v == ('in', nm):
        return nm
    return '%s(=%s)' % (nm, r.R(v))


def find_def(r, blk, i, n):
    """The instruction in the block before index i that last wrote register n, or None."""
    j = i - 1
    while j >= blk.first:
        if j not in r.in_states:
            j -= 1
            continue
        ins = r.insns[j]
        mn, ops = ins['mn'], ins['ops']
        if facts.is_branch(mn) or mn in facts.STORES:
            j -= 1
            continue
        if ops and facts.reg(ops[0]) == n and mn not in ('mtc1', 'dmtc1') and not mn.startswith('c.'):
            return j
        j -= 1
    return None


def cond_words(r, blk, i):
    """(taken, falls_through) wording for the conditional branch at index i."""
    ins = r.insns[i]
    mn, ops = ins['mn'], ins['ops']
    st = r.in_states[i]
    base = mn.rstrip('l') if mn.endswith('l') and mn not in ('bal',) else mn
    if base in ('beq', 'bne'):
        a, b = facts.reg(ops[0]), facts.reg(ops[1])
        if a == 0 and b != 0:
            a, b = b, a
        if b == 0:
            nz, z = '%s != 0' % short(r, st, a), '%s == 0' % short(r, st, a)
            j = find_def(r, blk, i, a)
            if j is not None:
                d, s2 = r.insns[j], r.in_states[j]
                dm, do = d['mn'], d['ops']
                rr = [facts.reg(o) for o in do]
                if dm in ('slt', 'sltu') and rr[1] is not None and rr[2] is not None:
                    u = 'unsigned' if dm == 'sltu' else 'signed'
                    nz = '%s < %s (%s)' % (short(r, s2, rr[1]), short(r, s2, rr[2]), u)
                    z = '%s >= %s (%s)' % (short(r, s2, rr[1]), short(r, s2, rr[2]), u)
                elif dm in ('slti', 'sltiu') and rr[1] is not None:
                    k = facts.imm(do[2])
                    u = 'unsigned' if dm == 'sltiu' else 'signed'
                    nz = '%s < %s (%s)' % (short(r, s2, rr[1]), facts.hexs(k), u)
                    z = '%s >= %s (%s)' % (short(r, s2, rr[1]), facts.hexs(k), u)
                elif dm in ('andi', 'and') and rr[1] is not None:
                    m = facts.hexs(facts.imm(do[2])) if dm == 'andi' else short(r, s2, rr[2])
                    nz = '(%s & %s) != 0' % (short(r, s2, rr[1]), m)
                    z = '(%s & %s) == 0' % (short(r, s2, rr[1]), m)
        else:
            nz = '%s != %s' % (short(r, st, a), short(r, st, b))
            z = '%s == %s' % (short(r, st, a), short(r, st, b))
        return (nz, z) if base == 'bne' else (z, nz)
    if base in ('blez', 'bgtz', 'bltz', 'bgez'):
        a = short(r, st, facts.reg(ops[0]))
        t = {'blez': ('<= 0', '> 0'), 'bgtz': ('> 0', '<= 0'), 'bltz': ('< 0', '>= 0'),
             'bgez': ('>= 0', '< 0')}[base]
        return '%s %s (signed)' % (a, t[0]), '%s %s (signed)' % (a, t[1])
    if base in ('bc1t', 'bc1f'):
        cc = 0
        if ops and ops[0].startswith('$fcc'):
            cc = int(ops[0][4:])
        cmp_ = None
        cmp_unanalyzed = False
        for j in range(i - 1, max(i - 16, -1), -1):
            x = r.insns[j]
            if x['mn'].startswith('c.'):
                o = x['ops']
                xc = int(o[0][4:]) if o and o[0].startswith('$fcc') else 0
                if xc == cc:
                    if j not in r.in_states:
                        cmp_unanalyzed = True
                    cmp_ = (j, x)
                    break
        if cmp_unanalyzed:
            t = f = '(condition not analyzed)'
        elif cmp_ is None:
            t, f = 'FP condition code %d is true' % cc, 'FP condition code %d is false' % cc
        else:
            j, x = cmp_
            o = [q for q in x['ops'] if not q.startswith('$fcc')]
            cond = x['mn'].split('.')[1]
            sj = r.in_states[j]

            def fv(q):
                m = facts.FREG.match(q)
                v = sj.f.get(int(m.group(1))) if m else None
                return 'f%s%s' % (m.group(1), '(=%s)' % r.R(v) if v is not None and v != ('in', 'f' + m.group(1))
                                  else '') if m else q
            w = FP_WORDS.get(cond, cond)
            if len(o) == 2 and cond not in ('f', 'sf', 'un', 'ngle'):
                t = '%s %s %s (%s at 0x%x)' % (fv(o[0]), w, fv(o[1]), x['mn'], x['addr'])
            else:
                t = '%s %s (%s at 0x%x)' % (', '.join(fv(q) for q in o), w, x['mn'], x['addr'])
            f = 'not (%s)' % t
        return (t, f) if base == 'bc1t' else (f, t)
    return None, None


def terminator(r, i):
    """(kind, detail) of the branch at index i: cond, always, never, jump, return, indirect, call."""
    ins = r.insns[i]
    mn = ins['mn']
    if mn in facts.CALLS:
        return 'call'
    if mn in ('jr', 'jr.hb'):
        return 'return' if facts.reg(ins['ops'][0]) == 31 else 'indirect'
    if mn == 'j':
        return 'jump'
    if i not in r.in_states:
        return 'cond'
    never, always = r.static_cond(r.in_states[i], ins)
    return 'always' if always else 'never' if never else 'cond'


def contains_scaled_index(value):
    if not isinstance(value, tuple):
        return False
    if len(value) == 4 and value[:2] == ('op', '<<') and facts.is_c(value[3]) and value[3][1] in (2, 3):
        return True
    return any(contains_scaled_index(part) for part in value[1:])


def unresolved_table_jump(r, i):
    """Whether an indirect jump uses a value loaded through a scaled table address."""
    ins = r.insns[i]
    if ins['mn'] not in ('jr', 'jr.hb') or not ins['ops']:
        return False
    n = facts.reg(ins['ops'][0])
    v = r.in_states.get(i, {}).get(n) if n is not None else None
    if not isinstance(v, tuple) or not v:
        return False
    # The analyzer already recognised a table entry read; its targets are listed only
    # when the table image could be read, so reaching here means they were not.
    if v[0] in ('tent', 'tent_gp'):
        return True
    if v[0] != 'ld':
        return False
    address = v[1]
    if not contains_scaled_index(address):
        return False
    # An indexed address based at gp or a constructed constant is characteristic of
    # the switch tables this analyzer cannot resolve from a flat or incomplete image.
    def has_table_base(x):
        if not isinstance(x, tuple):
            return False
        if facts.is_c(x) or x == ('in', 'gp'):
            return True
        return any(has_table_base(part) for part in x[1:])
    return has_table_base(address)


def wire(r, blocks, by_first):
    """Give each block its exit record and successors."""
    for b in blocks:
        bi = None
        for j in range(b.first, b.last + 1):
            mn = r.insns[j]['mn']
            if facts.is_branch(mn) and mn not in facts.CALLS and j + 1 >= b.last:
                bi = j
        if bi is None:
            nxt = by_first.get(b.last + 1)
            b.exit = {'kind': 'fallthrough', 'next_block': nxt}
            b.succ = [('falls through', nxt)] if nxt is not None else []
            continue
        ins = r.insns[bi]
        kind = terminator(r, bi)
        t = facts.branch_target(ins) if ins['mn'] not in ('jr', 'jr.hb') else None
        tb = by_first.get(r.at.get(t)) if t is not None else None
        nxt = by_first.get(bi + 2)
        b.exit = {'kind': kind, 'index': bi, 'target': t, 'target_block': tb, 'next_block': nxt}
        if kind == 'cond':
            b.succ = [('taken', tb), ('falls through', nxt)]
        elif kind == 'always':
            b.succ = [('taken', tb)]
        elif kind == 'never':
            b.succ = [('falls through', nxt)]
        elif kind == 'jump':
            b.succ = [('jump', tb)]
        else:
            b.succ = []
    for b in blocks:
        if b.first not in r.in_states:
            continue  # a block no path reaches is not a predecessor of anything
        for _, s in b.succ:
            if s is not None and b not in s.preds:
                s.preds.append(b)


def arg_text(r, st_in, i):
    """Argument registers as the callee at index i sees them (after the delay slot)."""
    ins = r.insns[i]
    st = st_in.copy()
    r.step(st, ins)
    if i + 1 < len(r.insns):
        r.step(st, r.insns[i + 1])
    out = []
    names = r.img.regnames
    for k in range(r.nargs):
        n = 4 + k
        v = st.get(n)
        if v is None:
            if k < 4:
                out.append('%s=?' % names[n])
            continue
        if v == ('in', names[n]):
            if k < 4:
                out.append('%s=%s at entry (arg%d)' % (names[n], names[n], k))
        elif v[0] == 'in':
            o = ARG_ORDINAL.get(v[1])
            out.append('%s=%s at entry%s' % (names[n], v[1], ' (arg%d)' % o if o is not None else ''))
        else:
            out.append('%s=%s' % (names[n], r.R(v)))
    fp = []
    for k in range(r.nargs):
        v = st.f.get(12 + k)
        if v is not None and v != ('in', 'f%d' % (12 + k)):
            fp.append('f%d=%s' % (12 + k, r.R(v)))
    return out, fp


# ===================================================================== text

def sgn(x):
    return ('-0x%x' % -x) if x < 0 else '+0x%x' % x


def origin_note(r, origin):
    o = ARG_ORDINAL.get(origin)
    if o is not None and o < r.nargs:
        return '%s (arg%d at entry)' % (origin, o)
    if origin in r.img.regnames:
        return '%s (at entry)' % origin
    return origin


def render(r, fs):
    if isinstance(r, FirmwareRoutine):
        return r.render(fs)
    img = r.img
    asm = facts.Recorder(r).text
    nop = lambda x: 'nop' if x and x['mn'] == 'sll' and x['ops'] == ['$0', '$0', '0x0'] else asm(x)  # noqa: E731
    rt = fs['routine']
    L = []
    cls = 'ELF %d-bit' % img.elf.elfclass if img.elf is not None else 'raw'
    L.append('routine %s  0x%x-0x%x  size 0x%x (%d bytes, %d words)' % (
        rt['name'] or '(unnamed)', r.addr, r.addr + r.size, r.size, r.size, r.size // 4))
    L.append('  file %s  %s %s  ABI %s  ISA %s  address from %s, size from %s' % (
        rt['file'], cls, rt['kind'], rt['abi'], rt['isa'], rt['address_source'], rt['size_source']))
    L.append('  frame %d bytes  gp %s  argument registers read before written: %s' % (
        rt['frame_size'], rt['gp'] or 'none', ', '.join(fs['args']['read_before_write']) or 'none'))
    L.append('  legend: [X+N] is the word loaded from X+N; sp is the stack pointer at entry; ret(F) is what F '
             'returned; ? is a value the tool cannot follow')
    resolved = {t['jump'] for t in fs['jump_tables']}
    unresolved_tables = {i for i in range(len(r.insns))
                         if '0x%x' % r.insns[i]['addr'] not in resolved and unresolved_table_jump(r, i)}
    if fs['unreached']:
        L.append('  not reached by any path from the entry: %s' % ' '.join(fs['unreached']))
        if unresolved_tables:
            L.append('  (code behind an unresolved jump table may be reachable through it)')

    L.append('')
    L.append('accesses (%d)' % len(fs['accesses']))
    for a in fs['accesses']:
        bo = a['base_origin']
        if 'absolute' in a:
            tgt = 'abs %s%s' % (a['absolute'], ' (%s)' % a['symbol'] if a.get('symbol') else '')
        elif 'reloc' in a:
            tgt = 'reloc %s' % a['reloc']
        elif 'origin' in a:
            tgt = '%s %s' % (origin_note(r, a['origin']) if a['origin'] in img.regnames else a['origin'],
                             sgn(a['origin_offset']))
        else:
            tgt = '? (base unknown)'
        verb = 'load ' if a['kind'] == 'load' else 'store'
        reg_ = a['text'].split(' ', 1)[1].split(',')[0]
        val = ('  value %s' % a['value']) if a.get('value') not in (None, '?') and a['kind'] == 'store' else ''
        L.append('  %s %s w%d %-5s %-4s base=%s (%s) disp %s => %s%s' % (
            a['address'], verb, a['width'], a['mnemonic'], reg_, a['base'], bo, sgn(a['offset']), tgt, val))

    L.append('')
    calls = {c['address']: c for c in fs['calls']}
    ncalls = [i for i in range(len(r.insns)) if i in r.in_states and r.insns[i]['mn'] in facts.CALLS
              or (i in r.in_states and r.insns[i]['mn'] in ('j', 'jr', 'jr.hb') and
                  ('0x%x' % r.insns[i]['addr']) in calls)]
    L.append('calls (%d)' % len(ncalls))
    for i in ncalls:
        ins = r.insns[i]
        c = calls.get('0x%x' % ins['addr'], {})
        args, fp = arg_text(r, r.in_states[i], i)
        name = c.get('callee') or ('(unnamed)' if c.get('target') else '(unknown callee)')
        if c.get('target'):
            name = '%s [%s]' % (name, c['target'])
        L.append('  0x%x %s%s %s via %s' % (ins['addr'], 'tail ' if c.get('tail') else '', ins['mn'], name,
                                          c.get('kind', '?')))
        L.append('      args: %s%s' % (', '.join(args) or 'none set', ('; fp ' + ', '.join(fp)) if fp else ''))
        if c.get('delay_slot'):
            L.append('      delay slot: %s' % c['delay_slot'])

    blocks, by_first = build_blocks(r)
    wire(r, blocks, by_first)
    L.append('')
    L.append('blocks (%d)' % len(blocks))
    for b in blocks:
        i_in = b.first in r.in_states
        a0, a1 = r.insns[b.first]['addr'], r.insns[b.last]['addr']
        L.append('  %s 0x%x-0x%x  preds: %s%s' % (b.id, a0, a1, ', '.join(p.id for p in b.preds) or 'entry' if
                 b.first == 0 else ', '.join(p.id for p in b.preds) or 'none',
                 '' if i_in else '  (never reached)'))
        ex = b.exit
        k = ex['kind']
        if k == 'fallthrough':
            L.append('      falls into %s' % (ex['next_block'].id if ex.get('next_block') else 'the end of the routine'))
            continue
        bi = ex['index']
        ins = r.insns[bi]
        dl = r.insns[bi + 1] if bi + 1 < len(r.insns) else None
        dltxt = ('delay slot 0x%x `%s`' % (dl['addr'], nop(dl))) if dl else 'no delay slot'
        txt = nop(ins)
        likely = ins['mn'] in facts.LIKELY
        if k == 'cond':
            tw, fw = cond_words(r, b, bi) if bi in r.in_states else ('condition not analyzed',
                                                                      'condition not analyzed')
            tb, nb = ex['target_block'], ex['next_block']
            L.append('      0x%x `%s` -> 0x%x%s' % (ins['addr'], txt, ex['target'], ' (%s)' % tb.id if tb else ' (outside)'))
            L.append('      taken when %s -> %s' % (tw or '(condition not decoded)', tb.id if tb else 'outside'))
            L.append('      falls through when %s -> %s' % (fw or '(condition not decoded)',
                                                            nb.id if nb else 'end of routine'))
            L.append('      %s: %s' % (dltxt, 'branch-likely: runs only when taken, annulled on fall-through'
                                       if likely else 'runs on both paths'))
        elif k == 'always':
            tb = ex['target_block']
            L.append('      0x%x `%s` always taken -> %s; %s runs' % (
                ins['addr'], txt, tb.id if tb else 'outside', dltxt))
        elif k == 'never':
            L.append('      0x%x `%s` never taken (its condition can never hold for these operands); falls through; %s' % (
                ins['addr'], txt, ('annulled' if likely else 'runs') if dl else dltxt))
        elif k == 'jump':
            tb = ex['target_block']
            L.append('      0x%x `%s` -> %s; %s runs' % (ins['addr'], txt, tb.id if tb else 'outside the routine (tail jump)',
                                                       dltxt))
        elif k == 'return':
            L.append('      0x%x `%s` returns; %s runs' % (ins['addr'], txt, dltxt))
        elif k == 'indirect':
            tabs = [t for t in fs['jump_tables'] if t['jump'] == '0x%x' % ins['addr']]
            if tabs:
                tg = []
                for tv in tabs[0]['targets']:
                    bb = by_first.get(r.at.get(int(tv, 16)))
                    tg.append('%s=%s' % (tv, bb.id if bb else 'outside'))
                L.append('      0x%x `%s` jump table at %s: %s' % (ins['addr'], txt, tabs[0]['table'], ' '.join(tg)))
                for tv in tabs[0]['targets']:
                    bb = by_first.get(r.at.get(int(tv, 16)))
                    if bb is not None and bb not in [s for _, s in b.succ]:
                        b.succ.append(('table', bb))
                        if b not in bb.preds:
                            bb.preds.append(b)
            else:
                if bi in unresolved_tables:
                    L.append('      0x%x `%s` (jump table; successors unresolved)' % (ins['addr'], txt))
                else:
                    L.append('      0x%x `%s` indirect jump, targets not resolved' % (ins['addr'], txt))
        elif k == 'call':
            nb = ex['next_block']
            L.append('      0x%x `%s` is a call; execution continues at 0x%x' % (ins['addr'], txt, ins['addr'] + 8))

    # returns: ancestors per return block
    L.append('')
    L.append('returns (%d%s)' % (len(fs['exits']),
                                '; CFG incomplete due to unresolved jump table' if unresolved_tables else ''))
    rblocks = {}
    for b in blocks:
        if b.exit['kind'] == 'return':
            rblocks[r.insns[b.exit['index']]['addr']] = b
    for e in fs['exits']:
        a = int(e['address'], 16)
        b = rblocks.get(a)
        anc, work = set(), [b] if b else []
        while work:
            x = work.pop()
            if x.id in anc:
                continue
            anc.add(x.id)
            work.extend(x.preds)
        L.append('  %s in %s: v0 = %s%s; reached from blocks %s' % (
            e['address'], b.id if b else '?', e['v0'], '; f0 = %s' % e['f0'] if e.get('f0') else '',
            ' '.join(sorted(anc, key=lambda s: int(s[1:]))) or '?'))
        for p in e['paths']:
            L.append('      from %s: v0 = %s' % (p['from'], p['v0']))

    L.append('')
    L.append('constants')
    for c in fs['constants']:
        L.append('  %s %s = %s%s' % (c['address'], c['register'], c['value'],
                                    ' (%s%s)' % (c['section'], ' ' + c['symbol'] if c.get('symbol') else '')
                                    if c.get('section') else ''))
    byval = collections.OrderedDict()
    for m in fs['immediates']:
        byval.setdefault(m['hex'], []).append(m['address'])
    L.append('immediates')
    for v, ads in byval.items():
        L.append('  %s at %s' % (v, ' '.join(ads)))
    if fs['literals']:
        L.append('literal pool loads')
        for m in fs['literals']:
            L.append('  %s w%d %s from %s = %s' % (m['address'], m['width'], m['word'], m['data_address'],
                                                  m.get('float', m.get('double', ''))))
    if fs['mmio']:
        L.append('addresses outside the file (memory-mapped I/O)')
        for m in fs['mmio']:
            L.append('  %s %s %s' % (m['address'], m['kind'], m.get('absolute') or m.get('constant_part')))
    return '\n'.join(L) + '\n'


def split_binary(arg):
    path, member = arg, None
    m = re.fullmatch(r'(.+)\((.+)\)', path)
    if m and not os.path.exists(path):
        path, member = m.groups()
    elif ':' in path and not os.path.exists(path):
        path, member = path.split(':', 1)
    return path, member


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('binary', help='file, or archive:member')
    ap.add_argument('routine', help='symbol name or 0xADDRESS')
    ap.add_argument('--size', type=lambda s: int(s, 0))
    ap.add_argument('--arch', default='mips', choices=('mips', 'm68k', 'coldfire', 'arm', 'thumb', 'ppc32', 'x86-16', 'x86-32'))
    ap.add_argument('--offset', type=lambda s: int(s, 0), default=0, help='flat payload file offset')
    ap.add_argument('--abi', choices=('unknown', 'm68k-sysv', 'arm-aapcs', 'ppc-sysv', 'cdecl32', 'cdecl16'))
    formats = ap.add_mutually_exclusive_group()
    formats.add_argument('--flat', action='store_true', help='raw payload (MIPS/M68K/PowerPC big-endian; ARM/x86 little-endian)')
    formats.add_argument('--elf', action='store_true', help='mapped ARM ELF32, linked coordinates and relocation taint')
    ap.add_argument('--load', type=lambda s: int(s, 0))
    ap.add_argument('--isa', default='mips4', choices=('mips3', 'mips4'))
    ap.add_argument('--error-routine', action='append')
    ap.add_argument('--json', action='store_true', help='the facts.py JSON instead of text')
    a = ap.parse_args(argv)
    if a.arch != 'mips' and a.load is None:
        ap.error('non-MIPS firmware requires an explicit --load ADDR')
    path, member = split_binary(a.binary)
    try:
        r = routine_for(path, a.routine, member, a.size, a.flat, a.load or 0, a.isa, a.error_routine,
                        a.arch, a.offset, a.abi, a.elf)
        fs = r.facts(False)
    except ValueError as exc:
        ap.error(str(exc))
    fs['routine']['file'] = a.binary
    sys.stdout.write(json.dumps(fs, indent=1, sort_keys=True) + '\n' if a.json else render(r, fs))


if __name__ == '__main__':
    main()
