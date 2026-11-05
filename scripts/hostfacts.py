#!/usr/bin/env python3
"""Mechanical facts for one MIPS routine, readable as text, with no container.

Usage: scripts/hostfacts.py BINARY[:MEMBER] ROUTINE [--size N] [--flat --load ADDR [--isa mips3|mips4]]
                            [--offset N] [--json]

  uv run --with capstone --with pyelftools \\
      python -I retools/scripts/hostfacts.py root/usr/lib32/libGLcore.so CISendFc

Same inputs and arguments as scripts/facts.py, and the same analysis: this script replaces
only the disassembler. It decodes the routine with Capstone instead of the MIPS objdump that
facts.py runs in the toolchain container, builds the instruction list facts.py builds, and lets
facts.py's Routine track registers (lui/addiu/daddiu/ori/or/move/addu/shifts, stack slots, GOT
loads, relocations, meeting the values of every path into a block). What it adds is the text
form and a control-flow graph with each condition stated in words. A hostfacts run and a
facts.py run of one routine agree on every access, call and constant; the disassembly is the
only difference, and scripts/test_hostfacts.py checks the decoder against hand-assembled words.

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

# facts.py finds docs/inventory/functions.tsv one level above its own scripts directory, and a
# workspace starts it through its scripts/ links. Started as retools/scripts/hostfacts.py, the
# workspace is the directory holding retools/; started from another checkout of this repository
# (a copy under a scratch directory), it is the current directory when that holds docs/inventory.
if os.path.basename(os.path.dirname(HERE)) == 'retools':
    facts.HERE = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'scripts')
elif os.path.isdir(os.path.join(os.getcwd(), 'docs', 'inventory')):
    facts.HERE = os.path.join(os.getcwd(), 'scripts')

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
    """Split a string at separators outside balanced parentheses."""
    parts = []
    depth = 0
    start = 0
    for index, char in enumerate(value):
        if char == '(':
            depth += 1
        elif char == ')':
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


def routine_for(path, routine, member=None, size=None, flat=False, load=0, isa='mips4', errors=None):
    img = host_image(path, member, flat, load, isa)
    name, addr, sz, sec, src = img.find(routine, size)
    if flat and not sz:
        sz = facts.scan_size(img, addr)
        src = 'scanned to the last reachable return'
    return facts.Routine(img, name, addr, sz, sec if not flat else None, src, errors or facts.DEFAULT_ERRORS)


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
            fmt = x['mn'].split('.')[2] if x['mn'].count('.') > 1 else ''
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
    ap.add_argument('--flat', action='store_true', help='raw big-endian payload')
    ap.add_argument('--load', type=lambda s: int(s, 0), default=0)
    ap.add_argument('--isa', default='mips4', choices=('mips3', 'mips4'))
    ap.add_argument('--error-routine', action='append')
    ap.add_argument('--json', action='store_true', help='the facts.py JSON instead of text')
    a = ap.parse_args(argv)
    path, member = split_binary(a.binary)
    r = routine_for(path, a.routine, member, a.size, a.flat, a.load, a.isa, a.error_routine)
    fs = r.facts(False)
    fs['routine']['file'] = a.binary
    sys.stdout.write(json.dumps(fs, indent=1, sort_keys=True) + '\n' if a.json else render(r, fs))


if __name__ == '__main__':
    main()
