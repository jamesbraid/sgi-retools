#!/usr/bin/env python3
"""List the words a routine stores to a command window, in program order.

Usage:
    fifo_words.py BINARY START END [--window LO-HI] [--blocks] [--all-stores]
                  [--entry-t9 ADDR] [--inventory FILE] [--no-calls]

BINARY is an IRIX N32 or o32 ELF shared object (a libGLcore.so), START and END
the routine's address range (END exclusive; the "Address:" line of the
generated listing gives both, or use the inventory's address and size).
The routine is disassembled with the MIPS objdump (see scripts/toolchain.py)
and walked as a control-flow graph, delay slots included. Register contents
are tracked symbolically through the whole routine:

  * constants built with lui/ori/addiu/li/or/and/shifts are folded;
  * the entry argument registers are named a0..a7 ("entry a0"), and moves of
    them (for example move s0,a0) keep the name, so "a0+0x7b4c" is the word
    at offset 0x7b4c of the first argument whatever register holds it;
  * a load is shown as u32[address], u16[address], f32[address] and so on;
  * the result of a call is shown as ret@ADDR (ADDR the call instruction);
  * at a control-flow join a register keeps its value only if every
    predecessor agrees, else it is unknown ("?");
  * a PIC routine's gp is computed from t9 (taken to be the routine's own
    address, or --entry-t9), so loads from the global offset table fold to
    the callee or data address, which is read from the file and named from
    the inventory.

Every store whose folded address lies in the window (default 0x10000-0x11000,
the command FIFO window the Odyssey library maps) is printed with the store's
instruction address, the byte offset in the window, the stored width and the
value or its source. Calls are printed in line (callee named from its target
address, never from objdump's nearest-symbol label, which is wrong for
statics) so words sent by a callee are not mistaken for the routine's own.
Blocks that sit inside a backward branch's range are marked "loop": their
stores repeat. --blocks groups consecutive constant words into class-1 blocks
(header 0x0001cccc, operand count in bits 13:10, the BUZZ.h reading; a count
of 15 means sixteen operands) and reports a group's operand shortfall.
--all-stores also lists stores to a symbolic or unknown address that are not
stack saves, so a store through a FIFO pointer held in a register shows up.

The summary line counts window stores in the instruction stream; compare it
with the assembly before relying on a listing (a store the walk never reaches,
or a jump-table dispatch it cannot follow, is reported at the end).
"""
import argparse
import bisect
import collections
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import toolchain  # noqa: E402

M64 = (1 << 64) - 1

# Registers (objdump -M gpr-names=n32 spelling).
GPR = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
       't0', 't1', 't2', 't3', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
       't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']
CALLER_SAVED = {'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7',
                't0', 't1', 't2', 't3', 't8', 't9'}
# Float registers a call preserves: $f20 and up (n32 even numbers $f20..$f30).
FP_PRESERVED = {'$f%d' % i for i in range(20, 32)}


# ---- values ---------------------------------------------------------------
# ('C', n)             constant, 64-bit
# ('S', name, off)     symbolic name plus constant
# ('L', kind, addr)    load of kind (u32, f64, ...) from value addr
# ('E', text)          other expression, text already rendered
# ('?',)               unknown
UNK = ('?',)


def C(n):
    return ('C', n & M64)


def sx32(n):
    n &= 0xffffffff
    return n - (1 << 32) if n & 0x80000000 else n


def render(v, depth=0):
    k = v[0]
    if k == 'C':
        n = v[1]
        lo = n & 0xffffffff
        if n == (sx32(lo) & M64):
            return hex(lo)
        return hex(n)
    if k == 'S':
        return v[1] if v[2] == 0 else '%s%s0x%x' % (v[1], '+' if v[2] > 0 else '-', abs(v[2]))
    if k == 'L':
        return '%s[%s]' % (v[1], render(v[2], depth + 1))
    if k == 'E':
        return v[1]
    return '?'


def expr(op, *args, at=None):
    if any(a[0] == '?' for a in args):
        return UNK
    txt = '%s(%s)' % (op, ', '.join(render(a) for a in args))
    if len(txt) > 110:
        return ('E', 'expr@0x%x' % at if at else '?')
    return ('E', txt)


def add(a, b):
    if a[0] == '?' or b[0] == '?':
        return UNK
    if a[0] == 'C' and b[0] == 'C':
        return C(a[1] + b[1])
    if a[0] == 'S' and b[0] == 'C':
        return ('S', a[1], a[2] + sx64(b[1]))
    if a[0] == 'C' and b[0] == 'S':
        return ('S', b[1], b[2] + sx64(a[1]))
    return None


def sx64(n):
    return n - (1 << 64) if n & (1 << 63) else n


def mask32(v):
    """A 32-bit result: constants wrap and sign-extend."""
    if v[0] == 'C':
        return C(sx32(v[1]))
    return v


# ---- disassembly -----------------------------------------------------------
Insn = collections.namedtuple('Insn', 'addr word op args')

LINE = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)\s*(.*)$')


def disassemble(binary, lo, hi):
    out = subprocess.run([toolchain.objdump(), '-d', '-z', '-M', 'gpr-names=n32',
                          '--start-address=0x%x' % lo, '--stop-address=0x%x' % hi, binary],
                         check=True, capture_output=True, text=True).stdout
    insns = []
    for ln in out.splitlines():
        m = LINE.match(ln)
        if not m:
            continue
        args = m.group(4).split('#')[0].strip()
        args = re.sub(r'\s*<[^>]*>', '', args)
        insns.append(Insn(int(m.group(1), 16), int(m.group(2), 16), m.group(3), args))
    return insns


def split_args(a):
    return [x.strip() for x in a.split(',')] if a else []


def parse_mem(s):
    m = re.match(r'^(-?(?:0x)?[0-9a-fA-F]+)\((\w+)\)$', s)
    if not m:
        return None
    off = int(m.group(1), 0) if m.group(1).lower().startswith(('0x', '-0x')) else int(m.group(1))
    return off, m.group(2)


def to_int(s):
    return int(s, 0)


# ---- ELF data ---------------------------------------------------------------
class Image:
    """Section bytes for folding loads of read-only data and the GOT."""

    def __init__(self, path, inventory):
        from elftools.elf.elffile import ELFFile
        self.f = open(path, 'rb')
        self.elf = ELFFile(self.f)
        self.secs = []
        for s in self.elf.iter_sections():
            if s['sh_addr'] and s['sh_type'] == 'SHT_PROGBITS' and s.name in (
                    '.got', '.rodata', '.lit4', '.lit8', '.data', '.sdata', '.sdata2', '.srdata'):
                self.secs.append((s['sh_addr'], s['sh_size'], s.name, s))
        self.syms = {}
        for sec in ('.dynsym', '.symtab'):
            st = self.elf.get_section_by_name(sec)
            if st is not None:
                for sym in st.iter_symbols():
                    if sym.name and sym['st_value'] and sym['st_info']['type'] in ('STT_FUNC', 'STT_OBJECT'):
                        self.syms.setdefault(sym['st_value'], sym.name)
        self.funcs = {}
        if inventory and os.path.exists(inventory):
            rel = os.path.relpath(os.path.realpath(path))
            for ln in open(inventory):
                c = ln.rstrip('\n').split('\t')
                if len(c) > 7 and c[0] and os.path.basename(c[0]) == os.path.basename(path) \
                        and os.path.basename(os.path.dirname(c[0])) == os.path.basename(os.path.dirname(path)) \
                        and c[4].startswith('0x') and int(c[4], 16):
                    self.funcs.setdefault(int(c[4], 16), (c[6], int(c[5] or 0)))
        for a, n in self.syms.items():
            self.funcs.setdefault(a, (n, 0))
        self.addrs = sorted(self.funcs)

    def read32(self, addr):
        for base, size, name, s in self.secs:
            if base <= addr and addr + 4 <= base + size:
                return struct.unpack('>I', s.data()[addr - base:addr - base + 4])[0], name
        return None, None

    def name(self, addr):
        if addr in self.funcs:
            return self.funcs[addr][0]
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i >= 0:
            b = self.addrs[i]
            n, sz = self.funcs[b]
            if sz == 0 or addr < b + sz:
                return '%s+0x%x' % (n, addr - b)
        return None


# ---- state ------------------------------------------------------------------
class State:
    def __init__(self, regs=None, fregs=None, mem=None):
        self.r = regs if regs is not None else {}
        self.f = fregs if fregs is not None else {}
        self.m = mem if mem is not None else {}   # stack slots: (offset, width) -> value

    def copy(self):
        return State(dict(self.r), dict(self.f), dict(self.m))

    def get(self, name):
        if name == 'zero':
            return C(0)
        return self.r.get(name, UNK)

    def put(self, name, v):
        if name != 'zero':
            self.r[name] = v

    def meet(self, other):
        changed = False
        for d, od in ((self.r, other.r), (self.f, other.f), (self.m, other.m)):
            for k in list(d):
                if k not in od or od[k] != d[k]:
                    if d[k] != UNK:
                        d[k] = UNK
                        changed = True
        return changed


# ---- instruction semantics ----------------------------------------------------
BRANCH_RE = re.compile(r'^(b|beq|bne|beqz|bnez|blez|bgtz|bltz|bgez|bltzal|bgezal|bal|bc1t|bc1f)(l?)$')
LOADS = {'lw': 'u32', 'lwu': 'u32', 'lh': 's16', 'lhu': 'u16', 'lb': 's8', 'lbu': 'u8',
         'ld': 'u64', 'lwc1': 'f32', 'ldc1': 'f64'}
STORES = {'sw': 4, 'sh': 2, 'sb': 1, 'sd': 8, 'swc1': 4, 'sdc1': 8}
IDX_STORES = {'swxc1': 4, 'sdxc1': 8}
IDX_LOADS = {'lwxc1': 'f32', 'ldxc1': 'f64'}


class Ctx:
    def __init__(self, img, window, t9):
        self.img = img
        self.window = window
        self.t9 = t9


def step(ctx, st, ins, events):
    """Apply one non-branch instruction. events collects ('store'...), ('call'...)."""
    op, a = ins.op, split_args(ins.args)
    at = ins.addr

    def rd(n):
        return st.get(n)

    if op == 'nop':
        return
    if op == 'lui':
        st.put(a[0], C(sx32(to_int(a[1]) << 16)))
    elif op in ('li', 'dli'):
        st.put(a[0], C(to_int(a[1])))
    elif op in ('move', 'daddu_zero'):
        st.put(a[0], rd(a[1]))
    elif op in ('addiu', 'addi', 'daddiu', 'daddi'):
        v = add(rd(a[1]), C(to_int(a[2])))
        if v is None:
            v = expr('add', rd(a[1]), C(to_int(a[2])), at=at)
        st.put(a[0], mask32(v) if op in ('addiu', 'addi') else v)
    elif op in ('addu', 'add', 'daddu', 'dadd'):
        v = add(rd(a[1]), rd(a[2]))
        if v is None:
            v = expr('add', rd(a[1]), rd(a[2]), at=at)
        st.put(a[0], mask32(v) if op in ('addu', 'add') else v)
    elif op in ('subu', 'sub', 'dsubu', 'dsub'):
        x, y = rd(a[1]), rd(a[2])
        if x[0] == 'C' and y[0] == 'C':
            v = C(x[1] - y[1])
            st.put(a[0], mask32(v) if op in ('subu', 'sub') else v)
        elif x[0] == 'S' and y[0] == 'C':
            st.put(a[0], ('S', x[1], x[2] - sx64(y[1])))
        else:
            st.put(a[0], expr('sub', x, y, at=at))
    elif op in ('or', 'ori', 'and', 'andi', 'xor', 'xori', 'nor'):
        x = rd(a[1])
        y = C(to_int(a[2])) if op.endswith('i') else rd(a[2])
        base = op.rstrip('i') if op != 'ori' else 'or'
        base = {'or': 'or', 'and': 'and', 'xor': 'xor', 'nor': 'nor'}.get(base, base)
        if op == 'andi':
            base = 'and'
        if op == 'xori':
            base = 'xor'
        if x[0] == 'C' and y[0] == 'C':
            f = {'or': lambda p, q: p | q, 'and': lambda p, q: p & q,
                 'xor': lambda p, q: p ^ q, 'nor': lambda p, q: ~(p | q)}[base]
            st.put(a[0], C(f(x[1], y[1])))
        elif base == 'or' and y == C(0):
            st.put(a[0], x)
        elif base == 'or' and x == C(0):
            st.put(a[0], y)
        else:
            st.put(a[0], expr(base, x, y, at=at))
    elif op in ('sll', 'srl', 'sra', 'dsll', 'dsrl', 'dsra', 'dsll32', 'dsrl32', 'dsra32'):
        x = rd(a[1])
        sh = to_int(a[2]) + (32 if op.endswith('32') else 0)
        if x[0] == 'C':
            n = x[1]
            if op == 'sll':
                v = C(sx32(n << sh))
            elif op == 'srl':
                v = C(sx32((n & 0xffffffff) >> sh))
            elif op == 'sra':
                v = C(sx32(n) >> sh)
            elif op.startswith('dsll'):
                v = C(n << sh)
            elif op.startswith('dsrl'):
                v = C(n >> sh)
            else:
                v = C(sx64(n) >> sh)
            st.put(a[0], v)
        else:
            st.put(a[0], expr(op.rstrip('32') if op.endswith('32') else op, x, C(sh), at=at))
    elif op in ('sllv', 'srlv', 'srav', 'dsllv', 'dsrlv', 'dsrav'):
        st.put(a[0], expr(op, rd(a[1]), rd(a[2]), at=at))
    elif op in LOADS:
        mem = parse_mem(a[1])
        if mem is None:
            st.put(a[0], UNK) if not a[0].startswith('$f') else st.f.__setitem__(a[0], UNK)
            return
        off, base = mem
        addr = add(rd(base), C(off))
        if addr is None:
            addr = ('E', '%s%+d' % (render(rd(base)), off))
        v = ('L', LOADS[op], addr)
        if addr[0] == 'S' and addr[1] == 'sp':
            slot = st.m.get((addr[2], {'lw': 4, 'lwu': 4, 'lwc1': 4, 'ld': 8, 'ldc1': 8}.get(op, 0)))
            if slot is not None and slot != UNK:
                v = slot
        if addr[0] == 'C' and op in ('lw', 'lwu'):
            word, sec = ctx.img.read32(addr[1])
            if word is not None and sec in ('.got', '.rodata') and addr[1] % 4 == 0:
                v = C(sx32(word)) if op == 'lw' else C(word)
        if op in ('lwc1', 'ldc1'):
            st.f[a[0]] = v
        else:
            st.put(a[0], v)
    elif op in IDX_LOADS:
        addr = add(rd(a[1].split('(')[0]), rd(a[1].split('(')[1].rstrip(')')))
        v = ('L', IDX_LOADS[op], addr if addr else ('E', a[1]))
        st.f[a[0]] = v
    elif op in ('mtc1', 'dmtc1'):
        st.f[a[1]] = ('E', 'bits(%s)' % render(rd(a[0])))
    elif op in ('mfc1', 'dmfc1'):
        st.put(a[0], ('E', 'bits(%s)' % render(st.f.get(a[1], UNK))) if st.f.get(a[1], UNK) != UNK else UNK)
        if a[1] in st.f and st.f[a[1]][0] == 'L' and st.f[a[1]][1] == 'f32':
            st.put(a[0], ('L', 'u32', st.f[a[1]][2]))
    elif op in STORES or op in IDX_STORES:
        if op in STORES:
            mem = parse_mem(a[1])
            if mem is None:
                return
            off, base = mem
            addr = add(rd(base), C(off))
        else:
            b, i = a[1].split('(')[0], a[1].split('(')[1].rstrip(')')
            addr = add(rd(b), rd(i))
            off = 0
        width = STORES.get(op) or IDX_STORES[op]
        if op in ('swc1', 'sdc1', 'swxc1', 'sdxc1'):
            val = st.f.get(a[0], UNK)
        else:
            val = rd(a[0])
            if width == 4:
                val = mask32(val)
        if addr is not None and addr[0] == 'S' and addr[1] == 'sp':
            for w in (4, 8):
                for o in range(addr[2] - 7, addr[2] + width):
                    st.m.pop((o, w), None)
            if width in (4, 8):
                st.m[(addr[2], width)] = val
        events.append(('store', at, op, width, addr, val, base if op in STORES else None))
    elif op in ('movn', 'movz', 'slt', 'sltu', 'slti', 'sltiu'):
        args = [rd(x) if x in GPR else C(to_int(x)) for x in a[1:]]
        st.put(a[0], expr(op, *args, at=at) if args else UNK)
    elif op in ('mult', 'multu', 'dmult', 'dmultu', 'div', 'divu', 'ddiv', 'ddivu'):
        st.r['hi'] = st.r['lo'] = UNK
    elif op in ('mflo', 'mfhi'):
        st.put(a[0], UNK)
    elif op in ('mul', 'dmul'):
        x, y = rd(a[1]), rd(a[2])
        st.put(a[0], mask32(C(x[1] * y[1])) if x[0] == 'C' and y[0] == 'C' else expr('mul', x, y, at=at))
    elif op in ('cvt.s.w', 'cvt.d.w', 'cvt.s.d', 'cvt.d.s', 'cvt.w.s', 'cvt.w.d', 'trunc.w.s',
                'trunc.w.d', 'abs.s', 'abs.d', 'neg.s', 'neg.d', 'mov.s', 'mov.d', 'sqrt.s', 'sqrt.d',
                'floor.w.s', 'floor.w.d', 'ceil.w.s', 'ceil.w.d', 'round.w.s', 'round.w.d',
                'trunc.l.s', 'trunc.l.d', 'cvt.s.l', 'cvt.d.l', 'recip.s', 'recip.d', 'rsqrt.s', 'rsqrt.d'):
        src = st.f.get(a[1], UNK)
        st.f[a[0]] = src if op in ('mov.s', 'mov.d') else expr(op, src, at=at)
    elif re.match(r'^(add|sub|mul|div|madd|msub|nmadd|nmsub)\.[sd]$', op):
        args = [st.f.get(x, UNK) for x in a[1:]]
        st.f[a[0]] = expr(op, *args, at=at)
    elif op in ('movt', 'movf', 'movt.s', 'movf.s', 'movn.s', 'movz.s', 'movn.d', 'movz.d',
                'movt.d', 'movf.d'):
        pass
    elif op.startswith('c.') or op in ('cfc1', 'ctc1', 'sync', 'break', 'syscall', 'teq', 'tne'):
        if op == 'cfc1':
            st.put(a[0], UNK)
    else:
        # Unknown instruction that names a destination: be conservative.
        if a and a[0] in GPR:
            st.put(a[0], UNK)
        if a and a[0].startswith('$f'):
            st.f[a[0]] = UNK


def do_call(ctx, st, ins, target, events):
    events.append(('call', ins.addr, target, {n: st.get(n) for n in ('a0', 'a1', 'a2', 'a3', 'a4', 'a5')}))
    for n in CALLER_SAVED:
        st.r[n] = UNK
    for k in list(st.f):
        if k not in FP_PRESERVED:
            st.f[k] = UNK
    st.r['v0'] = ('E', 'ret@0x%x' % ins.addr)
    st.r['hi'] = st.r['lo'] = UNK


# ---- control flow ----------------------------------------------------------------
def branch_target(ins):
    m = re.search(r'([0-9a-f]+)\s*$', ins.args)
    return int(m.group(1), 16) if m else None


def classify(ins):
    """('call', target|None) / ('jump', target|None) / ('cond', target, likely) / ('ret',) / None"""
    op = ins.op
    a = split_args(ins.args)
    if op in ('jal', 'bal') or (op in ('bgezal', 'bgezall') and a[0] == 'zero'):
        return ('call', branch_target(ins))
    if op == 'jalr':
        return ('call', a[-1])
    if op == 'j':
        return ('jump', branch_target(ins))
    if op == 'b':
        return ('jump', branch_target(ins))
    if op == 'jr':
        return ('ret',) if a[0] == 'ra' else ('indirect', a[0])
    m = BRANCH_RE.match(op)
    if m:
        return ('cond', branch_target(ins), m.group(2) == 'l')
    return None


def analyze(insns, ctx, entry_state):
    idx = {i.addr: n for n, i in enumerate(insns)}
    leaders = {insns[0].addr}
    for n, ins in enumerate(insns):
        c = classify(ins)
        if c is None:
            continue
        if c[0] in ('cond', 'jump') and c[1] in idx:
            leaders.add(c[1])
        if n + 2 < len(insns):
            leaders.add(insns[n + 2].addr)
    addrs = sorted(leaders)
    blocks = {}
    for k, b in enumerate(addrs):
        end = addrs[k + 1] if k + 1 < len(addrs) else insns[-1].addr + 4
        blocks[b] = [i for i in insns if b <= i.addr < end]
    # A delay slot never starts a block (its branch is the previous insn); fold it.
    succ = {}
    for b, body in blocks.items():
        last = body[-1]
        ctrl = None
        # the control instruction is the second-to-last when a delay slot ends the block
        if len(body) >= 2 and classify(body[-2]):
            ctrl = body[-2]
        elif classify(last):
            ctrl = last  # delay slot lies past the block end (next block's first insn)
        s = []
        if ctrl is not None:
            c = classify(ctrl)
            nxt = ctrl.addr + 8
            if c[0] == 'cond':
                if c[1] in idx:
                    s.append(c[1])
                if nxt in blocks:
                    s.append(nxt)
            elif c[0] == 'jump':
                if c[1] in idx:
                    s.append(c[1])
            elif c[0] == 'call':
                if nxt in blocks:
                    s.append(nxt)
        else:
            nxt = body[-1].addr + 4
            if nxt in blocks:
                s.append(nxt)
        succ[b] = (ctrl, s)
    return blocks, succ


def run_block(ctx, st, body, ctrl, insns_by_addr, events):
    """Execute a block's instructions; the delay slot runs before the branch effect."""
    i = 0
    n = len(body)
    while i < n:
        ins = body[i]
        c = classify(ins)
        if c is None:
            step(ctx, st, ins, events)
            i += 1
            continue
        slot = body[i + 1] if i + 1 < n else insns_by_addr.get(ins.addr + 4)
        if c[0] == 'call':
            # a call's delay slot runs before the callee sees its arguments
            if slot:
                step(ctx, st, slot, events)
            tgt = c[1]
            if isinstance(tgt, str):
                v = st.get(tgt)
                tgt = v[1] & 0xffffffff if v[0] == 'C' else ('reg', tgt, render(v))
            do_call(ctx, st, ins, tgt, events)
        elif c[0] == 'cond' and c[2]:
            # branch likely: the slot executes only when taken; keep it off the fall-through
            events.append(('likely', ins.addr, slot.addr if slot else None))
            if slot:
                taken = st.copy()
                step(ctx, taken, slot, events)
                st.meet(taken)
        else:
            if slot:
                step(ctx, st, slot, events)
            if c[0] in ('indirect',):
                events.append(('indirect', ins.addr, c[1]))
        i += 2


def fixpoint(insns, ctx, entry):
    blocks, succ = analyze(insns, ctx, entry)
    by_addr = {i.addr: i for i in insns}
    instate = {insns[0].addr: entry}
    work = [insns[0].addr]
    while work:
        b = work.pop(0)
        st = instate[b].copy()
        ev = []
        ctrl, _ = succ[b]
        run_block(ctx, st, blocks[b], ctrl, by_addr, ev)
        for s in succ[b][1]:
            if s not in instate:
                instate[s] = st.copy()
                work.append(s)
            elif instate[s].meet(st):
                work.append(s)
    return blocks, succ, instate, by_addr


# ---- output -------------------------------------------------------------------------
def fmt_word(v):
    if v[0] == 'C':
        return '0x%08x' % (v[1] & 0xffffffff)
    return render(v)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('start', type=lambda s: int(s, 0))
    ap.add_argument('end', type=lambda s: int(s, 0))
    ap.add_argument('--window', default='0x10000-0x11000')
    ap.add_argument('--blocks', action='store_true')
    ap.add_argument('--all-stores', action='store_true')
    ap.add_argument('--no-calls', action='store_true')
    ap.add_argument('--entry-t9', type=lambda s: int(s, 0))
    ap.add_argument('--inventory', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                         '..', 'docs', 'inventory', 'functions.tsv'))
    args = ap.parse_args()
    lo, hi = (int(x, 0) for x in args.window.split('-'))
    img = Image(args.binary, args.inventory)
    insns = disassemble(args.binary, args.start, args.end)
    if not insns:
        sys.exit('no instructions in range')
    ctx = Ctx(img, (lo, hi), args.entry_t9 or args.start)
    entry = State()
    for n in ('a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'):
        entry.r[n] = ('S', n, 0)
    entry.r['sp'] = ('S', 'sp', 0)
    entry.r['t9'] = C(ctx.t9)
    entry.r['ra'] = ('S', 'ra', 0)
    gpv = [t.entry.d_val for t in img.elf.get_section_by_name('.dynamic').iter_tags()
           if t.entry.d_tag in ('DT_MIPS_GP_VALUE', 0x70000030)] if img.elf.get_section_by_name('.dynamic') else []
    for n in ('s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8'):
        entry.r[n] = ('S', 'entry_' + n, 0)
    # A static routine inherits its caller's gp; an exported one recomputes it from t9.
    entry.r['gp'] = C(gpv[0]) if gpv else ('S', 'entry_gp', 0)
    blocks, succ, instate, by_addr = fixpoint(insns, ctx, entry)

    # Natural loops: a depth-first walk finds back edges (an edge to a block still on
    # the walk's stack); a loop body is the header plus every block that reaches the
    # edge's source without passing through the header.
    loop_blocks = set()
    state = {}
    preds = collections.defaultdict(set)
    for b, (_, ss) in succ.items():
        for t in ss:
            preds[t].add(b)
    stack = [(insns[0].addr, iter(succ[insns[0].addr][1]))]
    state[insns[0].addr] = 1
    backs = []
    while stack:
        b, it = stack[-1]
        for t in it:
            if state.get(t) == 1:
                backs.append((b, t))
            elif t not in state:
                state[t] = 1
                stack.append((t, iter(succ[t][1])))
                break
        else:
            state[b] = 2
            stack.pop()
    for src, hdr in backs:
        body, todo = {hdr}, [src]
        while todo:
            n = todo.pop()
            if n not in body:
                body.add(n)
                todo.extend(preds[n])
        loop_blocks |= body

    name = img.name(args.start) or 'routine'
    print('# %s 0x%x-0x%x %s   window 0x%x-0x%x' % (os.path.basename(args.binary), args.start, args.end,
                                                   name, lo, hi))
    print('# a0..a7 are the entry argument registers; u32[X] is a load from X; ret@A is the result of the call at A')
    nstores = 0
    seq = []
    unreached = [b for b in blocks if b not in instate]
    for b in sorted(blocks):
        if b not in instate:
            continue
        st = instate[b].copy()
        ev = []
        run_block(ctx, st, blocks[b], succ[b][0], by_addr, ev)
        loop = ' loop' if b in loop_blocks else ''
        print('L%x:%s' % (b, loop))
        for e in ev:
            if e[0] == 'store':
                _, at, op, width, addr, val, base = e
                if addr is not None and addr[0] == 'C' and lo <= addr[1] & 0xffffffff < hi:
                    nstores += 1
                    off = addr[1] & 0xffffffff
                    print('  %x  [+0x%x] %s%s <- %s' % (at, off - lo, op, '' if width == 4 else ' w%d' % width,
                                                       fmt_word(val)))
                    seq.append((at, off - lo, width, val, loop))
                elif args.all_stores and base != 'sp':
                    print('  %x  (other) %s [%s] <- %s' % (at, op, render(addr) if addr else '?', fmt_word(val)))
            elif e[0] == 'call' and not args.no_calls:
                _, at, tgt, regs = e
                if isinstance(tgt, int):
                    nm = img.name(tgt) or '?'
                    tg = '0x%x %s' % (tgt, nm)
                else:
                    tg = '%s=%s' % (tgt[1], tgt[2])
                a = ' '.join('%s=%s' % (k, render(v)) for k, v in regs.items() if v != UNK and k in ('a0', 'a1', 'a2', 'a3'))
                print('  %x  CALL %s  %s' % (at, tg, a))
            elif e[0] == 'indirect':
                print('  %x  INDIRECT JUMP via %s (jump table; run IrixJumpTables and read the cases)' % (e[1], e[2]))
            elif e[0] == 'likely':
                print('  %x  branch-likely: its delay slot runs only when taken' % e[1])
        ctrl, s = succ[b]
        if ctrl is not None:
            c = classify(ctrl)
            if c[0] == 'cond':
                print('  %x  %s %s -> L%x%s' % (ctrl.addr, ctrl.op, ctrl.args, c[1] or 0,
                                                '' if c[1] in blocks else ' (outside range)'))
            elif c[0] == 'jump':
                print('  %x  %s -> %s' % (ctrl.addr, ctrl.op, 'L%x' % c[1] if c[1] in blocks else
                                          '0x%x (outside range: tail call %s)' % (c[1] or 0, img.name(c[1] or 0))))
            elif c[0] == 'ret':
                print('  %x  return' % ctrl.addr)
    print('# %d stores to the window in %d instructions (%d blocks reached%s)' % (
        nstores, len(insns), len(instate), ', %d not reached' % len(unreached) if unreached else ''))
    raw = sum(1 for i in insns if i.op in STORES and re.search(r'\(%s\)$' % '|'.join(GPR), i.args))
    print('# %d store instructions of any kind in the range (count the window ones against the assembly)' % raw)
    if unreached:
        print('# blocks never reached by the walk (data after jr, or targets of an indirect jump): ' +
              ' '.join('L%x' % b for b in sorted(unreached)))
    if args.blocks:
        print('# class-1 grouping of the constant header words above (inferred from BUZZ.h)')
        k = 0
        while k < len(seq):
            at, off, width, val, loop = seq[k]
            if val[0] == 'C' and (val[1] & 0xffff0000) == 0x10000:
                cnt = (val[1] >> 10) & 0xf
                n = 16 if cnt == 15 else cnt
                got = 0
                j = k + 1
                while j < len(seq) and got < n:
                    got += 1
                    j += 1
                short = '' if got == n else '   SHORT: %d of %d operands before the next header or end' % (got, n)
                ops = ' '.join(fmt_word(x[3]) for x in seq[k + 1:j])
                print('  %x  block 0x%03x count %d%s: %s%s' % (at, val[1] & 0x3ff, n, ' loop' if loop else '', ops, short))
                k = j
            else:
                print('  %x  word %s' % (at, fmt_word(val)))
                k += 1


if __name__ == '__main__':
    main()
