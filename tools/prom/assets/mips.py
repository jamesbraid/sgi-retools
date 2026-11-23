"""A small MIPS reader for the asset finders: decode words, split code into routines, and run a routine on the
constants it loads (lui/ori/addiu and friends) while recording its stores and calls."""
import struct
from collections import namedtuple

JR_RA = 0x03e00008
Ins = namedtuple('Ins', 'pc word op rs rt rd sh fn imm uimm')
Call = namedtuple('Call', 'pc target slot args stack0 regs tags')
Write = namedtuple('Write', 'pc addr size value')
SP = 0x7fff0000
STEP_LIMIT = 40000


class Unknown(Exception):
    """The run needs a value it does not have (a branch on an unknown register, a jump to an unknown address)."""


def decode(word, pc):
    imm = word & 0xffff
    return Ins(pc, word, word >> 26, word >> 21 & 31, word >> 16 & 31, word >> 11 & 31, word >> 6 & 31, word & 63,
               imm - 0x10000 if imm & 0x8000 else imm, imm)


def decode_all(data, base):
    return [decode(w, base + 4 * i) for i, w in enumerate(struct.unpack('>%dI' % (len(data) // 4), data[:len(data) // 4 * 4]))]


def routines(code):
    """Start indexes of the routines in decoded code: the start, then the word after each `jr ra` delay slot."""
    return [0] + [i + 2 for i, c in enumerate(code) if c.word == JR_RA and i + 2 < len(code)]


def routine_at(starts, index):
    """(first, end) indexes of the routine holding instruction index."""
    lo = max(s for s in starts if s <= index)
    hi = min((s for s in starts if s > index), default=None)
    return lo, hi


def s32(v):
    return v - (1 << 32) if v & 0x80000000 else v


class Machine:
    """Registers hold an int or None (unknown); a tag follows a value that came from a call's out-pointer."""

    def __init__(self, code, base):
        self.code, self.base = code, base
        self.r = [0] * 32
        self.tag = {}
        self.src = {}               # register -> offset of the load that filled it (a call through a table slot)
        self.r[29] = SP
        self.mem = {}               # address -> (value, tag, size)
        self.writes, self.calls, self.seen = [], [], set()
        self.pc = 0

    def reg(self, n):
        return 0 if n == 0 else self.r[n]

    def put(self, n, value, tag=None):
        if n:
            self.src.pop(n, None)
            self.r[n] = None if value is None else value & 0xffffffff
            if value is not None:
                self.seen.add(self.r[n])
            self.tag[n] = tag

    def fetch(self, pc):
        i = (pc - self.base) // 4
        if pc & 3 or not 0 <= i < len(self.code):
            raise Unknown('jump outside the code at %#x' % pc)
        return self.code[i]

    def alu(self, c):
        a, b = self.reg(c.rs), self.reg(c.rt)
        if c.op == 0:
            f = c.fn
            if f in (0, 2, 3):
                if b is None:
                    return self.put(c.rd, None)
                self.put(c.rd, b << c.sh if f == 0 else b >> c.sh if f == 2 else s32(b) >> c.sh, self.tag.get(c.rt))
            elif f in (0x21, 0x23, 0x25) and (a is None or b is None):
                self.put(c.rd, None)
            elif f == 0x21:
                self.put(c.rd, a + b, self.tag.get(c.rt) if c.rs == 0 else self.tag.get(c.rs) if c.rt == 0 else None)
            elif f == 0x23:
                self.put(c.rd, a - b)
            elif f == 0x25:
                self.put(c.rd, a | b, self.tag.get(c.rs) if c.rt == 0 else self.tag.get(c.rt) if c.rs == 0 else None)
            else:
                raise Unknown('unhandled function %#x at %#x' % (f, c.pc))
        elif c.op == 0xf:
            self.put(c.rt, c.uimm << 16)
        elif c.op in (9, 0xd, 0xc, 0xa, 0xb):
            if a is None:
                return self.put(c.rt, None)
            if c.op == 9:
                self.put(c.rt, a + c.imm, self.tag.get(c.rs) if c.imm == 0 else None)
            elif c.op == 0xd:
                self.put(c.rt, a | c.uimm)
            elif c.op == 0xc:
                self.put(c.rt, a & c.uimm)
            else:
                lhs = s32(a) if c.op == 0xa else a
                self.put(c.rt, int(lhs < (c.imm if c.op == 0xa else c.imm & 0xffffffff)))
        else:
            raise Unknown('unhandled opcode %#x at %#x' % (c.op, c.pc))

    def memory(self, c):
        base = self.reg(c.rs)
        addr = None if base is None else (base + c.imm) & 0xffffffff
        size = {0x23: 4, 0x2b: 4, 0x29: 2, 0x21: 2, 0x25: 2, 0x28: 1, 0x20: 1, 0x24: 1}.get(c.op)
        if size is None:
            raise Unknown('unhandled opcode %#x at %#x' % (c.op, c.pc))
        if c.op in (0x2b, 0x29, 0x28):
            if addr is None:
                return
            value = self.reg(c.rt)
            old = self.mem.get(addr)
            keep = old[1] if old and str(old[1]).startswith('slot:') else None
            self.mem[addr] = (value, keep or self.tag.get(c.rt), size)
            if not SP - 0x10000 <= addr < SP + 0x10000 and value is not None:
                self.writes.append(Write(c.pc, addr, size, value & ((1 << 8 * size) - 1)))
        else:
            hit = self.mem.get(addr) if addr is not None else None
            if hit and hit[2] == size and c.op == 0x23:
                self.put(c.rt, hit[0], hit[1].replace('slot:', 'out:') if hit[1] and hit[1].startswith('slot:') else hit[1])
            else:
                self.put(c.rt, None)
            if c.op == 0x23:
                self.src[c.rt] = c.imm

    def call(self, c, target):
        a = [self.reg(n) for n in (4, 5, 6, 7)]
        sp = self.r[29]
        s0 = self.mem.get(sp + 16, (None, None))[0]
        slot = self.src.get(c.rs) if c.op == 0 else None
        self.calls.append(Call(c.pc, target, slot, a, s0, list(self.r),
                          (self.tag.get(6), self.tag.get(7), self.mem.get(sp + 16, (0, None))[1])))
        for n in range(4, 8):               # a pointer into the stack is an out parameter: its slot is now the callee's
            if a[n - 4] is not None and sp <= a[n - 4] < sp + 0x200:
                self.mem[a[n - 4]] = (None, 'slot:%x' % (target or 0), 4)
        for n in (1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 4, 5, 6, 7):
            self.put(n, None)
        self.put(2, 0)

    def run(self, start, stop_at=None):
        """Execute from the address start to the routine's `jr ra`, or until the next instruction to run is at
        stop_at. Raises Unknown when it cannot follow the code."""
        pc = start
        for _ in range(STEP_LIMIT):
            if pc == stop_at:
                return
            c = self.fetch(pc)
            nxt = pc + 4
            kind = None
            if c.op == 0 and c.fn == 8:
                kind, dest = 'jr', self.reg(c.rs)
            elif c.op == 0 and c.fn == 9:
                kind, dest = 'jalr', self.reg(c.rs)
            elif c.op == 3:
                kind, dest = 'jal', (pc & 0xf0000000) | (c.word & 0x3ffffff) << 2
            elif c.op in (4, 5, 0x14, 0x15):
                a, b = self.reg(c.rs), self.reg(c.rt)
                if a is None or b is None:
                    raise Unknown('branch on an unknown value at %#x' % pc)
                taken = (a == b) == (c.op in (4, 0x14))
                kind, dest = 'branch', pc + 4 + 4 * c.imm
                likely = c.op in (0x14, 0x15)
            if kind is None:
                if c.op in (0x23, 0x2b, 0x29, 0x28, 0x21, 0x25, 0x20, 0x24):
                    self.memory(c)
                else:
                    self.alu(c)
                pc = nxt
                continue
            delay = self.fetch(pc + 4)
            if kind == 'branch':
                if taken or not likely:
                    self.step(delay)
                pc = dest if taken else pc + 8
                continue
            if kind == 'jr' and c.rs == 31:
                self.step(delay)
                return
            if kind == 'jr':
                raise Unknown('indirect jump at %#x' % pc)
            self.step(delay)
            self.call(c, dest)
            pc += 8
        raise Unknown('step limit reached')

    def step(self, c):
        if c.op in (0x23, 0x2b, 0x29, 0x28, 0x21, 0x25, 0x20, 0x24):
            self.memory(c)
        else:
            self.alu(c)

    def sweep(self, start, end):
        """Execute the words from start to end in order, ignoring branches and jumps (callees are not entered and
        nothing is clobbered). For straight-line set-up code, and to see every constant a routine builds."""
        for pc in range(start, end, 4):
            c = self.fetch(pc)
            if c.op in (1, 2, 3, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17) or (c.op == 0 and c.fn in (8, 9)):
                continue
            try:
                self.step(c)
            except Unknown:
                if c.op == 0:
                    self.put(c.rd, None)
                elif not 0x28 <= c.op <= 0x2f:
                    self.put(c.rt, None)
