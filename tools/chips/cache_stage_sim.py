#!/usr/bin/env python3
"""Run the boot PROM's cache-staging routine against a small R10000 cache model.

Usage: cache_stage_sim.py PROM.bin [--sc-size BYTES] [--sc-block 64|128]
                          [--dword hi-lo|lo-hi] [--miss flash|zero] [--victim invalid-first|way0]
                          [--copy-len N] [--trace] [--regions] [--matrix]

PROM.bin is the flat `ip35prom` segment unpacked by retools/tools/chips/promgen64.py (load address
0xc00000001fc00000, physical 0x1fc00000). The routine under test is 0x1fc04980..0x1fc04e8c,
entered through its two callers, the copy wrapper (0x1fc05910) and the verify wrapper
(0x1fc059d0). The interpreter runs only the integer, CP1-move, CP0-move and CACHE
instructions those paths use, and stops on anything else.

Cache model (MIPS R10000 Microprocessor User's Manual, version 2.0, October 10, 1996):
  primary instruction cache  32 KB, 2-way, 64-byte blocks, index VA[13:6], way VA[0]  (4.1, 10.2)
  primary data cache         32 KB, 2-way, 32-byte blocks (4.2); not exercised by this routine
  secondary cache            2-way, size and block (64 or 128 bytes) are mode-bit choices (5.1);
                             index PA[size-2:block], way PA[0], quadword PA[block-1:4] (10.10, 10.22)
CACHE ops modelled: Index Store Tag (I, S) 0x08 0x0b, Index Load Tag (S) 0x07, Index Load Data
(I, S) 0x18 0x1b, Index Store Data (I, S) 0x1c 0x1f, Index Invalidate (I) 0x00; anything else stops.
Field layouts follow 10.5-10.22 and 14.21-14.23.

Choices the manual does not settle are options, each run reported:
  --dword   which of TagHi/TagLo carries which word of a secondary-cache doubleword. Figure 14-33
            says TagHi = bits 63:32, TagLo = bits 31:0 ("hi-lo"). "lo-hi" is the swapped order.
  --victim  on a primary instruction refill: invalid-first takes an Invalid way before a Valid one
            and way 0 if both are Invalid; way0 always replaces way 0. The manual gives LRU but
            not its encoding.
  --miss    what a cached fetch that misses both caches returns from the system: the flash bytes
            or zeroes. The miss itself is always reported.
Not modelled: predecode bits (the 4 high bits of a 36-bit instruction stay zero), parity and ECC
checking, the virtual-index/subset checks, cache-error exceptions.
"""
import argparse
import struct
import sys

import capstone

M64 = (1 << 64) - 1
BASE = 0x1fc00000
REG = {n: i for i, n in enumerate(
    'zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra'.split())}
CPU = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | capstone.CS_MODE_BIG_ENDIAN)
CPU.skipdata = True


def s64(x):
    return x - (1 << 64) if x >> 63 else x


def s32(x):
    x &= 0xffffffff
    return x - (1 << 32) if x >> 31 else x


class Stop(Exception):
    pass


class Machine:
    def __init__(self, flash, sc_size, sc_block, dword, miss, victim='invalid-first'):
        self.victim = victim
        self.flash = flash
        self.ram = {}
        self.sc_size, self.sc_block, self.dword, self.miss = sc_size, sc_block, dword, miss
        self.nset_s = sc_size // 2 // sc_block
        # primary I: [set][way] = dict(valid, tag, lru, words[16])
        self.ic = [[dict(valid=0, tag=0, lru=0, w=[0] * 16, src='-') for _ in range(2)] for _ in range(256)]
        # secondary: tags [set][way] = dict(state, tag, pidx, ecc, mru); data[(set,way,quad)] = [dw0, dw1, chk]
        self.st = {}
        self.sd = {}
        self.r = [0] * 32
        self.f = {}
        self.tlo = self.thi = self.ecc = 0
        self.log = []
        self.fetchlog = []
        self.pc = 0
        self.steps = 0

    # ---- address translation: (kind, pa)
    def xlate(self, va):
        top = va >> 62
        if top == 2:  # xkphys: cache algorithm in VA[61:59]
            cca = (va >> 59) & 7
            return ('cached' if cca in (3, 4, 5) else 'uncached'), va & 0xfffffffff, cca
        if va >> 32 == 0xffffffff and 0xa0000000 <= (va & 0xffffffff) < 0xc0000000:
            return 'uncached', va & 0x1fffffff, 2  # kseg1
        if top == 3 and (va >> 32) == 0xc0000000:  # window the PROM maps with TLB entry 62
            return 'uncached', va & 0xffffffff, 2
        raise Stop('untranslated address %#x at pc %#x' % (va, self.pc))

    def mem_read(self, pa, n):
        out = bytearray()
        for i in range(n):
            a = pa + i
            if 0x18000000 <= a < 0x18000000 + len(self.flash):  # boot-space source alias of flash offset 0
                out.append(self.flash[a - 0x18000000])
            elif BASE <= a < BASE + len(self.flash):
                out.append(self.flash[a - BASE])
            else:
                out.append(self.ram.get(a, 0))
        return bytes(out)

    def mem_write(self, pa, data):
        for i, b in enumerate(data):
            self.ram[pa + i] = b

    def flash_word(self, pa):
        return struct.unpack('>I', self.flash[pa - BASE:pa - BASE + 4])[0] if BASE <= pa < BASE + len(self.flash) else None

    # ---- secondary cache helpers
    def s_idx(self, pa):
        return (pa // self.sc_block) % self.nset_s

    def s_find(self, pa):
        s = self.s_idx(pa)
        for w in (0, 1):
            t = self.st.get((s, w))
            if t and t['state'] and t['tag'] == (pa >> 18):
                return s, w
        return None

    def s_dword(self, s, w, quad, half):
        q = self.sd.get((s, w, quad), [0, 0, 0])
        return q[half]

    # ---- instruction fetch
    def fetch(self, va):
        kind, pa, cca = self.xlate(va)
        if kind == 'uncached':
            return self.flash_word(pa) if self.flash_word(pa) is not None else struct.unpack('>I', self.mem_read(pa, 4))[0], 'uncached'
        idx = (va >> 6) & 0xff
        wi = (va >> 2) & 15
        for w in (0, 1):
            e = self.ic[idx][w]
            if e['valid'] and e['tag'] == pa >> 12:
                return e['w'][wi] & 0xffffffff, 'I-hit way%d (%s)' % (w, 'line staged by CACHE ops' if e['src'] != 'refill' else 'line refilled from S')
        hit = self.s_find(pa)
        if hit:
            s, w = hit
            base = pa & ~63
            words = []
            for q in range(4):
                p = base + 16 * q
                quad = (p // 16) % (self.sc_block // 16)
                for half in (0, 1):
                    d = self.s_dword(s, w, quad, half)
                    words += [d >> 32, d & 0xffffffff]
            e0, e1 = self.ic[idx]
            if self.victim == 'way0':
                vic = 0
            else:  # an Invalid way first, otherwise way 0 (the manual names LRU but not its encoding)
                vic = 1 if (e0['valid'] and not e1['valid']) else 0
            e = self.ic[idx][vic]
            e.update(valid=1, tag=pa >> 12, w=words, src='refill')
            return words[wi], 'I-miss, S-hit, refill way%d' % vic
        word = self.flash_word(pa) if self.miss == 'flash' else 0
        if word is None:
            word = struct.unpack('>I', self.mem_read(pa, 4))[0]
        return word, 'I-miss, S-miss (system read)'

    # ---- CACHE
    def cache(self, op, va):
        kind, pa, cca = self.xlate(va)
        way = va & 1
        name = {0x00: 'Index Invalidate (I)', 0x08: 'Index Store Tag (I)', 0x18: 'Index Load Data (I)',
                0x1c: 'Index Store Data (I)', 0x07: 'Index Load Tag (S)', 0x0b: 'Index Store Tag (S)',
                0x1b: 'Index Load Data (S)', 0x1f: 'Index Store Data (S)'}.get(op)
        if name is None:
            raise Stop('unmodelled CACHE op %#x at pc %#x' % (op, self.pc))
        tlo, thi, ecc = self.tlo, self.thi, self.ecc
        info = ''
        if op == 0x08:
            e = self.ic[(va >> 6) & 0xff][way]
            e.update(tag=(tlo >> 8 & 0xffffff) | (thi & 0xf) << 24, valid=tlo >> 6 & 1, lru=tlo >> 3 & 1, src='staged')
            info = 'set %#x way %d tag PA[39:12]=%#x valid=%d' % ((va >> 6) & 0xff, way, e['tag'], e['valid'])
        elif op == 0x18:
            e = self.ic[(va >> 6) & 0xff][way]
            v = e['w'][(va >> 2) & 15]
            self.tlo, self.thi, self.ecc = v & 0xffffffff, v >> 32 & 0xf, 0
            info = 'set %#x way %d word %d -> TagLo %#x' % ((va >> 6) & 0xff, way, (va >> 2) & 15, self.tlo)
        elif op == 0x1c:
            e = self.ic[(va >> 6) & 0xff][way]
            e['w'][(va >> 2) & 15] = (thi & 0xf) << 32 | tlo
            info = 'set %#x way %d word %d <- %#x' % ((va >> 6) & 0xff, way, (va >> 2) & 15, tlo)
        elif op == 0x00:
            self.ic[(va >> 6) & 0xff][way]['valid'] = 0
        else:
            s = self.s_idx(pa & ~1)
            quad = (pa >> 4) % (self.sc_block // 16)
            half = (pa >> 3) & 1
            if op == 0x0b:
                self.st[(s, way)] = dict(state=tlo >> 10 & 3, tag=(tlo >> 14 & 0x3ffff) | (thi & 0xf) << 18,
                                         pidx=tlo >> 7 & 3, ecc=tlo & 0x7f, mru=thi >> 31)
                info = 'set %#x way %d state %d tag PA[39:18]=%#x' % (s, way, tlo >> 10 & 3, self.st[(s, way)]['tag'])
            elif op == 0x07:
                t = self.st.get((s, way), dict(state=0, tag=0, pidx=0, ecc=0, mru=0))
                self.tlo = t['ecc'] | t['pidx'] << 7 | t['state'] << 10 | (t['tag'] & 0x3ffff) << 14
                self.thi = t['tag'] >> 18 & 0xf | t['mru'] << 31
            elif op == 0x1f:
                d = ((thi << 32 | tlo) if self.dword == 'hi-lo' else (tlo << 32 | thi)) & M64
                q = [0, 0, ecc & 0x3ff]
                q[half] = d
                self.sd[(s, way, quad)] = q
                info = 'set %#x way %d quad %d half %d <- %#018x' % (s, way, quad, half, d)
            elif op == 0x1b:
                d = self.s_dword(s, way, quad, half)
                if self.dword == 'hi-lo':
                    self.thi, self.tlo = d >> 32, d & 0xffffffff
                else:
                    self.tlo, self.thi = d >> 32, d & 0xffffffff
                self.ecc = self.sd.get((s, way, quad), [0, 0, 0])[2]
                info = 'set %#x way %d quad %d half %d -> %#018x' % (s, way, quad, half, d)
        self.log.append((self.steps, self.pc, name, va, pa, tlo, thi, ecc, info))

    # ---- interpreter
    def rd(self, n):
        return self.r[n]

    def wr(self, n, v):
        if n:
            self.r[n] = v & M64

    def ld(self, va, n):
        kind, pa, cca = self.xlate(va)
        if kind == 'cached':
            self.log.append((self.steps, self.pc, 'CACHED LOAD', va, pa, 0, 0, 0, 'data-cache access, not modelled; read from memory'))
        return int.from_bytes(self.mem_read(pa, n), 'big')

    def st_(self, va, v, n):
        kind, pa, cca = self.xlate(va)
        if kind == 'cached':
            self.log.append((self.steps, self.pc, 'CACHED STORE', va, pa, 0, 0, 0, 'data-cache access, not modelled'))
        self.mem_write(pa, (v & ((1 << 8 * n) - 1)).to_bytes(n, 'big'))

    def run(self, pc, stop, limit=5_000_000):
        self.pc = pc
        stops = stop if isinstance(stop, (set, frozenset)) else {stop}
        while self.pc not in stops:
            self.steps += 1
            if self.steps > limit:
                raise Stop('step limit')
            word, how = self.fetch(self.pc)
            kind, pa, cca = self.xlate(self.pc)
            if kind == 'cached':
                self.fetchlog.append((self.steps, self.pc, pa, how, word, self.flash_word(pa)))
            tgt = self.exec(word)
            if self.delay is not None:
                # execute the delay slot, then take the branch
                dpc = self.pc + 4
                self.steps += 1
                w2, h2 = self.fetch(dpc)
                k2, p2, c2 = self.xlate(dpc)
                if k2 == 'cached':
                    self.fetchlog.append((self.steps, dpc, p2, h2, w2, self.flash_word(p2)))
                self.pc = dpc
                self.exec(w2)
                self.pc = self.delay if self.delay is not True else dpc + 4
                self.delay = None
            else:
                self.pc += 4

    delay = None

    @staticmethod
    def absolute(pc, t):
        # the disassembler prints a target either in full or as its low 32 bits
        t &= M64
        return t if t >> 32 else (pc & ~0xffffffff) | t

    def exec(self, word):
        ins = list(CPU.disasm(struct.pack('>I', word), self.pc))
        if not ins or ins[0].mnemonic == '.byte':
            raise Stop('undecodable word %#x at pc %#x' % (word, self.pc))
        i = ins[0]
        m = i.mnemonic
        ops = [o.strip() for o in i.op_str.split(',')] if i.op_str else []

        def g(o):
            return self.r[REG[o.lstrip('$')]]

        def n(o):
            return REG[o.lstrip('$')]

        def imm(o):
            return int(o, 0)

        r = self.wr
        pc = self.pc
        if m == 'nop':
            return
        if m == 'lui':
            r(n(ops[0]), s32(imm(ops[1]) << 16))
        elif m in ('addiu', 'daddiu'):
            v = g(ops[1]) + imm(ops[2])
            r(n(ops[0]), s32(v) if m == 'addiu' else v)
        elif m == 'ori':
            r(n(ops[0]), g(ops[1]) | imm(ops[2]))
        elif m == 'andi':
            r(n(ops[0]), g(ops[1]) & imm(ops[2]))
        elif m == 'dsll':
            r(n(ops[0]), g(ops[1]) << imm(ops[2]))
        elif m == 'dsll32':
            r(n(ops[0]), g(ops[1]) << (32 + imm(ops[2])))
        elif m == 'dsrl':
            r(n(ops[0]), g(ops[1]) >> imm(ops[2]))
        elif m == 'dsrl32':
            r(n(ops[0]), g(ops[1]) >> (32 + imm(ops[2])))
        elif m == 'dsrlv':
            r(n(ops[0]), g(ops[1]) >> (g(ops[2]) & 63))
        elif m == 'and':
            r(n(ops[0]), g(ops[1]) & g(ops[2]))
        elif m == 'or':
            r(n(ops[0]), g(ops[1]) | g(ops[2]))
        elif m == 'xor':
            r(n(ops[0]), g(ops[1]) ^ g(ops[2]))
        elif m == 'move':
            r(n(ops[0]), g(ops[1]))
        elif m == 'daddu':
            r(n(ops[0]), g(ops[1]) + g(ops[2]))
        elif m == 'dsubu':
            r(n(ops[0]), g(ops[1]) - g(ops[2]))
        elif m == 'sltiu':
            r(n(ops[0]), int(g(ops[1]) < (imm(ops[2]) & M64)))
        elif m == 'sltu':
            r(n(ops[0]), int(g(ops[1]) < g(ops[2])))
        elif m in ('lw', 'sw'):
            off, base = ops[1].split('(')
            ea = (g(base.rstrip(')')) + (int(off, 0) if off else 0)) & M64
            if m == 'lw':
                r(n(ops[0]), s32(self.ld(ea, 4)))
            else:
                self.st_(ea, g(ops[0]), 4)
        elif m in ('ld', 'sd'):
            off, base = ops[1].split('(')
            off = int(off, 0) if off else 0
            ea = (g(base.rstrip(')')) + off) & M64
            if m == 'ld':
                r(n(ops[0]), self.ld(ea, 8))
            else:
                self.st_(ea, g(ops[0]), 8)
        elif m in ('beq', 'bne', 'beqz', 'bnez', 'bgtz', 'b'):
            if m == 'b':
                t, c = imm(ops[0]), True
            elif m in ('beqz', 'bnez', 'bgtz'):
                a = g(ops[0])
                t = imm(ops[1])
                c = {'beqz': a == 0, 'bnez': a != 0, 'bgtz': 0 < s64(a)}[m]
            else:
                a, b = g(ops[0]), g(ops[1])
                t = imm(ops[2])
                c = (a == b) if m == 'beq' else (a != b)
            self.delay = self.absolute(pc, t) if c else True
            return
        elif m in ('jr', 'jalr', 'jal'):
            if m == 'jal':
                tgt = self.absolute(pc, imm(ops[0]))
                r(31, pc + 8)
            elif m == 'jr':
                tgt = g(ops[0])
            else:
                if len(ops) == 2:
                    tgt = g(ops[1])
                    r(n(ops[0]), pc + 8)
                else:
                    tgt = g(ops[0])
                    r(31, pc + 8)
            self.delay = tgt
            return
        elif m == 'dmfc1':
            r(n(ops[0]), self.f.get(ops[1], 0))
        elif m == 'dmtc1':
            self.f[ops[1]] = g(ops[0])
        elif m == 'mtc0':
            v = g(ops[0]) & 0xffffffff
            cp = n(ops[1])
            if cp == 29:
                self.thi = v
            elif cp == 28:
                self.tlo = v
            elif cp == 26:
                self.ecc = v
            else:
                raise Stop('mtc0 to CP0 reg %d at pc %#x' % (cp, pc))
        elif m == 'mfc0':
            cp = n(ops[1])
            r(n(ops[0]), s32({29: self.thi, 28: self.tlo, 26: self.ecc}[cp]))
        elif m == 'cache':
            op = imm(ops[0])
            off, base = ops[1].split('(')
            off = int(off, 0) if off else 0
            self.cache(op, (g(base.rstrip(')')) + off) & M64)
        else:
            raise Stop('unmodelled instruction %s %s at pc %#x' % (m, i.op_str, pc))


def parity(x):
    return bin(x).count('1') & 1


def tag_masks(flash):
    return [struct.unpack('>Q', flash[0x4f80 + 8 * i:0x4f88 + 8 * i])[0] for i in range(10)]


def prom_ecc(flash, d):
    """The check word the routine computes for doubleword d from its mask table (0x1fc04f80)."""
    v = 0
    for m in tag_masks(flash):
        v = v << 1 | parity(d & m)
    return v


def classify(m):
    """class -> [count, differing from flash, sorted unique pcs]"""
    cls = {}
    for st, pc, pa, how, w, fw in m.fetchlog:
        c = how.replace(', refill way0', '').replace(', refill way1', '')
        e = cls.setdefault(c, [0, 0, set()])
        e[0] += 1
        e[1] += fw is not None and fw != w
        e[2].add(pc)
    return cls


def ranges(pcs):
    out = []
    for p in sorted(pcs):
        if out and p == out[-1][1] + 4:
            out[-1][1] = p
        else:
            out.append([p, p])
    return ', '.join('%#x' % lo if lo == hi else '%#x-%#x' % (lo, hi) for lo, hi in out)


def run_pair(flash, args):
    SP = 0x9600000000100000
    SENT = 0xc00000001fc3ff00

    def setup(m, copy):
        m.r[REG['sp']] = SP
        m.r[REG['ra']] = SENT
        m.r[REG['a0']] = 0x9000000018000000
        m.r[REG['a1']] = 0x9600000001a00000 if copy else 0x9000000018000000
        m.r[REG['a2']] = args.copy_len
        m.r[REG['a3']] = 0x9600000000200000

    out = []
    for name, copy, entry in (('copy wrapper', True, 0xc00000001fc05910), ('verify wrapper', False, 0xc00000001fc059d0)):
        m = Machine(flash, args.sc_size, args.sc_block, args.dword, args.miss, args.victim)
        setup(m, copy)
        try:
            m.run(entry, SENT)
            err = None
        except Stop as e:
            err = str(e)
        out.append((name, entry, m, err))
    return out


CALLERS = (  # call site, kind, register set at the site (the values the caller's own code builds)
    (0x1fc027e8, 'jal', {'a0': 0xc00000001fc028cc}),
    (0x1fc03490, 'jal', {'a0': 0xc00000001fc03630}),
    (0x1fc036dc, 'jal', {'a0': 0xc00000001fc03894}),
    (0x1fc0394c, 'jal', {'a0': 0xc00000001fc039a8}),
    (0x1fc05950, 'jal', {'a0': 0xc00000001fc059c4}),  # copy wrapper
    (0x1fc05a14, 'jal', {'a0': 0xc00000001fc05b2c}),  # verify wrapper
    # indirect calls through a global-pointer table slot (0x1fd67ce0) holding 0xc00000001fc04980;
    # a0 is the word in the slot the caller loads just before (0x1fd67cd8 and 0x1fd67cf8 in the image)
    (0x1fc368bc, 'jalr', {'t0': 0xc00000001fc04980, 'a0': 0xc00000001fc0dacc}),
    (0x1fc36fbc, 'jalr', {'a3': 0xc00000001fc04980, 'a0': 0xc00000001fc0dad4}),
)


def snapshot(m):
    """Cache state at the routine's return."""
    lines = [(i, w, e['tag']) for i, ways in enumerate(m.ic) for w, e in enumerate(ways) if e['valid']]
    stags = [(k, t) for k, t in sorted(m.st.items()) if t['state']]
    return dict(i_lines=lines, s_valid=stags, s_quads=len(m.sd), s_tags=len(m.st))


def op_table(m):
    """CACHE operations grouped by instruction address and operation."""
    g = {}
    for st, pc, name, va, pa, tlo, thi, ecc, info in m.log:
        if name.startswith('CACHED'):
            continue
        e = g.setdefault((pc & 0xffffffff, name), dict(n=0, va=[], pa=[]))
        e['n'] += 1
        e['va'].append(va)
        e['pa'].append(pa)
    return g


def run_caller(flash, args, site, regs, follow=20000):
    """Enter at the call site, let the routine return, then (a) fetch every word of the range it
    staged through the 0x98 alias and (b) keep running the caller's own code until an instruction the
    interpreter does not model."""
    m = Machine(flash, args.sc_size, args.sc_block, args.dword, args.miss, args.victim)
    m.r[REG['sp']] = 0x9600000000100000
    m.r[REG['gp']] = 0xc00000001fd6f740
    for k, v in regs.items():
        m.r[REG[k]] = v
    pc0 = 0xc000000000000000 | site
    # run the call, delay slot and routine until it executes its final `jr $31` (0x1fc04e78 or 0x1fc04e84)
    m.pc = pc0
    stops = {0xc00000001fc04e78, 0x980000001fc04e78}
    err = None
    try:
        m.run(pc0, stops)
        ret = m.r[REG['ra']]
        # execute the `jr $31` and its delay slot
        m.run(m.pc, {ret})
    except Stop as e:
        err = str(e)
        ret = None
    pre = classify(m)
    out = dict(site=site, err=err, ret=ret, staged=None, static=None, dyn=None, pre=pre,
               flags=m.f.get('$f6', 0) & 0xf)
    if err:
        return m, out
    out['alias'] = (ret >> 59) == 0x13 and ret >> 62 == 2
    out['snap'] = snapshot(m)
    out['optable'] = op_table(m)
    out['slotfetch'] = sorted({pa for st, pc, pa, how, w, fw in m.fetchlog if 0x1fc04f00 <= pa < 0x1fc06000})
    a0 = regs['a0']
    # range the routine stages: from the line holding the return address to the end address, 64-byte lines
    if out['alias']:
        lo = ret & ~0x3f
        hi = (a0 & 0x1fffffff | 0x9800000000000000) | 0x3c
        out['range'] = (lo, hi)
        res = dict(words=0, hit=0, miss=0, differ=0, miss_pcs=[], diff_pcs=[])
        for va in range(lo, hi + 4 - ((hi + 4) & 3), 4):
            w, how = m.fetch(va)
            kind, pa, cca = m.xlate(va)
            fw = m.flash_word(pa)
            res['words'] += 1
            if 'S-miss' in how:
                res['miss'] += 1
                res['miss_pcs'].append(va)
            else:
                res['hit'] += 1
            if fw is not None and fw != w:
                res['differ'] += 1
                res['diff_pcs'].append(va)
        out['static'] = res
    # follow the caller's code
    m.fetchlog = []
    m.steps = 0
    try:
        m.run(ret, set(), limit=follow)
    except Stop as e:
        out['dyn'] = str(e)
    cls = classify(m)
    out['dynfetch'] = {k: (v[0], v[1]) for k, v in cls.items()}
    out['ops'] = len([e for e in m.log if not e[2].startswith('CACHED')])
    return m, out


def staged_report(flash, args):
    args.dword = 'lo-hi'
    for site, kind, regs in CALLERS:
        m, o = run_caller(flash, args, site, regs, follow=1)
        print('## call site %#x, S-cache %d KB / %d-byte blocks, word order lo-hi' % (site, args.sc_size >> 10, args.sc_block))
        for (pc, name), e in sorted(o['optable'].items()):
            vas, pas = e['va'], e['pa']
            top = sorted({v >> 59 for v in vas})
            mapped = 'unmapped xkphys (VA[63:59]=%s)' % ','.join('%#x' % t for t in top) if all(v >> 62 == 2 for v in vas) else 'MAPPED/other'
            if '(I)' in name:
                idx = sorted({(v >> 6) & 0xff for v in vas})
                how = 'set VA[13:6] %#x-%#x (%d sets), way VA[0] in %s, word VA[5:2]' % (idx[0], idx[-1], len(idx), sorted({v & 1 for v in vas}))
            else:
                sets = sorted({m.s_idx(p & ~1) for p in pas})
                how = 'set PA[%d:%d] %#x-%#x (%d sets), way PA[0] in %s, quad PA[%d:4], half PA[3]' % (
                    m.sc_size.bit_length() - 2, m.sc_block.bit_length() - 1, sets[0], sets[-1], len(sets), sorted({p & 1 for p in pas}), m.sc_block.bit_length() - 2)
            print('  pc %#x %-22s x%-4d va %#x-%#x %s; pa %#x-%#x; %s' % (
                pc, name, e['n'], min(vas), max(vas), mapped, min(pas), max(pas), how))
        sn = o['snap']
        il = sn['i_lines']
        by = {}
        for i, w, t in il:
            by.setdefault(w, []).append(t << 12)
        print('  at return: primary I %d valid lines (%s); primary D 0 (no D-cache op issued); secondary %d valid tags of %d written, %d quadwords written'
              % (len(il), ', '.join('way %d: %d lines, PA %#x-%#x' % (w, len(v), min(v), max(v) + 0xfff) for w, v in sorted(by.items())) or 'none',
                 len(sn['s_valid']), sn['s_tags'], sn['s_quads']))
        if il:
            spans = sorted((t << 12) | (i << 6) for i, w, t in il)
            print('    primary I line PAs %#x-%#x' % (spans[0], spans[-1] + 63))
        print('  cached fetches of PA 0x1fc04f00-0x1fc05fff during the call: %s'
              % (', '.join('%#x' % x for x in o['slotfetch']) or 'none'))


def callers_report(flash, args):
    for dw in ('lo-hi', 'hi-lo'):
        args.dword = dw
        print('## word order %s, secondary cache %d KB / %d-byte blocks, miss %s, victim %s'
              % (dw, args.sc_size >> 10, args.sc_block, args.miss, args.victim))
        for site, kind, regs in CALLERS:
            m, o = run_caller(flash, args, site, regs)
            line = '%#x (%s): ' % (site, kind)
            if o['err']:
                line += 'STOPPED in routine: ' + o['err']
            elif not o['alias']:
                line += 'returned with $31 unchanged (%#x), no cached alias, flags %#x (%s), %d CACHE ops' % (
                    o['ret'], o['flags'], {4: 'success', 8: 'failure'}.get(o['flags'], 'left before pass two staged anything'), o['ops'])
                line += '; cached fetches during the call: ' + (', '.join('%s %d (%d differ)' % (k, v[0], v[1]) for k, v in sorted(o['pre'].items())) or 'none')
            else:
                st = o['static']
                line += 'staged %#x-%#x, %d words: %d hit, %d miss, %d differ from flash' % (
                    o['range'][0], o['range'][1], st['words'], st['hit'], st['miss'], st['differ'])
                if st['diff_pcs']:
                    line += ' (first differing %#x)' % st['diff_pcs'][0]
                dyn = o['dynfetch']
                line += '; then ran the caller: ' + ', '.join('%s %d (%d differ)' % (k, v[0], v[1]) for k, v in sorted(dyn.items())) + ' until ' + (o['dyn'] or 'step limit')
            print('  ' + line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('prom')
    ap.add_argument('--sc-size', type=lambda x: int(x, 0), default=1 << 20)
    ap.add_argument('--sc-block', type=int, default=128)
    ap.add_argument('--dword', choices=('hi-lo', 'lo-hi'), default='hi-lo')
    ap.add_argument('--miss', choices=('flash', 'zero'), default='flash')
    ap.add_argument('--victim', choices=('invalid-first', 'way0'), default='invalid-first')
    ap.add_argument('--copy-len', type=lambda x: int(x, 0), default=0x1686a8)
    ap.add_argument('--trace', action='store_true', help='print every CACHE op')
    ap.add_argument('--regions', action='store_true', help='print the address ranges fetched in each class')
    ap.add_argument('--staged', action='store_true', help='per call site: CACHE operand addresses and the staged set')
    ap.add_argument('--callers', action='store_true', help='run the other call sites of the routine')
    ap.add_argument('--matrix', action='store_true', help='one line per cache size, block size, word order and miss policy')
    args = ap.parse_args()
    flash = open(args.prom, 'rb').read()
    for label, d in (('first word', 0x0140000800000000), ('second word', 0x01400008)):
        print('check bits for a doubleword holding 0x01400008 in its %s: %#x (the routine stores 0x395)'
              % (label, prom_ecc(flash, d)))
    if args.staged:
        staged_report(flash, args)
        return
    if args.callers:
        callers_report(flash, args)
        return
    if args.matrix:
        for dw in ('lo-hi', 'hi-lo'):
            for miss in ('flash', 'zero'):
                for size in (1 << 19, 1 << 20, 1 << 21, 1 << 22, 1 << 23, 1 << 24):
                    for blk in (64, 128):
                        args.dword, args.miss, args.sc_size, args.sc_block = dw, miss, size, blk
                        row = []
                        for name, entry, m, err in run_pair(flash, args):
                            cls = classify(m)
                            tot = sum(v[0] for v in cls.values())
                            bad = sum(v[1] for v in cls.values())
                            smiss = sum(v[0] for k, v in cls.items() if 'S-miss' in k)
                            row.append('%s: %s, %d fetches, %d S-miss, %d differ' % (name.split()[0], 'ok' if not err else 'STOP', tot, smiss, bad))
                        print('word order %s, miss %-5s, S %2d KB x %3d B: %s' % (dw, miss, size >> 10, blk, '; '.join(row)))
        return
    for name, entry, m, err in run_pair(flash, args):
        print('## %s (entry %#x), S-cache %d KB / %d-byte blocks, word order %s, miss %s'
              % (name, entry, args.sc_size >> 10, args.sc_block, args.dword, args.miss))
        if name == 'copy wrapper':
            got = m.mem_read(0x1a00000, args.copy_len)
            print('copy result: destination %s source (%#x bytes)' % ('equals' if got == flash[:args.copy_len] else 'DIFFERS from', args.copy_len))
        else:
            print('verify result: v0 = %d (0 means the two buffers compared equal)' % m.r[REG['v0']])
        ops = [e for e in m.log if e[2].startswith('CACHED')]
        print('end: %s, %d instructions, %d CACHE ops, %d cached data accesses'
              % (err or 'returned normally', m.steps, len([e for e in m.log if not e[2].startswith('CACHED')]), len(ops)))
        for c, (cnt, bad, pcs) in sorted(classify(m).items()):
            print('  cached fetches %-44s %7d  differing from flash: %d' % (c, cnt, bad))
            if args.regions:
                print('      at %s' % ranges(pcs))
        if args.trace:
            for e in m.log:
                print('  op#%-6d pc %#x %-22s va %#018x pa %#011x TagLo %#010x TagHi %#x ECC %#x  %s' % e)


if __name__ == '__main__':
    main()
