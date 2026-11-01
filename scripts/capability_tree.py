#!/usr/bin/env python3
"""Tabulate what a switch-on-an-enum routine does for every value of its first argument.

The libGLcore routines __glim_Enable, __glim_Disable and __glim_IsEnabled compile their
switch into a tree of unsigned compares and branches on a0. This script walks that tree from
the disassembly: for each candidate value of a0 it runs the integer instructions of the
routine (constants and the compares of a0 are concrete, memory loads are symbolic), follows
every branch it can decide, forks on the ones it cannot (those that test loaded words), and
records the stores, calls and return value of each path. A branch-likely test on a loaded word
forks like any other, running its delay slot only on the taken path. A jr through a register
other than ra is a jump table: the register is worked out from the image (GOT slot, table word,
gp) and the path continues at that case; if the index is not a known number every distinct
target of the table in the fact sheet is followed, and with no table the run stops. One row per enum value comes out,
with the address of the first store or call on the path (the leaf), and the effect there.
Paths shared by every value (for example the begin-mode error) are listed once above the table.

Nothing is executed on the library: the instruction text comes from scripts/facts.py, and
each callee name from its call table (GOT slot formula), so a callee is named only where the
fact sheet names it; any other indirect call is shown by the load that forms its address.

Run from the repository root through tools/re-run:
  python3 scripts/capability_tree.py root/builds/.../libGLcore.so __glim_Enable [more routines] \
      [--range 0 0x10000] [--out docs/capability-trees.md]
Each routine argument is NAME or NAME@BINARY; the first binary is the default.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import facts  # noqa: E402

M64 = (1 << 64) - 1
STACK = 0x70000000        # the stack pointer is concrete so spills and reloads can be followed
REGS = ('zero at v0 v1 a0 a1 a2 a3 a4 a5 a6 a7 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 '
        'k0 k1 gp sp fp ra').split()     # t4 to t7 are the o32 names of registers 12 to 15
# a branch-likely runs its delay slot only when the branch is taken
LIKELY = {'beql', 'bnel', 'beqzl', 'bnezl', 'blezl', 'bgtzl', 'bltzl', 'bgezl'}
BRANCHES = {'beq', 'bne', 'beqz', 'bnez', 'blez', 'bgtz', 'bltz', 'bgez', 'b'} | LIKELY


def s32(v):
    v &= 0xffffffff
    return v - (1 << 32) if v & 0x80000000 else v


def u32(v):
    return s32(v) & M64        # 32-bit result, sign-extended to 64 bits, held unsigned


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


class Unsupported(Exception):
    pass


# values: int (concrete, 64-bit unsigned) or tuple ('ld', base, off) / ('op', name, a, b) / ('sym', text)
def is_int(v):
    return isinstance(v, int)


def render(v, ctx=None):
    if is_int(v):
        if v >> 63:
            return str(s64(v))          # a 64-bit register holding a negative number
        return hex(v) if v > 9 else str(v)
    k = v[0]
    if k == 'ld':
        if v[1] == 0:
            return '[%s]' % hex(v[2])
        if v[1] in CTXS:
            return '[ctx+%d]' % v[2]
        return '[%s+%d]' % (render(v[1]), v[2])
    if k == 'op':
        if v[1] in ('&', '|') and is_int(v[3]) and v[3] >> 32 == 0xffffffff:
            return '(%s %s %s)' % (render(v[2]), v[1], hex(v[3] & 0xffffffff))     # a 32-bit mask, sign-extended
        if v[1] == 'nor' and v[3] == 0:
            return '~%s' % render(v[2])
        return '(%s %s %s)' % (render(v[2]), v[1], render(v[3]))
    if k == 'ret':
        return 'ret(%s)' % v[1]
    return v[1]


# the word of the process page that holds the current context pointer: 4112 in the N32
# build, 0x1020 in the 64-bit build
CTXS = (('ld', 0, 4112), ('ld', 0, 0x1020))


def fold(base, off):
    """(x + c) + off  ->  x + (c + off), so an address formed with lui/addiu names its context word."""
    while isinstance(base, tuple) and base[0] == 'op' and base[1] == '+':
        if is_int(base[3]) and not is_int(base[2]):
            off += s64(base[3]); base = base[2]
        elif is_int(base[2]) and not is_int(base[3]):
            off += s64(base[2]); base = base[3]
        else:
            break
    return base, off


def binop(name, a, b):
    if name in ('|', '+', '-') and b == 0:
        return a
    if name in ('|', '+') and a == 0:
        return b
    if is_int(a) and is_int(b):
        if name == '+': return u32(a + b) if False else (a + b) & M64
        if name == '-': return (a - b) & M64
        if name == '|': return a | b
        if name == '&': return a & b
        if name == '^': return a ^ b
        if name == '<<': return (a << (b & 63)) & M64
        if name == '>>': return a >> (b & 63)
        if name == '<u': return int(a < b)
        if name == '<s': return int(s64(a) < s64(b))
    return ('op', name, a, b)


class Walker:
    def __init__(self, sheet, img=None):
        # img supplies read(addr, width) -> big-endian bytes or None, gp and gsz (the width of a
        # GOT slot); it is needed only to resolve jumps through a table
        self.img = img
        self.entry = int(sheet['routine']['address'], 16) if sheet.get('routine', {}).get('address') else None
        self.tables = {int(t['jump'], 16): t for t in sheet.get('jump_tables', [])}
        self.ldw = {}       # the load mnemonic that produced each ('ld', base, off) value
        self.ins = {}
        self.order = []
        for a, t in sheet['insns']:
            a = int(a, 16)
            self.ins[a] = t
            self.order.append(a)
        self.calls = {int(c['address'], 16): c for c in sheet['calls']}
        self.start = self.order[0]

    # --- one instruction -------------------------------------------------
    def parse(self, text):
        m = re.match(r'(\S+)\s*(.*)$', text)
        mn, ops = m.group(1), [o.strip() for o in m.group(2).split(',')] if m.group(2) else []
        return mn, ops

    def val(self, regs, name):
        if name == 'zero':
            return 0
        return regs[name]

    def step(self, regs, text, addr, events):
        mn, o = self.parse(text)
        g = lambda n: self.val(regs, n)
        imm = lambda s: int(s, 0)

        def put(r, v):
            if r != 'zero':
                regs[r] = v

        if mn in ('nop',) or text.startswith('sll zero,zero'):
            return
        if mn in ('addiu', 'addi'):
            v = binop('+', g(o[1]), imm(o[2]) & M64)
            put(o[0], u32(v) if is_int(v) else v)
        elif mn == 'daddiu':
            put(o[0], binop('+', g(o[1]), imm(o[2]) & M64))
        elif mn in ('addu', 'add'):
            v = binop('+', g(o[1]), g(o[2])); put(o[0], u32(v) if is_int(v) else v)
        elif mn in ('daddu', 'dadd'):
            put(o[0], binop('+', g(o[1]), g(o[2])))
        elif mn in ('subu', 'sub'):
            v = binop('-', g(o[1]), g(o[2])); put(o[0], u32(v) if is_int(v) else v)
        elif mn in ('dsubu', 'dsub'):
            put(o[0], binop('-', g(o[1]), g(o[2])))
        elif mn in ('li', 'dli'):
            put(o[0], imm(o[1]) & M64)
        elif mn == 'lui':
            put(o[0], u32(imm(o[1]) << 16))
        elif mn == 'ori':
            put(o[0], binop('|', g(o[1]), imm(o[2])))
        elif mn == 'andi':
            put(o[0], binop('&', g(o[1]), imm(o[2])))
        elif mn == 'xori':
            put(o[0], binop('^', g(o[1]), imm(o[2])))
        elif mn == 'or':
            put(o[0], binop('|', g(o[1]), g(o[2])))
        elif mn == 'and':
            put(o[0], binop('&', g(o[1]), g(o[2])))
        elif mn == 'xor':
            put(o[0], binop('^', g(o[1]), g(o[2])))
        elif mn == 'nor':
            a, b = g(o[1]), g(o[2])
            put(o[0], (~(a | b)) & M64 if is_int(a) and is_int(b) else ('op', 'nor', a, b))
        elif mn == 'move':
            put(o[0], g(o[1]))
        elif mn == 'negu':
            put(o[0], binop('-', 0, g(o[1])))
        elif mn in ('sll', 'srl', 'sra', 'dsll', 'dsrl', 'dsra', 'dsll32', 'dsrl32', 'dsra32'):
            n = imm(o[2]) + (32 if mn.endswith('32') else 0)
            a = g(o[1]); base = mn.rstrip('32')
            if is_int(a):
                if base == 'sll': r = u32(a << n)
                elif base == 'srl': r = u32((a & 0xffffffff) >> n)
                elif base == 'sra': r = u32(s32(a) >> n)
                elif base == 'dsll': r = (a << n) & M64
                elif base == 'dsrl': r = a >> n
                else: r = (s64(a) >> n) & M64
                put(o[0], r)
            else:
                put(o[0], ('op', {'sll': '<<', 'dsll': '<<', 'srl': '>>', 'dsrl': '>>'}.get(base, '>>s'), a, n))
        elif mn in ('sllv', 'srlv', 'srav', 'dsllv', 'dsrlv', 'dsrav'):
            a, b = g(o[1]), g(o[2])
            if is_int(a) and is_int(b):
                if mn == 'sllv': r = u32(a << (b & 31))
                elif mn == 'srlv': r = u32((a & 0xffffffff) >> (b & 31))
                elif mn == 'srav': r = u32(s32(a) >> (b & 31))
                elif mn == 'dsllv': r = (a << (b & 63)) & M64
                elif mn == 'dsrlv': r = a >> (b & 63)
                else: r = (s64(a) >> (b & 63)) & M64
                put(o[0], r)
            else:   # sllv rd, rt, rs: shifts rt (o[1]) by rs (o[2])
                put(o[0], ('op', '<<mod32' if 'l' in mn else '>>mod32', a, b))   # the count is its low 5 (or 6) bits
        elif mn in ('sltiu', 'sltu', 'slti', 'slt'):
            a = g(o[1]); b = g(o[2]) if mn in ('sltu', 'slt') else imm(o[2]) & M64
            put(o[0], binop('<u' if mn.endswith('u') else '<s', a, b))
        elif mn in ('lw', 'lwu', 'ld', 'lh', 'lhu', 'lb', 'lbu'):
            m = re.match(r'(-?\w+)\((\w+)\)', o[1])
            off, base = imm(m.group(1)), g(m.group(2))
            base, off = fold(base, off)
            if is_int(base) and base >= STACK - 0x10000 and ((base + off) & M64) in regs['@mem']:
                put(o[0], regs['@mem'][(base + off) & M64])
            elif is_int(base) and base and base < STACK - 0x10000:
                # a page address formed in a register (o32 adds the offset after addiu v0,zero,4096):
                # the same absolute word as a load with a zero base
                put(o[0], ('ld', 0, (base + off) & M64))
                self.ldw[('ld', 0, (base + off) & M64)] = mn
            else:
                put(o[0], ('ld', base, off))
                self.ldw[('ld', base, off)] = mn
        elif mn in ('sw', 'sd', 'sh', 'sb'):
            m = re.match(r'(-?\w+)\((\w+)\)', o[1])
            off, bname = imm(m.group(1)), m.group(2)
            fbase, foff = fold(g(bname), off)
            if not is_int(fbase):
                events.append(('store', addr, mn, fbase, foff, g(o[0])))
                return
            if is_int(g(bname)) and g(bname) >= STACK - 0x10000:
                regs['@mem'][(g(bname) + off) & M64] = g(o[0])      # register spills and reloads
                return
            events.append(('store', addr, mn, g(bname), off, g(o[0])))
        elif mn in ('mult', 'multu', 'mfhi', 'mflo', 'div', 'divu', 'mul', 'movz', 'movn'):
            if o:
                for r in o[:1]:
                    put(r, ('sym', '?'))
        else:
            raise Unsupported('%s at 0x%x' % (text, addr))

    # --- branch condition -----------------------------------------------
    def cond(self, regs, mn, o):
        g = lambda n: self.val(regs, n)
        if mn in LIKELY:
            mn = mn[:-1]
        if mn == 'b':
            return True, 'always'
        if mn in ('beq', 'bne'):
            a, b = g(o[0]), g(o[1])
            rel = '==' if mn == 'beq' else '!='
            if o[0] == o[1]:
                return mn == 'beq', None
        elif mn in ('beqz', 'bnez'):
            a, b = g(o[0]), 0
            rel = '==' if mn == 'beqz' else '!='
        else:
            a, b = g(o[0]), 0
            rel = {'blez': '<=', 'bgtz': '>', 'bltz': '<', 'bgez': '>='}[mn]
        if is_int(a) and is_int(b):
            sa, sb = s64(a), s64(b)
            res = {'==': a == b, '!=': a != b, '<=': sa <= sb, '>': sa > sb, '<': sa < sb, '>=': sa >= sb}[rel]
            return res, None
        return None, '%s %s %s' % (render(a), rel, render(b))

    # --- jumps through a table ---------------------------------------------
    WIDTH = {'lw': 4, 'lwu': 4, 'ld': 8, 'lh': 2, 'lhu': 2, 'lb': 1, 'lbu': 1}

    def resolve(self, v):
        """The number a value works out to, reading loads from the image; Unsupported if it needs more."""
        if is_int(v):
            return v
        k = v[0]
        if k == 'sym' and v[1] == 'gp' and self.img is not None and self.img.gp:
            return self.img.gp
        if k == 'sym' and v[1] == 't9' and self.entry is not None:
            return self.entry           # a PIC routine is entered with its own address in t9
        if k == 'op' and v[1] == '+':
            return self.fit(self.resolve(v[2]) + self.resolve(v[3]))
        if k == 'ld' and self.img is not None:
            mn = self.ldw.get(v, 'lw')
            addr = self.fit(self.resolve(v[1]) + v[2])
            raw = self.img.read(addr, self.WIDTH[mn])
            if raw is None:
                raise Unsupported('load from 0x%x is not in the image' % addr)
            n = int.from_bytes(raw, 'big')
            if mn in ('lw', 'lh', 'lb'):        # sign-extending loads
                n -= (1 << (8 * len(raw))) if n >> (8 * len(raw) - 1) else 0
            return n & M64
        raise Unsupported('cannot resolve %s' % render(v))

    def fit(self, n):
        return n & (0xffffffff if self.img is not None and self.img.gsz == 4 else M64)

    def jump_targets(self, pc, reg):
        """The addresses a `jr reg` at pc can reach: the one its register works out to, else every
        target of the table the fact sheet found for that jump. Unsupported when neither exists."""
        table = self.tables.get(pc)
        try:
            t = self.resolve(reg)
        except Unsupported:
            t = None
        if t is not None:
            t &= 0xffffffff
            if table is not None and '0x%x' % t not in table['targets']:
                raise Unsupported('jump at 0x%x resolves to 0x%x, which is not in its table' % (pc, t))
            if t not in self.ins:
                raise Unsupported('jump at 0x%x resolves to 0x%x, outside the routine' % (pc, t))
            return [t]
        if table is None:
            raise Unsupported('jr %s at 0x%x: no jump table resolved' % (render(reg), pc))
        ts = sorted({int(x, 16) for x in table['targets']})
        if not ts or any(x not in self.ins for x in ts):
            raise Unsupported('jump table at 0x%x leaves the routine' % pc)
        return ts

    # --- one value of a0 ---------------------------------------------------
    def run(self, a0, a1=None, limit=600):
        regs = {r: ('sym', r) for r in REGS}
        regs['zero'] = 0
        regs['a0'] = a0
        regs['gp'] = ('sym', 'gp')
        regs['sp'] = STACK
        regs['@mem'] = {}
        regs['ra'] = ('sym', 'ra')
        if a1 is not None:
            regs['a1'] = a1
        out = []
        work = [(self.start, regs, [], [], 0)]
        while work:
            pc, regs, events, conds, n = work.pop()
            while True:
                n += 1
                if n > limit or pc not in self.ins:
                    raise Unsupported('left the routine at 0x%x' % pc)
                mn, o = self.parse(self.ins[pc])
                if mn in BRANCHES or mn in ('jr', 'jalr', 'j', 'jal', 'bal', 'bgezal', 'bgezall'):
                    dpc = pc + 4
                    dtext = self.ins[dpc]
                    if mn == 'jr' and o[0] != 'ra':
                        regs2 = dict(regs)
                        regs2['@mem'] = dict(regs['@mem'])
                        self.step(regs2, dtext, dpc, events)
                        tg = self.jump_targets(pc, regs[o[0]])
                        label = 'jump table at %s' % hex(pc)
                        for t in tg[1:]:
                            r3 = dict(regs2); r3['@mem'] = dict(regs2['@mem'])
                            work.append((t, r3, list(events), conds + [(pc, '%s selects %s' % (label, hex(t)), True)], n))
                        regs = regs2
                        if len(tg) > 1:
                            conds = conds + [(pc, '%s selects %s' % (label, hex(tg[0])), True)]
                        pc = tg[0]
                        continue
                    if mn == 'jr':
                        regs2 = dict(regs)
                        self.step(regs2, dtext, dpc, events)
                        out.append((events, conds, ('ret', render(regs2['v0']))))
                        break
                    if mn in ('jalr', 'j', 'jal', 'bal', 'bgezal', 'bgezall'):
                        regs2 = dict(regs)
                        self.step(regs2, dtext, dpc, events)
                        if mn == 'j':
                            tgt = int(o[0], 16)
                            c = self.calls.get(pc)
                            events.append(('tail', pc, c['callee'] if c and c['callee'] else hex(tgt),
                                           ['%s=%s' % (k, render(regs2[k])) for k in sorted(c['args']) if k in ('a0', 'a1', 'a2', 'a3')
                                            if k in regs2] if c and c.get('args') else []))
                            out.append((events, conds, ('tail', '')))
                            break
                        c = self.calls.get(pc)
                        if mn in ('jalr',):
                            name = c['callee'] if c and c.get('callee') else '<%s>' % render(regs2[o[-1]])
                        else:
                            name = c['callee'] if c and c.get('callee') else 'sub_%x' % int(o[-1], 16)
                        args = ['%s=%s' % (k, render(regs2[k])) for k in sorted(c['args']) if k in ('a0', 'a1', 'a2', 'a3')
                                if c and k in regs2] if c and c.get('args') and c.get('callee') else []
                        events.append(('call', pc, name, args))
                        for r in REGS:
                            if r not in ('zero', 'sp', 'gp', 'ra', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 'fp'):
                                regs2[r] = ('sym', 'after-call-' + r)
                        regs2['v0'] = ('ret', name)
                        regs = regs2
                        pc = dpc + 4
                        continue
                    tgt = int(o[-1], 16)
                    res, text = self.cond(regs, mn, o[:-1] if mn != 'b' else o)
                    if mn in LIKELY:
                        if res is None:     # fork: the taken path runs the delay slot, the other skips it
                            r2 = dict(regs); r2['@mem'] = dict(regs['@mem']); e2 = list(events)
                            self.step(r2, dtext, dpc, e2)
                            work.append((tgt, r2, e2, conds + [(pc, text, True)], n))
                            conds = conds + [(pc, text, False)]
                            pc = dpc + 4
                            continue
                        if res:
                            self.step(regs, dtext, dpc, events); pc = tgt
                        else:
                            pc = dpc + 4
                        continue
                    if res is None:
                        r2 = dict(regs); r2['@mem'] = dict(regs['@mem']); e2 = list(events)
                        self.step(r2, dtext, dpc, e2)
                        work.append((tgt, r2, e2, conds + [(pc, text, True)], n))
                        self.step(regs, dtext, dpc, events)
                        conds = conds + [(pc, text, False)]
                        pc = dpc + 4
                        continue
                    self.step(regs, dtext, dpc, events)
                    pc = tgt if res else dpc + 4
                    continue
                self.step(regs, self.ins[pc], pc, events)
                pc += 4
        return out


def mask_for(mn, v):
    if is_int(v) and mn == 'sw':
        return v & 0xffffffff
    return v


def clear_form(mn, c):
    """A word-wide AND mask with its top bit set is shown as the complement of the bits it clears."""
    c = mask_for(mn, c)
    if is_int(c) and mn == 'sw' and c >> 31:
        return '~%s' % hex(~c & 0xffffffff)
    return render(c)


def describe(ev, final, returns=False):
    """One short text per path: its stores and calls in issue order, then the return value."""
    parts = []
    for e in ev:
        if e[0] == 'store':
            _, addr, mn, base, off, v = e
            tgt = render(('ld', base, off))
            if isinstance(v, tuple) and v[0] == 'op' and v[1] == '|' and v[2] == ('ld', base, off):
                parts.append('%s |= %s' % (tgt, render(mask_for(mn, v[3]))))
            elif isinstance(v, tuple) and v[0] == 'op' and v[1] == '&' and v[2] == ('ld', base, off):
                parts.append('%s &= %s' % (tgt, clear_form(mn, v[3])))
            else:
                parts.append('%s %s= %s' % (tgt, {'sw': 'w', 'sd': 'd', 'sh': 'h', 'sb': 'b'}[mn], render(mask_for(mn, v))))
        elif e[0] in ('call', 'tail'):
            parts.append('%s %s(%s)' % ('tail call' if e[0] == 'tail' else 'call', e[2], ', '.join(e[3])))
    if final[0] == 'ret' and returns:
        # a truth value masked to a byte (andi v0,v0,0xff) is the same truth value
        ret = re.sub(r'^\((\(0 <u .*\)) & 0xff\)$', r'\1', final[1])
        parts.append('return %s' % re.sub(r'^\(0 <u (.*)\)$', r'1 if \1 is nonzero, else 0', ret))
    elif final[0] == 'ret':
        parts.append('return')
    return '; '.join(parts)


def first_addr(ev):
    return ev[0][1] if ev else None


def paths(w, v, returns=False):
    res = []
    for ev, conds, fin in w.run(v):
        res.append(((tuple(c[1:] for c in conds)), describe(ev, fin, returns), first_addr(ev)))
    return res


def table(binary, routine, lo, hi, member=None, returns=False):
    sheet = facts.fact_sheet(binary, routine, member=member)
    w = Walker(sheet, facts.image(binary, member))
    rows = {}
    for v in range(lo, hi):
        rows[v] = paths(w, v, returns)
    # a path shared by every value goes in the header
    common = set(rows[lo])
    for v in rows:
        common &= {(c, d, a) for c, d, a in rows[v]}
    common_sig = {(c, d) for c, d, a in common}
    # the error leaf: the most frequent first-path text among values
    freq = {}
    for v, ps in rows.items():
        key = tuple(sorted((c, d) for c, d, a in ps if (c, d) not in common_sig))
        freq.setdefault(key, []).append(v)
    default = max(freq, key=lambda k: len(freq[k]))
    return sheet, rows, common_sig, default, freq[default]


def enum_names(path):
    """value -> name from the Khronos registry: names in the EnableCap group first, then
    the unsuffixed name over vendor aliases."""
    names = {}
    if not path or not os.path.exists(path):
        return names
    vendor = re.compile(r'_(EXT|SGI\w*|ARB|NV|ATI|SUN\w*|IBM|HP|INGR|APPLE|OES|3DFX|QCOM)$')
    score = {}
    for line in open(path):
        m = re.search(r'<enum value="(0x[0-9A-Fa-f]+)"[^>]*? name="(GL_\w+)"', line)
        if not m:
            continue
        v, n = int(m.group(1), 16), m.group(2)
        sc = 2 * ('EnableCap' in line) + 3 * (not vendor.search(n))
        if v not in names or sc > score[v]:
            names[v], score[v] = n, sc
    return names


def negate(text):
    """The text of a test, taken the other way round."""
    for a, b in ((' != ', ' == '), (' == ', ' != ')):
        head, sep, tail = text.rpartition(a)
        if sep and re.fullmatch(r'-?\w+', tail):
            return head + b + tail
    return 'not (%s)' % text


def runs(vals):
    vals = sorted(vals)
    out = []
    for v in vals:
        if out and out[-1][1] == v - 1:
            out[-1][1] = v
        else:
            out.append([v, v])
    return ', '.join(hex(a) if a == b else '%s to %s' % (hex(a), hex(b)) for a, b in out)


def report(binary, routine, lo, hi, member=None, returns=False, names=None):
    names = names or {}
    sheet, rows, common, default, dvals = table(binary, routine, lo, hi, member, returns)
    r = sheet['routine']
    lines = ['### %s (%s)' % (routine, os.path.basename(os.path.dirname(binary.rstrip('/')))), '',
             'Binary `%s`, routine at %s, %s bytes.' % (os.path.relpath(binary) if os.path.isabs(binary) else binary,
                                                          r.get('address', '?'), r.get('size', '?')), '']
    for c, d in sorted(common):
        cond = ' and '.join(x if t else negate(x) for x, t in c) or 'always'
        lines.append('Every value takes this path when %s: %s.' % (cond, d))
    if common:
        lines.append('')
    lines.append('Values with the same outcome as the default, with no leaf of their own: %d of %d '
                 '(%s). That outcome is: %s.' % (len(dvals), hi - lo, runs(dvals),
                                                 '; '.join(d for c, d in default) or 'return'))
    implied = {x for cc, d in common for x in cc}      # the common path's tests, taken the other way
    lines += ['', '| value | name | decimal | leaf | outcome |', '|---|---|---|---|---|']
    n = 0
    for v in sorted(rows):
        if v in dvals:
            continue
        for c, d, a in rows[v]:
            if (c, d) in common:
                continue
            cond = ' and '.join(x if t else negate(x) for x, t in c if (x, not t) not in implied)
            lines.append('| %s | %s | %d | %s | %s%s |' % (hex(v), names.get(v, '-'), v, hex(a) if a else '-', d,
                                                      (' (when %s)' % cond) if cond else ''))
        n += 1
    lines += ['', '%d capability values with a leaf of their own.' % n, '']
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('binary', help='default binary')
    ap.add_argument('routines', nargs='+', help='routine names')
    ap.add_argument('--range', nargs=2, type=lambda s: int(s, 0), default=[0, 0x10000])
    ap.add_argument('--returns', action='append', default=[], help='routines whose return value is meaningful')
    ap.add_argument('--registry', default='OpenGL-Registry/xml/gl.xml', help='gl.xml, for enum names')
    ap.add_argument('--out')
    a = ap.parse_args(argv)
    names = enum_names(a.registry)
    lines = []
    for rt in a.routines:
        name, _, binary = rt.partition('@')
        lines += report(binary or a.binary, name, a.range[0], a.range[1], returns=name in a.returns, names=names)
    text = '\n'.join(lines)
    if a.out:
        with open(a.out, 'w') as f:
            f.write(text + '\n')
    else:
        print(text)


if __name__ == '__main__':
    main()
