"""Disassemble the ARM firmware arm1.u and extract its command map.

Usage: arm1_disasm.py [ARM1_U] [OUTDIR]
       defaults: ucode/KONA/arm1.u ucode
       arm1_disasm.py --tport [TPORT_BIN] [OUTDIR] [ARM1_U]
       defaults: ucode/KONA/tport.bin ucode ucode/KONA/arm1.u

arm1.u (IRIX 6.5.30m, /usr/gfx/ucode/KONA/arm1.u) is a big-endian ARM
image in AIF layout: a 128-byte header (three no-ops or branches, a data
word, an SWI, then RO size, RW size, debug size, ZI size, debug type,
image base, workspace, address mode, data base), the read-only part, the
read-write part and a low-level debug table. The header is not part of the
loaded image: RO address A is file offset 0x80 + (A - image base), RW
address A is file offset 0x80 + RO size + (A - data base). The debug
table, at file end minus the debug size, holds a symbol count at +32 and
then {flags << 24 | name offset, value} pairs followed by the names.

Writes:
  OUTDIR/arm1_symbols.tsv  every debug-table symbol, sorted by address
  OUTDIR/arm1.s            the whole RO image, one instruction per line,
                           labelled with the symbols
  OUTDIR/icu_map.tsv       the 512-entry host-token map that init_hip copies
                           from the static table at vector_end (see
                           ucode/arm1.md for the entry format; the count
                           column reads bits 6-8 for geometry-form entries)

The disassembler covers the ARMv4 instructions the image uses (data
processing, multiply, single and block transfers, halfword transfers,
branches, SWI, MRS/MSR); anything else prints as cop or .word. Literal-pool
loads and pc-relative adds are annotated with the value or symbol.

With --tport the input is tport.bin (IRIX 6.5.30m, /usr/gfx/ucode/KONA/),
which puts five words (0xbadc0ffe, a version, a stamp, 0, 0) in front of
the same AIF header and has no debug table. It writes OUTDIR/tport.s only.
Functions are labelled by matching against arm1.u: every arm1.u function
whose instruction words, with branch offsets and pc-relative offsets
masked, equal the words at a tport.bin branch-and-link target lends its
name there; other call targets print as fn_<address>.
"""
import os
import struct
import sys

COND = ['eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
        'hi', 'ls', 'ge', 'lt', 'gt', 'le', '', 'nv']
DP = ['and', 'eor', 'sub', 'rsb', 'add', 'adc', 'sbc', 'rsc',
      'tst', 'teq', 'cmp', 'cmn', 'orr', 'mov', 'bic', 'mvn']
SH = ['lsl', 'lsr', 'asr', 'ror']


def reg(n):
    return {13: 'sp', 14: 'lr', 15: 'pc'}.get(n, 'r%d' % n)


def ror(v, r):
    r &= 31
    return ((v >> r) | (v << (32 - r))) & 0xffffffff


def shifted(i):
    rm = i & 15
    t = (i >> 5) & 3
    if i & 0x10:
        return '%s, %s %s' % (reg(rm), SH[t], reg((i >> 8) & 15))
    amt = (i >> 7) & 31
    if amt == 0 and t == 0:
        return reg(rm)
    if amt == 0 and t == 3:
        return '%s, rrx' % reg(rm)
    if amt == 0:
        amt = 32
    return '%s, %s #%d' % (reg(rm), SH[t], amt)


def dis(i, pc):
    """Return (text, address the instruction refers to or None)."""
    c = COND[i >> 28]
    if (i >> 28) == 15:
        return '.word 0x%08x' % i, None
    if (i & 0x0fffffd0) == 0x012fff10:
        return 'bx%s %s' % (c, reg(i & 15)), None
    if (i & 0x0fc000f0) == 0x00000090:
        s = 's' if i & (1 << 20) else ''
        rd, rn, rs, rm = (i >> 16) & 15, (i >> 12) & 15, (i >> 8) & 15, i & 15
        if (i >> 21) & 1:
            return 'mla%s%s %s, %s, %s, %s' % (c, s, reg(rd), reg(rm), reg(rs), reg(rn)), None
        return 'mul%s%s %s, %s, %s' % (c, s, reg(rd), reg(rm), reg(rs)), None
    if (i & 0x0f8000f0) == 0x00800090:
        u = 's' if i & (1 << 22) else 'u'
        a = 'mla' if i & (1 << 21) else 'mul'
        return '%s%sl%s %s, %s, %s, %s' % (u, a, c, reg((i >> 12) & 15), reg((i >> 16) & 15),
                                           reg(i & 15), reg((i >> 8) & 15)), None
    if (i & 0x0fb00ff0) == 0x01000090:
        return 'swp%s%s %s, %s, [%s]' % (c, 'b' if i & (1 << 22) else '', reg((i >> 12) & 15),
                                         reg(i & 15), reg((i >> 16) & 15)), None
    if (i & 0x0e000090) == 0x00000090 and (i & 0x60):
        p, u, imm, w, ld = [(i >> b) & 1 for b in (24, 23, 22, 21, 20)]
        rn, rd = (i >> 16) & 15, (i >> 12) & 15
        sfx = {1: 'h', 2: 'sb', 3: 'sh'}[(i >> 5) & 3]
        off8 = ((i >> 4) & 0xf0) | (i & 15)
        off = ('#%s%d' % ('' if u else '-', off8)) if imm else ('%s%s' % ('' if u else '-', reg(i & 15)))
        addr = ('[%s, %s]%s' % (reg(rn), off, '!' if w else '')) if p else ('[%s], %s' % (reg(rn), off))
        ref = pc + 8 + (off8 if u else -off8) if (rn == 15 and imm and p) else None
        return '%s%s%s %s, %s' % ('ldr' if ld else 'str', c, sfx, reg(rd), addr), ref
    if (i & 0x0fbf0fff) == 0x010f0000:
        return 'mrs%s %s, %s' % (c, reg((i >> 12) & 15), 'spsr' if i & (1 << 22) else 'cpsr'), None
    if (i & 0x0db0f000) == 0x0120f000:
        src = ('#0x%x' % ror(i & 255, 2 * ((i >> 8) & 15))) if i & (1 << 25) else reg(i & 15)
        return 'msr%s %s_%x, %s' % (c, 'spsr' if i & (1 << 22) else 'cpsr', (i >> 16) & 15, src), None
    t = (i >> 25) & 7
    if t in (0, 1):
        op, s, rn, rd = (i >> 21) & 15, (i >> 20) & 1, (i >> 16) & 15, (i >> 12) & 15
        o2 = ('#0x%x' % ror(i & 255, 2 * ((i >> 8) & 15))) if t == 1 else shifted(i)
        name = DP[op] + c + ('s' if s and op not in (8, 9, 10, 11) else '')
        if op in (13, 15):
            return '%s %s, %s' % (name, reg(rd), o2), None
        if op in (8, 9, 10, 11):
            return '%s %s, %s' % (name, reg(rn), o2), None
        ref = None
        if rn == 15 and t == 1 and op in (2, 4):
            v = ror(i & 255, 2 * ((i >> 8) & 15))
            ref = pc + 8 + (v if op == 4 else -v)
        return '%s %s, %s, %s' % (name, reg(rd), reg(rn), o2), ref
    if t in (2, 3):
        p, u, b, w, ld = [(i >> k) & 1 for k in (24, 23, 22, 21, 20)]
        rn, rd = (i >> 16) & 15, (i >> 12) & 15
        off = ('#%s0x%x' % ('' if u else '-', i & 0xfff)) if t == 2 else ('%s%s' % ('' if u else '-', shifted(i)))
        addr = ('[%s, %s]%s' % (reg(rn), off, '!' if w else '')) if p else ('[%s], %s' % (reg(rn), off))
        ref = pc + 8 + ((i & 0xfff) if u else -(i & 0xfff)) if (rn == 15 and t == 2 and p) else None
        return '%s%s%s %s, %s' % ('ldr' if ld else 'str', c, 'b' if b else '', reg(rd), addr), ref
    if t == 4:
        p, u, s, w, ld = [(i >> k) & 1 for k in (24, 23, 22, 21, 20)]
        regs = ','.join(reg(k) for k in range(16) if i & (1 << k))
        return '%s%s%s%s %s%s, {%s}%s' % ('ldm' if ld else 'stm', c, 'i' if u else 'd', 'b' if p else 'a',
                                           reg((i >> 16) & 15), '!' if w else '', regs, '^' if s else ''), None
    if t == 5:
        off = i & 0xffffff
        if off & 0x800000:
            off -= 0x1000000
        target = (pc + 8 + 4 * off) & 0xffffffff
        return '%s%s 0x%08x' % ('bl' if i & (1 << 24) else 'b', c, target), target
    if ((i >> 24) & 15) == 15:
        return 'swi%s 0x%x' % (c, i & 0xffffff), None
    return 'cop%s 0x%08x' % (c, i), None


def load(path, hoff=0):
    b = open(path, 'rb')
    b = b.read()[hoff:]
    hdr = struct.unpack('>14I', b[:56])
    ro, rw, dbg_size = hdr[5], hdr[6], hdr[7]
    base, dbase = hdr[10], hdr[13]
    mem = {}
    for o in range(0, ro, 4):
        mem[base + o] = struct.unpack('>I', b[0x80 + o:0x84 + o])[0]
    for o in range(0, rw, 4):
        mem[dbase + o] = struct.unpack('>I', b[0x80 + ro + o:0x84 + ro + o])[0]
    if dbg_size == 0:
        return mem, [], base, ro, dbase, rw
    dbg = len(b) - dbg_size
    n = struct.unpack('>I', b[dbg + 32:dbg + 36])[0]
    tab = dbg + 36
    strs = tab + 8 * n
    syms = []
    for k in range(n):
        f, v = struct.unpack('>II', b[tab + 8 * k:tab + 8 * k + 8])
        off = f & 0xffffff
        syms.append((v, f >> 24, b[strs + off:b.index(b'\0', strs + off)].decode()))
    syms.sort()
    return mem, syms, base, ro, dbase, rw


def mask(i):
    """An instruction word with its position-dependent offsets cleared."""
    if (i >> 25) & 7 == 5:                       # b, bl
        return i & 0xff000000
    if (i >> 26) & 3 == 1 and (i >> 16) & 15 == 15:  # ldr/str pc-relative
        return i & 0xfffff000
    if (i >> 26) & 3 == 0 and (i >> 16) & 15 == 15 and (i >> 25) & 1:  # add/sub pc
        return i & 0xfffff000
    return i


def tport(path, out, arm1):
    mem, _, base, ro, dbase, rw = load(path, 0x14)
    amem, asyms, abase, aro, _, _ = load(arm1)
    funcs = [(v, n) for v, f, n in asyms if abase <= v < abase + aro]
    funcs.sort()
    sig = {}
    for k, (v, n) in enumerate(funcs):
        end = funcs[k + 1][0] if k + 1 < len(funcs) else abase + aro
        if end - v < 16:
            continue
        words = tuple(mask(amem[a]) for a in range(v, end, 4))
        sig.setdefault(words[:4], []).append((words, n))
    targets = set()
    for pc in range(base, base + ro, 4):
        i = mem[pc]
        if (i >> 24) & 15 == 11:
            off = i & 0xffffff
            if off & 0x800000:
                off -= 0x1000000
            t = pc + 8 + 4 * off
            if base <= t < base + ro:
                targets.add(t)
    names = {}
    for t in sorted(targets):
        head = tuple(mask(mem.get(t + 4 * k, 0)) for k in range(4))
        for words, n in sig.get(head, []):
            if all(mask(mem.get(t + 4 * k, 0)) == w for k, w in enumerate(words)):
                names[t] = n
                break
        names.setdefault(t, 'fn_%08x' % t)
    # The display-request table: 93 entries of {name, word count, handler}
    # in the read-write data, found by its first entry's name, "Test".
    def cstr(a):
        out = b''
        while mem.get(a & ~3) is not None and len(out) < 64:
            c = struct.pack('>I', mem[a & ~3])[a & 3]
            if c == 0:
                return out.decode('latin-1')
            out += bytes([c])
            a += 1
        return None
    table = None
    for a in range(dbase, dbase + rw, 4):
        if mem[a] >= dbase and cstr(mem[a]) == 'Test' and mem.get(a + 4) == 1 \
                and base <= mem.get(a + 8, 0) < base + ro:
            table = a
            break
    requests = []
    if table is not None:
        k = 0
        while base <= mem.get(table + 12 * k + 8, 0) < base + ro:
            nm, cnt, h = cstr(mem[table + 12 * k]), mem[table + 12 * k + 4], mem[table + 12 * k + 8]
            if nm is None:
                break
            requests.append((k, nm, cnt, h))
            if h not in names or names[h].startswith('fn_'):
                names[h] = 'DoDGRqst' + nm
            k += 1
    pool = set()
    strs = {}
    for pc in range(base, base + ro, 4):
        text, ref = dis(mem[pc], pc)
        if ref is None or not (base <= ref < base + ro):
            continue
        if text.startswith('ldr') and ref % 4 == 0:
            pool.add(ref)
        elif text.startswith(('add', 'sub')):
            raw = b''.join(struct.pack('>I', mem.get(ref + 4 * k, 0)) for k in range(64))
            n = raw.find(b'\0')
            if n >= 3 and all(c in (9, 10) or 32 <= c < 127 for c in raw[:n]):
                strs[ref] = raw[:n]
    inside = set()
    for a, raw in strs.items():
        inside.update(range(a + 4, a + len(raw) + 1, 4))
    matched = sum(1 for n in names.values() if not n.startswith('fn_'))
    with open(os.path.join(out, 'tport.s'), 'w') as fh:
        fh.write('# tport.bin read-only image, base 0x%08x, %d bytes; read-write data base 0x%08x, %d bytes (IRIX 6.5.30m)\n' % (base, ro, dbase, rw))
        fh.write('# No symbols ship with this image. %d of %d call targets carry the name of the\n' % (matched, len(names)))
        fh.write('# arm1.u function whose masked words they equal; the rest are fn_<address>.\n')
        if table is not None:
            fh.write('# Display-request table at 0x%08x ({name, words, handler} x %d); handlers\n' % (table, len(requests)))
            fh.write('# are named DoDGRqst<name>. request\twords\thandler\tname:\n')
            for k, nm, cnt, h in requests:
                fh.write('#   %d\t%d\t0x%08x\t%s\n' % (k, cnt, h, nm))
        for pc in range(base, base + ro, 4):
            if pc in inside and pc not in names and pc not in pool:
                continue
            if pc in names:
                fh.write('%s:\n' % names[pc])
            i = mem[pc]
            if pc in strs:
                t = strs[pc].decode().replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t')
                fh.write('%08x: %08x  .asciz "%s"\n' % (pc, i, t))
                continue
            if pc in pool:
                fh.write('%08x: %08x  .word 0x%08x%s\n' % (pc, i, i, (' <%s>' % names[i]) if i in names else ''))
                continue
            text, ref = dis(i, pc)
            s = ''
            if ref is not None:
                if ref in names:
                    s = ' <%s>' % names[ref]
                if text.startswith('ldr') and ref in mem:
                    v = mem[ref]
                    s += ' =0x%08x%s' % (v, (' <%s>' % names[v]) if v in names else '')
            fh.write('%08x: %08x  %s%s\n' % (pc, i, text, s))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--tport':
        a = sys.argv[2:]
        tport(a[0] if a else 'ucode/KONA/tport.bin', a[1] if len(a) > 1 else 'ucode',
              a[2] if len(a) > 2 else 'ucode/KONA/arm1.u')
        return
    path = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/arm1.u'
    out = sys.argv[2] if len(sys.argv) > 2 else 'ucode'
    mem, syms, base, ro, dbase, rw = load(path)
    byaddr = {}
    for v, f, n in syms:
        byaddr.setdefault(v, []).append(n)
    byname = {n: v for v, f, n in syms}

    with open(os.path.join(out, 'arm1_symbols.tsv'), 'w') as fh:
        fh.write('# arm1.u debug-table symbols (IRIX 6.5.30m); flags is the top byte of the name word\n')
        fh.write('address\tflags\tname\n')
        for v, f, n in syms:
            fh.write('0x%08x\t%d\t%s\n' % (v, f, n))

    def note(text, ref):
        if ref is None:
            return ''
        s = ''
        if ref in byaddr:
            s = ' <%s>' % byaddr[ref][0]
        if text.startswith('ldr') and ref in mem:
            v = mem[ref]
            s += ' =0x%08x%s' % (v, (' <%s>' % byaddr[v][0]) if v in byaddr else '')
        return s

    # Data inside the code: a word an ldr names pc-relative is a literal-pool
    # word; an address an add or sub forms from pc is the start of a string.
    # Both print as data instead of as nonsense instructions.
    pool = set()
    strs = {}
    for pc in range(base, base + ro, 4):
        text, ref = dis(mem[pc], pc)
        if ref is None or not (base <= ref < base + ro):
            continue
        if text.startswith('ldr') and ref % 4 == 0:
            pool.add(ref)
        elif text.startswith(('add', 'sub')):
            raw = b''.join(struct.pack('>I', mem.get(ref + 4 * k, 0)) for k in range(64))
            n = raw.find(b'\0')
            if n >= 3 and all(c in (9, 10) or 32 <= c < 127 for c in raw[:n]):
                strs[ref] = raw[:n]
    inside = set()
    for a, raw in strs.items():
        inside.update(range(a + 4, a + len(raw) + 1, 4))

    with open(os.path.join(out, 'arm1.s'), 'w') as fh:
        fh.write('# arm1.u read-only image, base 0x%08x, %d bytes (IRIX 6.5.30m)\n' % (base, ro))
        fh.write('# Words an ldr reads pc-relative print as .word; strings an add or sub\n')
        fh.write('# forms from pc print as .asciz (the words they cover are not repeated).\n')
        for pc in range(base, base + ro, 4):
            if pc in inside and pc not in byaddr and pc not in pool:
                continue
            for n in byaddr.get(pc, []):
                fh.write('%s:\n' % n)
            i = mem[pc]
            if pc in strs:
                t = strs[pc].decode().replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t')
                fh.write('%08x: %08x  .asciz "%s"\n' % (pc, i, t))
                continue
            if pc in pool:
                fh.write('%08x: %08x  .word 0x%08x%s\n' % (pc, i, i, (' <%s>' % byaddr[i][0]) if i in byaddr else ''))
                continue
            text, ref = dis(i, pc)
            fh.write('%08x: %08x  %s%s\n' % (pc, i, text, note(text, ref)))

    # init_hip walks this table: a word with bit 0 set is a complete entry;
    # an even word is followed by a second word that is ORed in shifted
    # left by 4 (a zero word and an ARM handler address, in practice).
    p = byname['vector_end']
    names = {}
    kpm = 'diags/kpm/hp_commands.tsv'
    if os.path.exists(kpm):
        for line in open(kpm):
            if line[0] in '#v':
                continue
            _, tok, name = line.rstrip('\n').split('\t')
            names.setdefault(int(tok, 16), name)
    rows = []
    while True:
        w = mem[p]
        p += 4
        if w == 0xffffffff:
            break
        if w & 1 == 0:
            h = mem[p]
            p += 4
            rows.append(((w | (h << 4)) & 0xffffffff, h, w))
        else:
            rows.append((w, None, w))
    with open(os.path.join(out, 'icu_map.tsv'), 'w') as fh:
        fh.write('# Host-token map built by arm1.u init_hip from the static table at vector_end\n')
        fh.write('# (IRIX 6.5.30m). entry = the 32-bit value init_hip stores for the token.\n')
        fh.write('# ARM rows: entry = handler << 4 | low word; the handler is the arm1.u function\n')
        fh.write('# the token runs. Routed rows (bit 0 set): fields per ucode/arm1.md. count is the\n')
        fh.write('# word-count field: bits 6-8 in the geometry form (bit 31 set), bits 6-10 otherwise.\n')
        fh.write('token\tname\tentry\troute\tkind\tchain\tcount\tbits15_23\tbits27_28\tbits29_30\tarm_handler\n')
        for tok in range(512):
            e, h, w = rows[tok] if tok < len(rows) else (None, None, None)
            if e is None:
                continue
            nm = names.get(tok, '')
            if h is not None:
                fh.write('0x%03x\t%s\t0x%08x\tarm\t%d\t\t\t\t\t\t%s\n' % (
                    tok, nm, e, (e >> 1) & 3, ','.join(byaddr.get(h, ['0x%08x' % h]))))
            else:
                fh.write('0x%03x\t%s\t0x%08x\thw\t%d\t%d\t%d\t%d\t%d\t%d\t\n' % (
                    tok, nm, e, (e >> 1) & 3, (e >> 3) & 1, (e >> 6) & (7 if e >> 31 else 0x1f),
                    (e >> 15) & 0x1ff, (e >> 27) & 3, (e >> 29) & 3))


if __name__ == '__main__':
    main()
