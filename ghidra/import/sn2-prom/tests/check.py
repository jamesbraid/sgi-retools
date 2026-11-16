#!/usr/bin/env python3
"""Check what SN2PromImport.java laid out against the image itself.

Usage: check.py SYMBOLS IMAGE [--runtime] [--elfs]

SYMBOLS is run-ghidra.sh's symbols.tsv. The FIT, the top-of-flash words and
the SAL dispatch table are parsed again here, independently of the script;
every component, entry and table must carry its label, every entry must be a
function and SAL_B must have its global pointer. Prints the failures and
exits non-zero on any; prints that it skipped when IMAGE is absent. With --runtime
(the import ran with SAL_RUNTIME=1) the SAL runtime component is inflated here too and each
of its dynamic function symbols must be a function with its name at RUNTIME_BASE + value. --elfs
(GZIP_ELFS=1) does the same for the FIT type 0x13 and 0x1f components, at 2 * and 3 * RUNTIME_BASE.
"""
import os
import re
import struct
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'processors', 'ia64', 'tools'))
import ia64_isa as isa  # noqa: E402

TOP = 1 << 32
UNC = 1 << 63
RUNTIME_BASE = 1 << 32
ELF_BASE = {0x12: RUNTIME_BASE, 0x13: 2 * RUNTIME_BASE, 0x1f: 3 * RUNTIME_BASE}


def runtime_functions(gz):
    """[(name, link address)] of the dynamic function symbols of the gzip-packed ELF."""
    elf = zlib.decompressobj(31).decompress(gz)
    phoff, phnum = struct.unpack_from('<Q', elf, 32)[0], struct.unpack_from('<H', elf, 56)[0]
    segs = [struct.unpack_from('<IIQQQQQQ', elf, phoff + 56 * i) for i in range(phnum)]
    img = bytearray(max(s[3] + s[6] for s in segs if s[0] == 1))
    for t, _, off, va, _, filesz, _, _ in segs:
        if t == 1:
            img[va:va + filesz] = elf[off:off + filesz]
    dyn = [s[3] for s in segs if s[0] == 2][0]
    tags = {}
    while struct.unpack_from('<Q', img, dyn)[0]:
        tags.setdefault(*struct.unpack_from('<QQ', img, dyn))
        dyn += 16
    nsyms = struct.unpack_from('<I', img, tags[4] + 4)[0]
    out = []
    for i in range(1, nsyms):
        name, info, _, shndx, value, _ = struct.unpack_from('<IBBHQQ', img, tags[6] + 24 * i)
        if info & 15 == 2 and shndx and value:
            end = img.index(0, tags[5] + name)
            out.append((img[tags[5] + name:end].decode('latin1'), value))
    return out, tags.get(3, 0)


def main():
    syms, image = sys.argv[1], sys.argv[2]
    mapped = ([0x12] if '--runtime' in sys.argv[3:] else []) + ([0x13, 0x1f] if '--elfs' in sys.argv[3:] else [])
    if not os.path.isfile(image):
        print('check: %s is not here (no PROM root); skipped' % image)
        return 0
    data = open(image, 'rb').read()
    base = TOP - len(data)

    def q(a):
        return struct.unpack('<Q', data[a - base:a - base + 8])[0]
    labels, funcs, r1, blocks, noexec, pal = {}, set(), [], {}, set(), set()
    for line in open(syms):
        f = line.rstrip('\n').split('\t')
        if f[0] == 'label':
            labels.setdefault(int(f[1].split(':')[-1], 16), set()).add(f[2])
        elif f[0] == 'function':
            funcs.add(int(f[1].split(':')[-1], 16))
        elif f[0] == 'r1':
            r1.append((int(f[1].split(':')[-1], 16), int(f[2].split(':')[-1], 16), f[3]))
        elif f[0] == 'pal':
            pal.add(int(f[1].split(':')[-1], 16))
        elif f[0] == 'block':
            blocks[f[3]] = int(f[1].split(':')[-1], 16)
            if f[4] == '-':
                noexec.add(f[3])
    bad = []

    def br_ia_sites(lo, hi):
        # A br.ia is B-unit opcode 0, x6 0x20, btype 1; the B slots follow from the template.
        units = {0x10: 'MIB', 0x11: 'MIB', 0x12: 'MBB', 0x13: 'MBB', 0x16: 'BBB', 0x17: 'BBB',
                 0x18: 'MMB', 0x19: 'MMB', 0x1c: 'MFB', 0x1d: 'MFB'}
        for a in range(lo, hi - 15, 16):
            v = q(a) | q(a + 8) << 64
            for i, u in enumerate(units.get(v & 31, '')):
                x = v >> (5 + 41 * i) & (1 << 41) - 1
                if u == 'B' and x >> 37 & 15 == 0 and x >> 27 & 63 == 0x20 and x >> 6 & 7 == 1:
                    site = a + (0, 6, 12)[i]
                    if site not in pal:
                        bad.append('br.ia at %#x is not flagged as a PAL service call' % site)

    def pal_procs(lo, hi):
        # (index, mask, 0) triples ended by -1, then a link address per entry; PAL_B links at 0xfff00000.
        best = (0, 0)
        for a in range(lo, hi - 24, 8):
            n = 0
            while a + 24 * n + 24 <= hi and q(a + 24 * n) < 0x1000 and q(a + 24 * n + 8) \
                    and q(a + 24 * n + 8) >> 40 <= 1 and q(a + 24 * n + 16) == 0:
                n += 1
            if n >= 8 and q(a + 24 * n) == (1 << 64) - 1 and n > best[0]:
                best = (n, a)
        if not best[0]:
            # Newer PAL_B (SHub 2) has no such table; the import script reports the same.
            print('no PAL procedure table in %#x' % lo)
            return
        n, a = best
        h = a + 24 * (n + 1)
        while q(h) == 0:
            h += 8
        for i in range(n):
            link = q(h + 8 * i)
            handler = (link & 0xffffffff) + lo - 0xfff00000
            if link >> 32 == 0x80000000 and lo <= handler < hi:
                want(handler, 'pal_proc_%d' % q(a + 24 * i), True)

    def rfi_continuations(lo, hi):
        # The reference decoder's text: a branch to a helper that sets cr.iip and reaches an rfi,
        # after mov rN=ip; addl rN=imm,rN; mov b0=rN, continues at the address in b0.
        ins = []
        for a in range(lo, hi - 15, 16):
            ins += [(x, p, t or '') for x, p, t, _ in isa.decode_bundle(data[a - base:a - base + 16], a)]
        index = {a: i for i, (a, _, _) in enumerate(ins)}

        def helper(t):
            iip = False
            for _, p, text in ins[index.get(t, len(ins)):][:36]:
                if text.startswith('mov cr.iip='):
                    iip = True
                elif text == 'rfi':
                    return iip
                elif re.match(r'br\.(call|ret|cond)|br\.few|br\.ia', text):
                    return False
            return False
        out = set()
        for i, (a, p, text) in enumerate(ins):
            m = re.match(r'br\.few 0x([0-9a-f]+)$', text)
            if p or not m or not helper(int(m.group(1), 16)):
                continue
            seq, stage = ins[max(0, i - 24):i], 0
            for x, q_, t in reversed(seq):
                if stage == 0 and (m2 := re.match(r'mov b0=r(\d+)$', t)):
                    reg, stage = m2.group(1), 1
                elif stage == 1 and (m2 := re.match(r'addl r%s=(-?\d+),r%s$' % (reg, reg), t)):
                    off, stage = int(m2.group(1)), 2
                elif stage == 2 and re.match(r'mov r%s=ip$' % reg, t):
                    out.add((x & ~0xf) + off)
                    break
        return out

    def want(addr, name, func=False):
        if name not in labels.get(addr, ()):
            bad.append('no label %s at %#x (have %s)' % (name, addr, sorted(labels.get(addr, ()))))
        if func and addr not in funcs:
            bad.append('no function at %#x (%s)' % (addr, name))
    if blocks.get('flash') != base or blocks.get('flash_uc') != UNC | base:
        bad.append('blocks: %s' % blocks)
    fit = q(TOP - 0x20) & ~UNC
    want(fit, 'FIT')
    count = q(fit + 8) & 0xffffff
    names = {0x01: 'PAL_B', 0x0e: 'PAL_A', 0x10: 'SAL_A', 0x11: 'SAL_B', 0x12: 'SAL_runtime', 0x1f: 'EFI'}
    salb = None
    for i in range(1, count):
        e = fit + 16 * i
        kind = (q(e + 8) >> 48) & 0x7f
        size = (q(e + 8) & 0xffffff) * 16
        if kind == 0x7f or not size:
            continue
        ver = (q(e + 8) >> 32) & 0xffff
        start = q(e) & ~UNC
        name = '%s_%x_%02x' % (names.get(kind, 'OEM_%02x' % kind), ver >> 8, ver & 0xff)
        want(start, name)
        if kind not in (0x01, 0x0e, 0x0f, 0x10, 0x11) and (blocks.get(name) != start or name not in noexec):
            bad.append('%s is not a non-executable block at %#x' % (name, start))
        if kind in mapped:
            where = ELF_BASE[kind]
            funcs_rt, pltgot = runtime_functions(data[start - base:start - base + size])
            for fname, value in funcs_rt:
                want(where + value, fname, True)
            elf_block = name + '_elf'
            if blocks.get(elf_block) != where or elf_block in noexec:
                bad.append('%s is not an executable block at %#x' % (elf_block, where))
            if not any(a == where and v == '%x' % (where + pltgot) for a, b, v in r1):
                bad.append('r1 is not %#x over %s: %s' % (where + pltgot, name, r1))
            print('%s: %d functions at %#x, gp %#x' % (name, len(funcs_rt), where, where + pltgot))
            if not funcs_rt:
                bad.append('%s has no dynamic functions' % name)
        if kind in (0x01, 0x0e, 0x0f, 0x10, 0x11):
            conts = rfi_continuations(start, start + size)
            for c in conts:
                want(c, 'rfi_continuation_%x' % c, True)
            print('%s: %d rfi continuations' % (name, len(conts)))
        if kind == 0x0e:
            want(start + 0x300, name + '_entry', True)
        if kind in (0x0e, 0x0f):
            br_ia_sites(start, start + size)
        if kind == 0x01:
            want(start + 0x10080, name + '_check_entry', True)
            want(start + 0x10070, name + '_init_entry', True)
            pal_procs(start, start + size)
        if kind == 0x11:
            salb = (start, start + size)
            for off, n in ((0, 'sal_b_reset_entry'), (0x10, 'sal_b_entry_reason2'), (0x20, 'sal_b_entry_reason1')):
                want(start + off, n, True)
    want(q(TOP - 0x18) & ~UNC, 'SALE_ENTRY', True)
    want(TOP - 0x50, 'PALE_RESET', True)
    want(TOP - 0x60, 'PALE_INIT', True)
    want(TOP - 0x70, 'PALE_CHECK', True)
    br_ia_sites(q(TOP - 0x30) & ~UNC, TOP - 0x40)
    print('%d br.ia sites in PAL_A flagged as PAL service calls' % len(pal))
    # The dispatch table: the longest run of (id, descriptor) pairs in SAL_B.
    lo, hi = salb
    best, blen = None, 0
    for a in range(lo, hi - 16, 8):
        n = 0
        while a + 16 * n + 16 <= hi:
            i, d = q(a + 16 * n), q(a + 16 * n + 8)
            if not (0x01000000 <= i <= 0x010000ff or 0x02000000 <= i <= 0x020000ff):
                break
            if not (base <= d < TOP - 16) or not (lo <= q(d) < hi):
                break
            n += 1
        if n > blen:
            best, blen = a, n
    want(best, 'sal_dispatch_table')
    gps = set()
    for k in range(blen):
        i, d = q(best + 16 * k), q(best + 16 * k + 8)
        want(q(d), 'sal_%08x' % i, True)
        gps.add(q(d + 8))
    gp = gps.pop()
    if not any(a <= lo and hi - 1 <= b and v == '%x' % gp for a, b, v in r1):
        bad.append('r1 is not %#x over SAL_B %#x-%#x: %s' % (gp, lo, hi, r1))
    print('SAL dispatch table at %#x, %d entries, gp %#x' % (best, blen, gp))
    for b in bad:
        print('FAIL', b)
    print('%d failures' % len(bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
