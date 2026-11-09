"""Tabulate what each host-token handler in arm1.u does, and how a routed command finds its engine handler.

Usage: arm1_handlers.py [ARM1_U] [GEIF_U] [GE_SYMBOLS] [OUTDIR]
       defaults: ucode/KONA/arm1.u ucode/KONA/geif.u ucode/KONA/ge_symbols ucode
       Run it after arm1_disasm.py: it reads OUTDIR/icu_map.tsv.

Writes (see ucode/arm1_firmware.md for how to read them):
  OUTDIR/arm1_handlers.tsv   one row per ARM-handled token: group, size,
                             payload reads, host-interface ports written, the
                             geometry-engine handlers the code names, callees
  OUTDIR/ged_bound_table.tsv the 64-entry handler table init_ged fills
  OUTDIR/hw_route.tsv        every hardware-routed token with its 9-bit command
                             number, group, table index and bound handler
  OUTDIR/dg_dispatch.tsv     the display-generator command table (arm_video_cmd)

Everything is read from the firmware by a linear scan of each function; it
follows no branches, so a handler that reaches a GE handler only through a
callee shows the callee in its calls column and not the handler.
"""
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm1_disasm as A  # noqa: E402

GEPC = 0x04068654          # symbol gepc: copy of geif.u, 512 32-bit words
PACKED = 0x48              # r8 + 0x48: gepc[0..127] packed as halfword pairs
PORT = 0x400               # r9 + 0x400: descriptor register of the engine port
PORT_NAMES = {0x400: 'desc', 0x420: 'p420', 0x428: 'p428', 0x430: 'dest_one', 0x434: 'dest434',
              0x438: 'dest_all', 0x43c: 'dest43c', 0x470: 'w470', 0x474: 'w474', 0x478: 'w478',
              0x47c: 'w47c', 0x4f0: 'w4f0', 0x4f4: 'w4f4', 0x4f8: 'w4f8', 0x4fc: 'w4fc',
              0x800: 'd800', 0x840: 'data840', 0x880: 'data880', 0x8c0: 'cmd8c0', 0x980: 'd980'}

# First match wins. Matched against the handler's function name.
GROUPS = [
    ('unsupported', r'^$'),                       # filled by the stub test, not by name
    ('ignored', r'^$'),
    ('enable and disable', r'^arm_(enable|disable)$'),
    ('queries', r'^arm_get'),
    ('context, memory and host interface', r'^arm_(context_|mem_|kernel_private|dmapool_setup|rdata_setup|'
     r'start_selectfeed|restart_selectfeed|finish_selectfeed|pipe_setup|pipe_sync|gerollcall|eeprom_op|'
     r'arm_nop|ge_intr|f3_war|slop|diag_dispatch|ged_verif|end_of_simulation|seterror|wg_flush|data)'),
    ('display generator and swap', r'^arm_(video_cmd|dispmode|retrace_seqid|swap_cntrl|dplex_swap|video_source)$'),
    ('display lists and DMA', r'^arm_.*(_ldma|_idma|do_idma)'),
    ('vertex arrays, evaluators and patches', r'^arm_(varray|pvertex|mapdata|evalstrip|subdiv|rasterpos|set_current_raster)'),
    ('X server', r'^arm_x_'),
    ('texture', r'^arm_(tex|bind_|bindtexture|active_texture|shadow_texture|change_post|gentextures|istexture|'
     r'deletetextures|copytex|copyteximage|pixeltexgen|drawtexels)'),
    ('pixels, bitmaps and filters', r'^arm_(pixel|drawpixels|copypixels|readpixels|bitmap|polygonstipple|'
     r'colortable|copycolortable|convolution|copyconvolution|separablefilter|histogram|resethistogram|'
     r'minmax|resetminmax|copyisoverlapped|copyconvisoverlapped|resolveissinglecomp)'),
    ('clear and accumulate', r'^arm_(clear|accum)'),
    ('buffers and windows', r'^arm_(buffer_config|readbuffer|drawbuffer|validate_|finish|flush_raster)'),
    ('lighting and material', r'^arm_(light|colormaterial|lmc_color|poplights)'),
    ('matrices, viewport and clipping', r'^arm_(matrixmode|viewport|scissor|clipplane|depthrange)'),
    ('selection, feedback and attributes', r'^arm_(rendermode|feedback_type|selectbuffer|initnames|loadname|'
     r'pushname|popname|pushattrib|popattrib|passthrough)'),
    ('instruments', r'^arm_.*instruments'),
]


def group_of(name):
    for g, rx in GROUPS[2:]:
        if re.search(rx, name):
            return g
    return 'raster and pipeline state'


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/arm1.u'
    geif = sys.argv[2] if len(sys.argv) > 2 else 'ucode/KONA/geif.u'
    symf = sys.argv[3] if len(sys.argv) > 3 else 'ucode/KONA/ge_symbols'
    out = sys.argv[4] if len(sys.argv) > 4 else 'ucode'

    mem, syms, base, ro, dbase, rw = A.load(path)
    code = {}
    for pc in range(base, base + ro, 4):
        text, ref = A.dis(mem[pc], pc)
        code[pc] = (text.split(' ', 1)[0], text.split(' ', 1)[1] if ' ' in text else '')
    byname = {}
    for v, f, n in syms:
        byname.setdefault(n, v)
    csyms = sorted((v, n) for v, f, n in syms if base <= v < base + ro)
    addrs = [v for v, n in csyms]

    def name_at(a):
        import bisect
        i = bisect.bisect_right(addrs, a) - 1
        return csyms[i][1] if i >= 0 else '?'

    def end_of(a):
        import bisect
        i = bisect.bisect_right(addrs, a)
        e = addrs[i] if i < len(addrs) else a + 4
        # a symbol can sit inside a function; keep going while the code has not returned
        return e

    g = struct.unpack('>1024H', open(geif, 'rb').read())
    gsym = {}
    for line in open(symf):
        n, a = line.split()
        if n[0] == 'm':
            gsym.setdefault(int(a, 16), []).append(n)

    def slotname(k):
        pc = g[2 * k + 1]
        return (gsym.get(pc) or ['?%04x' % pc])[0]

    # ---- the 512-entry token map written by arm1_disasm.py
    icu = {}
    for line in open(os.path.join(out, 'icu_map.tsv')):
        if line[0] == '#' or line.startswith('token'):
            continue
        f = line.rstrip('\n').split('\t')
        icu[int(f[0], 16)] = f

    def clean(s):
        return re.sub(r'\s*<[^>]*>', '', s)

    def scan(h, e):
        """Linear scan of one function: ge slots named, ports written, reads, callees."""
        slots, ports, calls = [], {}, []
        reads0 = r40 = 0
        final = False
        gbase = set()
        pcs = [a for a in range(h, e, 4)]
        for k, a in enumerate(pcs):
            op, args = code[a]
            raw = mem[a]
            args = clean(args)
            if op == 'ldr' and re.search(r'\[pc, #-?0x[0-9a-f]+\]', args) and mem.get(
                    a + 8 + (int(re.search(r'#(-?)0x([0-9a-f]+)', args).group(2), 16) * (-1 if '#-' in args else 1)), 0) == GEPC:
                gbase.add(args.split(',')[0])
            m = re.match(r'(r\d+), \[(r\d+), #(0x[0-9a-f]+)\]!?$', args)
            if op == 'ldr' and m:
                off = int(m.group(3), 16)
                if m.group(2) in gbase and off % 4 == 0 and off < 0x800:
                    slots.append(off // 4)
                elif m.group(2) == 'r8' and PACKED <= off < PACKED + 0x100:
                    nxt = clean(code[pcs[k + 1]][0] + ' ' + code[pcs[k + 1]][1]) if k + 1 < len(pcs) else ''
                    r = m.group(1)
                    base_slot = 2 * ((off - PACKED) // 4)
                    if nxt == 'mov %s, %s, lsl #16' % (r, r):
                        slots.append(base_slot + 1)
                    elif nxt == 'mov %s, %s, lsr #16' % (r, r):
                        slots.append(base_slot)
                if m.group(2) == 'r9':
                    if off == 0:
                        reads0 += 1
                    elif off == 0x3c:
                        final = True
                    elif off == 0x40:
                        r40 += 1
            m = re.match(r'(r\d+), \[r9, #(0x[0-9a-f]+)\]$', args)
            if op.startswith('str') and m:
                o = int(m.group(2), 16)
                if o >= PORT:
                    ports[o] = ports.get(o, 0) + 1
            if op in ('bl',) or (op.startswith('bl') and re.match(r'bl(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)$', op)):
                t = re.search(r'0x0c[0-9a-f]{6}', args)
                if t:
                    calls.append(name_at(int(t.group(), 16)))
        return slots, ports, calls, reads0, r40, final

    stub_target = byname['arm_badcmd']

    def body_end(h):
        e = end_of(h)
        # a lone non-return instruction means a symbol cuts the body short
        if e - h == 4 and code[h][0] not in ('b',) and not code[h][1].startswith('pc, lr'):
            import bisect
            i = bisect.bisect_right(addrs, e)
            while i < len(addrs) and addrs[i] - h < 0x40:
                i += 1
            e = addrs[i] if i < len(addrs) else e
        return e

    rows = []
    for tok in sorted(icu):
        f = icu[tok]
        if f[3] != 'arm':
            continue
        h = int(f[2], 16) >> 4
        hname = name_at(h)
        op, args = code[h]
        stub = (op == 'b' and int(re.search(r'0x0c[0-9a-f]{6}', args).group(), 16) == stub_target) or hname == 'arm_badcmd'
        ign = op == 'mov' and args.startswith('pc, lr')
        e = body_end(h)
        slots, ports, calls, r0, r40, final = scan(h, e)
        uniq = []
        for s in slots:
            n = slotname(s)
            if n not in uniq:
                uniq.append(n)
        cu = []
        for c in calls:
            if c not in cu and c != hname:
                cu.append(c)
        grp = 'unsupported' if stub else 'ignored' if ign else group_of(hname)
        rows.append((tok, f[1], hname, h, grp, (e - h) // 4, r0 + (1 if final else 0) + r40, final,
                     ','.join(uniq), ','.join('%x' % p for p in sorted(ports)), ','.join(cu[:8])))
    with open(os.path.join(out, 'arm1_handlers.tsv'), 'w') as fh:
        fh.write('# Handlers of the ARM-run host tokens in arm1.u (IRIX 6.5.30m). Produced by scripts/arm1_handlers.py\n')
        fh.write('# from a linear scan of each function (no branch following). group: by function name, see the script.\n')
        fh.write('# pops: payload reads seen in the function body (r9+0, r9+0x3c, r9+0x40); final: reads r9+0x3c.\n')
        fh.write('# ge_handlers: engine handlers whose slot the body loads, in code order. ports: r9 offsets stored to.\n')
        fh.write('token\tname\thandler\taddress\tgroup\tinstrs\tpops\tfinal\tge_handlers\tports\tcalls\n')
        for r in rows:
            fh.write('0x%03x\t%s\t%s\t0x%08x\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n' % (
                r[0], r[1], r[2], r[3], r[4], r[5], r[6], 'y' if r[7] else 'n', r[8], r[9], r[10]))

    # ---- init_ged: trace the descriptor stores to find the handler table
    # abstract interpretation over one function: constants and gepc slots per register
    def trace(fn):
        h = byname[fn]
        e = end_of(h)
        regs, src, gbase, ev = {}, {}, set(), []
        pcs = list(range(h, e, 4))

        def val(t):
            t = t.strip()
            return int(t[1:], 16) if t.startswith('#') else regs.get(t)
        for k, a in enumerate(pcs):
            op, args = code[a]
            args = clean(args)
            parts = [p.strip() for p in re.split(r',(?![^\[]*\])', args)]
            mo = re.match(r'^(mov|add|sub|orr|ldr|str)(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?(b)?$', op)
            if not mo:
                if op.startswith('bl'):
                    for r in ('r0', 'r1', 'r2', 'r3', 'r12'):
                        regs.pop(r, None)
                        src.pop(r, None)
                elif op == 'mvn' or op.startswith('mvn'):
                    regs.pop(parts[0], None)
                continue
            o, c, sfx = mo.groups()
            if c and o != 'str':
                regs.pop(parts[0], None)
                src.pop(parts[0], None)
                continue
            if o == 'mov' and len(parts) == 2:
                v = val(parts[1])
                src.pop(parts[0], None)
                if v is not None:
                    regs[parts[0]] = v
                else:
                    regs.pop(parts[0], None)
            elif o in ('add', 'sub', 'orr') and len(parts) == 3:
                x, y = val(parts[1]), val(parts[2])
                src.pop(parts[0], None)
                if x is not None and y is not None:
                    regs[parts[0]] = {'add': x + y, 'sub': x - y, 'orr': x | y}[o] & 0xffffffff
                else:
                    regs.pop(parts[0], None)
            elif o == 'ldr' and not sfx:
                regs.pop(parts[0], None)
                src.pop(parts[0], None)
                m = re.search(r'\[pc, #(-?)0x([0-9a-f]+)\]', args)
                if m:
                    lit = mem.get(a + 8 + int(m.group(2), 16) * (-1 if m.group(1) else 1))
                    if lit == GEPC:
                        gbase.add(parts[0])
                    elif lit is not None:
                        regs[parts[0]] = lit
                    continue
                m = re.match(r'\[(r\d+), #(0x[0-9a-f]+)\]!?$', parts[1]) if len(parts) > 1 else None
                if m and m.group(1) in gbase:
                    src[parts[0]] = slotname(int(m.group(2), 16) // 4)
                elif m and m.group(1) == 'r8' and PACKED <= int(m.group(2), 16) < PACKED + 0x100:
                    nxt = clean(code[pcs[k + 1]][0] + ' ' + code[pcs[k + 1]][1]) if k + 1 < len(pcs) else ''
                    r = parts[0]
                    b0 = 2 * ((int(m.group(2), 16) - PACKED) // 4)
                    if nxt == 'mov %s, %s, lsl #16' % (r, r):
                        src[parts[0]] = slotname(b0 + 1)
                    elif nxt == 'mov %s, %s, lsr #16' % (r, r):
                        src[parts[0]] = slotname(b0)
            elif o == 'str':
                m = re.match(r'\[r9, #(0x[0-9a-f]+)\]$', parts[1]) if len(parts) > 1 else None
                if m:
                    r = parts[0]
                    ev.append((int(m.group(1), 16), regs.get(r), src.get(r)))
        return ev

    def table(fn, desc_ptr, desc_data):
        t, ptr, cur = {}, None, None
        for off, v, s in trace(fn):
            if off == PORT:
                cur = v
            elif off == 0x8c0:
                if cur == desc_ptr:
                    ptr = v
                elif cur == desc_data and ptr is not None:
                    if s:
                        t[ptr] = s
                    ptr += 1
        return t

    bound = table('init_ged', 0x46000020, 0x46200020)
    with open(os.path.join(out, 'ged_bound_table.tsv'), 'w') as fh:
        fh.write('# Handler table that init_ged writes through the engine port with descriptors 0x46000020 (set index)\n')
        fh.write('# and 0x46200020 (write entry, index then advances). IRIX 6.5.30m. Produced by scripts/arm1_handlers.py.\n')
        fh.write('# Entries 3-12 are the matrix operations for the matrix mode init_ged starts in; arm_matrixmode,\n')
        fh.write('# xform_init and xform_restore rewrite them. Indexes not listed are not written by init_ged.\n')
        fh.write('index\thandler\n')
        for i in sorted(bound):
            fh.write('%d\t%s\n' % (i, bound[i]))

    with open(os.path.join(out, 'hw_route.tsv'), 'w') as fh:
        fh.write('# Hardware-routed host tokens (bit 0 of the token-map entry set) with the command number in bits 15-23.\n')
        fh.write('# index = number & 63; bound = the handler init_ged writes at that index of the handler table\n')
        fh.write('# (ged_bound_table.tsv), blank if init_ged writes none, and blank for the geometry form (bit 31 set),\n')
        fh.write('# which does not use the handler table (ucode/arm1.md). form = geometry, pass (bit 5 clear) or\n')
        fh.write('# register (bit 5 set), per ucode/ged.md. See ucode/arm1.md for what is established.\n')
        fh.write('token\tname\tcommand\tgroup\tindex\tbound\tform\n')
        for tok in sorted(icu):
            f = icu[tok]
            if f[3] != 'hw':
                continue
            n = int(f[7])
            e = int(f[2], 16)
            form = 'geometry' if e >> 31 else ('register' if e & 0x20 else 'pass')
            b = '' if form == 'geometry' else bound.get(n & 63, '')
            fh.write('0x%03x\t%s\t%d\t%d\t%d\t%s\t%s\n' % (tok, f[1], n, n >> 6, n & 63, b, form))

    # ---- arm_video_cmd's table: {word count, handler} x 0x5d, in the initialised data
    def rd(a):
        if base <= a < base + ro:
            return mem[a]
        return mem.get(a)
    tbl = byname['DGDispatchTable']
    with open(os.path.join(out, 'dg_dispatch.tsv'), 'w') as fh:
        fh.write('# Display-generator commands: arm_video_cmd (token 0x1a6) reads a command number, then this many\n')
        fh.write('# payload words, then a checksum word. Table DGDispatchTable of arm1.u (IRIX 6.5.30m).\n')
        fh.write('command\twords\thandler\n')
        for i in range(0x5d):
            n, hdl = mem[tbl + 8 * i], mem[tbl + 8 * i + 4]
            fh.write('%d\t%d\t%s\n' % (i, n, name_at(hdl)))


if __name__ == '__main__':
    main()
