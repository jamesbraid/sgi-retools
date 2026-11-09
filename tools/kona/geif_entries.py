#!/usr/bin/env python3
"""Write one row for each of the 1024 entries of the geometry-engine slot
table geif.u (IRIX 6.5.30m).

Usage: geif_entries.py [UCODE_DIR] [OUT]
       defaults: ucode/KONA ucode/geif_entries.md

geif.u is 1024 big-endian 16-bit entries. arm1.u init_hip (0x0c001d78-
0x0c001dbc) copies it as 512 32-bit words into gepc (0x04068654), so word k
is entries 2k (high half) and 2k+1 (low half), and the low half is the
handler address of slot k. It then packs slots 0-127 two to a word into the
state block at r8 + 0x48: word j holds slot 2j in its high half and slot
2j+1 in its low half (gepc[2j] shifted left 16, ORed with gepc[2j+1]).

Per entry the script reads:

  - the 16-bit value and the ge_symbols label at that address;
  - the label's source file and line from the ge.u line table
    (ucode/ge_xref.tsv, written by scripts/ge_catalogue.py);
  - the gepc word that holds it, and for slots below 128 the packed word;
  - the arm1.u functions that load that slot: an ldr from a register the
    function loaded with the gepc literal, or an ldr of a packed word
    followed by the shift that keeps the slot's half (the same linear scan
    as scripts/ge_catalogue.py; a load through a computed index is not
    seen);
  - the distributor words that carry the slot number (ucode/ged_relocs.tsv);
  - the label's role line from ucode/ge_modules.tsv.

It checks the table's shape (every even entry 0, odd entries a label) before
writing anything.
"""
import bisect
import collections
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arm1_disasm as A  # noqa: E402

GEPC = 0x04068654
PACKED = 0x48
# A row joins table fields and the handler's role line; it reads no code of its own, so it locates the slot.
# What the slot runs is understood through the handler's entry, not through this row.
GRADE_ZERO = '**Established** word, located: a zero upper half, its effect not derived beyond the table'
GRADE_SPARE = '**Established** word, located: no handler, its effect not derived beyond the table'
GRADE_SLOT = "**Established** word, located: the role is the handler's, not derived for the slot"


def arm_loads(src):
    """({slot: arm1.u functions that load it}, {slot: those that load its whole gepc word}), constant offsets only."""
    mem, syms, base, ro, dbase, rw = A.load(os.path.join(src, 'arm1.u'))
    csyms = sorted((v, n) for v, f, n in syms if base <= v < base + ro)
    addrs = [v for v, n in csyms]

    def name_at(a):
        i = bisect.bisect_right(addrs, a) - 1
        return csyms[i][1] if i >= 0 else '?'
    arm = collections.defaultdict(set)
    full = collections.defaultdict(set)
    pcs = list(range(base, base + ro, 4))
    texts = {pc: re.sub(r'\s*<[^>]*>', '', A.dis(mem[pc], pc)[0]) for pc in pcs}
    gbase, fn = set(), None
    for i, pc in enumerate(pcs):
        f = name_at(pc)
        if f != fn:
            fn, gbase = f, set()
        op, _, args = texts[pc].partition(' ')
        m = re.match(r'(r\d+), \[pc, #(-?)0x([0-9a-f]+)\]$', args)
        if op.startswith('ldr') and m:
            off = int(m.group(3), 16) * (-1 if m.group(2) else 1)
            if mem.get(pc + 8 + off, 0) == GEPC:
                gbase.add(m.group(1))
        m = re.match(r'(r\d+), \[(r\d+), #(0x[0-9a-f]+)\]!?$', args)
        if op.startswith('ldr') and op not in ('ldrb', 'ldrh') and m:
            off = int(m.group(3), 16)
            if m.group(2) in gbase and off % 4 == 0 and off < 0x800:
                arm[off // 4].add(fn)
                full[off // 4].add(fn)
            elif m.group(2) == 'r8' and PACKED <= off < PACKED + 0x100 and i + 1 < len(pcs):
                r = m.group(1)
                nxt = texts[pcs[i + 1]]
                b = 2 * ((off - PACKED) // 4)
                if re.match(r'mov\w* %s, %s, lsl #16$' % (r, r), nxt):
                    arm[b + 1].add(fn)
                elif re.match(r'mov\w* %s, %s, lsr #16$' % (r, r), nxt):
                    arm[b].add(fn)
    return arm, full


def role_head(r):
    """The summary clause of a role line: the text before its first colon or parenthesis, so that the
    row names its own handler and not the constants the role line lists."""
    r = re.split(r'[:(;]', r, maxsplit=1)[0].strip().rstrip('.,')
    return r


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA'
    out = sys.argv[2] if len(sys.argv) > 2 else 'ucode/geif_entries.md'
    g = struct.unpack('>1024H', open(os.path.join(src, 'geif.u'), 'rb').read())
    names = collections.defaultdict(list)
    for line in open(os.path.join(src, 'ge_symbols')):
        n, a = line.split()
        names[int(a, 16)].append(n)
    for k in range(512):
        if g[2 * k] != 0:
            sys.exit('entry %d is not 0: the table changed shape' % (2 * k))
        if g[2 * k + 1] not in names:
            sys.exit('entry %d holds 0x%x, which is no label' % (2 * k + 1, g[2 * k + 1]))
    where = {}
    for line in open('ucode/ge_xref.tsv'):
        f = line.rstrip('\n').split('\t')
        if line.startswith('#') or f[0] == 'address':
            continue
        where[f[1]] = (f[2], f[3])
    role = {}
    for line in open('ucode/ge_modules.tsv'):
        f = line.rstrip('\n').split('\t')
        if line.startswith('#') or len(f) < 2 or f[0] == 'source':
            continue
        role[f[0]] = f[1]
    ged = collections.defaultdict(list)
    for line in open('ucode/ged_relocs.tsv'):
        f = line.rstrip('\n').split('\t')
        if line.startswith('#') or f[0] == 'ged_word':
            continue
        ged[int(f[3])].append(f[0])
    arm, full = arm_loads(src)

    def armcell(k):
        fs = sorted(arm.get(k, ()))
        if not fs:
            return '0 constant-offset ARM loads'
        if len(fs) > 3:
            return 'reached from %d ARM functions' % len(fs)
        return 'reached from ' + ', '.join('`%s`' % f for f in fs)

    def gedcell(k):
        w = ged.get(k, [])
        if not w:
            return '0 distributor words'
        if len(w) == 1:
            return 'distributor word %s' % w[0]
        return '%d distributor words' % len(w)

    def packcell(k):
        if k >= 128:
            return 'none above slot 127'
        return '%s half, r8 + 0x%x' % ('high' if k % 2 == 0 else 'low', PACKED + 4 * (k // 2))

    rows = []
    unused = 0
    for n in range(1024):
        k, v = n // 2, g[n]
        gw = 'gepc word at 0x%08x' % (GEPC + 4 * k)
        if n % 2 == 0:
            h = g[n + 1]
            rows.append('| %d | %d | `0x%04x`, high half | %s | 0, the `HereWeGo` address | upper half, slot %d (`%s`) | %s | %s | 0 distributor words | %s |' % (
                n, k, v, gw, k, names[h][0] if h else 'HereWeGo',
                'sent as bits 31-16, zero' if full.get(k) else 'not sent alone',
                'shifted out when packed' if k < 128 else 'none above slot 127', GRADE_ZERO))
            continue
        lab = names[v][0]
        if v == 0:
            unused += 1
            rows.append('| %d | %d | `0x0000`, low half | %s | program entry `HereWeGo` | spare slot with no handler | %s | %s | %s | %s |' % (
                n, k, gw, armcell(k), packcell(k), gedcell(k), GRADE_SPARE))
            continue
        fsrc, fline = where.get(lab, ('?', '?'))
        al = len(names[v]) - 1
        lab_cell = '`%s`' % lab
        r = role_head(role.get(lab, ''))
        rows.append('| %d | %d | `0x%04x`, low half | %s | %s, %s:%s%s | %s | %s | %s | %s | %s |' % (
            n, k, v, gw, lab_cell, fsrc, fline, ' (+%d alias%s)' % (al, 'es' if al > 1 else '') if al else '', r if r else 'see its entry', armcell(k), packcell(k), gedcell(k), GRADE_SLOT))

    hdr = """# geif.u entries one by one

Generated by `scripts/geif_entries.py` from `ucode/KONA/geif.u`, `ucode/KONA/ge_symbols`, `ucode/KONA/arm1.u`, [ge_xref.tsv](ge_xref.tsv), [ge_modules.tsv](ge_modules.tsv) and [ged_relocs.tsv](ged_relocs.tsv); do not edit by hand. One row per 16-bit entry of `geif.u` (IRIX 6.5.30m), 1024 in all. How the table is loaded and used is in [ge.md](ge.md#command-dispatch-table-geifu) and [arm1.md](arm1.md#how-a-command-reaches-a-geometry-engine-handler); what each handler's words do is in [ge_handlers.md](ge_handlers.md) and [ge_compute.md](ge_compute.md).

**Established** (the words and their copies). `init_hip` (`arm1.u` 0x0c001d78-0x0c001dbc) copies the file as 512 big-endian 32-bit words into `gepc` at 0x04068654, so word k is entries 2k (high half) and 2k + 1 (low half), and the ARM sends a slot by loading word k and storing it to the engine port r9 + 0x8c0, or into a module chain it writes to control memory (`SetupGE_FFT` does both). It then packs slots 0-127 two to a word at r8 + 0x48: packed word j is gepc[2j] shifted left 16, ORed with gepc[2j + 1], so it keeps only the low halves, slot 2j in its high half and slot 2j + 1 in its low half. Every even entry is 0, the upper half of a slot's word: packing shifts it out, and a full-word send from `gepc` puts it in bits 31-16 of the word the engine receives. %d odd entries are 0, the address of the program entry `HereWeGo`; those slots have no handler.

**Located** (every row). A row joins the table's words with the handler's role line and the ARM scan below; it reads no code for its slot, so it locates the slot and no more. What a slot runs is understood through the handler's own entry.

**Inferred** (roles and effects). The role of a handler slot is the summary clause of its label's role line in [ge_modules.tsv](ge_modules.tsv), up to the first colon; the full line and the handler's reading are in [ge_handlers.md](ge_handlers.md). A slot with a constant-offset ARM load is one the firmware sends; slots with none are reached through a computed index, the distributor's relocated words, or not at all. A send of a spare slot would run `HereWeGo`, the program entry, which reinitialises the engine and waits for a command. The ARM-load column comes from a linear scan of `arm1.u`: an `ldr` at a constant offset from a register that holds the `gepc` address, or an `ldr` of a packed word followed by the shift that keeps the slot's half.

| Entry | Slot | Holds | ARM copy | Label or value | Runs | Sent | Packed copy | Distributor | Grade |
|---|---|---|---|---|---|---|---|---|---|
""" % unused
    with open(out, 'w') as fh:
        fh.write(hdr)
        fh.write('\n'.join(rows) + '\n')


if __name__ == '__main__':
    main()
