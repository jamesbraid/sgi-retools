#!/usr/bin/env python3
"""Generate include/<chip>.h from the census tables.

Usage: retools/tools/chips/gen_headers.py            (from the repository root; rewrites include/*.h)

Inputs per chip: chips/<dir>/census/census.tsv and fields.tsv (written by retools/tools/chips/run.sh). Output: one C header
per chip with the register offsets grouped by block, the access width, the bit-field masks the code isolates
and the constants it writes, each define carrying a label and a short source comment. Never edit a header by
hand; improve the entry or the census and regenerate.

Labels: [E] established (read from the disassembly or a specification page), [I] inferred, [U] unknown.
What the census can establish is only that code reaches an offset with a width and direction; names come from
the shipped routines' accessor names and are [I]; a field mask says the code isolates those bits, its meaning is [I].
Reset values are [U] everywhere: no census row reads them.

The labels map to the shared decode-header grades (retools/tools/defs) as [E] established, [I] inferred, [U] unknown.
Comments must pass that checker's publish-safety rules: no vendor header file names, no binary offsets and no board
tokens. Say "the public Linux SN0 Hub register headers", "window base 0x200000", "Origin 2000", not the file, the
"at 0x..." offset or the IPnn token. CRIME and GBE are generated in the crime repository, not here.
"""
import collections
import csv
import json
import os
import re

# CRIME and GBE are not generated here: the crime repository is
# canonical for both. chips/crime and chips/gbe keep their notes and census as evidence only.
# chip -> (census directory, variant in that census, window base to add, title, block rules)
CHIPS = {
 'pic':    ('pic', 'pic', 0, 'PIC (dual-head PCI-X bridge), Origin 3000 family', None),
 'bridge': ('bridge', 'bridge', 0, 'Bridge (XIO-to-PCI bridge), Origin 2000 and Octane', None),
 'xbridge':('bridge', 'xbridge', 0, 'XBridge (XIO-to-PCI bridge, later), Origin 2000 and Octane', None),
 'bedrock':('bedrock', 'bedrock', 0, 'Bedrock (node controller), Origin 3000 family', 'bedrock'),
 'xbow': ('xbow', None, 0, 'Xbow (crossbar)', None),
 'heart':('heart', None, 0, 'HEART (Octane system controller)', 'heart'),
 'hub':  ('hub', None, 0, 'Hub (Origin 2000 node controller)', 'hub'),
 'ioc3': ('ioc3', None, 0, 'IOC3 (PCI I/O controller)', None),
 'ioc4': ('ioc4', None, 0, 'IOC4 (PCI I/O controller, later)', None),
 'mace': ('mace', None, 0, 'MACE (O2 I/O ASIC)', 'mace'),
 'vice': ('vice', None, 0, 'VICE (O2 video engine, presence only)', None),
 'tiocp': ('pic', 'tiocp', 0, 'TIOCP (PCI-X bridge, later family), as the Origin 3000 family Bridge driver reaches it', None),
 'l1': ('l1', 'bedrock', 0, 'L1 system controller UART path (node-local window), Origin 3000 family', None),
 'router_origin2000': ('router', 'ip27', 0, 'network router as the Origin 2000 kernel reaches it (register numbers of a vector access)', None),
 'router_origin3000': ('router', 'ip35', 0, 'network router as the Origin 3000 kernel reaches it (register numbers of a vector access)', None),
}
MACE_BLOCKS = [  # the specification's block map (table 91 and 92); offsets are from physical 0x1f000000
 (0x080000, 'PCI host bridge'),
 (0x280000, 'Ethernet'),
 (0x300000, 'audio'),
 (0x304000, 'peripheral controller gap (not a listed register)'),
 (0x310000, 'ISA control, parallel and serial DMA'),
 (0x320000, 'PS/2 keyboard and mouse'),
 (0x330000, 'I2C'),
 (0x340000, 'timers'),
 (0x380000, 'external ISA (calendar clock block, base 0x3a0000)'),
]
BEDROCK_BLOCKS = [  # inferred from routine-name prefixes (see chips/bedrock/README.md)
 (0x1000000, 0x1200000, 'PROCESSOR_INTERFACE_LIKE', 'low window: interrupt send, clocks, error masks, time counter'),
 (0x1600000, 0x1800000, 'NETWORK_INTERFACE_LIKE', 'ports, router tables, a counter'),
 (0x1800000, 0x1c00000, 'PROCESSOR_INTERFACE_ALIAS', 'second alias: dump and error routines'),
 (0x1c00000, 0x1e00000, 'IO_INTERFACE_LIKE', 'widget, crossbar-buffer and error registers'),
 (0x1e00000, 0x1f00000, 'LOCAL_BLOCK_LIKE', 'chip revision, partition, vector, network state'),
 (0x1f00000, 0x2000000, 'MEMORY_DIRECTORY_LIKE', 'memory and directory'),
]


HEART_BLOCKS = [  # (first offset, name); the widget block is reported 0x100000 above its widget offset
 (0x0, 'PIU registers (8-byte slots): mode, memory, flow control, status, error latches'),
 (0x10000, 'interrupt registers: mask per processor, status, cause'),
 (0x20000, 'timer, trigger, processor number, sync'),
 (0x100000, "widget block of HEART's own XIO port (physical 0x18000000), offset = 0x100000 + widget offset"),
]


HUB_BLOCKS = [  # (first offset, name); both aliases (local 0x01000000, node-addressed 0x01800000) share these offsets
 (0x0, 'PI: processor interface, 8-byte slots (identity, interrupts, real-time clock, error latches)'),
 (0x20000, 'PI space above 0x20000: the hard-reset bit and the real-time counter (the local block, grouped by address)'),
 (0x200000, 'MD: memory and directory (configuration, migration, error latches)'),
 (0x210000, 'MD performance counters'),
 (0x220000, 'MD junk-bus block: microcontroller registers, slot id, LEDs'),
 (0x400000, 'II: I/O interface (widget, protection, error, CRB and PRB registers)'),
 (0x410000, 'II block transfer engines 0 and 1'),
 (0x430000, 'II performance counters'),
 (0x600000, 'NI: network interface (status, port, vector, routing tables)'),
]


def stem(f):
    f = f.replace('pcireg_', '')
    return re.sub(r'(_bit_set|_bit_clr|_get|_set|_addr)$', '', f)


def load(dirn, variant):
    p = 'chips/%s/census/census.tsv' % dirn
    if not os.path.exists(p):
        return [], {}
    rows = [r for r in csv.DictReader(open(p), delimiter='\t') if variant is None or r['variant'] == variant]
    fl = collections.defaultdict(list)
    fp = 'chips/%s/census/fields.tsv' % dirn
    if os.path.exists(fp):
        for r in csv.DictReader(open(fp), delimiter='\t'):
            if variant is None or r['variant'] in (variant, '?'):
                fl[int(r['register'], 16)].append(r)
    return rows, fl


# A PROM image has no symbols; the scanner cuts it into pseudo-functions named after the address they start at.
# Such a name says nothing about the register and embeds a raw address, so it never names a define.
PSEUDO_FUNCTION = re.compile(r'^prom_[0-9a-f]+$')


def pseudo_only_slots(dirn, variant):
    """(slot, idx) pairs that only pseudo-functions reach."""
    p = 'chips/%s/census/census-sites.tsv' % dirn
    d = set()
    if os.path.exists(p):
        for r in csv.DictReader(open(p), delimiter='\t'):
            if PSEUDO_FUNCTION.match(r['function'].split('@')[0]) and (variant is None or variant in r['variant'].split('|')):
                d.add((int(r['offset'], 16) & ~7, r['idx']))
    return d


def names_by_slot(dirn, variant):
    p = 'chips/%s/census/census-sites.tsv' % dirn
    d = collections.defaultdict(collections.Counter)
    if os.path.exists(p):
        for r in csv.DictReader(open(p), delimiter='\t'):
            if PSEUDO_FUNCTION.match(r['function'].split('@')[0]):
                continue
            if variant is None or variant in r['variant'].split('|'):
                d[(int(r['offset'], 16) & ~7, r['idx'])][stem(r['function'])] += 1
    return d


def ident(s):
    s = re.sub(r'[^A-Za-z0-9]+', '_', s).strip('_').upper()
    return s or 'REG'


def mask_of(bits):
    v = 0
    for part in bits.split(','):
        if ':' in part:
            hi, lo = map(int, part.split(':'))
        else:
            hi = lo = int(part)
        v |= ((1 << (hi - lo + 1)) - 1) << lo
    return v


def view_widths(widths, halves):
    """Width text for one register. The Bridge-family code reads and writes a 32-bit register as the low
    word of its 64-bit slot, at slot +4 on a big-endian machine; the census records that as halves 4. The
    listed offset stays the slot address, so say where the access lands."""
    ws, hs = widths.split(','), halves.split(',')
    if len(hs) != len(ws) or not low_word_access({'widths': widths, 'halves': halves}):
        return '%s byte(s)' % '/'.join(ws)
    return ' / '.join('%s byte(s)%s' % (w, ' at slot+4' if (w == '4' and h == '4') else '') for w, h in zip(ws, hs))


def low_word_access(r):
    ws, hs = r['widths'].split(','), r.get('halves', '').split(',')
    return len(ws) == len(hs) and any(w == '4' and h == '4' for w, h in zip(ws, hs))


def view_notes(rows, rules):
    """Preamble lines that say which view of a register the offsets and widths describe."""
    out = []
    if any(low_word_access(r) for r in rows):
        out += [' * Views: the offset is the 8-byte slot address. "4 at slot+4" is a 32-bit load or store at that',
                ' * address plus 4, the low word of the slot on a big-endian machine; a 64-bit access to the slot',
                ' * address reaches the same register.']
    if rules == 'bedrock':
        out += [' * Bedrock offsets: bits 23:0 of the window address the code forms; the window literals sit 0x1000000',
                ' * above them, so add 0x1000000 for the offset the kernel uses. Offsets with bit 23 set come through the',
                ' * node-indexed alias (the code adds the node number << 33); the same register is at offset - 0x800000',
                ' * in the local alias [I]. Example: 0xe80100, the network-interface error word, is 0x680100 in the local',
                ' * alias, where the code reads its neighbours (0x680108 to 0x680120) directly.']
    return out


def gen(chip, spec):
    dirn, variant, base, title, rules = spec
    P = chip.upper()
    rows, fl = load(dirn, variant)
    nm = names_by_slot(dirn, variant)
    pseudo_only = pseudo_only_slots(dirn, variant) - set(nm)
    # where a census row's name comes from: the config's "name_source" (for example the specification the rows
    # were joined with), else the HEART text
    cfgp = 'tools/configs/%s.json' % dirn
    name_source = (json.load(open(cfgp)) if os.path.exists(cfgp) else {}).get('name_source') or (
        'the shipped diagnostic or monitor name, or the public Linux driver name where none is printed (config register_names)')
    out = ['/*', ' * %s.h - %s' % (chip, title), ' *', ' * Generated by retools/tools/chips/gen_headers.py from chips/%s/census/. Do not edit.' % dirn,
           ' * Labels: [E] established, [I] inferred, [U] unknown.',
           ' * Offsets and widths: [E] a load or store in the cited routine reaches that offset with that width.',
           ' * Names: [I] from the accessor routine names the shipped objects carry. Fields: [I] masks and constants',
           ' * the code applies; their meaning is not read. Reset values: [U] throughout.'] + view_notes(rows, rules) + (
          [' * HEART: names come from the config register_names (the shipped diagnostic prints them, or the public',
           ' * Linux driver where it prints none); offsets 0x100000 and up are the widget block, see the chip page.']
          if rules == 'heart' else []) + [' */',
           '#ifndef %s_H' % P, '#define %s_H' % P, '']
    if not rows:
        out += ['/* No census rows yet: nothing is established for this chip by the census.', ' * Mode and sources: chips/%s/README.md. */' % chip, '', '#endif /* %s_H */' % P, '']
        return '\n'.join(out)
    cur_block = None
    seen = set()
    emitted = set()
    cfg = json.load(open(cfgp)) if os.path.exists(cfgp) else {}
    skip = set(cfg.get('header_skip', []))
    for r in sorted(rows, key=lambda r: (int(r['offset'], 16), r['idx'])):
        off = int(r['offset'], 16)
        if r['offset'] in skip:
            continue
        # the Hub is reached through two aliases of one register file: one define per offset
        key = (off,) if rules == 'hub' else (off, r['idx'])
        if key in seen:
            continue
        seen.add(key)
        blk = 'registers'
        if rules == 'bedrock':
            for lo, hi, n, d in BEDROCK_BLOCKS:
                if lo <= off + 0 < hi or (off < 0x1000000 and lo <= off + 0x1000000 < hi):
                    blk = '%s: %s [I, routine-name prefixes]' % (n, d)
            full = off if off >= 0x1000000 else off
        elif rules == 'heart':
            blk = [n for lo, n in HEART_BLOCKS if off >= lo][-1]
        elif rules == 'hub':
            blk = [n for lo, n in HUB_BLOCKS if off >= lo][-1]
        elif rules == 'mace':
            blk = [n for lo, n in MACE_BLOCKS if off >= lo][-1]
        elif off >= 0x10000:
            blk = 'arrays and windows (offset is the array base)'
        else:
            blk = 'registers (8-byte slots)' if off < 0x1000 else 'registers'
        if blk != cur_block:
            out += ['', '/* ---- %s %s */' % (blk, '-' * max(3, 60 - len(blk))), '']
            cur_block = blk
        names = [n for n, _ in nm.get((off, r['idx']), collections.Counter()).most_common(3)]
        given = r.get('name', '')
        # Only a symbol-less PROM reaches the register: name it by its offset, which is a hardware fact, rather
        # than by the address of a pseudo-function. Other unnamed registers keep their bare offset.
        label = ident(given) if given else (ident(names[0]) if names else
                                            ('REG_%06X' if (off, r['idx']) in pseudo_only else '%X') % off)
        macro = '%s_%s' % (P, label)
        if '%s ' % macro in ''.join(out[-400:]):
            macro += '_%X' % off
        w = view_widths(r['widths'], r.get('halves', ''))
        acc = r['access_seen']
        out.append('#define %-34s 0x%06x   /* [E] width %s, access %s%s; name [I] from %s; reached in %s sites, %s routine(s) */' % (
            macro, base + off, w, acc, ', indexed (family base)' if r['idx'] == '1' else '',
            name_source if given else (', '.join(names) or 'no accessor name'),
            r['sites'], r['functions']))
        for f in sorted(fl.get(off, []), key=lambda x: (x['kind'], x['bits_or_value'])):
            b = f['bits_or_value']
            if f['kind'] in ('mask', 'clear-mask') or 'via' in f['kind'] and re.fullmatch(r'[0-9:,]+', b):
                if not re.fullmatch(r'[0-9:,]+', b):
                    continue
                m = mask_of(b)
                nm2 = '%s_B_%s' % (macro, b.replace(':', '_').replace(',', '_'))
                if nm2 in emitted:
                    continue
                emitted.add(nm2)
                out.append('#define   %-32s 0x%x   /* [I] %s %s: the code %s these bits (%s sites) */' % (
                    '%s_B_%s' % (macro, b.replace(':', '_').replace(',', '_')), m, f['source'], f['kind'],
                    'isolates' if f['source'] == 'load' else 'writes', f['sites']))
            elif f['kind'].startswith('shift'):
                continue
            elif f['kind'] == 'const' and b.startswith('0x'):
                out.append('#define   %-32s %s   /* [I] a constant the code writes here (%s sites); meaning unknown [U] */' % (
                    '%s_V_%s' % (macro, b[2:].upper()), b, f['sites']))
    out += ['', '#endif /* %s_H */' % P, '']
    return '\n'.join(out)


def main():
    os.makedirs('include', exist_ok=True)
    for chip, spec in CHIPS.items():
        open('include/%s.h' % chip, 'w').write(gen(chip, spec))
    open('include/chips_check.c', 'w').write('/* Compile check: every header must parse together. Built by retools/tools/chips/check-headers.sh. */\n' +
        ''.join('#include "%s.h"\n' % c for c in CHIPS) + 'int chips_headers_ok(void) { return 1; }\n')


if __name__ == '__main__':
    main()
