#!/usr/bin/env python3
"""Generate devices/<chip>/registers.toml (old layout: defs/<chip>.toml) from the census tables.

Usage: retools/tools/chips/gen_headers.py            (from the repository root; rewrites the census units)

Inputs per chip: devices/<dir>/census/census.tsv and fields.tsv (chips/<dir>/census/ on the old layout) (written by retools/tools/chips/run.sh). Output: one
hardware-definition source per chip (the format of retools/tools/defs) with the registers, their access width and
source, the bit masks the code isolates and the constants it writes. Run retools/tools/defs/defs-gen afterwards for
the C headers, Rust crate and reference pages. Never edit these sources by hand; improve the census or its config
and regenerate. The hand-written companions (`registers-extra.toml`, `defs/*_extra.toml` on the old layout, `l1_requests`, `xio_fc`, `ice1724`) are not touched.
(The name is from when this wrote C headers.)

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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import slots  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'defs'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from _layout import Layout  # noqa: E402
from defslib import toml_emit  # noqa: E402
from defslib.model import normalize  # noqa: E402

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


def layout():
    return Layout('.')


def current():
    """Whether this workspace is on the current layout: register maps under devices/, or none yet and
    the current layout's directories already there."""
    lay = layout()
    return lay.defs_mode == 'new' or (lay.defs_mode is None and lay.on_current_layout)


def source_path(chip, base=None):
    """Where the unit of `chip` is written; with `base` the overlay on that base chip's unit."""
    if current():
        return 'devices/%s/registers.%s.toml' % (base, chip) if base else 'devices/%s/registers.toml' % chip
    return 'defs/%s.%s.toml' % (base, chip) if base else 'defs/%s.toml' % chip


def stem(f):
    f = f.replace('pcireg_', '')
    return re.sub(r'(_bit_set|_bit_clr|_get|_set|_addr)$', '', f)


def load(dirn, variant):
    p = '%s/census.tsv' % layout().census_dir(dirn)
    if not os.path.exists(p):
        return [], {}
    rows = [r for r in csv.DictReader(open(p), delimiter='\t') if variant is None or r['variant'] == variant]
    for r in rows:
        r['space'] = r.get('space') or ''       # a census written before address spaces were separated has none
    fl = collections.defaultdict(list)
    fp = '%s/fields.tsv' % layout().census_dir(dirn)
    if os.path.exists(fp):
        for r in csv.DictReader(open(fp), delimiter='\t'):
            if variant is None or r['variant'] in (variant, '?'):
                fl[(r.get('space') or '', int(r['register'], 16))].append(r)
    return rows, fl


# A PROM image has no symbols; the scanner cuts it into pseudo-functions named after the address they start at.
# Such a name says nothing about the register and embeds a raw address, so it never names a define.
PSEUDO_FUNCTION = re.compile(r'^prom_[0-9a-f]+$')


class SiteNames:
    """The accessor names the census sites give each register row.

    A site is recorded under its exact (space, offset, width, idx). A row asks for the sites whose offset the
    census folded into its slot (the chip's own slot rules, the same ones the join used) and whose width the row
    saw, so a 4-byte register never takes the name of the 4-byte neighbour that shares its 8-byte-aligned slot.
    """

    def __init__(self, dirn, variant, slot_of):
        self.slot_of = slot_of
        self.exact = collections.defaultdict(lambda: [collections.Counter(), 0])   # key -> [names, pseudo sites]
        self.by_slot = collections.defaultdict(list)
        p = '%s/census-sites.tsv' % layout().census_dir(dirn)
        if not os.path.exists(p):
            return
        for r in csv.DictReader(open(p), delimiter='\t'):
            if not (variant is None or variant in r['variant'].split('|')):
                continue
            space, off, width = r.get('space') or '', int(r['offset'], 16), int(r['width'])
            key = (space, off, width, r['idx'])
            if key not in self.exact:
                self.by_slot[(space, slot_of(off, space), r['idx'])].append(key)
            ent = self.exact[key]
            if PSEUDO_FUNCTION.match(r['function'].split('@')[0]):
                ent[1] += 1
            else:
                ent[0][stem(r['function'])] += 1

    def of_row(self, r):
        """(names by count, whether only pseudo-functions reach the row) for a census row."""
        space, slot = r.get('space') or '', int(r['offset'], 16)
        widths = {int(w) for w in r['widths'].split(',') if w != ''}
        names, pseudo = collections.Counter(), 0
        for key in self.by_slot.get((space, slot, r['idx']), ()):
            if key[2] in widths:
                names.update(self.exact[key][0])
                pseudo += self.exact[key][1]
        return [n for n, _ in names.most_common(3)], bool(pseudo) and not names


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


def census_comment(r, w, given, names, name_source, space):
    """The census text for one register: how it was reached and where its name comes from."""
    return 'width %s, access %s%s%s; name [I] from %s; reached in %s sites, %s routine(s)' % (
        w, r['access_seen'], ', indexed (family base)' if r['idx'] == '1' else '',
        ', through the %s window' % space if space else '',
        name_source if given else (', '.join(names) or 'no accessor name'),
        r['sites'], r['functions'])


# A census row is a register only when it states one width list and one plain access; anything else (an address
# taken without a load or store, or a mixed view) is carried as a constant, which keeps its offset and comment.
REG_WIDTH = re.compile(r'width ([\d/]+) byte')
REG_ACCESS = re.compile(r'width [\d/]+ byte\(s\)(?: at slot\+\d+)?, access (rw|r|w)\b')

LABEL_DOC = ('Offsets and widths are established: a load or store in the cited routine reaches that offset with that width. '
             'Names are inferred from the accessor routine names the shipped objects carry. Constants are masks and values '
             'the code applies; their meaning is not read. Reset values are unknown throughout.')

HEADER = '# Written by retools/tools/chips/gen_headers.py from %s/%%s/census/. Do not edit: fix the census or its config and rerun.'


def header(chip):
    """The first line of a unit: it names the census directory the chip's rows are read from, under the
    layout the workspace is on (a chip can share another's census, as xbridge does)."""
    return HEADER % ('devices' if current() else 'chips') % CHIPS[chip][0]


def gen(chip, spec):
    """The unit dictionary for one chip, in the shape of a register-map source, and the block titles.

    Returns (unit, blocks): blocks maps the name of the first register of each block to the block's title.
    """
    dirn, variant, base, title, rules = spec
    P = chip.upper()
    rows, fl = load(dirn, variant)
    cfgp = 'tools/configs/%s.json' % dirn
    cfg = json.load(open(cfgp)) if os.path.exists(cfgp) else {}
    slot_of, _part_of = slots.make(cfg)
    nm = SiteNames(dirn, variant, slot_of)
    # where a census row's name comes from: the config's "name_source" (for example the specification the rows
    # were joined with), else the HEART text
    name_source = cfg.get('name_source') or (
        'the shipped diagnostic or monitor name, or the public Linux driver name where none is printed (config register_names)')
    doc = [LABEL_DOC] + [ln[3:] for ln in view_notes(rows, rules)]
    if cfg.get('register_resets'):
        doc[0] = doc[0].replace('Reset values are unknown throughout.',
                                'Reset values are unknown unless a register entry cites the source that states one.')
    if rules == 'heart':
        doc.append("Names come from the config register_names (the shipped diagnostic prints them, or the public Linux driver "
                   "where it prints none); offsets 0x100000 and up are the widget block, see the chip page.")
    unit = {'unit': chip, 'prefix': P, 'title': title, 'doc': ' '.join(doc),
            'c': {}}
    if not current():       # the current layout has no forwarding headers: consumers include generated/c
        unit['c'] = {'legacy_header': 'include/%s.h' % chip, 'legacy_guard': '%s_H' % P}
    blocks = {}
    if not rows:
        unit['from'] = 'census: no rows yet, nothing is established for this chip by the census (%s/%s/README.md)' % ('devices' if current() else 'chips', chip)
        return unit, blocks
    unit['from'] = 'census: loads and stores in the shipped binaries; names from %s' % name_source
    unit['public_from'] = ['census:']
    unit['c']['offset_macro'] = 'bare'
    regs, consts, spaces, aliases = {}, {}, {}, {}
    cur_block = pending = None
    seen = set()
    emitted = set()
    skip = set(cfg.get('header_skip', []))
    # A name whose meaning changed stays as an alias of the macro that now carries the meaning, so no downstream
    # name disappears: config "deprecated_defines" [{name, space, offset, why, field}]. The old name follows the
    # row's own macro, or with "field" (a suffix such as "_B_0") the row's field macro.
    deprecated = collections.defaultdict(list)
    for d in cfg.get('deprecated_defines', []):
        deprecated[(d.get('space', ''), int(d['offset'], 0))].append(d)
    used_aliases = set()
    taken = set()          # macros a row has already used
    last = {}              # (space, offset) -> macro of the last register at that offset
    # The Hub keeps one register per offset, but its rows differ by index (an idx-0 read row, a node-alias store
    # row): the register's access is every kind any row at the offset saw, and each row's site counts stay in "from".
    merged = collections.defaultdict(list)
    if rules == 'hub':
        for r in rows:
            merged[(r['space'], int(r['offset'], 16))].append(r)
    for r in sorted(rows, key=lambda r: (r['space'] != '', r['space'], int(r['offset'], 16), r['idx'])):
        off = int(r['offset'], 16)
        space = r['space']
        if r['offset'] in skip and not space:
            continue
        # the Hub is reached through two aliases of one register file: one register per offset
        key = (space, off) if rules == 'hub' else (space, off, r['idx'])
        if key in seen:
            continue
        seen.add(key)
        blk = 'registers'
        if space:
            blk = ('%s: accesses through a separate address-space window, not registers of this ASIC; offsets are from the '
                   'window base [E]' % space)
        elif rules == 'bedrock':
            for lo, hi, n, d in BEDROCK_BLOCKS:
                if lo <= off + 0 < hi or (off < 0x1000000 and lo <= off + 0x1000000 < hi):
                    blk = '%s: %s [I, routine-name prefixes]' % (n, d)
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
            cur_block = pending = blk
        names, pseudo_only = nm.of_row(r)
        given = r.get('name', '')
        # Only a symbol-less PROM reaches the register: name it by its offset, which is a hardware fact, rather
        # than by the address of a pseudo-function. Other unnamed registers keep their bare offset.
        if space:
            prefix = '%s_%s' % (P, ident(space))
            label = ident(given) if given else (ident(names[0]) if names else 'OFF_%06X' % off)
        else:
            prefix = P
            label = ident(given) if given else (ident(names[0]) if names else
                                                ('REG_%06X' if pseudo_only else '%X') % off)
        macro = '%s_%s' % (prefix, label)
        if macro in taken:
            macro += '_%X' % off
        while macro in taken:           # the same offset reached with and without an index
            macro += '_IDX' if r['idx'] == '1' and not macro.endswith('_IDX') else '_X'
        taken.add(macro)
        text = census_comment(r, view_widths(r['widths'], r.get('halves', '')), given, names, name_source, space)
        wd, acc = REG_WIDTH.search(text), REG_ACCESS.search(text)
        name = macro[len(P) + 1:]
        if not (wd and acc) or max(int(x) for x in wd.group(1).split('/')) == 0:
            consts[name] = {'value': base + off, 'grade': 'established'}
            if len(text) < 600:
                consts[name]['doc'] = text
        elif r['idx'] == '1' and (space, off) in last:
            # the indexed view of a register an unindexed row already names: the same offset under a second name
            aliases[macro] = last[(space, off)]
        else:
            if pending:
                blocks[name.lower()] = pending
                pending = None
            width = 8 * max(int(x) for x in wd.group(1).split('/'))
            access, origin = acc.group(1), 'census: %s sites, %s routines' % (r['sites'], r['functions'])
            if rules == 'hub':
                group = sorted(merged[(space, off)], key=lambda x: x['idx'])
                kinds = ''.join(sorted({c for x in group for c in x['access_seen'] if c in 'rw'}))
                access = {'r': 'r', 'w': 'w', 'rw': 'rw'}.get(kinds, access)
                if len(group) > 1:
                    origin = '; '.join('census: %s sites, %s routines (%s%s)' % (
                        x['sites'], x['functions'], x['access_seen'], ', indexed' if x['idx'] == '1' else '') for x in group)
            reg = {'offset': base + off, 'access': access, 'width': width, 'grade': 'established', 'fields': {},
                   'tests': [], 'from': origin}
            if space:
                sp = '%s_%s' % (chip, re.sub(r'[^a-z0-9]+', '_', space.lower()).strip('_'))
                reg['space'] = sp
                spaces.setdefault(sp, {'unit': 'byte', 'doc': 'Registers reached through the %s window.' % space})
            regs[name.lower()] = reg
            last[(space, off)] = macro
        mine = deprecated.get((space, off), [])
        used_aliases.update(d['name'] for d in mine if d.get('field', '') == '')

        def alias(suffix, target):
            for d in mine:
                if d.get('field', '') == suffix:
                    aliases[d['name']] = target
        alias('', macro)
        for f in sorted(fl.get((space, off), []), key=lambda x: (x['kind'], x['bits_or_value'])):
            b = f['bits_or_value']
            if f['kind'] in ('mask', 'clear-mask') or 'via' in f['kind'] and re.fullmatch(r'[0-9:,]+', b):
                if not re.fullmatch(r'[0-9:,]+', b):
                    continue
                nm2 = '%s_B_%s' % (macro, b.replace(':', '_').replace(',', '_'))
                if nm2 in emitted:
                    continue
                emitted.add(nm2)
                # a bit mask the code applies, not a layout: the census says the code isolates or writes these bits
                consts[nm2[len(P) + 1:]] = {'value': mask_of(b), 'grade': 'inferred'}
                alias(nm2[len(macro):], nm2)
                used_aliases.update(d['name'] for d in mine if d.get('field') == nm2[len(macro):])
            elif f['kind'].startswith('shift'):
                continue
            elif f['kind'] == 'const' and b.startswith('0x'):
                nm2 = '%s_V_%s' % (macro, b[2:].upper())
                consts[nm2[len(P) + 1:]] = {'value': int(b, 16), 'grade': 'inferred'}
                alias(nm2[len(macro):], nm2)
                used_aliases.update(d['name'] for d in mine if d.get('field') == nm2[len(macro):])
    # Reset values a source states, kept beside the census because the census cannot see them: config
    # "register_resets" names a JSON file of {register name: {"value": N, "from": source, "grade": label}}. The
    # grade defaults to established, which the checks accept only with the source in "from".
    if cfg.get('register_resets'):
        resets = json.load(open(cfg['register_resets']))
        missing = sorted(set(resets) - set(regs))
        if missing:
            raise SystemExit('%s: register_resets name registers the census does not have: %s' % (chip, ', '.join(missing)))
        for n, r in resets.items():
            regs[n]['reset'] = r['value']
            regs[n]['reset_grade'] = r.get('grade', 'established')
            regs[n]['reset_from'] = r['from']
    unused = {d['name'] for ds in deprecated.values() for d in ds} - used_aliases
    if unused:
        raise SystemExit('%s: deprecated_defines name a row the census does not have: %s' % (chip, ', '.join(sorted(unused))))
    if spaces:
        unit['spaces'] = spaces
    if regs:
        unit['registers'] = regs
    if consts:
        unit['constants'] = consts
    if aliases:
        unit['c']['aliases'] = aliases
    return unit, blocks


def toml_of(chip, spec):
    """Register-map text for one chip. Block titles go in as comments above the first register of each block."""
    unit, blocks = gen(chip, spec)
    text = toml_emit.emit_unit(normalize(unit), header(unit['unit']))
    for reg, title in blocks.items():
        text = text.replace('\n[registers.%s]\n' % reg, '\n# ---- %s\n[registers.%s]\n' % (title, reg), 1)
    return text


# A chip that is a revision of another is written as an overlay on it (registers.<chip>.toml), so what the
# census found different is all that the file says. chip -> base chip.
OVERLAYS = {'xbridge': 'bridge'}


def overlay_of(chip, base):
    """Overlay text: the census unit of chip as a patch on the unit of base, or None when the
    two differ in a way an overlay cannot say (a property removed from an item)."""
    u, _ = gen(chip, CHIPS[chip])
    b, _ = gen(base, CHIPS[base])
    tu, tb = toml_emit.trimmed(normalize(u)), toml_emit.trimmed(normalize(b))
    override = {k: tu[k] for k in ('unit', 'prefix', 'title', 'doc', 'from', 'public_from', 'c') if tu.get(k) != tb.get(k)}
    remove, patch, add = [], {}, {}
    for sect in ('spaces', 'registers', 'constants'):
        iu, ib = tu.get(sect, {}), tb.get(sect, {})
        remove += ['%s.%s' % (sect, n) for n in ib if n not in iu]
        for n in iu:
            if n not in ib:
                add.setdefault(sect, {})[n] = iu[n]
            elif iu[n] != ib[n]:
                if set(ib[n]) - set(iu[n]):
                    return None
                patch['%s.%s' % (sect, n)] = {k: v for k, v in iu[n].items() if ib[n].get(k) != v}
    for k in ('enums', 'words'):
        if tu.get(k) or tb.get(k):
            return None
    out = [header(chip) + ' It patches %s.' % source_path(base), '']
    if remove:
        out += ['remove = [%s]' % ', '.join(toml_emit._s(x) for x in remove), '']
    out.append('[override]')
    for k, v in override.items():
        out.append('%s = %s' % (toml_emit._key(k), toml_emit._val(k, v)))
    for path, props in patch.items():
        out += ['', '[patch.%s]' % toml_emit._key(path)]
        toml_emit._scalars(props, 'const' if path.startswith('constants.') else '', out)
    for sect, items in add.items():
        for n, item in items.items():
            if sect == 'constants':
                continue
            out += ['', '[add.%s.%s]' % (sect, toml_emit._key(n))]
            toml_emit._scalars(item, '', out, skip=('fields', 'tests'))
    if add.get('constants'):
        out += ['', '[add.constants]']
        for n, k in add['constants'].items():
            out.append('%s = %s' % (toml_emit._key(n), toml_emit._inline(k, 'const')))
    return '\n'.join(out) + '\n'


def main():
    if not current():
        os.makedirs('defs', exist_ok=True)
    for chip, spec in CHIPS.items():
        base = OVERLAYS.get(chip)
        text = overlay_of(chip, base) if base else None
        path = source_path(chip, base) if text else source_path(chip)
        for stale in (source_path(chip), source_path(chip, base) if base else None):
            if stale and stale != path and os.path.exists(stale):
                os.remove(stale)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(text or toml_of(chip, spec))


if __name__ == '__main__':
    main()
