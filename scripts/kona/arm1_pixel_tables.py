#!/usr/bin/env python3
"""Write ucode/arm1_pixel_tables.md: one row per converter list, converter
group and single output-module record of the ARM firmware's pixel path
(arm1.u, IRIX 6.5.30m).

Usage: arm1_pixel_tables.py [ARM1_U] [SYMBOLS] [OUT]
       defaults: ucode/KONA/arm1.u ucode/arm1_symbols.tsv ucode/arm1_pixel_tables.md

Every value comes from the image itself, read through the AIF layout that
scripts/arm1_disasm.py describes:

  - converter groups: every symbol named cvmg_*. Each is two words, a
    count and a pointer; the pointer must land on a symbol, which becomes
    a converter list of that many words;
  - converter lists: the words each group points at. A word holds a field
    width in bits 16-23, a bit position in bits 8-13, a low byte, bit 25
    and bit 30; the script checks that bit 30 is set on the last word and
    that no other bits are set, and stops otherwise;
  - output-module records: every symbol whose name ends in OutputModule
    or outputModule and is not a table. Each is seven words: slot, variant
    slot, parameter writer, pixel tag table, texel tag table, converter
    group, flag. The script checks that the writer is a code symbol and
    the group one of the cvmg_ symbols.

Where a word is used is found by scanning every word of the read-only and
read-write images for its address.
"""
import bisect
import struct
import sys

ARM1 = sys.argv[1] if len(sys.argv) > 1 else 'ucode/KONA/arm1.u'
SYMS = sys.argv[2] if len(sys.argv) > 2 else 'ucode/arm1_symbols.tsv'
OUT = sys.argv[3] if len(sys.argv) > 3 else 'ucode/arm1_pixel_tables.md'

d = open(ARM1, 'rb').read()
h = struct.unpack('>32I', d[:128])
RO, RW, BASE, DBASE = h[5], h[6], h[10], h[13]


def off(a):
    if BASE <= a < BASE + RO:
        return 0x80 + a - BASE
    if DBASE <= a < DBASE + RW:
        return 0x80 + RO + a - DBASE
    raise SystemExit('address 0x%08x is outside the image' % a)


def words(a, n):
    o = off(a)
    return list(struct.unpack('>%dI' % n, d[o:o + 4 * n]))


def src(a):
    if DBASE <= a < DBASE + RW:
        return '`arm1.u` RW +0x%x' % (a - DBASE)
    return '`arm1.u` +0x%x' % (a - BASE)


syms, names = {}, {}
for line in open(SYMS):
    if line.startswith('#') or line.startswith('address'):
        continue
    a, _, n = line.rstrip('\n').split('\t')
    syms[n] = int(a, 16)
    names.setdefault(int(a, 16), n)
ordered = sorted((a, n) for n, a in syms.items())
starts = [a for a, _ in ordered]


def owner(a):
    i = bisect.bisect_right(starts, a) - 1
    return ordered[i]


refs = {}
for base, start, size in ((BASE, 0x80, RO), (DBASE, 0x80 + RO, RW)):
    for i in range(0, size, 4):
        v = struct.unpack('>I', d[start + i:start + i + 4])[0]
        refs.setdefault(v, []).append(base + i)


def users(a):
    out = []
    for r in refs.get(a, []):
        oa, on = owner(r)
        out.append((on, (r - oa) // 4))
    return out


# Two symbols are named ptagBig (and ptagSmall); a record names the pair
# by address, so match on the names at its two tag words.
TAGS = {('ptagBig', 'ttagBig'): 'wide', ('ptagSmall', 'ttagSmall'): 'narrow'}

groups = sorted((a, n) for n, a in syms.items() if n.startswith('cvmg_'))
lists = {}
grows = []
for a, n in groups:
    count, ptr = words(a, 2)
    if ptr not in names:
        raise SystemExit('%s points at 0x%08x, which no symbol names' % (n, ptr))
    lists.setdefault(ptr, count)
    if lists[ptr] != count:
        raise SystemExit('%s gives %d words for a list another group sizes %d' % (n, count, lists[ptr]))
    u = users(a)
    grows.append((n, a, count, names[ptr], u))

lrows = []
layouts = []
for a in sorted(lists):
    n, count = names[a], lists[a]
    ws = words(a, count)
    if not ws[-1] & 0x40000000:
        raise SystemExit('%s: last word lacks bit 30' % n)
    for w in ws:
        if w & ~0x42ff3fff:
            raise SystemExit('%s: unexpected bits in 0x%08x' % (n, w))
    sizes, cur = [], 0
    for w in ws:
        cur += 1
        if w & 0x40000000:
            sizes.append(cur)
            cur = 0
    first = ws[:sizes[0]]
    alike = all(ws[i * sizes[0]:(i + 1) * sizes[0]] == first for i in range(len(sizes))) and len(set(sizes)) == 1
    widths = sorted({(w >> 16) & 0xff for w in ws if (w >> 16) & 0xff}, reverse=True)
    top = max((w >> 8) & 0x3f for w in ws)
    empty = sum(1 for w in ws if not (w >> 16) & 0xff)
    flag25 = sum(1 for w in ws if w & 0x02000000)
    lowfill = sum(1 for w in ws if (w & 0xff) and (w & 0xff) == (w >> 16) & 0xff)
    total = sum(((w >> 16) & 0xff) for w in first)
    lrows.append((n, a, count, len(sizes), sizes[0], alike, widths, top, total, empty, flag25, lowfill))
    layouts.append((n, sizes, ws))

mrows = []
for n, a in sorted(syms.items(), key=lambda t: t[1]):
    if not (n.endswith('OutputModule') or n.endswith('outputModule')):
        continue
    if not DBASE <= a < DBASE + RW:
        continue
    w = words(a, 7)
    if names.get(w[5], '').startswith('cvmg_') and names.get(w[2], '') and BASE <= w[2] < BASE + RO:
        tags = TAGS.get((names.get(w[3]), names.get(w[4])))
        if tags is None or w[6] != (1 if tags == 'wide' else 0):
            raise SystemExit('%s: tag tables or flag differ from the wide-1, narrow-0 pairing' % n)
        mrows.append((n, a, w, users(a), tags))

L = []
L.append('# Pixel-path converter lists, converter groups and output-module records')
L.append('')
L.append('Generated by `scripts/arm1_pixel_tables.py` from `ucode/KONA/arm1.u` (IRIX 6.5.30m) and '
         '[arm1_symbols.tsv](arm1_symbols.tsv); do not edit by hand. Every value is read from the image, and the '
         'script stops if a record does not have the shape described here. How the path builders choose these '
         'records is in [arm1_functions.md](arm1_functions.md#pixel-path-output-module-records-and-conversion-lists).')
L.append('')
L.append('## Converter lists')
L.append('')
L.append('**Established** (the layout, every word below). A converter list is a run of 32-bit words, split into '
         'groups by bit 30, which is set on the last word of each group. Each word carries a field width in bits '
         '16-23 and a bit position in bits 8-13; some carry the width again in the low byte, and some set bit 25. '
         'No list sets any other bit. The firmware writes a list to engine control memory when it sets up the '
         'output module whose record names the list\'s group ([below](#output-module-records)). **Inferred** '
         '(the role): each word tells the engine\'s output module where one component goes in a 64-bit output '
         'word, its width at its position; the lists for RGB5A1 give exactly 5-5-5-1 and those for R5G6B5 '
         '5-6-5, and a width of 0 is an empty slot that adds no data. Bit 25 is set in the lists the float and '
         'short-source paths use. The columns: the word count the group gives, the number of groups and the '
         'words in one, whether every group repeats the first, the distinct widths, the highest bit position, '
         'the bits one group fills, and counts of empty fields, bit-25 words and words whose low byte repeats '
         'the width.')
L.append('')
L.append('| List | Address | Source | Kind | Words | Groups | Per group | Groups alike | Widths | Top position | '
         'Bits per group | Empty fields | Bit 25 words | Width in low byte | Label |')
L.append('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
for n, a, count, ng, per, alike, widths, top, total, empty, flag25, lowfill in lrows:
    wtxt = ' and '.join(str(x) for x in widths) + ' bits' if widths else 'none'
    L.append('| `%s` | 0x%08x | %s | output component field list | %d words | %d | %d | %s | %s | bit %d | %d '
             'bits | %d | %d | %d | **Established** |'
             % (n, a, src(a), count, ng, per, 'yes' if alike else 'no', wtxt, top, total, empty, flag25, lowfill))
L.append('')
L.append('## Converter groups')
L.append('')
L.append('**Established** (every group below). A converter group is two words: a word count and a pointer to '
         'a converter list. The record that uses a group names it in its sixth word (word 5 from zero): the '
         'single output-module records [below](#output-module-records) and the record tables '
         '`RGBAoutputModuleTable`, `OneCmpntoutputModuleTable`, `ShortCircuitOutput`, `BitmapOutput` and '
         '`CIoutputModuleTable`, whose entries are seven words, so a table entry k names its group at word '
         '7k + 5. The "named by" column gives the first record that holds the group\'s address and the word it '
         'sits in; the count after it is how many words of the image hold that address. When the first holder is '
         'a routine (`X_PixSetupGE` for the X server\'s pixel groups), the word is a literal-pool word counted '
         'from the routine\'s start, the place the routine loads the group\'s address from.')
L.append('')
L.append('| Group | Address | Source | Kind | Count | List | Named by | Word | References | Label |')
L.append('|---|---|---|---|---|---|---|---|---|---|')
for n, a, count, lname, u in grows:
    if u:
        by, word = u[0]
        bytxt, wtxt = '`%s`' % by, 'word %d' % word
    else:
        bytxt, wtxt = 'no record', 'none'
    L.append('| `%s` | 0x%08x | %s | count and pointer to list | %d words | `%s` | %s | %s | %d | **Established** |'
             % (n, a, src(a), count, lname, bytxt, wtxt, len(u)))
L.append('')
L.append('## Output-module records')
L.append('')
L.append('**Established** (every record below). An output-module record is seven words: the engine dispatch '
         'slot of the output module, the slot of its variant (the handler named with the suffix NC; `geif.u` '
         'entry 2k + 1 holds slot k\'s handler), the ARM parameter writer that sizes the transfer, a pixel tag '
         'table and a texel tag table (`ptagBig` and `ttagBig`, or the narrow pair `ptagSmall` and '
         '`ttagSmall`), the converter group, and a flag word. These records are the ones `AddOutput` loads '
         'directly from its literal pool for a format case of its own, instead of indexing a record table; the '
         'last column gives the pool word. The flag is 1 with the wide tag tables and 0 with the narrow ones '
         'in every record; the script checks it.')
L.append('')
L.append('| Record | Address | Source | Kind | Slot | Variant slot | Parameter writer | Tag tables | Group | Flag | '
         'Pool word | Label |')
L.append('|---|---|---|---|---|---|---|---|---|---|---|---|')
for n, a, w, u, tags in mrows:
    pool = ['%s word %d' % (o, i) for o, i in u if o == 'AddOutput']
    L.append('| `%s` | 0x%08x | %s | fixed record for one format | 0x%x | 0x%x | `%s` | %s | `%s` | %d | %s | '
             '**Established** |'
             % (n, a, src(a), w[0], w[1], names[w[2]], tags, names[w[5]], w[6],
                pool[0].replace('AddOutput ', '') if pool else 'none'))
L.append('')
L.append('## Field layouts')
L.append('')
L.append('Each list word by word, as width@position, one line per group (a group that repeats the one before is '
         'counted, not repeated).')
L.append('')
L.append('```')
for n, sizes, ws in layouts:
    L.append(n)
    i, prev, rep = 0, None, 0
    for sz in sizes:
        g = ws[i:i + sz]
        i += sz
        if g == prev:
            rep += 1
            continue
        if rep:
            L.append('    (previous group %d more times)' % rep)
            rep = 0
        L.append('    ' + ' '.join('%d@%d' % ((w >> 16) & 0xff, (w >> 8) & 0x3f) for w in g))
        prev = g
    if rep:
        L.append('    (previous group %d more times)' % rep)
L.append('```')
L.append('')
open(OUT, 'w').write('\n'.join(L))
print('lists %d, groups %d, records %d' % (len(lrows), len(grows), len(mrows)))
