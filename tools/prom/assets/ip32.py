"""The O2 (IP32) PROM's assets, found from the code that draws and plays them. Formats and grades are from the
chips page platforms/ip32/prom-assets.md; each finder anchors on a routine or structure that page names and
refuses an image where the anchor is missing or ambiguous, so both 4.18 and 4.8 take the same path."""
import hashlib
import json
import os

from . import AssetError, glyphs, png
from .firmware import Firmware
from .mips import Machine, Unknown, routine_at, routines

PALETTE_SLOT = 8            # device table slot 2: set one palette entry (device, index, r, g, b)
RAMP_STEPS = (0x8199, 0xb800, 0xb333)
MIN_RAMP = 32


def dumps(doc):
    return json.dumps(doc, indent=1, sort_keys=False) + '\n'


class Reader:
    """One image's firmware, its decoded text and routine boundaries, and the files the finders write."""

    def __init__(self, segment):
        self.fw = Firmware(segment)
        self.code, self.base = self.fw.code()
        self.starts = routines(self.code)
        self.files = []             # {'kind', 'name', 'address', 'file', 'grade', ...}

    def span(self, index):
        lo, hi = routine_at(self.starts, index)
        return lo, hi if hi is not None else len(self.code)

    def routine_of(self, word_match):
        """The routines holding an instruction for which word_match(ins) is true, as {first index: end index}."""
        return {self.span(i)[0]: self.span(i)[1] for i, c in enumerate(self.code) if word_match(c)}

    def immediates(self, lo, hi):
        return {c.imm for c in self.code[lo:hi] if c.op in (9, 0xa, 0xd)} | {c.uimm for c in self.code[lo:hi] if c.op in (0xd, 0xf)}

    def addr(self, index):
        return self.base + 4 * index

    def machine(self):
        return Machine(self.code, self.base)

    def only(self, what, found):
        if len(found) != 1:
            raise AssetError('%s: %d candidate routines, expected one' % (what, len(found)))
        return next(iter(found.items()))

    def add(self, out, kind, name, rel, data, address, grade, **extra):
        """Write one output file under out and record it for the manifest."""
        path = os.path.join(out, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        with open(path, 'wb') as f:
            f.write(data)
        entry = {'kind': kind, 'name': name, 'address': self.fw.place(address), 'file': rel, 'grade': grade,
                 'sha256': hashlib.sha256(data).hexdigest()}
        entry.update(extra)
        self.files.append(entry)


def find_palette(r):
    """Run the routine that carries the ramp's three increments; return its set-entry calls and the ramp."""
    hits = [r.routine_of(lambda c, v=v: c.word == 0x34010000 | v) for v in RAMP_STEPS]
    (lo, hi), = [r.only('palette routine', {k: hi for k, hi in hits[0].items() if all(k in h for h in hits)})]
    m = r.machine()
    try:
        m.run(r.addr(lo))
    except Unknown as e:
        raise AssetError('palette routine at %#x: %s' % (r.addr(lo), e))
    calls = [c for c in m.calls if c.slot == PALETTE_SLOT and None not in c.args[1:4] and c.stack0 is not None]
    if len(calls) < 100:
        raise AssetError('palette routine at %#x makes only %d set-entry calls' % (r.addr(lo), len(calls)))
    return r.addr(lo), calls


def ramp_of(calls):
    """The longest run of consecutive indexes written one after another, with each channel's 32-bit running sum
    recovered from the register that holds it (the argument is that register shifted right by 16)."""
    best = (0, 0)
    for i in range(len(calls)):
        j = i
        while j + 1 < len(calls) and calls[j + 1].args[1] == calls[j].args[1] + 1:
            j += 1
        best = max(best, (j - i + 1, i))
    n, i = best
    if n < MIN_RAMP:
        raise AssetError('no ramp of %d or more consecutive palette entries' % MIN_RAMP)
    run = calls[i:i + n]
    channels = []
    for ch in range(3):
        want = [c.args[2] if ch == 0 else c.args[3] if ch == 1 else c.stack0 for c in run]
        for reg in range(1, 32):
            vals = [c.regs[reg] for c in run]
            if None in vals or any(((v - (1 << 32) if v >> 31 else v) >> 16) & 0xffffffff != w for v, w in zip(vals, want)):
                continue
            steps = {(b - a) & 0xffffffff for a, b in zip(vals, vals[1:])}
            if len(steps) == 1:
                channels.append({'start': vals[0], 'step': steps.pop()})
                break
        else:
            raise AssetError('ramp channel %d is not a running sum in any register' % ch)
    return run[0].args[1], n, channels


def palette(r, out):
    addr, calls = find_palette(r)
    first, count, channels = ramp_of(calls)
    entries = {}
    for c in calls:
        index = c.args[1]
        if index in entries:
            raise AssetError('palette index %#x is written twice' % index)
        tagged = any(c.tags)
        entries[index] = {'index': index, 'rgb': [c.args[2], c.args[3], c.stack0]}
        if tagged:
            entries[index]['source'] = 'pagecolor variable when it parses, else this default'
    if any(not 0 <= v < 256 for e in entries.values() for v in e['rgb']) or max(entries) > 255:
        raise AssetError('palette entry out of range')
    doc = {'format': 'promkit-palette', 'version': 1, 'routine': '0x%x' % addr,
           'entries': [entries[i] for i in sorted(entries)],
           'ramp': {'first_index': first, 'count': count, 'shift': 16,
                    'channels': [dict(zip(('channel', 'start', 'step'), (n, '0x%08x' % c['start'], '0x%x' % c['step'])))
                                 for n, c in zip('rgb', channels)],
                    'rule': 'value = (start + step * i) >> 16, each channel a running 32-bit sum, i from 0'},
           'unwritten': [i for i in range(256) if i not in entries]}
    r.add(out, 'palette', 'palette', 'assets/palette.json', dumps(doc), addr, 'established')
    px = bytearray()
    for y in range(256):
        for x in range(256):
            e = entries.get((y // 16) * 16 + x // 16)
            px += bytes(e['rgb']) + b'\xff' if e else b'\0\0\0\0'
    r.add(out, 'palette', 'palette swatch', 'assets/palette.png', png.png(256, 256, bytes(px), png.RGBA), addr,
          'established', details={'cells': '16 by 16, index = row * 16 + column, 16 pixels each; unwritten entries transparent'})


def gradient(r, out):
    """The scanline fill: step = 0xa00000 / (height - 1), index = (0x600000 + y * step) >> 16."""
    def has(lo, hi, test):
        return any(test(c) for c in r.code[lo:hi])
    found = {}
    for i, c in enumerate(r.code):
        if c.op == 0xf and c.uimm == 0xa0:
            lo, hi = r.span(i)
            if (has(lo, hi, lambda c: c.op == 0xf and c.uimm == 0x60) and has(lo, hi, lambda c: c.op == 0 and c.fn == 0x1a) and
                    has(lo, hi, lambda c: c.op == 0 and c.fn == 3 and c.sh == 16)):
                found[lo] = hi
    lo, hi = r.only('gradient routine', found)
    doc = {'format': 'promkit-gradient', 'version': 1, 'routine': '0x%x' % r.addr(lo),
           'numerator': '0xa00000', 'base': '0x600000', 'shift': 16, 'first_index': 0x60,
           'rule': 'step = numerator / (height - 1), integer division; row y from the bottom, 0 to height - 1, '
                   'is drawn in palette index (base + y * step) >> shift'}
    r.add(out, 'layout', 'background gradient', 'assets/gradient.json', dumps(doc), r.addr(lo), 'established')


MENU_IMMEDIATES = {1051, 65, 150, 50, 60, 15, 75, 25, 3, 2}      # the graphical menu draw
LOGO_IMMEDIATES = {1051, 601, 150, 200, 530, 520, 65, 445, 80, 66, 48, 49, 50}      # the background and logo draw


def find_with(r, what, needed):
    """The one routine that uses the slti-1051 width test and every immediate in needed (negatives count by size)."""
    found = {}
    for i, c in enumerate(r.code):
        if c.op == 0xa and c.imm == 1051:
            lo, hi = r.span(i)
            have = {abs(v) for v in r.immediates(lo, hi)}
            if needed <= have:
                found[lo] = hi
    lo, _ = r.only(what, found)
    return r.addr(lo)


def layout(r, out):
    """The menu and logo placement. The values are the chips page's; each is accepted only when the routine that
    draws it carries the constants it is built from."""
    menu = find_with(r, 'menu draw routine', MENU_IMMEDIATES)
    logo = find_with(r, 'background draw routine', LOGO_IMMEDIATES)
    doc = {'format': 'promkit-layout', 'version': 1, 'origin': 'bottom left, y up', 'wide_width_threshold': 1051,
           'menu': {'routine': '0x%x' % menu, 'button_size': 50, 'pitch': 75, 'stack_trim': 25,
                    'left_wide': 150, 'left_narrow': 65, 'label_dx': 60, 'label_dy': 15, 'label_font': 2,
                    'height_fraction_with_logo': [2, 3],
                    'rule': 'V = H when the big logo is off, else H * 2 / 3 (integer division); stack = pitch * n - '
                            'stack_trim; button 0 bottom = H - ((V - stack) >> 1) - button_size, each next one pitch lower; '
                            'left is left_wide when W >= wide_width_threshold, else left_narrow; label pen = '
                            '(left + label_dx, bottom + label_dy)'},
           'background': {'routine': '0x%x' % logo, 'logo_ink_index': 0x31, 'logo_shadow_index': 0x32, 'tagline_index': 0x30,
                          'wide': {'left': 150, 'logo_x': 530}, 'narrow': {'left': 65, 'logo_x': 445},
                          'heading_y': 200, 'heading_shadow_offset': [5, -6], 'logo_y': 80, 'logo_shadow_offset': [10, -14],
                          'tagline_dx': 520, 'tagline_y': 50, 'second_branch_logo_width': 601, 'second_branch_grade': 'unknown',
                          'rule': 'heading pen = (left, heading_y); logo bottom-left = (logo_x, logo_y); tagline pen = '
                                  '(left + tagline_dx, tagline_y); each shadow is drawn first at its offset from the ink'}}
    r.add(out, 'layout', 'menu and logo layout', 'assets/layout.json', dumps(doc), menu, 'established')


FONT_HEIGHTS, FONT_DESCENTS = (17, 20, 23, 14), (4, 4, 5, 3)
FONT_ROLES = ('console text, fixed advance', 'box and keycap pieces (inferred)', 'serif bold 23 pixel: menu labels and titles',
              'sans 14 pixel: button captions')
LOOKUP_IMMEDIATES = {7, 32, 66, 128}


def find_font_records(r):
    """The routine that stores four {bitmap base, entry table, height, descent} records, found by the heights and
    descents it writes. Returns (routine address, [(bitmap, table, height, descent)] for fonts 0 to 3)."""
    need = set(FONT_HEIGHTS)
    cands = {}
    for i, c in enumerate(r.code):
        if c.op == 9 and c.rs == 0 and c.imm == FONT_HEIGHTS[0]:
            lo, hi = r.span(i)
            if need <= {x.imm for x in r.code[lo:hi] if x.op == 9 and x.rs == 0}:
                cands[lo] = hi
    found = {}
    for lo in cands:
        m = r.machine()
        try:
            m.run(r.addr(lo))
        except Unknown:
            continue
        w = {x.addr: x.value for x in m.writes}
        for a in sorted({x.addr - 8 for x in m.writes if x.size == 2 and x.value == FONT_HEIGHTS[0]}):
            recs = [(w.get(a + 12 * k), w.get(a + 12 * k + 4), w.get(a + 12 * k + 8), w.get(a + 12 * k + 10)) for k in range(4)]
            if all(None not in rec for rec in recs) and [x[2] for x in recs] == list(FONT_HEIGHTS) and \
                    [x[3] for x in recs] == list(FONT_DESCENTS):
                found[lo] = recs
    lo, recs = r.only('font table routine', found)
    return r.addr(lo), recs


def entry_count(r, k, recs):
    """Fonts 0 to 2: the next font's bitmap follows the table. The last: the entries are taken until they have
    used the bitmap region (to within its two-byte pad)."""
    bitmap, table = recs[k][:2]
    if k < 3:
        n, rem = divmod(recs[k + 1][0] - table, 8)
        if rem or n < 1:
            raise AssetError('font %d: the next bitmap does not follow its entry table by whole entries' % k)
        return n
    used, n = 0, 0
    while used < table - bitmap - 2:
        e = glyphs.parse_entries(r.fw.read(table + 8 * n, 8), 1)[0]
        if e.off * 2 != used or n > 255:
            raise AssetError('font %d: entry %d does not continue the bitmap region' % (k, n))
        used = glyphs.entry_span(e)[1]
        n += 1
    return n


def find_lookup(r):
    """The character-to-entry routine, by the constants of its rule."""
    found = {}
    for i, c in enumerate(r.code):
        if c.op == 0xa and c.imm == 7:
            lo, hi = r.span(i)
            ims = {x.imm for x in r.code[lo:hi] if x.op in (9, 0xa, 0xc)}
            if LOOKUP_IMMEDIATES <= ims:
                found[lo] = hi
    lo, _ = r.only('character lookup routine', found)
    return r.addr(lo)


def glyph_of(r, bitmap, size, e):
    """The entry's rows (bottom first), or None when it has none or claims rows past its bitmap region."""
    lo, hi = glyphs.entry_span(e)
    if e.width == 0 or e.height == 0 or lo < 0 or hi > size:
        return None
    return glyphs.unpack_rows(r.fw.read(bitmap + lo, hi - lo), e.width, e.height)


def bdf_glyph(code, e, rows):
    return {'encoding': code, 'name': 'code%02X' % code, 'width': e.width, 'height': e.height, 'xoffset': e.xoffset,
            'yoffset': e.yoffset, 'advance': e.advance, 'rows': rows}


def fonts(r, out):
    routine, recs = find_font_records(r)
    lookup = find_lookup(r)
    for k, (bitmap, table, height, descent) in enumerate(recs):
        n = entry_count(r, k, recs)
        size = table - bitmap
        entries = glyphs.parse_entries(r.fw.read(table, 8 * n), n)
        rows = [glyph_of(r, bitmap, size, e) for e in entries]
        advances = {e.advance for e in entries}
        doc = {'format': 'promkit-font', 'version': 1, 'font': k, 'role': FONT_ROLES[k], 'height': height, 'descent': descent,
               'ascent': height - descent, 'fixed_advance': advances.pop() if len(advances) == 1 else None,
               'bitmap_address': '0x%x' % bitmap, 'bitmap_size': size, 'table_address': '0x%x' % table, 'entry_count': n,
               'entry_fields': 'off is in halfwords from the bitmap base; the glyph is height rows of ceil(width / 16) '
                               'halfwords, bottom row first, leftmost pixel most significant; left = pen x + xoffset, '
                               'bottom = pen y + yoffset; the pen then moves by advance',
               'lookup': {'routine': '0x%x' % lookup, 'rule': 'code < 7: entry code of font 1, whatever font was asked for; '
                          'else index = code - 0x20 for code < 0x80 and code - 0x42 for code >= 0x80; no glyph when the '
                          'index is negative or not below entry_count',
                          'small_code_limit': 7, 'subtract_low': 0x20, 'subtract_high': 0x42, 'high_bit': 0x80,
                          'aliases': 'codes 0x80..0x9f reuse the entries of 0x5e..0x7d and 0xa0 that of ~ (inferred: unintended)'},
               'entries': [dict(index=i, off=e.off, width=e.width, height=e.height, xoffset=e.xoffset, yoffset=e.yoffset,
                                advance=e.advance, **({} if rows[i] else {'drawable': False}))
                           for i, e in enumerate(entries)]}
        grade = 'inferred' if k == 1 else 'established'      # the page rates font 1's role inferred
        r.add(out, 'font', 'font %d' % k, 'assets/font-%d.json' % k, dumps(doc), bitmap, grade)
        if k == 1:
            chars = [bdf_glyph(c, entries[c], rows[c]) for c in range(min(7, n)) if rows[c]]
        else:
            chars = []
            for c in range(7, 256):
                i = c - 0x20 if c < 0x80 else c - 0x42
                if 0 <= i < n and rows[i]:
                    chars.append(bdf_glyph(c, entries[i], rows[i]))
        r.add(out, 'font', 'font %d bitmap' % k, 'assets/font-%d.bdf' % k, glyphs.bdf('promfont%d' % k, height, descent, chars),
              bitmap, grade, format='bdf')


def find_tagline(r):
    """The routine that draws the tagline: it ends a byte list on 0xff, loads each entry's word halves unaligned
    and indexes 8-byte entries. Its three table pointers in the data chunk, in address order, are the bitmap pool,
    the entries and the index list."""
    found = {}
    for i, c in enumerate(r.code):
        if c.op == 9 and c.rs == 0 and c.imm == 255:
            lo, hi = r.span(i)
            if {x.op for x in r.code[lo:hi]} >= {0x22, 0x26} and any(x.word and x.op == 0 and x.fn == 0 and x.sh == 3 for x in r.code[lo:hi]):
                m = r.machine()
                m.sweep(r.addr(lo), r.addr(hi))
                data = {v for v in m.seen if r.fw.in_data(v)}
                ptrs = sorted(v for v in data if v - 1 not in data)      # a list pointer stepped by one is not a table
                if len(ptrs) == 3:
                    found[lo] = ptrs
    lo, ptrs = r.only('tagline routine', found)
    return r.addr(lo), ptrs


def tagline(r, out):
    routine, (pool, table, index) = find_tagline(r)
    n, rem = divmod(index - table, 8)
    if rem or n < 1:
        raise AssetError('tagline: the index list does not follow the entries by whole entries')
    entries = glyphs.parse_entries(r.fw.read(table, 8 * n), n)
    size = table - pool
    if max(glyphs.entry_span(e)[1] for e in entries) != size:
        raise AssetError('tagline: the glyphs do not consume the %d-byte pool exactly' % size)
    lst, p = [], index
    while r.fw.read(p, 1)[0] != 0xff:
        lst.append(r.fw.read(p, 1)[0])
        p += 1
    if not lst or max(lst) >= n:
        raise AssetError('tagline: the index list names an entry the table does not have')
    rows = [glyph_of(r, pool, size, e) for e in entries]
    doc = {'format': 'promkit-tagline', 'version': 1, 'routine': '0x%x' % routine, 'pool_address': '0x%x' % pool,
           'pool_size': size, 'table_address': '0x%x' % table, 'entry_count': n, 'index_address': '0x%x' % index,
           'index': lst, 'index_rule': 'one entry per character, spaces included; the list ends at a 0xff byte (not listed)',
           'entries': [dict(index=i, off=e.off, width=e.width, height=e.height, xoffset=e.xoffset, yoffset=e.yoffset,
                            advance=e.advance, **({} if rows[i] else {'drawable': False})) for i, e in enumerate(entries)]}
    r.add(out, 'font', 'tagline glyphs', 'assets/tagline.json', dumps(doc), pool, 'established')
    chars = [bdf_glyph(i, e, rows[i]) for i, e in enumerate(entries) if rows[i]]
    top = max(c['yoffset'] + c['height'] for c in chars)
    low = max(0, -min(c['yoffset'] for c in chars))
    r.add(out, 'font', 'tagline glyph bitmap', 'assets/tagline.bdf', glyphs.bdf('promtagline', top + low, low, chars), pool,
          'established', format='bdf')
