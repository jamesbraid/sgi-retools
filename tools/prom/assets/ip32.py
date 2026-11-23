"""The O2 (IP32) PROM's assets, found from the code that draws and plays them. Formats and grades are from the
chips page platforms/ip32/prom-assets.md; each finder anchors on a routine or structure that page names and
refuses an image where the anchor is missing or ambiguous, so both 4.18 and 4.8 take the same path."""
import hashlib
import json
import os
import struct

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


def palette_entries(r):
    """{index: {'index', 'rgb', maybe 'source'}} of the palette routine, and the routine's address and ramp."""
    if hasattr(r, 'palette_cache'):
        return r.palette_cache
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
    r.palette_cache = entries, addr, first, count, channels
    return r.palette_cache


def palette(r, out):
    entries, addr, first, count, channels = palette_entries(r)
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


ICON_USES = {'menu': 6, 'install': 4}
MAX_ICON, MAX_LAYERS = 128, 32


def icon_at(r, addr):
    """The five-word icon object at addr, with its layer records, or None when the words are not one."""
    fw = r.fw
    if not fw.in_data(addr, 20):
        return None
    w, h, xo, yo, lst = struct.unpack('>IIiiI', fw.read(addr, 20))
    if not (1 <= w <= MAX_ICON and 1 <= h <= MAX_ICON and abs(xo) <= 16 and abs(yo) <= 16):
        return None
    layers = []
    while len(layers) <= MAX_LAYERS:
        if not fw.in_data(lst + 24 * len(layers), 24):
            return None
        colour, x, y, lw, lh, bmp = struct.unpack('>6I', fw.read(lst + 24 * len(layers), 24))
        if bmp == 0:
            break
        size = glyphs.stride(lw) * 2 * lh
        if not (colour < 256 and 1 <= lw and 1 <= lh and x + lw <= w and y + lh <= h and fw.in_data(bmp, size)):
            return None
        layers.append({'colour': colour, 'x': x, 'y': y, 'width': lw, 'height': lh, 'bitmap': bmp})
    else:
        return None
    return {'address': addr, 'width': w, 'height': h, 'xoffset': xo, 'yoffset': yo, 'list': lst, 'layers': layers} if layers else None


def find_icons(r):
    """Every five-word icon object in the initialised data, as {address: icon}."""
    lo, hi = r.fw.region('data')
    found = {a: i for a in range(lo, hi - 20, 4) if (i := icon_at(r, a))}
    return found


def icon_uses(r, icons):
    """(menu icons in record order, install-dialog icons in table order): the menu builder stores each icon's address
    in a record, and the install dialog's table holds the others as data words."""
    m = r.machine()
    m.sweep(r.base, r.base + 4 * len(r.code))
    stores = sorted((w.addr, w.value) for w in m.writes if w.size == 4 and w.value in icons)
    lo, hi = r.fw.region('data')
    data = r.fw.read(lo, hi - lo)
    table = [struct.unpack_from('>I', data, o)[0] for o in range(0, len(data) - 3, 4)]
    dialog = [(lo + 4 * i, v) for i, v in enumerate(table) if v in icons]
    return [v for _, v in stores], [v for _, v in dialog]


def icons(r, out):
    found = find_icons(r)
    menu, dialog = icon_uses(r, found)
    if len(menu) != ICON_USES['menu'] or len(dialog) != ICON_USES['install'] or len(set(menu + dialog)) != len(found):
        raise AssetError('icons: %d objects, %d menu uses, %d dialog uses' % (len(found), len(menu), len(dialog)))
    rgb = {i: e['rgb'] for i, e in palette_entries(r)[0].items()}
    listing = []
    for use, addrs in (('menu', menu), ('install', dialog)):
        for n, a in enumerate(addrs):
            ic, name = found[a], '%s-%d' % (use, n)
            canvas = [[(0, 0, 0, 0)] * ic['width'] for _ in range(ic['height'])]
            layer_files = []
            for k, ly in enumerate(ic['layers']):
                rows = glyphs.unpack_rows(r.fw.read(ly['bitmap'], glyphs.stride(ly['width']) * 2 * ly['height']), ly['width'], ly['height'])
                if ly['colour'] not in rgb:
                    raise AssetError('icon %s: layer colour %d is not a written palette entry' % (name, ly['colour']))
                for yy, row in enumerate(rows):             # rows are bottom first, y measured up from the icon's bottom edge
                    for xx, v in enumerate(row):
                        if v:
                            canvas[ic['height'] - 1 - ly['y'] - yy][ly['x'] + xx] = tuple(rgb[ly['colour']]) + (255,)
                rel = 'assets/icons/%s-layer-%d.png' % (name, k)
                r.add(out, 'icon', '%s layer %d' % (name, k), rel, png.mask_png(rows[::-1]), ly['bitmap'], 'established',
                      details={'colour_index': ly['colour'], 'x': ly['x'], 'y': ly['y']})
                layer_files.append(rel)
            px = b''.join(bytes(p) for row in canvas for p in row)
            rel = 'assets/icons/%s.png' % name
            r.add(out, 'icon', name, rel, png.png(ic['width'], ic['height'], px, png.RGBA), a, 'established')
            listing.append({'name': name, 'role': name, 'object_address': '0x%x' % a,
                            'width': ic['width'], 'height': ic['height'], 'xoffset': ic['xoffset'], 'yoffset': ic['yoffset'],
                            'composite': rel,
                            'layers': [{'file': f, 'colour_index': ly['colour'], 'x': ly['x'], 'y': ly['y'], 'width': ly['width'],
                                        'height': ly['height'], 'bitmap_address': '0x%x' % ly['bitmap']}
                                       for f, ly in zip(layer_files, ic['layers'])]})
    doc = {'format': 'promkit-icons', 'version': 1,
           'object': 'five words: width, height, xoffset, yoffset, layer list; layer record: colour index, x, y, width, '
                     'height, bitmap, the list ending at a record whose bitmap is 0',
           'layer_rule': 'each layer is a 1-bit stipple in the glyph bitmap format, x from the left and y up from the '
                         "icon's bottom edge, painted in list order in its palette colour",
           'centring': 'x = left + ((right - left - width + 1) >> 1), y = bottom + ((top - bottom - height + 1) >> 1) '
                       "inside a button box with inclusive corners (signed shift), then the icon's own offsets apply",
           'icons': listing}
    r.add(out, 'icon', 'icon list', 'assets/icons/icons.json', dumps(doc), min(found), 'established')


LOGO_SIZE = (494, 237)
LOGO_LEAD = 12              # leading zero bytes the data starts with (six zero-length gap and run pairs)


def logo(r, out):
    """The run-length logo: anchored on the width and height words that follow it, then walked back to the start."""
    w, h = LOGO_SIZE
    lo, hi = r.fw.region('data')
    data = r.fw.read(lo, hi - lo)
    anchors = [i for i in range(0, len(data) - 7, 4) if data[i:i + 8] == struct.pack('>II', w, h)]
    if len(anchors) != 1:
        raise AssetError('logo: %d places hold the width and height words, expected one' % len(anchors))
    a = anchors[0]
    valid = []
    for s in range(a - 1, max(-1, a - 4096), -1):
        try:
            _, used = glyphs.decode_rle(data[s:a], w, h)
        except ValueError:
            continue
        if used >= a - s - 3:           # the rows end within the word-alignment padding before the anchor
            valid.append(s)
    # row 0 begins with zero-length gap and run pairs, so the start is a zero byte. Zero bytes that merely decode
    # ahead of other bytes are not the image: take the zero run nearest the image, and no more than LOGO_LEAD of it.
    def first_ink(s):
        return s + len(data[s:a]) - len(data[s:a].lstrip(b'\0'))
    zero_starts = [s for s in valid if data[s] == 0]
    if not zero_starts:
        raise AssetError('logo: no run-length data of %d rows ends at the anchor' % h)
    p = max(first_ink(s) for s in zero_starts)
    start = max(min(s for s in zero_starts if first_ink(s) == p), p - LOGO_LEAD)
    rows, used = glyphs.decode_rle(data[start:a], w, h)
    addr = lo + start
    r.add(out, 'logo', 'logo', 'assets/logo.png', png.mask_png([list(row) for row in rows[::-1]]), addr, 'inferred',
          format='png mask', details={'width': w, 'height': h, 'encoded_length': used, 'anchor': '0x%x' % (lo + a)})
