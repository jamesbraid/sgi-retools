"""The O2 (IP32) PROM's assets, found from the code that draws and plays them. Formats and grades are from the
chips page platforms/ip32/prom-assets.md; each finder anchors on a routine or structure that page names and
refuses an image where the anchor is missing or ambiguous, so both 4.18 and 4.8 take the same path."""
import hashlib
import json
import os

from . import AssetError, png
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
        return self.code[index].pc

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
