#!/usr/bin/env python3
"""Decode a legacy ATI video option ROM image (the Onyx4 sg2.bin, sg3.bin, sg3a.bin).

Usage: scripts/option_rom.py dump IMAGE
       scripts/option_rom.py walk IMAGE
       scripts/option_rom.py diff IMAGE_A IMAGE_B SHIFT

  dump   the PCI expansion ROM header, the PCI data structure, the legacy ATI header
         and the table slots it holds, each slot with the first bytes of its target.
  walk   decode the register-initialisation tables the way the public Linux radeon
         driver walks them (radeon_combios.c): the MMIO tables, the PLL tables, the
         clock table, the connector table and the external transmitter script.
  diff   compare two images after removing a constant displacement of SHIFT bytes
         between them (image B at offset N matches image A at offset N+SHIFT). Runs
         that differ only by a pointer fix-up of exactly SHIFT are not listed.

The slot names and table layouts are those of the public driver. They are a
cross-check, not proof of what the shipped IRIX driver reads. Reads the image only;
needs no other file. Run it on the host: python3 -I scripts/option_rom.py ...
"""
import struct
import sys

# header slot offset -> name, as radeon_combios.c numbers them
SLOTS = {
    0x0c: 'asic_init_1', 0x14: 'bios_support', 0x2a: 'dac_programming', 0x2c: 'max_color_depth',
    0x2e: 'crtc_info', 0x30: 'pll_info', 0x32: 'tv_info', 0x34: 'dfp_info', 0x36: 'hw_config',
    0x38: 'multimedia', 0x3e: 'tv_std_patch', 0x40: 'lcd_info', 0x42: 'mobile_info',
    0x46: 'pll_init', 0x48: 'mem_config', 0x4a: 'save_mask', 0x4c: 'hardcoded_edid',
    0x4e: 'asic_init_2', 0x50: 'connector_info', 0x52: 'dyn_clk_1', 0x54: 'reserved_mem',
    0x58: 'ext_tmds_info', 0x5a: 'mem_clk_info', 0x5c: 'ext_dac_info', 0x5e: 'misc_info',
    0x60: 'crt_info', 0x62: 'integrated_system_info', 0x64: 'component_video_info',
    0x66: 'fan_speed_info', 0x68: 'overdrive_info',
}
BY_NAME = {v: k for k, v in SLOTS.items()}


class Rom:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.d = f.read()
        self.pcir = self.u16(0x18)
        self.hdr = self.u16(0x48)

    def u8(self, o):
        return self.d[o]

    def u16(self, o):
        return struct.unpack_from('<H', self.d, o)[0]

    def u32(self, o):
        return struct.unpack_from('<I', self.d, o)[0]

    def slot(self, name):
        """Absolute target of a header slot, or None when the header is too short."""
        off = BY_NAME[name]
        return self.u16(self.hdr + off) if off < self.u8(self.hdr + 6) else None


def mmio_table(r, o):
    """Entries of an MMIO init table: (cmd, register, values...). Returns (entries, end)."""
    out = []
    while r.u16(o):
        w = r.u16(o)
        cmd, addr = w >> 13, w & 0x1fff
        o += 2
        if cmd in (0, 1):
            out.append((cmd, addr, r.u32(o)))
            o += 4
        elif cmd in (2, 3):
            out.append((cmd, addr, r.u32(o), r.u32(o + 4)))
            o += 8
        elif cmd in (4, 5):
            out.append((cmd, addr, r.u16(o)))
            o += 2
        else:
            out.append((cmd, addr))
    return out, o + 2


def pll_table(r, o):
    """Entries of a PLL init table: (cmd, index, values...). Returns (entries, end)."""
    out = []
    while r.u8(o):
        b = r.u8(o)
        cmd, idx = b >> 6, b & 0x3f
        o += 1
        if cmd == 0:
            out.append((cmd, idx, r.u32(o)))
            o += 4
        elif cmd == 1:
            out.append((cmd, idx, r.u8(o), r.u8(o + 1), r.u8(o + 2)))
            o += 3
        else:
            out.append((cmd, idx))
    return out, o + 1


def show_entries(entries):
    for e in entries:
        print('   ', e[0], hex(e[1]), *[hex(x) for x in e[2:]])


def cmd_dump(r):
    d = r.d
    print('size', len(d), 'sum8', sum(d) & 0xff, 'signature', d[:2].hex(), 'length', d[2] * 512)
    print('init entry: jmp rel16 at 3 ->', hex(6 + r.u16(4)))
    p = r.pcir
    print('PCIR at', hex(p), d[p:p + 4], 'vendor', hex(r.u16(p + 4)), 'device', hex(r.u16(p + 6)),
          'list', hex(r.u16(p + 8)), 'len', hex(r.u16(p + 10)), 'rev', r.u8(p + 12),
          'class', d[p + 13:p + 16].hex(), 'image_len', r.u16(p + 16) * 512,
          'code_rev', hex(r.u16(p + 18)), 'type', r.u8(p + 20), 'indicator', hex(r.u8(p + 21)))
    h = r.hdr
    print('ATI header at', hex(h), 'size', r.u8(h + 6), 'bytes at +4:', d[h + 4:h + 8])
    for off in sorted(SLOTS):
        v = r.slot(SLOTS[off])
        tgt = '(beyond header)' if v is None else hex(v)
        peek = d[v:v + 12].hex(' ') if v and v < len(d) else ''
        print(f'  +{off:#04x} {SLOTS[off]:24s} {tgt:8s} {peek}')


def cmd_walk(r):
    for name in ('asic_init_1', 'asic_init_2'):
        o = r.slot(name)
        ents, end = mmio_table(r, o)
        print(name, hex(o), 'to', hex(end), len(ents), 'entries')
        show_entries(ents)
    m = r.slot('misc_info')
    print('misc_info', hex(m), 'revision', r.u8(m))
    for label, off in (('asic_init_3', 3), ('asic_init_4', 5)):
        o = r.u16(m + off)
        ents, end = mmio_table(r, o)
        print(label, hex(o), 'to', hex(end), len(ents), 'entries')
        show_entries(ents)
    det = r.u16(m + 7)
    print('detected_mem', hex(det), 'rev', r.u8(det), 'mem_cntl', hex(r.u32(det + 1)),
          'size', r.u16(det + 5))
    for name in ('pll_init', 'dyn_clk_1'):
        o = r.slot(name)
        ents, end = pll_table(r, o)
        print(name, hex(o), 'to', hex(end), len(ents), 'entries')
        show_entries(ents)
    o = r.slot('pll_info')
    print('pll_info', hex(o), 'rev', r.u8(o), 'length', r.u8(o + 1),
          'ref_clk', r.u16(o + 0xe), 'ref_div', r.u16(o + 0x10),
          'pll_out', r.u32(o + 0x12), r.u32(o + 0x16),
          'sclk', r.u16(o + 0xa), 'mclk', r.u16(o + 8))
    o = r.slot('mem_config')
    print('mem_config', hex(o), 'rev', r.u8(o - 1), 'first byte', r.u8(o))
    o = r.slot('connector_info')
    ents = []
    for i in range(4):
        w = r.u16(o + 2 + 2 * i)
        if not w:
            break
        ents.append(w)
    print('connector_info', hex(o), [(hex(w), 'type', (w >> 12) & 15, 'ddc', (w >> 8) & 15,
                                      'bit4', (w >> 4) & 1, 'bit0', w & 1) for w in ents])
    o = r.slot('ext_tmds_info')
    if o:
        print('ext_tmds_info', hex(o), 'rev', r.u8(o), 'slave', hex(r.u8(o + 6)), 'ddc', r.u8(o + 7),
              'flags', hex(r.u8(o + 9)))
        i = o + 10
        while r.u16(i) != 0xffff:
            w = r.u16(i)
            print('   id', hex(w), 'class', w >> 13, 'reg', hex(w & 0x1fff), 'value', hex(r.u8(i + 2)))
            i += 3
    else:
        print('ext_tmds_info absent')


def cmd_diff(a, b, shift):
    """b[i] against a[i + shift], skipping bytes that differ by exactly shift (a pointer)."""
    res = []
    for i in range(0x19c, min(len(b.d), len(a.d) - shift)):
        x, y = b.d[i], a.d[i + shift]
        if x == y:
            continue
        delta = (y - x) & 0xff
        if delta == shift:
            continue
        if delta == 1 and i and (a.d[i + shift - 1] - b.d[i - 1]) & 0xff == shift:
            continue
        res.append(i)
    runs = []
    for i in res:
        if runs and i <= runs[-1][1] + 2:
            runs[-1][1] = i
        else:
            runs.append([i, i])
    for s, e in runs:
        print(hex(s), '..', hex(e), b.d[s - 2:e + 3].hex(' '), '|', a.d[s + shift - 2:e + shift + 3].hex(' '))


def main(argv):
    if len(argv) >= 3 and argv[1] == 'dump':
        cmd_dump(Rom(argv[2]))
    elif len(argv) >= 3 and argv[1] == 'walk':
        cmd_walk(Rom(argv[2]))
    elif len(argv) == 5 and argv[1] == 'diff':
        cmd_diff(Rom(argv[2]), Rom(argv[3]), int(argv[4], 0))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
