#!/usr/bin/env python3
"""Decode the display-table files of the VPro install and write the tables of docs/display-files.md.

Usage: display_files.py [--root DIR]    (prints the tables on stdout)

Reads, under root/usr/gfx/ucode/: ODSY/vof/*.vfo (video formats of the VPro board),
STINGRAY/vfo/*.vfo (the compositor's own copies) and STINGRAY/cmb/*.cmb (format
combinations of the compositor). All three are one container, a big-endian symbol
database: version word 4, the tag "sdb ", a description string at +28, the field
count at +128 and the name table's offset at +136, values from +144, and a name table
(count, then per field the name length, the name padded to 4 bytes, a type word, an
array length word and the value's offset). Types: 2 and 7 integers, 10 boolean,
15 string, 16 float32, 17 float64; an array stores its element count first.
Every cell is read from its file; nothing here is a template.
"""
import glob
import os
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path):
    d = open(path, 'rb').read()
    u32 = lambda o: struct.unpack('>I', d[o:o + 4])[0]
    assert u32(0) == 4 and d[4:8] == b'sdb ', path
    count, table = u32(128), u32(136)
    for slack in range(4):
        if u32(table - slack) == count:
            table -= slack
            break
    else:
        raise SystemExit('%s: no name table' % path)
    o, vals = table + 4, {}
    for _ in range(count):
        ln = u32(o)
        name = d[o + 4:o + 4 + ln].decode()
        o += 4 + ((ln + 3) & ~3)
        typ, arr, off = u32(o), u32(o + 4), u32(o + 8)
        o += 12
        n, p = 1, off
        if arr:
            n, p = u32(p), p + 4
        out = []
        for _ in range(n):
            if typ in (2, 7, 10):
                out.append(struct.unpack('>i', d[p:p + 4])[0]); p += 4
            elif typ == 16:
                out.append(struct.unpack('>f', d[p:p + 4])[0]); p += 4
            elif typ == 17:
                out.append(struct.unpack('>d', d[p:p + 8])[0]); p += 8
            elif typ == 15:
                l = u32(p); out.append(d[p + 4:p + 4 + l].decode('latin1')); p += 4 + ((l + 3) & ~3)
            else:
                raise SystemExit('type %d' % typ)
        vals[name] = out if arr else out[0]
    return d, d[28:128].split(b'\0')[0].decode('latin1'), count, table, vals


def g(v, k, default='-'):
    return v.get(k, default)


def num(x, nd=3):
    s = ('%.*f' % (nd, x)).rstrip('0').rstrip('.')
    return s or '0'


def vfo_row(path, d, desc, count, table, v):
    name = 'ODSY/vof/' + os.path.basename(path)
    clk = g(v, 'FormatInfo_PixelClock')
    clk = num(clk / 1e6) if clk != '-' else '-'
    if v.get('FormatInfo_Interlaced'):
        scan = 'interlaced'
    else:
        scan = 'progressive'
    flds = '%d field%s' % (v['FieldsPerFrame'], '' if v['FieldsPerFrame'] == 1 else 's')
    dual = 'two-channel' if v.get('FormatInfo_DualHead') else 'one channel'
    hp = '%s/%s/%s' % (g(v, 'DCDHorizontalFrontPorch'), g(v, 'DCDHorizontalSync'), g(v, 'DCDHorizontalBackPorch'))
    vp = '%s/%s/%s' % (g(v, 'VerticalFrontPorch'), g(v, 'VerticalSync'), g(v, 'VerticalBackPorch'))
    pll = 'divider %s, oscillator %s' % (g(v, 'ODY_PLL_FdBkDiv0'), g(v, 'ODY_PLL_Osc_Div'))
    st = 'stereo' if (v.get('FormatInfo_Stereo') or v.get('FormatInfo_FullScreenStereo')) else 'mono'
    return '| `%s` | established | %sx%s | %sx%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | table at 0x%x | %d fields |' % (
        name, v['ActivePixelsPerLine'], v['ActiveLinesPerFrame'], v['TotalPixelsPerLine'], v['TotalLinesPerFrame'],
        num(v['FramesPerSecond']), clk, hp, vp, scan, st, flds, dual, pll, 'VTG control %d' % v['ODY_VTG_Control']
        if 'ODY_VTG_Control' in v else '-', table, count)


def sting_row(path, d, desc, count, table, v):
    name = 'STINGRAY/vfo/' + os.path.basename(path)
    flds = '%d field%s' % (v['FieldsPerFrame'], '' if v['FieldsPerFrame'] == 1 else 's')
    return '| `%s` | established | %sx%s | %sx%s | %s | %s | %s/%s/%s | %s | %s | %s | %d states | %d line types | %d edges | table at 0x%x | %d fields |' % (
        name, v['ActivePixelsPerLine'], v['ActiveLinesPerFrame'], v['TotalPixelsPerLine'], v['TotalLinesPerFrame'],
        num(v['FramesPerSecond']), num(v['FormatInfo_PixelClock'] / 1e6), v['FormatInfo_H_FrontPorch'],
        v['FormatInfo_H_Sync'], v['FormatInfo_H_BackPorch'], 'interlaced' if v.get('FormatInfo_Interlaced') else 'progressive',
        'stereo' if v.get('FormatInfo_Stereo') else 'mono', flds, v['StateTableValidStates'], v['LineTypeCount'],
        v['TotalEdgeCount'], table, count)


SHEAD = ('| File | Label | Active (x by lines) | Total (x by lines) | Frame rate (Hz) | Pixel clock (MHz) | '
         'H front/sync/back (pixels) | Scan | Mode | Fields | State table | Line types | Edges | Container | File fields |\n|' + '---|' * 15)

VHEAD = ('| File | Label | Active (x by lines) | Total (x by lines) | Frame rate (Hz) | Pixel clock (MHz) | '
         'H front/sync/back (pixels) | V front/sync/back (lines) | Scan | Mode | Fields | Channels | '
         'Clock part | VTG control | Container | File fields |\n|' + '---|' * 16)


def cmb_row(path, d, desc, count, table, v):
    name = 'STINGRAY/cmb/' + os.path.basename(path)
    alt = os.path.join(REPO, 'root', 'usr', 'diags', 'compositor', 'data', os.path.basename(path))
    if os.path.exists(alt) and open(alt, 'rb').read() == d:
        name = 'usr/diags/compositor/data/' + os.path.basename(path)
    n = v['NumPipes']
    sizes = {(v['Pipe%02dRectX2' % i] - v['Pipe%02dRectX1' % i], v['Pipe%02dRectY2' % i] - v['Pipe%02dRectY1' % i])
             for i in range(n)}
    pipes = '%d x %dx%d' % (n, *sizes.pop()) if n and len(sizes) == 1 else '-'
    return '| `%s` | established | %s | %s | %s | %dx%d | %d | %d | %s | %s%s | table at 0x%x | %d fields |' % (
        name, v['OdsyFmtName'], v['CmpFmtName'], v['SyncFmtName'], v['nSize'][0], v['nSize'][1], v['TilingMode'],
        n, pipes, v['SyncSrc'], '/%d' % v['SyncPipe'], table, count)


CHEAD = ('| File | Label | VPro format | Compositor format | Sync format | Size (x by lines) | Tiling mode | Pipes | '
         'Pipe rectangles | Sync source/pipe | Container | File fields |\n|' + '---|' * 12)

if __name__ == '__main__':
    root = os.path.join(REPO, 'root', 'usr', 'gfx', 'ucode')
    print('## vof\n\n' + VHEAD)
    for p in sorted(glob.glob(os.path.join(root, 'ODSY', 'vof', '*.vfo'))):
        print(vfo_row(p, *load(p)))
    print('\n## stingray vfo\n\n' + SHEAD)
    for p in sorted(glob.glob(os.path.join(root, 'STINGRAY', 'vfo', '*.vfo'))):
        print(sting_row(p, *load(p)))
    print('\n## cmb\n\n' + CHEAD)
    for p in sorted(glob.glob(os.path.join(root, 'STINGRAY', 'cmb', '*.cmb'))):
        print(cmb_row(p, *load(p)))
