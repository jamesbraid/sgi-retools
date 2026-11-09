"""Dump a KONA display-table file (.vfo video format, .cmb combination).

Usage: sdb_dump.py FILE [FILE...]        print every field with its value
       sdb_dump.py --check FILE...      also check a .vfo against its own totals

Both file kinds share one container (ucode/dg.md, "The container"):

  0      u32  version (4)
  4      "sdb "
  8      u32  0, u32 1, u32 1 (vfo) or 0 (cmb), u32 string capacity (100 at +24)
  28     description string, zero padded to 128
  128    u32 field count, u32 0, u32 table offset, u32 0
  144    field values, back to back
  table  u32 count, then per field: u32 name length, name padded to 4 bytes,
         u32 type, u32 array length (0 = scalar), u32 value offset

Types: 2 and 7 int32, 10 boolean int32, 15 string (u32 length + bytes padded
to 4), 16 float32, 17 float64. A value with a nonzero array length starts
with a u32 element count, then the elements. Everything is big-endian.

Run from the repository root; the files are under ucode/KONA/dg4/.
"""
import struct
import sys


def parse(path):
    d = open(path, 'rb').read()

    def u32(o):
        return struct.unpack('>I', d[o:o + 4])[0]

    if u32(0) != 4 or d[4:8] != b'sdb ':
        raise SystemExit('%s: not an sdb container' % path)
    count, _, table, _ = [u32(128 + 4 * i) for i in range(4)]
    n = u32(table)
    assert n == count, (path, n, count)
    o = table + 4
    fields = []
    for _ in range(n):
        ln = u32(o)
        name = d[o + 4:o + 4 + ln].decode()
        o += 4 + ((ln + 3) & ~3)
        fields.append((name, u32(o), u32(o + 4), u32(o + 8)))
        o += 12
    assert o == len(d), (path, o, len(d))
    desc = d[28:128].split(b'\0')[0].decode()
    return d, desc, fields


def values(d, typ, arr, off):
    def u32(o):
        return struct.unpack('>I', d[o:o + 4])[0]

    n, o = 1, off
    if arr:
        n, o = u32(o), o + 4
    out = []
    for _ in range(n):
        if typ in (2, 7, 10):
            out.append(struct.unpack('>i', d[o:o + 4])[0])
            o += 4
        elif typ == 16:
            out.append(round(struct.unpack('>f', d[o:o + 4])[0], 7))
            o += 4
        elif typ == 17:
            out.append(struct.unpack('>d', d[o:o + 8])[0])
            o += 8
        elif typ == 15:
            ln = u32(o)
            out.append(d[o + 4:o + 4 + ln].decode('latin1'))
            o += 4 + ((ln + 3) & ~3)
        else:
            raise SystemExit('unknown type %d' % typ)
    return out, o


def load(path):
    d, desc, fields = parse(path)
    vals, pos = {}, 144
    for name, typ, arr, off in sorted(fields, key=lambda f: f[3]):
        assert off == pos, (path, name, off, pos)  # values are contiguous
        vals[name], pos = values(d, typ, arr, off)
    return desc, fields, vals


def check(path, v):
    """Relations that hold in every shipped .vfo (ucode/dg.md)."""
    if 'StateTableRepetitions' not in v:
        return []
    bad = []
    nv = v['StateTableValidStates'][0]
    if sum(v['StateTableRepetitions'][:nv]) != v['TotalLinesPerFrame'][0]:
        bad.append('repetitions do not sum to TotalLinesPerFrame')
    ratio = v['VideoClockRatio'][0]
    for ln, ok in zip(v['LineTypeLength'], v['LineTypeValid']):
        if ok and abs(ln - v['TotalPixelsPerLine'][0] * ratio) > 1:
            bad.append('line length is not pixels per line * clock ratio')
            break
    px = v['TotalPixelsPerLine'][0] * v['TotalLinesPerFrame'][0] * v['FramesPerSecond'][0]
    if abs(v['FormatInfo_PixelClock'][0] - px) > 0.002 * px:
        bad.append('pixel clock is not pixels * lines * rate')
    return bad


def main(argv):
    do_check = argv and argv[0] == '--check'
    files = argv[1:] if do_check else argv
    rc = 0
    for path in files:
        desc, fields, vals = load(path)
        print('# %s: %s, %d fields' % (path, desc, len(fields)))
        for name, typ, arr, off in sorted(fields, key=lambda f: f[3]):
            v = vals[name]
            print('%d\t%s\ttype %d\tarray %d\t%s' % (off, name, typ, arr, v if len(v) != 1 or arr else v[0]))
        if do_check:
            for msg in check(path, vals):
                print('CHECK FAILED %s: %s' % (path, msg))
                rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
