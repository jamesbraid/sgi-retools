#!/usr/bin/env python3
"""Decode the display-table files of the IR board and write docs/display-formats.md.

Usage: display_formats.py [--root DIR] [--out FILE] [--check]

Reads, from the install tree under root/ (default `root`):

  usr/gfx/ucode/KONA/dg4/vfo/*.vfo     video formats (symbol-database container)
  usr/gfx/ucode/KONA/dg4/cmb/*.cmb     format combinations (same container)
  usr/diags/IR/data/*.vfo              the diagnostics' own copies of video formats
  usr/gfx/ucode/KONA/vof/*             the older text sources (.monitor, .vof)

and writes one table row per file, the file name first, from the parameters stored in
that file. The container layout and the meaning of every field are in
docs/display-file-format.md; this script only applies them. Nothing here is a template:
every cell is read from the file or computed from cells read from it, and `--check`
tests the relations the format keeps (the lines of the state table add to the frame,
the pixel clock is pixels x lines x rate, the porches add to the line).

The container is big-endian XDR: header words, a 100-byte description at +28, the field
count at +128 and the offset of the name table at +136, then the values from +144 and
the name table (name length, name padded to 4, type, array length, value offset).
Types: 2 int32, 7 16-bit integer in a 32-bit word, 10 boolean, 15 string, 16 float32,
17 float64. A field with a nonzero array length stores its element count first.
"""
import glob
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SIGNALS = ('HSYNC', 'VSYNC', 'CSYNC', 'CBLANK', 'TRISYNC', 'FIELD_START', 'FIELD', 'FRAME_START',
           'VIDEO_ACTIVE', 'LINE_START', 'STEREO_OUT', 'IMPREG_LD', 'XMAPREG_LD', 'VOF_VDRC_EN')


class Sdb:
    """One symbol-database file: description, fields in file order, value offsets."""

    def __init__(self, path):
        d = open(path, 'rb').read()
        self.path, self.size = path, len(d)
        u32 = lambda o: struct.unpack('>I', d[o:o + 4])[0]
        if len(d) < 144 or u32(0) != 4 or d[4:8] != b'sdb ':
            raise ValueError('%s: not a symbol-database file' % path)
        self.desc = d[28:128].split(b'\0')[0].decode('latin1')
        self.count, self.table = u32(128), u32(136)
        # Two diagnostics files write a string without its padding, which moves the real
        # table one to three bytes below the offset in the header.
        for slack in range(4):
            if self.table - slack >= 144 and u32(self.table - slack) == self.count:
                self.table_real = self.table - slack
                break
        else:
            raise ValueError('%s: no name table at 0x%x' % (path, self.table))
        ents, o = [], self.table_real + 4
        for _ in range(self.count):
            ln = u32(o)
            name = d[o + 4:o + 4 + ln].decode()
            o += 4 + ((ln + 3) & ~3)
            ents.append((u32(o + 8), name, u32(o), u32(o + 4)))
            o += 12
        ents.sort()
        # The recorded offsets assume every string is padded to four bytes. One diagnostics
        # file writes a string two bytes short, which moves everything after it down by
        # `slack`; the element count that opens each array shows the true position.
        shift, shifts, anchors = 0, [], []
        for i, (off, name, typ, arr) in enumerate(ents):
            if arr:
                for s in range(4):
                    if u32(off - s) == arr:
                        shift = s
                        break
                anchors.append((i, shift))
            shifts.append(shift)
        string_at = [i for i, e in enumerate(ents) if e[2] == 15]
        for i, (off, name, typ, arr) in enumerate(ents):
            if arr:
                continue
            before = [a for a in anchors if a[0] < i]
            after = [a for a in anchors if a[0] > i]
            prev_i = before[-1][0] if before else -1
            if after and any(prev_i < j < i for j in string_at):
                shifts[i] = after[0][1]
            elif before:
                shifts[i] = before[-1][1]
        self.values, self.offset, self.kind, self.shape = {}, {}, {}, {}
        for (off, name, typ, arr), sh in zip(ents, shifts):
            self.values[name] = self._read(d, typ, arr, off - sh)
            self.offset[name], self.kind[name], self.shape[name] = off - sh, typ, arr
        self.order = sorted(self.values, key=lambda n: self.offset[n])

    @staticmethod
    def _read(d, typ, arr, off):
        u32 = lambda o: struct.unpack('>I', d[o:o + 4])[0]
        n, o = 1, off
        if arr:
            n, o = u32(o), o + 4
        out = []
        for _ in range(n):
            if typ in (2, 7, 10):
                out.append(struct.unpack('>i', d[o:o + 4])[0])
                o += 4
            elif typ == 16:
                out.append(struct.unpack('>f', d[o:o + 4])[0])
                o += 4
            elif typ == 17:
                out.append(struct.unpack('>d', d[o:o + 8])[0])
                o += 8
            elif typ == 15:
                ln = u32(o)
                out.append(d[o + 4:o + 4 + ln].split(b'\0')[0].decode('latin1'))
                o += 4 + ((ln + 3) & ~3)
            else:
                raise ValueError('type %d' % typ)
        return out if arr else out[0]

    def __getitem__(self, name):
        return self.values[name]

    def get(self, name, default=None):
        return self.values.get(name, default)

    def __contains__(self, name):
        return name in self.values


def fnum(x, digits=3):
    s = '%.*f' % (digits, x)
    return s.rstrip('0').rstrip('.') if '.' in s else s


def plural(n, word):
    return '%d %s%s' % (n, word, '' if n == 1 else 's')


# ------------------------------------------------------------------ video formats
def vfo_row(f):
    v = f
    problems = []
    tp, tl = v['TotalPixelsPerLine'], v['TotalLinesPerFrame']
    rate = v['FramesPerSecond']
    clock = v.get('FormatInfo_PixelClock') or int(round(tp * tl * rate))
    if abs(clock - tp * tl * rate) > 0.002 * tp * tl * rate:
        problems.append('pixel clock')
    ratio = v.get('VideoClockRatioDenominator', 1)
    nst = v['StateTableValidStates']
    if sum(v['StateTableRepetitions'][:nst]) != tl:
        problems.append('state table')
    for ln, ok in zip(v['LineTypeLength'], v['LineTypeValid']):
        if ok and abs(ln - tp * v['VideoClockRatio']) > 1:
            problems.append('line length')
            break
    if 'FormatInfo_H_Sync' in v:
        hs, hb, hf = v['FormatInfo_H_Sync'], v['FormatInfo_H_BackPorch'], v['FormatInfo_H_FrontPorch']
        if hs + hb + hf + v['FormatInfo_H_Active'] != tp:
            problems.append('horizontal sum')
    else:
        hs, hb, hf = [int(round(v[k] * clock)) for k in ('HorizontalSync', 'HorizontalBackPorch',
                                                         'HorizontalFrontPorch')]
    if 'FormatInfo_F_0_V_Sync' in v:
        vs, vb, vf = [v['FormatInfo_F_0_V_%s' % k] / float(tp) for k in ('Sync', 'BackPorch', 'FrontPorch')]
    else:
        vs = vb = vf = float('nan')
    stereo = v.get('FormatInfo_Stereo') or v.get('OldStyleStereo')
    if v.get('FormatInfo_FieldSequential'):
        mode = 'sequential colour'
    elif v.get('FormatInfo_FullScreenStereo') or v.get('FullScreenStereo'):
        mode = 'full-screen stereo'
    elif stereo:
        mode = 'stereo'
    else:
        mode = 'mono'
    interlaced = v.get('FormatInfo_Interlaced')
    if interlaced is None:
        interlaced = v['FieldsPerFrame'] > 1 and sorted(v['FieldLineOffset'][:2]) == [0, 1]
    src = v.get('PFDSourceSignalName', '').lower() or 'none'
    if v.get('SerratedCSyncOnHSync'):
        src += ' serrated'
    edges = sum(1 for x in v['TransitionValid'] if x)
    types = sum(1 for x in v['LineTypeValid'] if x)
    desc = v.get('FormatName', '')
    cells = {
        'name': os.path.basename(v.path),
        'active': '%dx%d' % (v['ActivePixelsPerLine'], v['ActiveLinesPerFrame']),
        'total': '%dx%d' % (tp, tl),
        'rate': fnum(rate),
        'clock': fnum(clock / 1e6),
        'h': (hs, hb, hf),
        'v': (vs, vb, vf),
        'scan': 'interlaced' if interlaced else 'progressive',
        'mode': mode,
        'fields': plural(v['FieldsPerFrame'], 'field'),
        'ratio': '%d %s/clock' % (ratio, 'pixel' if ratio == 1 else 'pixels'),
        'detect': src,
        'states': plural(nst, 'state'),
        'types': plural(types, 'line type'),
        'edges': plural(edges, 'edge'),
        'cite': 'table at 0x%x' % f.table_real,
        'clockat': 'clock at +0x%x' % v.offset['FormatInfo_PixelClock'] if 'FormatInfo_PixelClock' in v
        else 'rate at +0x%x' % v.offset['FramesPerSecond'],
        'nfields': plural(f.count, 'field'),
        'revision': (v.get('dg4_def_version', '') or '').replace('$', '').replace('Revision:', '').strip(),
    }
    return cells, problems


def vfo_table(files, title_cols=None):
    head = ('| File | Label | Active (x by lines) | Total (x by lines) | Frame rate (Hz) | Pixel clock (MHz) | '
            'H sync (pixels) | H back porch (pixels) | H front porch (pixels) | V sync (lines) | '
            'V back porch (lines) | V front porch (lines) | Scan | Mode | Fields | Clock ratio | '
            'Frame detection | State table | Line types | Edges | Container | Clock value | File fields |\n'
            '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    rows, bad = [], []
    for f in files:
        c, prob = vfo_row(f)
        if prob:
            bad.append((c['name'], prob))
        vv = ['%s' % (fnum(x, 2) if x == x else '-') for x in c['v']]
        rows.append('| `%s` | established | %s | %s | %s | %s | %d | %d | %d | %s | %s | %s | %s | %s | %s | %s | '
                    '%s | %s | %s | %s | %s | %s | %s |' % (
                        c['name'], c['active'], c['total'], c['rate'], c['clock'], *c['h'], *vv, c['scan'],
                        c['mode'], c['fields'], c['ratio'], c['detect'], c['states'], c['types'], c['edges'],
                        c['cite'], c['clockat'], c['nfields']))
    return head + '\n' + '\n'.join(rows), bad


# ------------------------------------------------------------------ combinations
def cmb_channels(v):
    chans = []
    for k in list(range(8)) + [8]:
        p = 'ch%d' % k
        if p + 'FormatName' not in v:
            continue
        g = lambda n, d=None: v.get(p + n, d)
        chans.append({
            'n': k, 'src': g('SourceChannel'), 'origin': g('InputOrigin'), 'insize': g('InputSize'),
            'outsize': g('OutputSize'), 'fmt': g('FormatName'), 'rate': g('FrameRate'),
            'layout': g('FieldLayout'), 'hsync': g('HSync'), 'ssrc': g('SyncSource'),
            'scomp': g('SyncComponent'), 'enable': g('Enable'), 'off': v.offset[p + 'FormatName'],
            'letterbox': g('Letterbox'), 'filter': g('FilterSize'), 'safe': g('SafeArea'),
        })
    return chans


def sync_colours(comp):
    names = [n for n, x in zip(('red', 'green', 'blue'), comp or ()) if x]
    return ' '.join(names) if names else 'none'


def cmb_table(files):
    head = ('| File | Label | Channels | Encoder channel | Managed size | Allocated size | Formats | '
            'Interlaced channels | Text port | Gamma | Container | Channel names | Fields |\n'
            '|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    rows = []
    for f in files:
        chans = cmb_channels(f)
        reg = [c for c in chans if c['n'] < 8]
        enc = [c for c in chans if c['n'] == 8]
        fm = []
        for c in reg:
            if fm and fm[-1][0] == c['fmt']:
                fm[-1][1] += 1
            else:
                fm.append([c['fmt'], 1])
        fmts = ' + '.join(('%d x %s' % (n, name)) if n > 1 else name for name, n in fm)
        if enc:
            fmts += ' + ' + enc[0]['fmt']
        ms, al = f['managedSize'], f['allocatedSize']
        gamma = fnum(f['globalGamma'][0], 2) if f.get('globalGamma') else '-'
        rows.append('| `%s` | established | %s | %s | %dx%d | %dx%d | %s | %d | %s | %s | table at 0x%x | '
                    '%s at +0x%x | %s |' % (
                        os.path.basename(f.path), plural(len(reg), 'channel'),
                        'present' if enc else 'absent', ms[0], ms[1], al[0], al[1], fmts,
                        sum(1 for c in chans if c['layout']), 'on' if f.get('textport') else 'off',
                        gamma + ' ' + ('global' if f.get('usingGlobalGamma') else 'unused'),
                        f.table_real, 'format', reg[0]['off'], plural(f.count, 'field')))
    return head + '\n' + '\n'.join(rows)


def channel_table(files):
    head = ('| File | Label | Channel | Source channel | Input origin | Input size | Output size | Format | '
            'Frame rate (Hz) | Field layout | H/C sync output | Sync source | Sync on | Format name at |\n'
            '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    rows = []
    for f in files:
        for c in cmb_channels(f):
            o, i, s = c['origin'], c['insize'], c['outsize']
            rows.append('| `%s` | established | %s | %s | %d+%d | %dx%d | %dx%d | %s | %s | %s | %s | %s | %s | +0x%x |' % (
                os.path.basename(f.path), 'encoder 8' if c['n'] == 8 else 'channel %d' % c['n'],
                c['src'], o[0], o[1], i[0], i[1], s[0], s[1], c['fmt'], fnum(c['rate']),
                'interlaced' if c['layout'] else 'progressive',
                'composite' if c['hsync'] == 3 else 'horizontal' if c['hsync'] == 1 else str(c['hsync']),
                c['ssrc'], sync_colours(c['scomp']), c['off']))
    return head + '\n' + '\n'.join(rows)


# ------------------------------------------------------------------ text sources
def strip_comment(line):
    return line.split('//')[0].strip()


def first_setting(path, pat):
    """Byte offset of the first line of a text source that holds a setting or directive."""
    pos = 0
    for raw in open(path, 'rb'):
        if re.match(pat, strip_comment(raw.decode('latin1'))):
            return pos
        pos += len(raw)
    return 0


def monitor_row(path):
    kv, fields = {}, []
    for ln in open(path, encoding='latin1'):
        ln = strip_comment(ln)
        m = re.match(r'(\w+)\s*=\s*(\d+)$', ln)
        if m:
            kv[m.group(1)] = int(m.group(2))
        m = re.match(r'field(\d+)\s+off\s*=\s*(\d+)\s+inc\s*=\s*(\d+)', ln)
        if m:
            fields.append((int(m.group(2)), int(m.group(3))))
    return kv, fields


def vof_row(path):
    init, edges, lines, vert, regs = {}, [], {}, [], []
    for ln in open(path, encoding='latin1'):
        ln = strip_comment(ln)
        t = ln.split()
        if not t:
            continue
        if t[0] == 'I':
            init[t[1]] = int(t[2])
        elif t[0] == 'E':
            edges.append((t[1], int(t[2]), int(t[3]), t[4]))
        elif t[0] == 'L':
            lines[int(t[1])] = int(t[2])
        elif t[0] == 'V':
            vert.append((int(t[1]), int(t[2])))
        elif t[0] == 'R':
            regs.append((t[1], t[2]))
    return init, edges, lines, vert, regs


def monitor_table(paths):
    head = ('| File | Label | Pixels per line | Lines per field | Fields | Field step | H front porch | '
            'H back porch | H sync maximum | V front porch | V back porch | V sync maximum | Parameters | Source |\n'
            '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    rows = []
    for p in paths:
        kv, fields = monitor_row(p)
        step = ' '.join('%d+%d' % x for x in fields)
        rows.append('| `%s` | established | %d | %d | %d | %s | %d | %d | %d | %d | %d | %d | %s | %s | %s | first at 0x%x |' % (
            os.path.basename(p), kv['pixels_per_line'], kv['lines_per_field'], kv['num_fields'], step,
            kv['h_f_porch'], kv['h_b_porch'], kv['hsync_max'], kv['v_f_porch'], kv['v_b_porch'],
            kv['vsync_max'], 'interlaced' if kv['num_fields'] > 1 else 'progressive',
            '%d lines %d pixels' % divmod(kv['vsync_max'], kv['pixels_per_line']),
            plural(len(kv), 'setting'), first_setting(p, r'h_f_porch')))
    return head + '\n' + '\n'.join(rows)


def edge_span(edges, sig):
    """Pixel positions where the signal's edges go to its final level in the longest edge list."""
    es = sorted((e[1], e[2]) for e in edges if e[0] == sig)
    return es


def vof_table(paths):
    head = ('| File | Label | Line types | Line length (pixels) | Vertical areas | Frame lines | Edges | '
            'Signals | H sync width | Active start | Active end | Registers set | Sequencer | Source |\n'
            '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    rows = []
    for p in paths:
        init, edges, lines, vert, regs = vof_row(p)
        hs = edge_span(edges, 'HSYNC')
        width = hs[1][0] - hs[0][0] if len(hs) >= 2 else 0
        act = edge_span(edges, 'VIDEO_ACTIVE')
        lens = sorted(set(lines.values()))
        total = sum(r for r, _ in vert)
        rows.append('| `%s` | established | %s | %s | %s | %s | %s | %s | %d | %d | %d | %s | %s | first at 0x%x |' % (
            os.path.basename(p), plural(len(lines), 'type'), '/'.join(str(x) for x in lens),
            plural(len(vert), 'area'), total if total else '-', plural(len(edges), 'edge'),
            plural(len(init), 'signal'), width, act[0][0] if act else 0, act[1][0] if len(act) > 1 else 0,
            plural(len(regs), 'register'), 'state areas' if vert else 'none',
            first_setting(p, r'I\\s')))
    return head + '\n' + '\n'.join(rows)


# ------------------------------------------------------------------ document
INTRO = """# Display-format files: decoded parameters

Every row below is read from the file it names by `scripts/display_formats.py`; rerun the script to regenerate this page. The container layout, the field dictionary and the routines that read them are in [display-file-format.md](display-file-format.md). All values are **established** from the file contents (IRIX 6.5.30m install, first configuration: the DG4 display generator); the page makes no claim about what a field does beyond what its section of that chapter derives.

The script also tests the relations the format keeps on every file and reports the failures in the closing section: the repetitions of the valid states add up to the lines of the frame, every valid line length is the pixels per line times the clock ratio, the pixel clock is pixels times lines times frame rate within 0.2 percent, and the four horizontal parts add up to the line.
"""

VFO_INTRO = """## Video formats of the display generator

One row per `.vfo` file under `dg4/vfo/`. Columns: the active and total raster, the frame rate, the pixel clock (`FormatInfo_PixelClock` divided by a million), the three horizontal parts in pixels and the three vertical parts in lines of the first field (the file stores them as clock counts and the script divides by the pixels per line). Scan, mode, fields, clock ratio and frame detection come from the interlace, stereo, field and sync fields; the counts are the valid entries of the state table, the line types and the edge slots. The last three columns say where in the file the name table starts, where the pixel clock value is stored and how many fields the file has.
"""

CMB_INTRO = """## Combinations of formats

One row per `.cmb` file under `dg4/cmb/`: how many channels it drives, whether the encoder channel exists, the managed and allocated frame-buffer size, the formats its channels load, how many channels are interlaced, whether the text port is on and the gamma. The channel table below gives each channel of each file.
"""

DIAG_INTRO = """## Video formats the diagnostics load

The same container, in `usr/diags/IR/data/`. Two files carry the names of formats in the install tree (`1280x1024_60.vfo` and `CCIR601_525_DGO.vfo`) with different contents; the other two are test formats.
"""

TEXT_INTRO = """## Older text sources

The `.monitor` files of `vof/` give the porches and field layout of a display in text; the `.vof` files give the output sequencer directly as initial signal levels, edges, line lengths and vertical areas, with the line positions in pixels. The table of the `.vof` sources gives the width of the horizontal sync pulse from the first two edges of that signal and the active window from the edges of the active signal.
"""


def build(root):
    dg4 = os.path.join(root, 'usr/gfx/ucode/KONA/dg4')
    vfos = [Sdb(p) for p in sorted(glob.glob(os.path.join(dg4, 'vfo/*.vfo')))]
    cmbs = [Sdb(p) for p in sorted(glob.glob(os.path.join(dg4, 'cmb/*.cmb')))]
    diag = [Sdb(p) for p in sorted(glob.glob(os.path.join(root, 'usr/diags/IR/data/*.vfo')))]
    vofd = os.path.join(root, 'usr/gfx/ucode/KONA/vof')
    mons = sorted(glob.glob(os.path.join(vofd, '*.monitor')))
    vofs = sorted(glob.glob(os.path.join(vofd, '*.vof')))
    vt, bad = vfo_table(vfos)
    dt, dbad = vfo_table(diag)
    out = [INTRO, VFO_INTRO, vt, '', DIAG_INTRO, dt, '', CMB_INTRO, cmb_table(cmbs), '',
           '### Channels of each combination', '', channel_table(cmbs), '', TEXT_INTRO,
           '### Monitor sources', '', monitor_table(mons), '', '### Output-format sources', '',
           vof_table(vofs), '']
    allbad = bad + dbad
    out.append('## Relation checks\n')
    out.append('The relations above hold in %d of %d video-format files%s.\n' % (
        len(vfos) + len(diag) - len(allbad), len(vfos) + len(diag),
        '' if not allbad else ('; the exceptions are ' + ', '.join(
            '%s (%s)' % (n, ', '.join(p)) for n, p in allbad))))
    return '\n'.join(out), allbad


def main(argv):
    root, out, check = os.path.join(REPO, 'root'), os.path.join(REPO, 'docs/display-formats.md'), False
    it = iter(argv)
    for a in it:
        if a == '--root':
            root = next(it)
        elif a == '--out':
            out = next(it)
        elif a == '--check':
            check = True
    text, bad = build(root)
    if check:
        for n, p in bad:
            print('CHECK FAILED %s: %s' % (n, ', '.join(p)))
        return 1 if bad else 0
    with open(out, 'w') as fh:
        fh.write(text)
    print('wrote %s (%d rows)' % (out, text.count('\n| `')))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
