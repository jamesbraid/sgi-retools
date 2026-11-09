#!/usr/bin/env python3
"""Fit the antialiased point and line frames of the VPro field diagnostics.

Usage: scripts/odydiags_aa_fit.py [--table]

Replays the aapts and aalines streams (__clog_aapts, __clog_aalines of the
odydiags binary) through the transform reading of odydiags_frame_check.py,
takes the window positions the board's rasteriser receives (output words 5
and 6, truncated to 1/256 pixel), and compares every stored pixel near a
primitive with the rule of docs/raster.md, "Antialiased coverage":

  coverage a = G(c), with c the exact area of the pixel square inside the
  primitive (a strip of the line width, extended past its ends; a square of
  the point size) and G one curve for points and lines.

Blending is source alpha over the grey background (0.2, 0.2, 0.2, 1): a
colour channel with source value 1 stores 51 + 204 a, so a = (R - 51) / 204.

It prints G read from the axis-aligned lines, then for the near-axis
lines, the 15-degree line and the size 1 and size 2 points the mean and
largest difference between the stored a and G(c) (steps of 1/204), and the
line end test. --table prints G at every 1/64.
"""
import math
import os
import struct
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import buzz_ucode_dataflow as df  # noqa: E402
import odydiags_frame_check as m  # noqa: E402
from buzz_ucode_disasm import records  # noqa: E402

BG = 0x333333ff


def snap(v):
    return math.floor(v * 256) / 256


def load(func, key, ptype):
    """Primitives of TYPE ptype in the stream: window positions, colour at
    each vertex, block 0x04a operands, scissor box and the stored frame."""
    W, H, loads = 1280, 1024, (0x1c8, 0x1df)
    cmds = m.decode(m.stream(os.path.join(m.ROOT, 'odydiags'), func))
    stored = struct.unpack(f'>{W * H}I', open(os.path.join(m.ROOT, 'checksum', key + '.SUM'), 'rb').read())
    recs = [df.decode(w) for w in records(os.path.join(m.ROOT, 'ucode', 'diagxform.bin'))[0]]
    seq, table, scissor, prim = {}, [math.nan] * 68, None, None
    colour, size, out = [math.nan] * 4, (0, 0), []
    for idx, w, ops in cmds:
        top = w >> 24
        if w & 0xc000 == 0x8000 and 0x20 <= top <= 0x3f:
            seq[top] = m.enc_val(w)
        elif top == 0x90 and w & 0x3ff in loads:
            for k, o in enumerate(ops):
                if seq.get(0x34, 0) + k < 68:
                    table[seq.get(0x34, 0) + k] = m.fl(o)
        elif w == 0x0001081d:
            scissor = ops
        elif w == 0xc580d015:
            colour = [m.fl(o) for o in ops]
        elif w == 0x0001084a:
            size = tuple(ops)
        elif w == 0x00014400:
            prim = dict(type=ops[0], verts=[], cols=[], seq=dict(seq), size=size, scissor=scissor,
                        regs={str(r): table[4 * r:4 * r + 4] for r in range(17)}, colour=list(colour))
        elif w == 0x00014001:
            if prim and prim['type'] == ptype and prim['verts']:
                out.append(prim)
            prim = None
        elif w in m.VERTEX and prim is not None:
            v = [m.fl(o) for o in ops]
            prim['verts'].append(v + [0.0, 1.0][len(v) - 2:])
            prim['cols'].append(list(colour))
    for p in out:
        s, n = p['seq'], len(p['verts'])
        entries = [f"{s[0x29]}.."] + [f"{s[0x2a]}.."] * (n - 1) + [str(s[0x2c])]
        dom = df.Numbers(dict(regs=p['regs'], slots={'5': p['colour']}, passes=[{'0': v} for v in p['verts']]), {}, None)
        df.run(recs, entries, dom)
        got = {}
        for k, rec, word, v in dom.emits:
            got.setdefault(k - 1, {})[word] = v
        p['pos'] = [(snap(got.get(k, {}).get(5, math.nan)), snap(got.get(k, {}).get(6, math.nan))) for k in range(n)]
    return W, H, out, stored


def clip(poly, nx, ny, c):
    """Keep the part of POLY with nx x + ny y <= c."""
    out = []
    for i in range(len(poly)):
        a, b = poly[i], poly[(i + 1) % len(poly)]
        fa, fb = nx * a[0] + ny * a[1] - c, nx * b[0] + ny * b[1] - c
        if fa <= 0:
            out.append(a)
        if (fa < 0 < fb) or (fb < 0 < fa):
            t = fa / (fa - fb)
            out.append((a[0] + t * (b[0] - a[0]), a[1] + t * (b[1] - a[1])))
    return out


def area(p):
    return abs(sum(p[i][0] * p[(i + 1) % len(p)][1] - p[(i + 1) % len(p)][0] * p[i][1]
                   for i in range(len(p)))) / 2 if len(p) > 2 else 0.0


def strip_area(px, py, seg, width, ext):
    """Area of pixel (px, py) inside the strip of WIDTH about segment SEG,
    its ends moved out EXT along the line."""
    x0, y0, x1, y1 = seg
    L = math.hypot(x1 - x0, y1 - y0)
    ux, uy = (x1 - x0) / L, (y1 - y0) / L
    nx, ny = -uy, ux
    poly = [(px, py), (px + 1, py), (px + 1, py + 1), (px, py + 1)]
    poly = clip(poly, nx, ny, nx * x0 + ny * y0 + width / 2)
    poly = clip(poly, -nx, -ny, -(nx * x0 + ny * y0 - width / 2))
    poly = clip(poly, ux, uy, ux * x1 + uy * y1 + ext)
    return area(clip(poly, -ux, -uy, -(ux * x0 + uy * y0 - ext)))


def channel_a(w, col):
    """Coverage from a stored pixel: the first channel whose source value is 1."""
    for c in range(3):
        if col[c] == 1.0:
            return ((w >> (24 - 8 * c)) & 255) - 51, c
    return None, None


def main():
    # lines: five segments per quarter, width 1, 2 and 3 in the three quarters
    W, H, lines, st = load('__clog_aalines', 'aalines', 1)
    segs = []
    for p in lines:
        for k in range(0, len(p['verts']), 2):
            segs.append((p['size'][0] / 128, k // 2, p, p['pos'][k] + p['pos'][k + 1], p['cols'][k + 1]))

    def lit(wd, li, seg, col, ext):
        """Pixels of one line far from every other line: (area, a, t, L)."""
        res = []
        x0, y0, x1, y1 = seg
        L = math.hypot(x1 - x0, y1 - y0)
        ux, uy = (x1 - x0) / L, (y1 - y0) / L
        others = [s[3] for s in segs if s[0] == wd and s[1] != li]
        sc = [s for s in segs if s[0] == wd and s[1] == li][0][2]['scissor']
        bx0, bx1, by0, by1 = sc[0] >> 12 & 0xfff, sc[0] & 0xfff, sc[1] >> 12 & 0xfff, sc[1] & 0xfff
        for py in range(int(min(y0, y1)) - 4, int(max(y0, y1)) + 5):
            for px in range(int(min(x0, x1)) - 4, int(max(x0, x1)) + 5):
                if not (bx0 <= px <= bx1 and by0 <= py <= by1):
                    continue
                far = True
                for o in others:
                    ox0, oy0, ox1, oy1 = o
                    dx, dy = ox1 - ox0, oy1 - oy0
                    t = max(0, min(1, ((px + .5 - ox0) * dx + (py + .5 - oy0) * dy) / (dx * dx + dy * dy)))
                    if math.hypot(px + .5 - ox0 - t * dx, py + .5 - oy0 - t * dy) < wd + 3:
                        far = False
                        break
                if not far:
                    continue
                w = st[(H - 1 - py) * W + px]
                if w == BG:
                    a = 0.0
                else:
                    v, _ = channel_a(w, col)
                    if v is None:
                        continue
                    a = v / 204
                t = (px + .5 - x0) * ux + (py + .5 - y0) * uy
                d = (px + .5 - x0) * -uy + (py + .5 - y0) * ux
                res.append((a, t, L, d, px, py))
        return res

    # G from the axis-aligned lines: c = w/2 - |d| + 1/2
    g = defaultdict(list)
    cache = {}
    for wd, li, p, seg, col in segs:
        cache[(wd, li)] = lit(wd, li, seg, col, 0.5)
        if li in (0, 1, 2, 4):
            for a, t, L, d, px, py in cache[(wd, li)]:
                if 2 < t < L - 2:
                    c = wd / 2 - abs(d) + .5
                    if -0.1 <= c <= 1.1:
                        g[round(c * 64)].append(a)
    G = {k / 64: sum(v) / len(v) for k, v in g.items() if len(v) >= 3}
    ks = sorted(G)

    def Gf(c):
        c = min(max(c, ks[0]), ks[-1])
        for i in range(len(ks) - 1):
            if ks[i] <= c <= ks[i + 1]:
                t = (c - ks[i]) / (ks[i + 1] - ks[i])
                return G[ks[i]] * (1 - t) + G[ks[i + 1]] * t
        return G[ks[-1]]

    if '--table' in sys.argv:
        print('; G(c) read from the axis-aligned lines, c = pixel area inside the strip')
        for k in ks:
            print(f'G({k:.4f}) = {G[k]:.3f}  ({len(g[round(k * 64)])} pixels)')
    for name, ls in (('near-axis lines (0, 1, 2, 4)', (0, 1, 2, 4)), ('15-degree line (3)', (3,))):
        errs = []
        for wd, li, p, seg, col in segs:
            if li not in ls:
                continue
            for a, t, L, d, px, py in cache[(wd, li)]:
                if 2 < t < L - 2 and 0.01 < a < 0.99:
                    errs.append(abs(Gf(strip_area(px, py, seg, wd, 0.5)) - a) * 204)
        print(f'; {name}: {len(errs)} edge pixels, mean difference {sum(errs) / len(errs):.2f} steps, largest {max(errs):.0f}')
    print('; line end extension (edge pixels within 1.5 of an end, mean difference in steps)')
    for ext in (-0.5, -0.25, 0, 0.25, 0.5):
        errs = []
        for wd, li, p, seg, col in segs:
            for a, t, L, d, px, py in cache[(wd, li)]:
                if (t < 1.5 or t > L - 1.5) and 0.01 < a < 0.99:
                    errs.append(abs(Gf(strip_area(px, py, seg, wd, ext)) - a) * 204)
        print(f';   extension {ext}: {len(errs)} edge pixels, mean {sum(errs) / len(errs):.2f}')

    # points: size 1 (block 0x04a second operand 0x80) and size 2 (0x100)
    W, H, pts, st = load('__clog_aapts', 'aapts', 0)
    allp = [(x, y) for p in pts for (x, y) in p['pos']]
    for size, s in ((128, 1.0), (256, 2.0)):
        errs = []
        for p in pts:
            if p['size'][1] != size or p['colour'] != [1.0] * 4:
                continue
            sc = p['scissor']
            bx0, bx1, by0, by1 = sc[0] >> 12 & 0xfff, sc[0] & 0xfff, sc[1] >> 12 & 0xfff, sc[1] & 0xfff
            for (x, y) in p['pos']:
                if any(math.hypot(x - a, y - b) < 6 for (a, b) in allp if (a, b) != (x, y)):
                    continue
                for py in range(math.floor(y) - 3, math.floor(y) + 4):
                    for px in range(math.floor(x) - 3, math.floor(x) + 4):
                        if not (bx0 <= px <= bx1 and by0 <= py <= by1):
                            continue
                        w = st[(H - 1 - py) * W + px]
                        a = 0.0 if w == BG else ((w >> 24 & 255) - 51) / 204
                        cx = min(1, max(0, s / 2 - abs(px + .5 - x) + .5))
                        cy = min(1, max(0, s / 2 - abs(py + .5 - y) + .5))
                        if 0.01 < a < 0.99:
                            errs.append(abs(Gf(cx * cy) - a) * 204)
        print(f'; points of size {s:g}: {len(errs)} edge pixels, mean difference {sum(errs) / len(errs):.2f} steps, '
              f'largest {max(errs):.0f}')


if __name__ == '__main__':
    main()
