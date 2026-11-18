#!/usr/bin/env python3
"""Measure the blend test's frames against the raster rules, and fit the
colour-interpolation residue of the first panel.

Usage: retools/tools/odsy/odydiags_blend_fit.py [panels|amplify|dither|fit|frame|iris|all]
                                     [--image IMAGE]

Needs numpy for fit and frame (for example `uv run --with numpy python
retools/tools/odsy/odydiags_blend_fit.py fit`), and the odydiags files under root/ that
odydiags_frame_check.py reads. frame rebuilds the whole frame six times and
takes about two minutes.

The VPro field diagnostics' "blend" test (__clog_blend) draws nine panels of
two quads each. Its frame, blend.SUM, is the board simulator's output, not a
capture from a board. odydiags_frame_check.py rebuilds it with 12,598 of
1,310,720 pixels different; this script takes that rebuild apart. Each part
imports the frame builder from odydiags_frame_check.py, so the rules under
test are that script's rules (docs/raster.md).

  panels   the pixels the rebuild gets wrong, per panel, and how many differ
           from the stored frame by more than 3 in some byte
  amplify  for the logic-operation panels, whether those large errors vanish
           when the operation is applied to the stored COPY and NOOP panels
           instead of the rebuild's
  dither   the states of block 0x004 bit 18 over the drawn primitives, and
           the quads drawn under each block 0x004 value and logic operation
  fit      candidate arithmetic for the first panel's colour, which draws no
           logic operation: the pixels each candidate leaves different
  frame    the same candidates as one change to the packing of the whole
           frame, counting all nine panels
  iris     the first panel under the f64, f32 and iris colour models, and
           the iris model on every panel and on the frames that reproduce
           exactly (needs numpy; about two minutes)

The results are in docs/blend-residue-fit.md and ucode/runs/odydiags-blend-fit-candidates.txt.
"""
import collections
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import odydiags_frame_check as m  # noqa: E402

W, H = 1280, 1024
XR = [(0, 425), (426, 851), (852, 1277)]
YR = [(1, 341), (342, 682), (683, 1023)]
OPS = ['none', 'CLEAR', 'AND', 'AND_REVERSE', 'COPY', 'AND_INVERTED', 'NOOP', 'XOR', 'OR']


def panel(x, y):
    """Panel number (row * 3 + column, rows from the bottom) of a pixel."""
    c = [i for i, (a, b) in enumerate(XR) if a <= x <= b]
    r = [i for i, (a, b) in enumerate(YR) if a <= y <= b]
    return r[0] * 3 + c[0] if c and r else None


def rebuild(image):
    """The workspace's frame and the stored frame, as lists of 32-bit words."""
    _, _, frame, stored, _, _, _ = m.build('blend', False, image, log=lambda *a: None)
    return frame, stored


def step(a, b):
    """Largest difference over the four bytes of two frame words."""
    return max(abs(((a >> s) & 255) - ((b >> s) & 255)) for s in (24, 16, 8, 0))


def per_panel(frame, stored):
    """Per panel: [pixels differing, pixels differing by more than 3]."""
    per = collections.defaultdict(lambda: [0, 0])
    for k in range(W * H):
        a, b = frame[k], stored[k]
        if a != b:
            p = panel(k % W, H - 1 - k // W)
            per[p][0] += 1
            per[p][1] += step(a, b) > 3
    return per


def cmd_panels(image):
    frame, stored = rebuild(image)
    per = per_panel(frame, stored)
    print(f'total pixels differing {sum(v[0] for v in per.values())}')
    print('panel operation     differing  over 3 steps')
    for p in range(9):
        print(f'{p:5d} {OPS[p]:14s} {per[p][0]:7d} {per[p][1]:12d}')
    print(f'over 3 steps in all panels {sum(v[1] for v in per.values())}')
    cmp = [(0, 4), (0, 6), (4, 6)]
    for a, b in cmp:
        n = sum(at(stored, a, ox, oy) != at(stored, b, ox, oy)
                for oy in range(341) for ox in range(426))
        print(f'stored panel {a} ({OPS[a]}) against panel {b} ({OPS[b]}): {n} pixels differ')


def at(frm, p, ox, oy):
    """The word at offset (OX, OY) from the lower-left corner of panel P."""
    x, y = XR[p % 3][0] + ox, YR[p // 3][0] + oy
    return frm[(H - 1 - y) * W + x]


def cmd_amplify(image):
    frame, stored = rebuild(image)
    print('panel operation     differing  over 3  explained by stored sources')
    tot = [0, 0, 0]
    for p in (1, 2, 3, 5, 7, 8):
        d = big = ok = 0
        for oy in range(341):
            for ox in range(426):
                a, b = at(frame, p, ox, oy), at(stored, p, ox, oy)
                if a == b:
                    continue
                d += 1
                if step(a, b) <= 3:
                    continue
                big += 1
                src, dst = at(stored, 4, ox, oy), at(stored, 6, ox, oy)
                # Where the second quad covers the output is op(src, dst);
                # elsewhere it is the destination.
                if m.LOGIC[p - 1](src, dst) & 0xffffffff == b or dst == b:
                    ok += 1
        print(f'{p:5d} {OPS[p]:14s} {d:7d} {big:7d} {ok:10d}')
        tot[0] += d
        tot[1] += big
        tot[2] += ok
    print(f'total {tot[0]} differing, {tot[1]} over 3 steps, {tot[2]} explained, '
          f'{tot[1] - tot[2]} not')


def cmd_dither(image):
    words = m.stream(os.path.join(m.ROOT, 'odydiags'), '__clog_blend')
    cmds = m.decode(words)
    c = collections.Counter()
    for p in m.primitives(cmds, (0x1c8, 0x1df), (m.POINTS, m.LINES, m.TRIANGLES, m.QUADS, 10, 0)):
        logic = p['logic'] if p['enables'] >> 17 & 1 else None
        c[(p['type'], hex(p['enables']), logic, len(p['verts']))] += 1
    print('type  block 0x004  logic op  vertices  count')
    for k, v in sorted(c.items(), key=str):
        print(k, v)
    en, cur, setbit = 0, None, []
    for idx, w, ops in cmds:
        if w == 0x00010404:
            en = ops[0]
        elif w == 0x00014400:
            cur = [idx, ops[0], en]
        elif w == 0x00014001 and cur:
            if cur[2] >> 18 & 1:
                setbit.append(tuple(cur))
            cur = None
    print('begin/end pairs drawn with block 0x004 bit 18 (dither) set '
          '(word index, begin operand, value):', [(i, o, hex(e)) for i, o, e in setbit])


def samples(image):
    """Every pixel of panel 0 as the builder shaded it: window position,
    triangle vertices, the three 1/w words, the three vertex colours, and the
    stored word."""
    import numpy as np
    orig, rec = m.smooth, {}

    def hook(v, q, cols, px, py, shift=None):
        if px <= 425 and 1 <= py <= 341:
            rec[(px, py)] = (tuple(v), tuple(q), tuple(map(tuple, cols)))
        return orig(v, q, cols, px, py, shift)

    m.smooth = hook
    try:
        _, stored = rebuild(image)
    finally:
        m.smooth = orig
    keys = list(rec)
    px = np.array([k[0] for k in keys], float)
    py = np.array([k[1] for k in keys], float)
    V = np.array([rec[k][0] for k in keys])
    Q = np.array([rec[k][1] for k in keys])
    C = np.array([rec[k][2] for k in keys])
    st = np.array([stored[(H - 1 - y) * W + x] for x, y in keys], dtype=np.uint64)
    stored_b = np.stack([(st >> np.uint64(s)) & np.uint64(255) for s in (24, 16, 8, 0)], 1).astype(int)
    tri, ids = np.zeros(len(keys), int), {}
    for i, k in enumerate(keys):
        tri[i] = ids.setdefault((rec[k][0], rec[k][2]), len(ids))
    return px, py, V, Q, C, stored_b, tri


def weights(px, py, V, Q):
    """Screen-space barycentric weights L and perspective-correct weights B
    at the pixel centres."""
    import numpy as np
    x, y = px + 0.5, py + 0.5
    x0, y0, x1, y1, x2, y2 = V[:, 0, 0], V[:, 0, 1], V[:, 1, 0], V[:, 1, 1], V[:, 2, 0], V[:, 2, 1]
    d = (x1 - x0) * (y2 - y0) - (x2 - x0) * (y1 - y0)
    l1 = ((x - x0) * (y2 - y0) - (x2 - x0) * (y - y0)) / d
    l2 = ((x1 - x0) * (y - y0) - (x - x0) * (y1 - y0)) / d
    L = np.stack([1 - l1 - l2, l1, l2], 1)
    return L, persp(L, Q)


def persp(L, Q):
    w = L * Q
    return w / w.sum(1, keepdims=True)


def cmd_fit(image):
    import numpy as np
    px, py, V, Q, C, stored, tri = samples(image)
    L, B = weights(px, py, V, Q)
    n = len(px)
    print(f'panel 0: {n} pixels; triangles (pixels): '
          f'{[(t, int((tri == t).sum())) for t in range(int(tri.max()) + 1)]}')

    def lim(a):
        return np.minimum(255, a).astype(int)

    def score(out):
        d = out != stored
        return int(d.any(1).sum()), d

    exact = np.einsum('ni,nic->nc', B, C)

    def show(label, out):
        px_, d = score(out)
        print(f'{label:70s} {px_:6d}  per channel {d.sum(0).tolist()}')
        return px_

    show('baseline floor(256 c)', lim(np.floor(exact * 256)))
    for b in (0.01, 0.02, 0.03, 0.04, 0.0625, 0.08, 0.1, 0.15):
        show(f'floor(256 c + {b})', lim(np.floor(exact * 256 + b)))

    print('\n12-bit vertex colours (1.0 as 4095 or 4096), the sum quantised, then converted:')
    rows = []
    for vn, vc in (('4096c clamp 4095', lambda c: np.minimum(4095, np.floor(c * 4096))),
                   ('4095c round', lambda c: np.round(c * 4095))):
        y12 = np.einsum('ni,nic->nc', B, vc(C))
        for qn, q in (('floor', np.floor), ('round', np.round), ('ceil', np.ceil), ('exact', lambda t: t)):
            for fn, fin in (('>>4', lambda t: np.floor(t / 16)),
                            ('round /16', lambda t: np.floor(t / 16 + .5)),
                            ('256 t/4095', lambda t: np.floor(256 * t / 4095)),
                            ('255 t/4095 round', lambda t: np.round(255 * t / 4095)),
                            ('ceil /16', lambda t: np.ceil(t / 16))):
                rows.append((score(lim(fin(q(y12))))[0], f'vertex {vn}, sum {qn}, then {fn}'))
    rows.sort()
    for r in rows[:3] + rows[-2:]:
        print(f'{r[1]:70s} {r[0]:6d}')
    print(f'({len(rows)} combinations; the best 3 and the worst 2)')

    print('\nweights held to 10 to 16 bits (three weights, or two with the third by '
          'subtraction; summed or as vertex 0 plus two weighted differences), plus 0, 0.5 or 1 low bit:')

    def quant(b, bits, mode):
        s = 2.0 ** bits
        return {'floor': np.floor, 'round': np.round, 'ceil': np.ceil, 'none': lambda t: t * s}[mode](b * s) / s

    results = []
    vconv = {'4095r': lambda c: np.round(c * 4095),
             '4096clamp': lambda c: np.minimum(4095, np.floor(c * 4096)),
             '4096': lambda c: np.floor(c * 4096)}
    for vn, vf in vconv.items():
        C12 = vf(C)
        for form in ('sum', 'offset'):
            for bits in (10, 11, 12, 13, 14, 16, 0):
                for mode in (('floor', 'round', 'ceil') if bits else ('none',)):
                    for which in ('b12', 'b0b12'):
                        Bq = B.copy()
                        if bits and which == 'b12':
                            Bq[:, 1] = quant(B[:, 1], bits, mode)
                            Bq[:, 2] = quant(B[:, 2], bits, mode)
                            Bq[:, 0] = 1 - Bq[:, 1] - Bq[:, 2]
                        elif bits:
                            for i in range(3):
                                Bq[:, i] = quant(B[:, i], bits, mode)
                        if form == 'sum':
                            y = np.einsum('ni,nic->nc', Bq, C12)
                        else:
                            y = C12[:, 0] + Bq[:, 1, None] * (C12[:, 1] - C12[:, 0]) \
                                + Bq[:, 2, None] * (C12[:, 2] - C12[:, 0])
                        for add in (0, 0.5, 1.0):
                            for fin in ('floor', 'round'):
                                t = (y + add) / 16
                                out = lim(np.floor(t) if fin == 'floor' else np.floor(t + 0.5))
                                results.append((score(out)[0], vn, form, bits, mode, which, add, fin))
    results.sort()
    print(f'best of {len(results)} variants: {results[0][0]} {results[0][1:]}')

    print('\nvertex 1/w with a 6 to 14 bit mantissa, three rounding modes, then RGB plus one 12-bit low bit:')
    C12 = np.minimum(4095, np.floor(C * 4096))

    def qmant(a, bits, mode):
        mant, e = np.frexp(a)
        s = 2.0 ** bits
        mant = {'floor': np.floor, 'round': np.round, 'ceil': np.ceil}[mode](mant * s) / s
        return np.ldexp(mant, e)

    best = []
    for bits in range(6, 15):
        for mode in ('floor', 'round', 'ceil'):
            y = np.einsum('ni,nic->nc', persp(L, qmant(Q, bits, mode)), C12)
            y[:, :3] += 1.0
            best.append((score(lim(np.floor(y / 16)))[0], bits, mode))
    best.sort()
    print(f'best: {best[0]}, then {best[1]}, {best[2]}')

    print('\nRGB plus one 12-bit low bit (1/16 of an output step), alpha unchanged:')

    def conv(one, add_rgb):
        c12 = np.where(C >= 1.0, one, np.where(C >= 0.5, 2048, 0.0))
        y = np.einsum('ni,nic->nc', B, c12)
        y[:, :3] += add_rgb
        return lim(np.floor(y / 16))

    for label, out in (('1.0 as 4096, no bias', conv(4096, 0)),
                       ('1.0 as 4096, RGB + 1', conv(4096, 1.0)),
                       ('1.0 as 4095, RGB + 1', conv(4095, 1.0))):
        px_, d = score(out)
        print(f'{label:70s} {px_:6d}  per triangle and channel '
              f'{[[int(d[tri == t, c].sum()) for c in range(4)] for t in range(int(tri.max()) + 1)]}')
    out = np.concatenate([conv(4095, 1.0)[:, :3], conv(4096, 0)[:, 3:]], 1)
    px_, _ = score(out)
    print(f'{"RGB 1.0 as 4095 + 1, alpha 1.0 as 4096":70s} {px_:6d}')

    print('\nthe constant that fits triangle 2 (RGB values 0 to 0.5): pixels left different, per channel:')
    sel = tri == 2
    for s in (0, 0.06, 0.062, 0.0625, 0.063, 0.0635, 0.064, 0.065, 0.07):
        out = lim(np.floor(exact[sel, :3] * 256 + s))
        print(f'  floor(256 c + {s}): {(out != stored[sel, :3]).sum(0).tolist()} of {int(sel.sum())}')

    print('\noffset (in output steps) every stored byte allows, by value of the exact colour '
          'in bins of 32, for the 12-bit model with RGB + 1/16 (lo/hi; * = no single offset):')
    y = np.einsum('ni,nic->nc', B, C12) / 16.0
    y[:, :3] += 1 / 16.0
    e = exact * 256
    for t in range(int(tri.max()) + 1):
        s_ = tri == t
        for ch in range(4):
            ee, bb, yy = e[s_, ch], stored[s_, ch], y[s_, ch]
            if ee.max() - ee.min() < 1e-9:
                continue
            row = []
            for a, b_ in zip(range(0, 256, 32), range(32, 257, 32)):
                mk = (yy >= a) & (yy < b_) & (bb < 255)
                if mk.sum() < 20:
                    row.append('     -      ')
                    continue
                lo = (bb[mk] - yy[mk]).max()
                hi = (bb[mk] + 1 - yy[mk]).min()
                row.append(f'{lo:+.3f}/{hi:+.3f}{"*" if lo > hi else " "}')
            print(f'  triangle {t} {"RGBA"[ch]} ' + ' | '.join(row))


def cmd_frame(image):
    orig = m.pack

    def make(add_rgb=0.0, add_a=0.0, rgb4095=False):
        def pk(c, rule):
            out = 0
            for i, x in enumerate(c):
                x = min(max(x, 0.0), 1.0)
                if rgb4095 and i < 3:
                    v = math.floor(x * 4095 + 0.5)
                else:
                    v = min(4095, math.floor(x * 4096))
                t = (v + (add_rgb if i < 3 else add_a)) / 16.0
                out = out << 8 | min(255, math.floor(t))
            return out
        return pk

    print('whole frame, with the packing of each colour changed:')
    print('candidate                                        differing  panel 0  over 3 steps')
    try:
        for label, pk in (('baseline (the script as is)', orig),
                          ('12-bit, floor(4096 c) >> 4', make()),
                          ('RGB + 1 low bit, alpha + 0', make(1.0, 0.0)),
                          ('RGB + 0.5 low bit', make(0.5, 0.0)),
                          ('RGB + 1 low bit, alpha + 0.5', make(1.0, 0.5)),
                          ('RGB as round(4095 c) + 1, alpha as 4096 c', make(1.0, 0.0, True))):
            m.pack = pk
            frame, stored = rebuild(image)
            per = per_panel(frame, stored)
            print(f'{label:48s} {sum(v[0] for v in per.values()):7d} {per[0][0]:8d} '
                  f'{sum(v[1] for v in per.values()):13d}')
    finally:
        m.pack = orig


# The iris VPro colour path, as written in iris (techomancer/iris main 9bc81b0,
# src/dev/odyssey/pipe), in its own operation order. f32 steps use numpy
# scalars so each operation rounds to single as the Rust does.
IRIS_ONE = 1 << 24          # fixed.rs:16, colour 1.0 in 12.12
IRIS_W_ONE = 1 << 15        # fixed.rs:20


def iris_from_f64(c):
    """fixed.rs:31-39: a colour in [0, 1] to 12.12 by truncation, 1.0 to MAX."""
    if not c > 0.0:
        return 0
    if c >= 1.0:
        return IRIS_ONE - 1
    return min(int(c * IRIS_ONE), IRIS_ONE - 1)


def iris_smooth(v, q, cols, px, py, shift=None):
    """Colour of pixel (PX, PY) of triangle V as iris computes it: integer edge
    values at the pixel centre in 1/256 pixel units (raster.rs:330-343,
    357-359), area and its swap to a positive winding (raster.rs:303-316),
    f32 reciprocal of the area (raster.rs:352) and f32 barycentrics
    (raster.rs:511-512), 0.15 perspective weights in f32 (interp.rs:54-64),
    12.4 vertex colours times the weights, shifted back to 12.12
    (fixed.rs:119-125; vertex colours by fixed.rs:31, setup.rs:443). Returns
    the 12.12 value as a double, exact, for the packer."""
    import numpy as np
    f = np.float32
    P = [(round(x * 256), round(y * 256)) for x, y in v]

    def edge(a, b, x, y):
        return (b[0] - a[0]) * (y - a[1]) - (b[1] - a[1]) * (x - a[0])

    area = edge(P[0], P[1], P[2][0], P[2][1])
    order = [0, 1, 2]
    if area < 0:
        order, area = [0, 2, 1], -area
    Pv = [P[i] for i in order]
    iw = [f(q[i]) for i in order]                       # setup.rs:507
    cv = [[iris_from_f64(cols[i][k]) for k in range(4)] for i in order]
    X, Y = px * 256 + 128, py * 256 + 128
    inv = f(1.0 / area)                                  # (1/area as f64) as f32
    l1 = f(edge(Pv[2], Pv[0], X, Y)) * inv
    l2 = f(edge(Pv[0], Pv[1], X, Y)) * inv
    w1 = l1 * iw[1]
    w2 = l2 * iw[2]
    one = f(1.0)
    total = ((one - l1) - l2) * iw[0] + w1 + w2
    if total == 0 or not np.isfinite(total):
        return [0.0] * 4
    r = f(IRIS_W_ONE) / total

    def rnd(w):
        return int(w * r + f(0.5))                       # truncation, as `as i32`

    p1 = min(max(rnd(w1), 0), IRIS_W_ONE)
    rest = IRIS_W_ONE - p1
    p2 = min(max(rnd(w2), 0), rest)
    pw = [rest - p2, p1, p2]
    out = []
    for k in range(4):
        sm = sum((cv[i][k] >> 8) * pw[i] for i in range(3))
        out.append((sm >> 7) / IRIS_ONE)
    return out


def iris_pack(c, rule):
    """A colour as iris stores it without a blend: 12.12, clamped, to 12 bits
    (backend.rs:213-215, setup.rs:570), then to 8 bits by >> 4
    (backend.rs:424); the same as the top eight bits of the 12.12 value."""
    out = 0
    for x in c:
        out = out << 8 | (min(max(iris_from_f64(x), 0), IRIS_ONE - 1) >> 12) >> 4
    return out


def cmd_iris(image):
    """The iris model on blend (every panel), then on the frames that
    reproduce exactly."""
    import numpy as np
    px, py, V, Q, C, stored, tri = samples(image)
    n = len(px)

    def score(out):
        return int((out != stored).any(1).sum())

    def lim(a):
        return np.minimum(255, a).astype(int)

    L64, B64 = weights(px, py, V, Q)
    print(f'panel 0, {n} pixels')
    print(f'{"f64 exact, floor(256 c)":50s} {score(lim(np.floor(np.einsum("ni,nic->nc", B64, C) * 256))):6d}')
    f = np.float32
    V32, Q32, C32 = V.astype(f), Q.astype(f), C.astype(f)
    x, y = (px + 0.5).astype(f), (py + 0.5).astype(f)
    x0, y0, x1, y1, x2, y2 = V32[:, 0, 0], V32[:, 0, 1], V32[:, 1, 0], V32[:, 1, 1], V32[:, 2, 0], V32[:, 2, 1]
    d = (x1 - x0) * (y2 - y0) - (x2 - x0) * (y1 - y0)
    a1 = ((x - x0) * (y2 - y0) - (x2 - x0) * (y - y0)) / d
    a2 = ((x1 - x0) * (y - y0) - (x - x0) * (y1 - y0)) / d
    w = np.stack([f(1) - a1 - a2, a1, a2], 1) * Q32
    Bp = w / w.sum(1, keepdims=True)
    col = np.einsum('ni,nic->nc', Bp, C32).astype(np.float64)
    print(f'{"f32 plane form, floor(256 c)":50s} {score(lim(np.floor(col * 256))):6d}')
    A = d
    e0 = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1)
    e1 = (x0 - x2) * (y - y2) - (y0 - y2) * (x - x2)
    b0, b1 = e0 / A, e1 / A
    bb = np.stack([b0, b1, f(1) - b0 - b1], 1)
    qi = (bb * Q32).sum(1)
    cb = bb * Q32 / qi[:, None]
    print(f'{"f32 edge distances, area reciprocal (patent)":50s} '
          f'{score(lim(np.floor(np.einsum("ni,nic->nc", cb, C32).astype(np.float64) * 256))):6d}')
    out = np.zeros_like(stored)
    for i in range(n):
        c12 = iris_smooth(V[i], Q[i], C[i], int(px[i]), int(py[i]))
        out[i] = [min(max(iris_from_f64(c), 0), IRIS_ONE - 1) >> 16 for c in c12]
    print(f'{"iris VPro (f32 weights, 12.12 colour, >> 16)":50s} {score(out):6d}  '
          f'per channel {(out != stored).sum(0).tolist()}')
    off = max(abs(V * 256 - np.round(V * 256)).max(), 0)
    print(f'largest distance of a vertex from the 1/256 grid: {off}')

    orig = (m.pack, m.smooth)
    log = lambda *a: None
    print('\nwhole frames, iris colour model (pixels differing from the stored frame; baseline in brackets):')
    try:
        for name, small, prog in (('points', False, None), ('points', True, (214, 224, 234)),
                                  ('lines', False, None), ('lines', True, (214, 224, 234)),
                                  ('triangle', False, None), ('triangle', True, (214, 224, 234)),
                                  ('alpha', False, None), ('alpha', True, (214, 224, 234)),
                                  ('checkr3d', True, None), ('blend', False, None), ('blend', True, (214, 224, 234))):
            m.pack, m.smooth = orig
            _, _, fr0, st0, _, _, _ = m.build(name, small, image, prog=prog, log=log)
            base = sum(a != b for a, b in zip(fr0, st0))
            m.pack, m.smooth = iris_pack, iris_smooth
            _, _, fr, st, _, _, _ = m.build(name, small, image, prog=prog, log=log)
            per = per_panel(fr, st) if name == 'blend' and not small else None
            tot = sum(a != b for a, b in zip(fr, st))
            line = f'{name:9s} {"small" if small else "large":6s} {tot:7d}  ({base})'
            if per:
                line += '  per panel ' + str([per[p][0] for p in range(9)])
                m.pack, m.smooth = orig
                _, _, fr0, st0, _, _, _ = m.build(name, small, image, prog=prog, log=log)
                line += '\n' + ' ' * 40 + 'baseline per panel ' + str([per_panel(fr0, st0)[p][0] for p in range(9)])
            print(line)
    finally:
        m.pack, m.smooth = orig


def main():
    args = sys.argv[1:]
    image = os.path.join(m.ROOT, 'ucode', 'diagxform.bin')
    if '--image' in args:
        i = args.index('--image')
        image = args[i + 1]
        del args[i:i + 2]
    cmds = {'panels': cmd_panels, 'amplify': cmd_amplify, 'dither': cmd_dither,
            'fit': cmd_fit, 'frame': cmd_frame, 'iris': cmd_iris}
    which = args[0] if args else 'all'
    if which == 'all':
        for name, fn in cmds.items():
            print(f'== {name}')
            fn(image)
    elif which in cmds and len(args) == 1:
        cmds[which](image)
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
