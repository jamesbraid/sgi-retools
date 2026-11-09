#!/usr/bin/env python3
"""Replay an odydiags drawing test through the microcode reading and the
raster rules, and compare the frame it predicts with the test's stored frame
and checksum.

Usage: scripts/odydiags_frame_check.py [--test points|lines|triangle|alpha|blend|checkr3d]
                                       [--r-low] [--texel-edge] [--blend-fit]
                                       [--round f32|tN] [--small]
                                       [--image IMAGE] [--program A,B,C] [--dump]
       scripts/odydiags_frame_check.py --survey | --logic | --residue

The VPro field diagnostics (odydiags, Internal Support Tools 2.7, 6.5.15
build) carry each drawing test as a function __clog_<test> that replays a
command stream recorded from the board's C simulator, one call of
_odsy_diag_wr_hw (board, address, value, size, flag) per write. The test then
reads the frame back and compares a CRC-32 of it with usr/diags/ody/checksum/
csumlist (csumlist.sml for the 128 x 64 screen); <test>.SUM and <test>.sml
hold the frames themselves (ucode/buzz_isa.md, "Pass 18").

This script handles the points, lines, triangle, alpha, blend and checkr3d
tests (__clog_pts, __clog_lines, __clog_tri, __clog_alpha, __clog_blend,
__clog_chk3d and their _small forms; blend and checkr3d do not yet match,
docs/raster.md): it extracts the writes,
tracks the sequencer registers, the matrix table and the primitives, runs
each primitive's vertices through scripts/buzz_ucode_dataflow.py (first
part, loop once per further vertex, closing part, the slot-0 values changing
per pass), takes output words 5 and 6 as the window position, and draws the
primitives with the raster rules of docs/raster.md into a black frame, rows
stored top first, colours packed and alpha-tested as docs/raster.md states. It prints, per vertex, the output words, then
the CRC of the built frame against csumlist and a pixel comparison against the
stored frame. The transform rules are those of the dataflow script; the
frame-side rules are stated in buzz_isa.md, pass 18, and docs/raster.md.

--image picks the microcode image (default: the diagnostics' own
diagxform.bin, the image odydiags loads). --round is passed to the dataflow
run. --program replaces the start, loop and closing entries the stream
sets in sequencer 0x29, 0x2a and 0x2c (the 128 x 64 stream names a program
layout no held image has). --dump prints the decoded command stream instead.
--r-low holds r below 1.0 and --texel-edge limits a texel index of 32 to 31
(the checkr3d test only; docs/raster.md, "Texturing").
--blend-fit applies the residue model of the blend frames (docs/raster.md,
"Colour interpolation"), which is fitted, not established.
--residue prints the offsets the blend frame's first panel allows against
exact perspective-correct colour (docs/raster.md, "Colour interpolation").
--logic checks the logic operations against the blend frame's own panels.
--survey builds all eight frames under each rule variant in VARIANTS, one rule
changed at a time, and prints the number of pixels each frame then differs
by (docs/raster.md cites this table for what each frame rules out).
"""
import itertools
import math
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import buzz_ucode_dataflow as df  # noqa: E402
from buzz_ucode_disasm import records  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'root',
                    'builds', 'odydiags-6.5.15', 'usr', 'diags', 'ody')
WR_HW = '_odsy_diag_wr_hw'
FIFO = {0x110000: 'F', 0x100000: 'P'}


def elf(path):
    """Return (bytes, sections, symbols) of a big-endian ELF32 file."""
    d = open(path, 'rb').read()
    shoff, = struct.unpack_from('>I', d, 0x20)
    shentsize, shnum = struct.unpack_from('>HH', d, 0x2e)
    secs = [struct.unpack_from('>IIIIIIIIII', d, shoff + k * shentsize) for k in range(shnum)]
    syms = {}
    for s in secs:
        if s[1] != 11:              # SHT_DYNSYM
            continue
        strtab = secs[s[6]]
        for o in range(s[4], s[4] + s[5], 16):
            name, value, size = struct.unpack_from('>III', d, o)
            n = d[strtab[4] + name:d.index(b'\0', strtab[4] + name)].decode()
            syms[n] = (value, size)
    return d, [(s[3], s[4], s[5]) for s in secs if s[3]], syms


def sx(v, bits):
    return v - (1 << bits) if v >> (bits - 1) & 1 else v


def writes(path, func):
    """Follow FUNC's straight-line code and list its _odsy_diag_wr_hw calls.

    Only the instructions the generated code uses to build arguments are
    modelled; anything else makes its destination unknown. Branches are not
    followed: the clog functions are straight lines apart from local polling
    loops that make no calls to the write routine."""
    d, secs, syms = elf(path)
    start, size = syms[func]
    target = syms[WR_HW][0]
    M = (1 << 64) - 1

    def rd(addr, n):
        for a, o, s in secs:
            if a <= addr and addr + n <= a + s:
                return int.from_bytes(d[o + addr - a:o + addr - a + n], 'big')
        return None

    def off(addr):
        for a, o, s in secs:
            if a <= addr < a + s:
                return o + addr - a
        raise SystemExit(f'{addr:#x} is in no section')

    R = [None] * 32
    R[0], R[25] = 0, start          # $zero; $t9 holds the entry address
    stack, out = {}, []
    base = off(start)
    for pc in range(start, start + size, 4):
        w, = struct.unpack_from('>I', d, base + pc - start)
        op, rs, rt, rd_, sa, fn = w >> 26, w >> 21 & 31, w >> 16 & 31, w >> 11 & 31, w >> 6 & 31, w & 63
        imm = w & 0xffff
        a, b = R[rs], R[rt]
        if op == 0x0f:                                  # lui
            R[rt] = sx(imm << 16, 32) & M
        elif op == 0x0d:                                # ori
            R[rt] = None if a is None else a | imm
        elif op in (0x09, 0x19):                        # addiu, daddiu
            R[rt] = None if a is None else (a + sx(imm, 16)) & M
            if op == 0x09 and R[rt] is not None:
                R[rt] = sx(R[rt] & 0xffffffff, 32) & M
        elif op in (0x23, 0x37, 0x27):                  # lw, ld, lwu
            o = sx(imm, 16)
            if rs == 29:
                R[rt] = stack.get(o)
            elif a is not None:
                v = rd((a + o) & 0xffffffff, 8 if op == 0x37 else 4)
                R[rt] = None if v is None else (sx(v, 32) & M if op == 0x23 else v)
            else:
                R[rt] = None
        elif op in (0x2b, 0x3f):                        # sw, sd
            if rs == 29:
                stack[sx(imm, 16)] = b
        elif op == 0x03:                                # jal
            t = (pc & 0xf0000000) | (w & 0x3ffffff) << 2
            if t == target:
                out.append((pc, R[5], R[6], R[7]))
        elif op == 0 and fn in (0x21, 0x2d, 0x25):      # addu, daddu, or
            v = None if a is None or b is None else (a | b if fn == 0x25 else a + b) & M
            if fn == 0x21 and v is not None:
                v = sx(v & 0xffffffff, 32) & M
            R[rd_] = v
        elif op == 0 and fn in (0x38, 0x3c, 0x3e):      # dsll, dsll32, dsrl32
            R[rd_] = None if b is None else (
                (b << sa) if fn == 0x38 else (b << (sa + 32)) if fn == 0x3c else (b >> (sa + 32))) & M
        elif op == 0 and fn in (0x08, 0x09, 0x00) and w:  # jr, jalr, sll as nop
            if fn == 0x09:
                R[31] = None
            elif fn == 0x00:
                R[rd_] = None if b is None else sx((b << sa) & 0xffffffff, 32) & M
        elif w == 0 or op in (0x04, 0x05, 0x06, 0x07, 0x01):  # nop, branches
            pass
        else:
            for r in (rt, rd_):
                if r:
                    R[r] = None
        R[0] = 0
    return out


def stream(path, func):
    """The words reaching the two FIFO windows, doublewords high word first."""
    words = []
    for pc, addr, val, size in writes(path, func):
        if addr not in FIFO:
            continue
        if val is None:
            raise SystemExit(f'{pc:#x}: value not resolved')
        if size == 8:
            words += [(FIFO[addr], val >> 32), (FIFO[addr], val & 0xffffffff)]
        else:
            words.append((FIFO[addr], val & 0xffffffff))
    return words


def fl(w):
    return struct.unpack('>f', struct.pack('>I', w))[0]


def decode(words):
    """Split the stream into commands: (index, word, operands)."""
    i, cmds = 0, []
    while i < len(words):
        w = words[i][1]
        i0, i = i, i + 1
        top = w >> 24
        if w & 0xc000 == 0x8000 and 0x20 <= top <= 0x7f:
            cmds.append((i0, w, []))          # sequencer word, no operands
            continue
        n = (w >> 10) & 15
        n = 16 if n == 15 else n
        cmds.append((i0, w, [x[1] for x in words[i:i + n]]))
        i += n
    return cmds


def enc_val(w):
    return (w & 0x3ff) | ((w >> 23) & 1) << 10


VERTEX = {0x8080c801: 2, 0x8080cc03: 3, 0x8080d005: 4}
# Primitive types of the 0x00014400 word that the streams use (GL numbering).
POINTS, LINES, TRIANGLES, QUADS, POLYGON = 0, 1, 4, 7, 9
PER = {POINTS: 1, LINES: 2, TRIANGLES: 3, QUADS: 4}


def primitives(cmds, loads, types=(POINTS,)):
    """Yield each primitive of one of TYPES with the state it is drawn
    under. LOADS are the opcodes of the two matrix-table stores."""
    seq, table, scissor, prim = {}, [math.nan] * 68, None, None
    colour, alpha, enables, logic, tex = [math.nan] * 4, 0, 0, 3, [0.0, 0.0, 0.0]
    for idx, w, ops in cmds:
        top = w >> 24
        if w & 0xc000 == 0x8000 and 0x20 <= top <= 0x3f:
            seq[top] = enc_val(w)
        elif top == 0x90 and w & 0x3ff in loads:
            for k, o in enumerate(ops):
                if seq.get(0x34, 0) + k < 68:
                    table[seq.get(0x34, 0) + k] = fl(o)
        elif w == 0x0001081d:
            scissor = ops
        elif w == 0xc380cc23:
            tex = [fl(o) for o in ops]
        elif w == 0xc580d015:
            colour = [fl(o) for o in ops]
        elif w == 0x0001041e:
            alpha = ops[0]
        elif w == 0x00010404:
            enables = ops[0]
        elif w == 0x00010422:
            logic = ops[0]
        elif w == 0x00014400:
            prim = dict(type=ops[0], verts=[], idx=idx, seq=dict(seq),
                        regs={str(r): table[4 * r:4 * r + 4] for r in range(17)},
                        scissor=scissor, colour=list(colour), alpha=alpha,
                        enables=enables, logic=logic, cols=[], texs=[])
        elif w == 0x00014001:
            if prim and prim['type'] in types and prim['verts']:
                yield prim
            prim = None
        elif w in VERTEX and prim is not None:
            v = [fl(o) for o in ops]
            v += [0.0, 1.0][len(v) - 2:]
            prim['verts'].append(v)
            prim['colour'] = list(colour)
            prim['cols'].append(list(colour))
            prim['texs'].append(list(tex))


def snap(v, grid=256, mode='floor'):
    """A window coordinate on the rasteriser's sub-pixel grid: truncated
    toward minus infinity to 1/256 pixel (docs/raster.md, "Position
    precision"); mode 'nearest' rounds instead."""
    return (round(v * grid) if mode == 'nearest' else math.floor(v * grid)) / grid


def point_pixels(v, rule):
    """A one-pixel point: the pixel holding the position (points test)."""
    return [(math.floor(v[0]), math.floor(v[1]))]


def line_pixels(a, b, rule):
    """A one-pixel-wide line by centre sampling along the major axis: every
    column (x-major) or row (y-major) whose centre lies between the two
    ends, the other coordinate taken where the line crosses that centre
    and turned into a pixel by ceil(v) - 1, so a crossing exactly on a
    pixel edge goes to the lower pixel (rule['tie'] = 'down'), or by
    floor ('up'). rule['span'] = 'floor' instead runs from the pixel
    holding the first end to the one before the pixel holding the last."""
    (x0, y0), (x1, y1) = a, b
    dx, dy = x1 - x0, y1 - y0
    xmajor = abs(dx) >= abs(dy)
    s, e = (x0, x1) if xmajor else (y0, y1)
    if rule.get('span') == 'floor':
        step = 1 if e > s else -1
        major = range(math.floor(s), math.floor(e), step)
    else:
        lo, hi = sorted((s, e))
        major = [i for i in range(math.floor(lo) - 1, math.ceil(hi) + 1) if lo <= i + 0.5 < hi]
    minor = (lambda v: math.ceil(v) - 1) if rule.get('tie', 'down') == 'down' else math.floor
    slope = dy / dx if xmajor else dx / dy
    if 'slope' in rule:             # a slope kept to rule['slope'] fraction bits
        g = 2 ** rule['slope']
        slope = (round if rule.get('slope_round', 'nearest') == 'nearest' else math.floor)(slope * g) / g
    out = []
    for i in major:
        c = i + 0.5
        if xmajor:
            out.append((i, minor(y0 + (c - x0) * slope)))
        else:
            out.append((minor(x0 + (c - y0) * slope), i))
    return out


def triangle_pixels(v, rule):
    """Every pixel whose centre is inside the triangle (rule['sample'] =
    'corner' samples the pixel's lower-left corner instead). A centre on
    an edge is kept under rule['edge'] = 'all', dropped under 'none', and
    kept on top and left edges only under 'top-left' (the default)."""
    off = 0.0 if rule.get('sample') == 'corner' else 0.5
    (x0, y0), (x1, y1), (x2, y2) = v

    def cross(ax, ay, bx, by, px, py):
        return (bx - ax) * (py - ay) - (by - ay) * (px - ax)
    area = cross(x0, y0, x1, y1, x2, y2)
    if area == 0:
        return []
    if area < 0:
        (x1, y1), (x2, y2) = (x2, y2), (x1, y1)
    edges = [(x0, y0, x1, y1), (x1, y1, x2, y2), (x2, y2, x0, y0)]
    out = []
    for j in range(math.floor(min(y0, y1, y2)) - 1, math.ceil(max(y0, y1, y2)) + 1):
        for i in range(math.floor(min(x0, x1, x2)) - 1, math.ceil(max(x0, x1, x2)) + 1):
            keep = True
            for ax, ay, bx, by in edges:
                c = cross(ax, ay, bx, by, i + off, j + off)
                if c < 0 or c == 0 and not (
                        rule.get('edge', 'top-left') == 'all' or
                        rule.get('edge', 'top-left') == 'top-left' and (by < ay or by == ay and bx < ax)):
                    keep = False
                    break
            if keep:
                out.append((i, j))
    return out


def f32_low(v):
    """The single-precision value one step below V rounded to single, as
    a reciprocal truncated rather than rounded would leave it."""
    b, = struct.unpack('>I', struct.pack('>f', v))
    return struct.unpack('>f', struct.pack('>I', b - 1 if v > 0 else b + 1))[0]


def quad_pixels(v, rule):
    """A quadrilateral as the triangles (0, 1, 2) and (0, 2, 3)."""
    return triangle_pixels(v[:3], rule) + triangle_pixels([v[0], v[2], v[3]], rule)


RASTER = {POINTS: point_pixels, LINES: line_pixels, TRIANGLES: triangle_pixels, QUADS: quad_pixels}


def smooth(v, q, cols, px, py, shift=None):
    """The colour at the centre of pixel (PX, PY) inside triangle V (window
    positions), interpolated with perspective correction from the vertex
    colours COLS and the 1/w words Q (output word 3). SHIFT = (eps, i, j)
    moves eps of weight from vertex i to vertex j after the perspective
    division (the --blend-fit residue model, docs/raster.md)."""
    (x0, y0), (x1, y1), (x2, y2) = v
    d = (x1 - x0) * (y2 - y0) - (x2 - x0) * (y1 - y0)
    x, y = px + 0.5, py + 0.5
    l1 = ((x - x0) * (y2 - y0) - (x2 - x0) * (y - y0)) / d
    l2 = ((x1 - x0) * (y - y0) - (x - x0) * (y1 - y0)) / d
    w = [(1 - l1 - l2) * q[0], l1 * q[1], l2 * q[2]]
    b = [wi / sum(w) for wi in w]
    if shift:
        eps, i, j = shift
        b[i] -= eps
        b[j] += eps
    return [sum(b[m] * cols[m][c] for m in range(3)) for c in range(4)]


# The logic operations of block 0x022 (GL_CLEAR to GL_SET), source S and
# destination D as frame words.
LOGIC = [lambda s, d: 0, lambda s, d: s & d, lambda s, d: s & ~d, lambda s, d: s,
         lambda s, d: ~s & d, lambda s, d: d, lambda s, d: s ^ d, lambda s, d: s | d,
         lambda s, d: ~(s | d), lambda s, d: ~(s ^ d), lambda s, d: ~d, lambda s, d: s | ~d,
         lambda s, d: ~s, lambda s, d: ~s | d, lambda s, d: ~(s & d), lambda s, d: 0xffffffff]


def pack(c, rule):
    """A colour as the frame stores it: red in bits 31:24, then green, blue
    and alpha, each component as floor(256 c) limited to 255
    (rule['pack'] = 'round255' or 'floor255' for the usual alternatives)."""
    how = rule.get('pack', 'floor256')
    out = 0
    for x in c:
        x = min(max(x, 0.0), 1.0)
        if rule.get('mid'):
            # The --blend-fit residue model: the value held in steps of
            # 1/16 of an output step, as an offset from 0.5 truncated
            # toward zero (docs/raster.md, "Colour interpolation").
            x = (math.trunc((x * 256 - 128) * 16) / 16 + 128) / 256
        n = (min(255, math.floor(x * 256)) if how == 'floor256' else
             math.floor(x * 255 + 0.5) if how == 'round255' else math.floor(x * 255))
        out = out << 8 | n
    return out


def alpha_pass(a, word, rule):
    """The alpha test of block 0x01e (docs/tokens.md): bits 14:12 the GL
    comparison (NEVER to ALWAYS), bits 11:0 the reference times 4096.
    The fragment's alpha is compared as the frame stores it, floor(256 a)
    against the reference's top eight bits (rule['alpha'] = 'float'
    compares the unconverted alpha with the reference over 4096)."""
    func, ref = word >> 12 & 7, word & 0xfff
    if rule.get('alpha') == 'float':
        x, r = a, ref / 4096
    else:
        x, r = min(255, math.floor(a * 256)), ref >> 4
    return [False, x < r, x == r, x <= r, x > r, x != r, x >= r, True][func]


def crc32(data):
    """CRC-32, polynomial 0x04c11db7, most significant bit first, initial
    value all ones, no final inversion: the odydiags crcgen routine."""
    t = []
    for k in range(256):
        c = k << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04c11db7) & 0xffffffff if c & 0x80000000 else (c << 1) & 0xffffffff
        t.append(c)
    c = 0xffffffff
    for x in data:
        c = ((c << 8) & 0xffffffff) ^ t[((c >> 24) ^ x) & 0xff]
    return c


# test name: (large stream, small stream, frame and checksum-list key)
TESTS = {'points': ('__clog_pts', '__clog_pts_small', 'points', (POINTS,)),
         'lines': ('__clog_lines', '__clog_lines_small', 'lines', (LINES,)),
         'triangle': ('__clog_tri', '__clog_tri_small', 'triangle', (TRIANGLES,)),
         'alpha': ('__clog_alpha', '__clog_alpha_small', 'alpha', (QUADS,)),
         'blend': ('__clog_blend', '__clog_blend_small', 'blend', (QUADS,)),
         'checkr3d': ('__clog_chk3d', '__clog_chk3d_small', 'checkr3d', (POLYGON,))}
def build_textured(small, image, rule, log):
    """The 3D checkerboard test: three polygons through the textured
    program, each pixel taking the nearest texel of the 32 x 32 x 32 image
    the test sends by DMA (odydiags symbol texbuf), at the perspective-
    correct (s, t, r) of its centre. The program's output words for this
    stream: 3 to 5 are s, t and r times 1/w, 7 is depth, 8 and 9 are x
    and y, and the 1/w of each vertex arrives as word 6 one pass earlier.
    The stream sets GL_CLAMP on all three axes with the clamp limit at the
    whole level (32, BUZZ.h TEXMODE1); a coordinate of exactly 1.0 then
    gives texel 32, which rule['texel'] = 'wrap' (default) takes modulo
    32 and 'edge' limits to 31."""
    func, W, H, frame_file, listfile, loads = (
        ('__clog_chk3d_small', 128, 64, 'checkr3d.sml', 'csumlist.sml', (0x28d, 0x2a4)) if small else
        ('__clog_chk3d', 1280, 1024, 'checkr3d.SUM', 'csumlist', (0x1c8, 0x1df)))
    path = os.path.join(ROOT, 'odydiags')
    d, secs, syms = elf(path)
    base, size = syms['texbuf']
    off = next(o + base - a for a, o, sz in secs if a <= base < a + sz)
    texels = struct.unpack(f'>{size // 4}I', d[off:off + size])
    cmds = decode(stream(path, func))
    recs = [df.decode(w) for w in records(image)[0]]
    frame = [0] * (W * H)
    for p in primitives(cmds, loads, (POLYGON,)):
        s = p['seq']
        entries = (243, 255, 267) if small else (s[0x29], s[0x2a], s[0x2c])
        n = len(p['verts'])
        run = [f'{entries[0]}..'] + [f'{entries[1]}..'] * (n - 1) + [str(entries[2])]
        scen = dict(regs=p['regs'], slots={'5': p['colour']},
                    passes=[{'0': v, '3': t + [1.0]} for v, t in zip(p['verts'], p['texs'])])
        dom = df.Numbers(scen, {}, None)
        df.run(recs, run, dom)
        got = {}
        for k, rec, word, v in dom.emits:
            got.setdefault(k - 1, {})[word] = v
        how = rule.get('snap', 'floor')
        g = rule.get('grid', 256)
        vs = [dict(xy=(snap(got[k][8], g, how), snap(got[k][9], g, how)), q=got[k - 1][6],
                   str=[got[k][3], got[k][4], got[k][5]]) for k in range(n)]
        log(f"; polygon at word {p['idx']}: entries {' '.join(run)}; "
            + '; '.join(f"({v['xy'][0]:.3f}, {v['xy'][1]:.3f}) 1/w {v['q']:.6g}" for v in vs))
        x0, x1 = p['scissor'][0] >> 12 & 0xfff, p['scissor'][0] & 0xfff
        y0, y1 = p['scissor'][1] >> 12 & 0xfff, p['scissor'][1] & 0xfff

        def texel(u):
            i = math.floor(min(max(u, 0.0), 1.0) * 32)
            return i % 32 if rule.get('texel', 'wrap') == 'wrap' else min(i, 31)
        for t in [(0, k, k + 1) for k in range(1, n - 1)]:
            tri = [vs[m]['xy'] for m in t]
            for px, py in triangle_pixels(tri, rule):
                if not (x0 <= px <= x1 and y0 <= py <= y1 and 0 <= px < W and 0 <= py < H):
                    continue
                # Each of s q, t q, r q and q as a plane through the
                # three vertices, from the first vertex's value and the
                # x and y gradients, evaluated at the pixel centre and
                # divided. In this form a coordinate that is the same at
                # all three vertices (r here) comes out exactly, as
                # checkr3d.sml requires of r = 0.5 and r = 1.
                (ax, ay), (bx, by), (cx, cy) = tri
                dd = (bx - ax) * (cy - ay) - (cx - ax) * (by - ay)
                x, y = px + 0.5, py + 0.5
                val = []
                for c in range(4):
                    a0, a1, a2 = (vs[t[m]]['str'][c] if c < 3 else vs[t[m]]['q'] for m in range(3))
                    gx = ((a1 - a0) * (cy - ay) - (a2 - a0) * (by - ay)) / dd
                    gy = ((a2 - a0) * (bx - ax) - (a1 - a0) * (cx - ax)) / dd
                    val.append(a0 + gx * (x - ax) + gy * (y - ay))
                u = [val[c] / val[3] for c in range(3)]
                if rule.get('r_low'):
                    u[2] = min(u[2], 1.0 - 1e-6)
                frame[(H - 1 - py) * W + px] = texels[texel(u[0]) + 32 * texel(u[1]) + 1024 * texel(u[2])]
    stored = struct.unpack(f'>{W * H}I', open(os.path.join(ROOT, 'checksum', frame_file), 'rb').read())
    want = dict(l.split() for l in open(os.path.join(ROOT, 'checksum', listfile)) if l.strip())['checkr3d']
    return W, H, frame, stored, want, frame_file, listfile


# The tests whose frames the rules rebuild with the CRC matching; the
# survey runs these.
MATCHED = ('points', 'lines', 'triangle', 'alpha')
# The program the 128 x 64 streams name sits where no held image has it;
# --survey substitutes the held one (pass 18).
HELD_PROGRAM = (214, 224, 234)


def build(test, small, image, rnd=None, prog=None, rule=None, log=print, drawn=None):
    """Replay TEST's stream and return (width, height, frame, stored frame,
    csumlist value)."""
    rule = rule or {}
    if test == 'checkr3d':
        return build_textured(small, image, rule, log)
    func, func_small, key, types = TESTS[test]
    # The matrix-table stores are routine entries 456 and 479 in the
    # images held (buzz_isa.md); the 128 x 64 stream was recorded under a
    # build whose every entry opcode sits 197 higher (pass 18).
    func, W, H, frame_file, listfile, loads = (
        (func_small, 128, 64, key + '.sml', 'csumlist.sml', (0x28d, 0x2a4)) if small else
        (func, 1280, 1024, key + '.SUM', 'csumlist', (0x1c8, 0x1df)))
    words = stream(os.path.join(ROOT, 'odydiags'), func)
    cmds = decode(words)
    recs = [df.decode(w) for w in records(image)[0]]
    frame = [0] * (W * H)
    log(f'; {func}: {len(words)} FIFO words; image {os.path.basename(image)}; round {rnd}')
    for p in primitives(cmds, loads, types):
        s = p['seq']
        if prog:
            s = {0x29: prog[0], 0x2a: prog[1], 0x2c: prog[2]}
        n = len(p['verts'])
        entries = [f"{s[0x29]}.."] + [f"{s[0x2a]}.."] * (n - 1) + [str(s[0x2c])]
        scen = dict(regs=p['regs'], slots={'5': p['colour']},
                    passes=[{'0': v} for v in p['verts']])
        dom = df.Numbers(scen, {}, rnd)
        df.run(recs, entries, dom)
        # A pass outputs the vertex before it (buzz_routines.md, routine 214).
        got = {}
        for k, rec, word, v in dom.emits:
            got.setdefault(k - 1, {})[word] = v
        # Block 0x01d's operands read as x and y ranges, low end in bits
        # 23:12 and high end in 11:0 (inferred from the four quadrant
        # boxes this stream sends).
        x0, x1 = p['scissor'][0] >> 12 & 0xfff, p['scissor'][0] & 0xfff
        y0, y1 = p['scissor'][1] >> 12 & 0xfff, p['scissor'][1] & 0xfff
        log(f"; primitive at word {p['idx']}: entries {' '.join(entries)}; scissor x {x0}-{x1} y {y0}-{y1}")
        if not alpha_pass(p['colour'][3], p['alpha'], rule):
            log(f"; alpha test word {p['alpha']:#06x} rejects alpha {p['colour'][3]!r}")
            continue
        value = pack(p['colour'], rule)
        win, qs = [], []
        for k, v in enumerate(p['verts']):
            o = got.get(k, {})
            x, y = o.get(5, math.nan), o.get(6, math.nan)
            if math.isnan(x) or math.isnan(y):
                log(f'vertex {v}: words {o}: no position')
                win.append(None)
                continue
            if test == 'points':
                px, py = math.floor(x), math.floor(y)
                inside = x0 <= px <= x1 and y0 <= py <= y1 and 0 <= px < W and 0 <= py < H
                log(f'vertex {[f"{c:g}" for c in v]}: word 5 = {x!r}, word 6 = {y!r}, '
                    f'1/w = {o.get(3, math.nan)!r} -> pixel ({px}, {py}){"" if inside else " clipped"}')
            else:
                log(f'vertex {[f"{c:g}" for c in v]}: word 5 = {x!r}, word 6 = {y!r}')
            if rule.get('low'):
                x, y = f32_low(x), f32_low(y)
            qs.append(o.get(3, math.nan))
            win.append((snap(x, rule.get('grid', 256), rule.get('snap', 'floor')),
                        snap(y, rule.get('grid', 256), rule.get('snap', 'floor'))))
        per = PER[p['type']]
        # Block 0x004 bit 17 with the stream's blend state applies the
        # logic operation of block 0x022 (docs/raster.md, "Logic operations").
        op = LOGIC[p['logic'] & 15] if p['enables'] >> 17 & 1 else None
        flat = all(c == p['cols'][0] for c in p['cols'])
        covered = set()
        if drawn is not None:
            drawn.append((p, covered))
        for k in range(0, n - per + 1, per):
            vs = win[k:k + per]
            if None in vs:
                continue
            # Quads interpolate as their two triangles (0, 1, 2), (0, 2, 3).
            tris = ([(0, 1, 2)] if per == 3 else [(0, 1, 2), (0, 2, 3)]) if per >= 3 else [None]
            for t in tris:
                if t is None:
                    pixels = RASTER[p['type']](*vs, rule)
                else:
                    pixels = triangle_pixels([vs[m] for m in t], rule)
                for px, py in pixels:
                    if not (x0 <= px <= x1 and y0 <= py <= y1 and 0 <= px < W and 0 <= py < H):
                        continue
                    # --blend-fit: weight moves from the quad's third
                    # vertex to the other vertex that is not the first.
                    shift = None
                    if 'shift' in rule and t is not None:
                        shift = (rule['shift'], 2, 1) if t == (0, 1, 2) else (rule['shift'], 1, 2)
                    c = value if flat or t is None else pack(smooth(
                        [vs[m] for m in t], [qs[k + m] for m in t], [p['cols'][k + m] for m in t],
                        px, py, shift), rule)
                    at = (H - 1 - py) * W + px
                    covered.add((px, py))
                    frame[at] = c if op is None else op(c, frame[at]) & 0xffffffff
    stored = struct.unpack(f'>{W * H}I', open(os.path.join(ROOT, 'checksum', frame_file), 'rb').read())
    want = dict(l.split() for l in open(os.path.join(ROOT, 'checksum', listfile)) if l.strip())[key]
    return W, H, frame, stored, want, frame_file, listfile


# Alternatives to the rules the matching frames use, each changing one rule
# (docs/raster.md). The survey prints how many pixels each moves.
VARIANTS = [
    ('as matched', {}),
    ('line: ties to the upper pixel', dict(tie='up')),
    ('line: run from the pixel holding the first end', dict(span='floor')),
] + [(f'line: slope to nearest 1/{2 ** n}', dict(slope=n)) for n in (6, 8, 10, 12, 14)] + [
    (f'line: slope floored to 1/{2 ** n}', dict(slope=n, slope_round='floor')) for n in (8, 12, 16)] + [
    ('colour: round(255 c)', dict(pack='round255')),
    ('colour: floor(255 c)', dict(pack='floor255')),
    ('alpha test: unconverted alpha against reference / 4096', dict(alpha='float')),
    ('triangle: sample the lower-left corner', dict(sample='corner')),
    ('triangle: keep every edge centre', dict(edge='all')),
    ('triangle: drop every edge centre', dict(edge='none')),
    ('texture: index 32 limited to 31', dict(texel='edge')),
    ('positions unrounded', dict(grid=2 ** 40)),
    ('positions one single step low, unrounded', dict(grid=2 ** 40, low=True)),
    ('positions one single step low, to nearest 1/256', dict(low=True, snap='nearest')),
    ('positions one single step low, truncated 1/256', dict(low=True)),
    ('positions one single step low, truncated 1/16', dict(low=True, grid=16, snap='floor')),
] + [(f'positions to nearest 1/{2 ** n}', dict(grid=2 ** n, snap='nearest')) for n in (0, 1, 2, 4, 6, 7, 8, 10)] + [
    (f'positions truncated to 1/{2 ** n}', dict(grid=2 ** n, snap='floor')) for n in (0, 1, 2, 3, 4, 7, 8, 9, 10, 16)]


def survey(image, rnd):
    print('; pixels differing from the stored frame, per rule variant; "=" marks a CRC match')
    cols = [(t, sm) for t in MATCHED for sm in (False, True)] + [('checkr3d', True)]
    print('; ' + ' | '.join(f"{t}{' 128x64' if sm else ''}" for t, sm in cols))
    for name, rule in VARIANTS:
        cells = []
        for t, sm in cols:
            W, H, frame, stored, want, _, _ = build(t, sm, image, rnd, HELD_PROGRAM if sm else None,
                                                   rule, log=lambda *a: None)
            n = sum(1 for a, b in zip(frame, stored) if a != b)
            ok = f'{crc32(struct.pack(f">{W * H}I", *frame)):08x}' == want
            cells.append(f"{n}{'=' if ok else ''}")
        print(f"{name:45s} " + ' '.join(f'{c:>7s}' for c in cells))


def logic_check(image):
    """Test the logic operations against the blend frame itself. Each panel
    of __clog_blend draws the same two quads, the second under one logic
    operation; the panel drawn with GL_COPY holds the source words and the
    one drawn with GL_NOOP the destination words, both as the simulator
    interpolated them. Every other panel should then hold op(source,
    destination) where the second quad covers and the destination
    elsewhere. Prints the differing pixels per operation, and how many of
    them a source one step away in some byte explains."""
    drawn = []
    W, H, _, stored, _, _, _ = build('blend', False, image, drawn=drawn, log=lambda *a: None)
    quads = [(p, c) for p, c in drawn if p['type'] == QUADS and c]
    panels = [(quads[k + 1][0]['logic'], min(quads[k][1])) for k in range(0, len(quads), 2)]
    # Panel origins: the first quad's lowest covered pixel, relative to the first panel's.
    first = panels[0][1]
    origin = {op: (o[0] - first[0], o[1] - first[1]) for op, o in panels[1:]}
    cover = quads[1][1]

    def at(op, x, y):
        dx, dy = origin[op]
        return stored[(H - 1 - (y + dy)) * W + x + dx]
    xs = range(min(x for x, _ in quads[0][1] | cover), max(x for x, _ in quads[0][1] | cover) + 1)
    ys = range(min(y for _, y in quads[0][1] | cover), max(y for _, y in quads[0][1] | cover) + 1)
    print('; panel origins relative to the first:', {op: origin[op] for op in sorted(origin)})
    for op in sorted(origin):
        bad = explained = 0
        for x in xs:
            for y in ys:
                s_, d = at(3, x, y), at(5, x, y)
                want = LOGIC[op](s_, d) & 0xffffffff if (x, y) in cover else d
                got = at(op, x, y)
                if want == got:
                    continue
                bad += 1
                bs = [s_ >> b & 255 for b in (24, 16, 8, 0)]
                for e in itertools.product((-1, 0, 1), repeat=4):
                    nb = [a + b for a, b in zip(bs, e)]
                    if all(0 <= a <= 255 for a in nb) and (x, y) in cover and \
                            LOGIC[op](int.from_bytes(bytes(nb), 'big'), d) & 0xffffffff == got:
                        explained += 1
                        break
        print(f'; logic operation {op}: {len(xs) * len(ys)} pixels, {bad} differ, '
              f'{explained} of them explained by a source one step off in some byte')


def residue(image):
    """The blend frame's first panel against exact perspective-correct
    colour: for each of its four triangles and each component, the range
    of offsets (in output steps) that every stored byte allows, split at
    the value 0.5 (docs/raster.md, "Colour interpolation")."""
    global smooth
    tris, plain = [], smooth

    def record(v, q, cols, px, py, shift=None):
        if len(tris) < 4 and (v, q) not in [(a, b) for a, b, _ in tris]:
            tris.append((v, q, cols))
        return plain(v, q, cols, px, py, shift)
    smooth = record
    try:
        W, H, _, stored, _, _, _ = build('blend', False, image, log=lambda *a: None)
    finally:
        smooth = plain
    owner = {}
    for k, (v, q, cols) in enumerate(tris):
        for pix in triangle_pixels(v, {}):
            owner[pix] = k
    print('; blend.SUM first panel: offset range allowed per triangle (quad, split), component and value range')
    print(f'; {len(owner)} pixels')
    for k, (v, q, cols) in enumerate(tris):
        for c in range(4):
            for lo_half in (True, False):
                lo, hi, n = -9.0, 9.0, 0
                for (px, py), kk in owner.items():
                    if kk != k:
                        continue
                    e = plain(v, q, cols, px, py)[c] * 256
                    byte = stored[(H - 1 - py) * W + px] >> (24 - 8 * c) & 255
                    if (e < 128) != lo_half or byte == 255:
                        continue
                    lo, hi, n = max(lo, byte - e), min(hi, byte + 1 - e), n + 1
                if n:
                    print(f"quad {k // 2 + 1} triangle {('(0, 1, 2)', '(0, 2, 3)')[k % 2]} "
                          f"component {'RGBA'[c]} value {'below' if lo_half else 'from'} 0.5: "
                          f"{n:5d} pixels, offset in [{lo:+.4f}, {hi:+.4f})" + ('  none fits' if lo > hi else ''))


def main():
    args = sys.argv[1:]
    rnd, small, dump, prog, test, do_survey = None, False, False, None, 'points', False
    rule_cli = {}
    image = os.path.join(ROOT, 'ucode', 'diagxform.bin')
    while args:
        a = args.pop(0)
        if a == '--round':
            rnd = args.pop(0)
        elif a == '--small':
            small = True
        elif a == '--image':
            image = args.pop(0)
        elif a == '--dump':
            dump = True
        elif a == '--program':
            prog = [int(x) for x in args.pop(0).split(',')]
        elif a == '--r-low':
            rule_cli['r_low'] = True
        elif a == '--texel-edge':
            rule_cli['texel'] = 'edge'
        elif a == '--blend-fit':
            rule_cli.update(mid=True, shift=0.06 / 256)
        elif a == '--test' and args and args[0] in TESTS:
            test = args.pop(0)
        elif a == '--survey':
            do_survey = True
        elif a == '--logic':
            logic_check(image)
            return
        elif a == '--residue':
            residue(image)
            return
        else:
            sys.exit(__doc__)
    if do_survey:
        survey(image, rnd)
        return
    if dump:
        func = TESTS[test][1 if small else 0]
        words = stream(os.path.join(ROOT, 'odydiags'), func)
        for idx, w, ops in decode(words):
            print(f"{idx:5d} {words[idx][0]} {w:08x} {' '.join(f'{o:x}' for o in ops)}")
        return
    W, H, frame, sw, want, frame_file, listfile = build(test, small, image, rnd, prog, rule_cli)
    data = struct.pack(f'>{W * H}I', *frame)
    stored = struct.pack(f'>{W * H}I', *sw)
    diff = [(k % W, H - 1 - k // W, sw[k], frame[k]) for k in range(W * H) if sw[k] != frame[k]]
    print(f'; CRC-32 of built frame {crc32(data):08x}; {listfile} {TESTS[test][2]} {want}; '
          f'CRC-32 of {frame_file} {crc32(stored):08x}')
    print(f'; pixels differing from {frame_file}: {len(diff)}')
    for x, y, a, b in diff[:20]:
        print(f';   window ({x}, {y}): stored {a:08x}, built {b:08x}')


if __name__ == '__main__':
    main()
