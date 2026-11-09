#!/usr/bin/env python3
"""Print the blend-control state each quad of the blend test is drawn under.

Usage: scripts/odydiags_blend_state.py DUMP [DUMP ...]
       ODYDIAGS_STREAMS=DIR scripts/odydiags_blend_state.py

Each DUMP is a decoded command stream of the blend test, as written by
odydiags_frame_check.py --dump (one line per command: index, flag, word,
operands). With ODYDIAGS_STREAMS set and no DUMP given, the streams are
read from DIR/blend-1280x1024.dump.txt and DIR/blend-128x64.dump.txt.

For every quad the script prints the block 0x004 word and its bit 17 (blending
in use), the first operand of block 0x021 (word 0x00010c21) and the block 0x022
logic operation (word 0x00010422), each as the value in effect at the quad's
begin. The test draws nine panels of two quads each, so quad 2k and 2k+1 are
panel k; panel 0 draws no logic operation. The panel numbers are the quad
order, not positions read from the vertices. The state is checked against the
primitive reader of odydiags_frame_check.py, and any disagreement is printed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import odydiags_frame_check as m  # noqa: E402

GL_LOGIC = ['CLEAR', 'AND', 'AND_REVERSE', 'COPY', 'AND_INVERTED', 'NOOP', 'XOR', 'OR']
WORD_ENABLE, WORD_CONTROL, WORD_LOGIC = 0x00010404, 0x00010c21, 0x00010422
BEGIN, END = 0x00014400, 0x00014001
QUADS = 7


def read_dump(path):
    cmds = []
    with open(path) as f:
        for line in f:
            t = line.split()
            cmds.append((int(t[0]), int(t[2], 16), [int(x, 16) for x in t[3:]]))
    return cmds


def quads(cmds):
    """(quad number, begin index, block 0x004 word, block 0x021 operand, block 0x022 word)
    for each quad that has vertices, as the primitive reader counts them."""
    enable, control, logic = 0, None, None
    out, cur, verts = [], None, 0
    for idx, w, ops in cmds:
        if w in m.VERTEX and cur is not None:
            verts += 1
        elif w == WORD_ENABLE:
            enable = ops[0]
        elif w == WORD_CONTROL:
            control = ops[0]
        elif w == WORD_LOGIC:
            logic = ops[0]
        elif w == BEGIN:
            cur, verts = (idx, ops[0], enable, control, logic), 0
        elif w == END and cur is not None:
            if cur[1] == QUADS and verts:
                out.append(cur)
            cur = None
    return [(k, i, e, c, l) for k, (i, _, e, c, l) in enumerate(out)]


def check(cmds, rows):
    """Compare the state with the primitive reader's view of the same quads."""
    prims = [p for p in m.primitives(cmds, (0x1c8, 0x1df), (QUADS,))]
    bad = 0
    if len(prims) != len(rows):
        print(f'; primitive reader found {len(prims)} quads, this reader {len(rows)}')
        return 1
    for (k, i, e, c, l), p in zip(rows, prims):
        if p['idx'] != i or p['enables'] != e or p['logic'] != l:
            bad += 1
            print(f'; quad {k}: reader disagrees ({p["idx"]}, {p["enables"]:#x}, {p["logic"]})')
    return bad


def report(path, cmds):
    rows = quads(cmds)
    print(f'{os.path.basename(path)}: {len(rows)} quads')
    print('quad  panel  begin  block 0x004  bit 17  block 0x021  block 0x022  logic operation')
    for k, i, e, c, l in rows:
        name = GL_LOGIC[l] if l is not None and e >> 17 & 1 else '-'
        print(f'{k:4d}  {k // 2:5d}  {i:5d}  {e:#011x}  {e >> 17 & 1:6d}  '
              f'{"-" if c is None else f"{c:#011x}"}  '
              f'{"-" if l is None else f"{l:#011x}"}  {name}')
    bad = check(cmds, rows)
    print(f'; {bad} quad(s) disagree with the primitive reader' if bad else
          '; state agrees with the primitive reader for every quad')
    print()
    return bad


def main():
    paths = sys.argv[1:]
    if not paths and os.environ.get('ODYDIAGS_STREAMS'):
        d = os.environ['ODYDIAGS_STREAMS']
        paths = [os.path.join(d, 'blend-1280x1024.dump.txt'), os.path.join(d, 'blend-128x64.dump.txt')]
    if not paths:
        sys.exit(__doc__)
    bad = 0
    for path in paths:
        bad += report(path, read_dump(path))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
