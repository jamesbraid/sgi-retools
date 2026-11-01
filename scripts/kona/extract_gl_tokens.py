#!/usr/bin/env python3
# Copyright (c) 2026, Dominik Behr. BSD 3-Clause; see scripts/LICENSE-gr4.
# Adapted from scripts/extract_gl_tokens.py in https://github.com/techomancer/gr4 for the KONA
# workspace; board-specific tables were removed.
"""Map OpenGL command-processor tokens to the libGLcore functions that send
them: the first command word each decompiled function stores to the
command FIFO.

Usage: extract_gl_tokens.py DECOMP_DIR FIFO_ADDR [SHIFT MASK]
  DECOMP_DIR  directory of m2c output, e.g. libglcore/decomp/<category>
  FIFO_ADDR   the FIFO register address you found
  SHIFT MASK  how the token is carved out of the word (default: whole word)
The token layout is board-specific; take it from your own findings."""
import re,sys,glob,collections,struct
fn_re=re.compile(r'^[A-Za-z_][\w \*]*?\b(\w+)\(.*\)\s*\{\s*$')
if len(sys.argv)<3: sys.exit(__doc__)
SHIFT=int(sys.argv[3],0) if len(sys.argv)>4 else 0
MASK=int(sys.argv[4],0) if len(sys.argv)>4 else 0xFFFFFFFF
wr_re=re.compile(r'\*\([^)]*\)\s*'+re.escape(hex(int(sys.argv[2],0)))+r'\s*=\s*([^;]+);')
def word(v):
    v=v.strip()
    v=re.sub(r'^\([^)]*\)\s*','',v)
    try:
        if v.endswith('f') and ('.' in v or 'e' in v):
            x=float(v[:-1]); b=round(x/2**-149)
            return b if b < 0x800000 else struct.unpack('>I',struct.pack('>f',x))[0]
        return int(v,0)
    except ValueError:
        return None
tok=collections.defaultdict(set)
for f in sorted(glob.glob(sys.argv[1]+'/*.c')):
    cur=None; seen=False
    for line in open(f,errors='replace'):
        m=fn_re.match(line)
        if m: cur=m.group(1); seen=False; continue
        if cur and not seen:
            w=wr_re.search(line)
            if w:
                seen=True
                v=word(w.group(1))
                if v is not None:
                    tok[(v>>SHIFT)&MASK].add((cur, v))
for t in sorted(tok):
    names=sorted(tok[t])
    print(f"0x{t:x}  " + ", ".join(f"{n}[0x{b:x}]" for n,b in names[:4]) + (f" (+{len(names)-4})" if len(names)>4 else ""))
