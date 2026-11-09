#!/usr/bin/env python3
"""Map OpenGL command-processor tokens to the libGLcore functions that send
them: the first command word each decompiled function stores to the
command FIFO (0x74080). Usage: extract_gl_tokens.py libglcore/decomp/MGRAS"""
import re,sys,glob,collections,struct
fn_re=re.compile(r'^[A-Za-z_][\w \*]*?\b(\w+)\(.*\)\s*\{\s*$')
wr_re=re.compile(r'\*\([^)]*\)\s*0x74080\s*=\s*([^;]+);')
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
                if v is not None and v < 0x200000 and not v & 0x80000000:
                    tok[(v>>8)&0x1FFF].add((cur, v&0xFF))
for t in sorted(tok):
    names=sorted(tok[t])
    print(f"0x{t:03x}  " + ", ".join(f"{n}[{b}]" for n,b in names[:4]) + (f" (+{len(names)-4})" if len(names)>4 else ""))
