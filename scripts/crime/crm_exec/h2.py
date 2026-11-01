from mips import *
import struct,random,collections
GP=0x5b0ea0
class Env:
    def __init__(s,bpp=8,W=64,H=64,pitch=None):
        c=s.c=CPU()
        s.bpp=bpp;s.W=W;s.H=H;s.pitch=pitch or W*bpp//8
        c.w32(GP-26136,1)
        for off,val in {-26088:2,-25908:2,-25920:2,-25900:2,-25904:3,-25916:3}.items(): c.w32(GP+off,val)
        s.S=c.alloc(1024);s.P=c.alloc(256);s.D=c.alloc(64);s.GC=c.alloc(512);s.G=c.alloc(256)
        s.DP=c.alloc(64);s.GCP=c.alloc(64);s.WP=c.alloc(256);s.R=c.alloc(32);s.RD=c.alloc(8+8*64)
        s.fb=c.alloc(s.pitch*H+64)
        c.w32(s.S+116,s.P);c.w32(s.S+436,s.DP);c.w32(s.DP+4,0);c.w32(s.DP+12,s.P)
        c.w32(s.P+28,s.pitch);c.w32(s.P+32,s.fb)
        c.put(s.P+12,struct.pack('>HH',W,H))
        c.w32(s.D+16,s.S)
        c.w32(s.GC+76,s.GCP);c.w32(s.GCP+8,s.G);c.w32(s.G+8,s.R)
    def bias(s,b): s.c.w32(s.DP+4,b)
    def setclip(s,boxes):
        c=s.c
        if len(boxes)==1:
            c.put(s.R,struct.pack('>hhhh',*boxes[0])); c.w32(s.R+8,0)
        else:
            xs=[b[0] for b in boxes]+[b[2] for b in boxes];ys=[b[1] for b in boxes]+[b[3] for b in boxes]
            c.put(s.R,struct.pack('>hhhh',min(xs),min(ys),max(xs),max(ys))); c.w32(s.R+8,s.RD)
            c.w32(s.RD,64);c.w32(s.RD+4,len(boxes))
            for i,b in enumerate(boxes): c.put(s.RD+8+8*i,struct.pack('>hhhh',*b))
    def clear(s,v=0): s.c.put(s.fb,bytes([v])*(s.pitch*s.H+64))
    def img(s): return s.c.bytes(s.fb,s.pitch*s.H)
