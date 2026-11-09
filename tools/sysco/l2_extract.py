#!/usr/bin/env python3
"""Carve the kernel and the big-endian cramfs out of an L2 image.

usage: l2_extract.py l2.bin OUTDIR [--list FILE]

Writes OUTDIR/kernel.bin (the gunzipped Linux image) and OUTDIR/rootfs/ (the
cramfs tree). Needs nothing outside the standard library. The cramfs layout is
the public one: a 64-byte superblock, 12-byte inodes (mode and uid; size and
gid; name length and data offset in words), and per-block zlib streams
addressed through a table of end offsets.
"""
import hashlib
import os
import struct
import sys
import zlib

MAGIC = bytes.fromhex("28cd3d45")


def carve(path, out):
    d = open(path, "rb").read()
    os.makedirs(out, exist_ok=True)
    g = d.find(b"\x1f\x8b\x08")
    dec = zlib.decompressobj(16 + 15)
    kern = dec.decompress(d[g:])
    gz_end = len(d) - len(dec.unused_data)
    open(os.path.join(out, "kernel.bin"), "wb").write(kern)
    base = d.find(MAGIC, gz_end)
    # Every offset inside this cramfs counts from 512 bytes before the
    # superblock, so keep those bytes in front of the slice.
    cram = d[base - 512:]
    magic, size, flags, _future = struct.unpack(">4I", cram[512:528])
    print("kernel gzip at 0x%x..0x%x, %d bytes" % (g, gz_end, len(kern)))
    print("cramfs at 0x%x, size field %d, flags 0x%x" % (base, size, flags))
    root = os.path.join(out, "rootfs")
    rows = []
    walk(cram, 512 + 64, root, 0, "", rows)
    if "--list" in sys.argv:
        with open(sys.argv[sys.argv.index("--list") + 1], "w") as f:
            f.write("path\tkind\tmode\tsize\tsha256\ttarget\n")
            for r in sorted(rows):
                f.write("\t".join(r) + "\n")


def inode(cram, off):
    mode, uid = struct.unpack(">HH", cram[off:off + 4])
    sg, = struct.unpack(">I", cram[off + 4:off + 8])
    no, = struct.unpack(">I", cram[off + 8:off + 12])
    return mode, uid, sg >> 8, sg & 0xff, no >> 26, (no & 0x3ffffff) * 4


def data(cram, size, offset):
    nblk = (size + 4095) // 4096
    if size == 0:
        return b""
    ends = struct.unpack(">%dI" % nblk, cram[offset:offset + 4 * nblk])
    pos = offset + 4 * nblk
    out = b""
    for e in ends:
        chunk = cram[pos:e]
        out += zlib.decompress(chunk) if chunk else b""
        pos = e
    return out[:size]


def walk(cram, ioff, path, depth, rel, rows):
    mode, uid, size, gid, nlen, off = inode(cram, ioff)
    os.makedirs(path, exist_ok=True)
    pos = off
    end = off + size
    while pos < end:
        m, u, s, g, nl, o = inode(cram, pos)
        name = cram[pos + 12:pos + 12 + nl * 4].rstrip(b"\0").decode("latin1")
        p = os.path.join(path, name)
        r = rel + "/" + name
        kind = m & 0o170000
        if kind == 0o040000:
            rows.append((r, "dir", "%o" % (m & 0o7777), "", "", ""))
            walk(cram, pos, p, depth + 1, r, rows)
        elif kind == 0o120000:
            tgt = data(cram, s, o).decode("latin1")
            rows.append((r, "symlink", "%o" % (m & 0o7777), "", "", tgt))
            try:
                os.symlink(tgt, p)
            except FileExistsError:
                pass
        elif kind == 0o100000:
            blob = data(cram, s, o)
            rows.append((r, "file", "%o" % (m & 0o7777), str(len(blob)), hashlib.sha256(blob).hexdigest(), ""))
            open(p, "wb").write(blob)
            os.chmod(p, m & 0o7777)
        else:
            label = {0o020000: "chr", 0o060000: "blk", 0o010000: "fifo", 0o140000: "sock"}.get(kind, "other")
            rows.append((r, label, "%o" % (m & 0o7777), "", "",
                         "%d,%d" % (s >> 8, s & 0xff) if label in ("chr", "blk") else ""))
            # cramfs keeps st_rdev of a device node in the size field
            open(p + ".node", "w").write("mode %o rdev %d,%d\n" % (m, s >> 8, s & 0xff))
        pos += 12 + nl * 4


if __name__ == "__main__":
    carve(sys.argv[1], sys.argv[2])
