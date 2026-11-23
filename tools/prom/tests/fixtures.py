"""Synthetic containers for the tests. Every byte is invented here; no SGI image is read or copied."""
import gzip
import random
import struct


MARK_RODATA, MARK_DATA = 0x726f6461, 0x64617461


def _words(n, seed):
    return [random.Random(seed + i).getrandbits(32) for i in range(n)]


def balanced(words):
    """words plus one word that makes the 32-bit sum zero."""
    return words + [-sum(words) & 0xffffffff]


def shdr(name, version, body, kind=0):
    """An O2 flash segment: a 0x40-byte header (branch, SHDR, length, name, version, balance word) and the body
    words plus a last word that balances them."""
    body = balanced(body)
    head = bytearray(0x40)
    struct.pack_into('>IIII', head, 0, 0x10000011, 0, 0x53484452, 0x40 + 4 * len(body))
    head[0x10:0x13] = bytes([len(name), len(version), kind])
    head[0x14:0x14 + len(name)] = name.encode()
    head[0x34:0x34 + len(version)] = version.encode()
    struct.pack_into('>I', head, 0x3c, -sum(struct.unpack_from('>15I', head)) & 0xffffffff)
    return bytes(head) + struct.pack('>%dI' % len(body), *body)


def firmware_segment(chunks=(0x400, 0x200, 0x100)):
    """A firmware segment with the O2's load map: the first record at +0x40 inside the text chunk, each later record
    where the previous chunk ends with its chunk 8 bytes after it, then a zero-length closing record and the balance.
    The second and third chunks start with the markers MARK_RODATA and MARK_DATA."""
    base = 0x81000000
    rec2 = chunks[0]
    rec3 = rec2 + 8 + chunks[1]
    end = rec3 + 8 + chunks[2]
    words = _words(end // 4 + 2, 100)

    def put(off, *values):
        words[off // 4:off // 4 + len(values)] = values

    put(0x40, base, chunks[0])
    put(rec2, base + chunks[0], chunks[1])
    put(rec2 + 8, MARK_RODATA)
    put(rec3, base + chunks[0] + chunks[1], chunks[2])
    put(rec3 + 8, MARK_DATA)
    put(end, base, 0)
    return shdr('firmware', '1.0', words[0x10:], kind=3)


def o2_flash(firmware=None):
    parts = [shdr('sloader', '1.0', _words(0x3f0, 1)), shdr('env', '1.0', [0] * 0xef),
             shdr('post1', '1.0', _words(0x40, 2)), firmware or firmware_segment(),
             shdr('version', '1.0', _words(8, 3))]
    flash = b''
    for p in parts:
        flash += b'\0' * (-len(flash) % 0x200) + p
    return flash


def installer(flash):
    head = b'PROM' + struct.pack('>III', 0, 0x4400, len(flash)).ljust(0xfc, b'\0')
    return head + flash


def halfword_sum(data):
    data += b'\0' * (len(data) & 1)
    return sum(struct.unpack('>%dH' % (len(data) // 2), data)) & 0xffffffff


def jfk4(payload, load=0x81800000, build=109):
    return b'JFK4' + struct.pack('>IIIII', halfword_sum(payload), load, len(payload), load, build) + payload


def compress_z(data, clear_when_full=False):
    """compress(1) output, block mode, 16-bit maximum. With clear_when_full the table is cleared (code 256) once
    its 65536 entries are used, as compress does when it stops paying; otherwise no clear code is written."""
    out, group, table = bytearray(b'\x1f\x9d\x90'), [], {}
    nbits, free = 9, 257

    def flush(full):
        bits = 0
        for i, c in enumerate(group):
            bits |= c << (i * nbits)
        out.extend(bits.to_bytes(nbits if full else (len(group) * nbits + 7) // 8, 'little'))
        group.clear()

    def emit(code):
        nonlocal nbits
        group.append(code)
        if len(group) == 8:
            flush(True)
        if free > (1 << nbits) - 1 and nbits < 16:      # the next entry needs a wider code: pad the group out
            if group:
                flush(True)
            nbits += 1

    ent = data[0]
    for c in data[1:]:
        if (ent, c) in table:
            ent = table[(ent, c)]
            continue
        emit(ent)
        if free < 65536:
            table[(ent, c)] = free
            free += 1
        elif clear_when_full:
            emit(256)
            if group:
                flush(True)
            table.clear()
            nbits, free = 9, 257
        ent = c
    emit(ent)
    flush(False)
    return bytes(out)


def lzw_payload(data, pad=0, pad_byte=b'\0'):
    """pad extra bytes are compressed after the data without being counted in its header (the stream decodes longer)."""
    return b'_LZW' + struct.pack('>III', len(data), sum(data) & 0xffffffff, 1) + compress_z(data + pad_byte * pad)


def jksw(payloads, loader=b'LOADER-' * 40, **pad):
    """An IO4 segmented container: header, SEG2 table (offsets biased by 0xce0), loader at 0x320, payloads."""
    bias = 0xce0
    segs = [(0xff01, loader, 0xa800000001b00000, 0xa800000001b00110)]
    segs += [(sid, lzw_payload(body, **pad), 0xa800000001800000, 0xa800000001801000) for sid, body in payloads]
    table, blob = b'SEG2' + struct.pack('>I', len(segs)), b''
    off = 0x320
    for sid, stored, load, entry in segs:
        table += struct.pack('>IIQQII', sid, off + bias, entry, load, len(stored), halfword_sum(stored)) + bytes(16)
        blob += stored
        off += len(stored)
    head = b'JKSW' + struct.pack('>IIIII', halfword_sum(loader), 0x81b00000, len(loader), 0x81b00110, 0x137)
    return (head + table).ljust(0x320, b'\0') + blob


def promgen64(segments):
    """segments: [(name, bytes, load, gzip?)] in a promgen64 container with the magic at 0x40."""
    head = bytearray(0x1000)
    head[0x40:0x48] = b'JFKSWCSM'
    struct.pack_into('>I', head, 0x7c, len(segments))
    blob, off = b'', 0x1000
    for i, (name, body, load, gz) in enumerate(segments):
        stored = gzip.compress(body, mtime=0) if gz else body
        rec = name.encode().ljust(16, b'\0') + struct.pack('>9Q', 0, off, load, load, len(body),
                                                            len(stored) if gz else 0, sum(body), 0, len(body))
        head[0x80 + 0x80 * i:0x80 + 0x80 * i + len(rec)] = rec
        blob += stored
        off += len(stored)
    return bytes(head) + blob


def mips_text(n=64, swapped=False):
    """n `jr ra` / nop pairs, big-endian, optionally with each 16-bit pair of bytes swapped."""
    data = bytearray(struct.pack('>II', 0x03e00008, 0) * n)
    if swapped:
        data[0::2], data[1::2] = bytes(data[1::2]), bytes(data[0::2])
    return bytes(data)
