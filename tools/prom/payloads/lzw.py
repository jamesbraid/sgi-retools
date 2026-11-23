"""compress(1) LZW (magic 1f 9d), the stream inside the Everest IO4 `_LZW` payloads."""


def decompress(data):
    if data[:2] != b'\x1f\x9d':
        raise ValueError('not a compress stream')
    maxbits, block = data[2] & 0x1f, bool(data[2] & 0x80)
    if not 9 <= maxbits <= 16:
        raise ValueError('compress stream with %d-bit codes' % maxbits)
    maxmax = 1 << maxbits
    prefix = [0] * maxmax
    suffix = list(range(256)) + [0] * (maxmax - 256)
    free = 257 if block else 256
    nbits, maxcode = 9, 511
    # compress packs codes LSB first in groups of 8, so a width change or clear skips to a group boundary
    base, group, offset = 3, nbits, 0
    out = bytearray()

    def getcode(clear=False):
        nonlocal base, group, offset, nbits, maxcode
        if clear or offset >= group * 8 or free > maxcode:
            base += group
            offset = 0
            if free > maxcode:
                nbits += 1
                maxcode = maxmax if nbits == maxbits else (1 << nbits) - 1
            if clear:
                nbits, maxcode = 9, 511
            group = nbits
        pos = base * 8 + offset
        if pos + nbits > len(data) * 8:
            return -1
        offset += nbits
        chunk = int.from_bytes(data[pos >> 3:(pos + nbits + 7) >> 3], 'little')
        return (chunk >> (pos & 7)) & ((1 << nbits) - 1)

    def string(code):
        s = []
        while code >= 256:
            s.append(suffix[code])
            code = prefix[code]
        s.append(code)
        s.reverse()
        return s

    old = getcode()
    if old < 0:
        return b''
    fin = old
    out.append(old)
    while True:
        code = getcode()
        if code < 0:
            break
        if block and code == 256:
            free = 256
            code = getcode(True)
            if code < 0:
                break
        if code > free:
            raise ValueError('compress code %d beyond the table (%d entries)' % (code, free))
        incode = code
        s = string(old) + [fin] if code >= free else string(code)
        fin = s[0]
        out += bytes(s)
        if free < maxmax:
            prefix[free], suffix[free] = old, fin
            free += 1
        old = incode
    return bytes(out)
