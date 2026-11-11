#!/usr/bin/env python3
"""Container reader and conservative disassembler for the IMPACT host-interface
microcode listings (hq3*.u) and their raw images (hq3*.bin).

Container (".u", big-endian 32-bit words), established by comparing three
builds:
  word 0      0x00030003 (format tag)
  word 1,2    offset and length of the assembler banner string
  word 3      offset of the instruction section (jump words in it carry
              symbolic fix-ups; the raw .bin is the authoritative image)
  word 4      offset of a second table (not decoded)
  word 5      offset of the source-line table
  word 6      mid-table offset (the line table is one run of 8-byte records
              from word 5 to word 7; this offset only splits it unevenly)
  word 7,8    offset and length of the table of name offsets (16-bit each)
  word 9,10   offset and length of the NUL-separated source-name strings
  words 11..522  the 512-entry command-token dispatch table (microcode
              address of each token's handler)
Line record: u32 microcode address, u16 source line, u16 index into the names.

Image (".bin"): one 32-bit big-endian word per instruction, 24 bits used.

Instruction forms. Only forms with direct evidence are named; the rest print
as raw fields. "inferred" forms are consistent with the data but no document
states them.
  0x80-0xBF  jump (inferred): target = low 12 bits; the bits between are a
             condition/flag field printed raw. 0x83 with byte1 0xA0 is the
             return form; the code after a call shows up to three
             instructions executing before the jump takes effect (delay
             slots, inferred from the call sites).
  0x44-0x4F  load 16-bit immediate into pointer register (op & 15)
             (inferred: the vendor's instruction-set exerciser loads then
             reads back such immediates)
  0xC0-0xDF  register move: source register op & 31, destination field in
             byte1 bits 7:3 (inferred). Source 27 (0xDB) feeds the data path.
"""
import argparse
import struct
import sys
from collections import namedtuple

Ucode = namedtuple('Ucode', 'banner dispatch names lines')

HEADER_WORDS = 11
DISPATCH_ENTRIES = 512
LINE_RECORD = struct.Struct('>IHH')


def parse_u(data):
    if len(data) < 4 * (HEADER_WORDS + DISPATCH_ENTRIES):
        raise ValueError('too short for a microcode listing')
    h = struct.unpack('>%dI' % HEADER_WORDS, data[:4 * HEADER_WORDS])
    if h[0] != 0x00030003:
        raise ValueError('unexpected format tag 0x%08x' % h[0])
    banner = data[h[1]:h[1] + h[2]].decode('latin-1').strip()
    dispatch = struct.unpack('>%dI' % DISPATCH_ENTRIES,
                             data[4 * HEADER_WORDS:4 * (HEADER_WORDS + DISPATCH_ENTRIES)])
    names = [n.decode('latin-1') for n in data[h[9]:h[9] + h[10]].split(b'\0') if n]
    lines = {}
    for off in range(h[5], h[7] - LINE_RECORD.size + 1, LINE_RECORD.size):
        addr, line, fidx = LINE_RECORD.unpack_from(data, off)
        if fidx >= len(names):
            raise ValueError('line record at 0x%x names file %d of %d' % (off, fidx, len(names)))
        lines[addr] = (names[fidx].rsplit('/', 1)[-1], line)
    return Ucode(banner, dispatch, names, lines)


def parse_bin(data):
    n = len(data) // 4
    return [w & 0xFFFFFF for w in struct.unpack('>%dI' % n, data[:4 * n])]


def disasm(word, addr=0):
    op, b1, b2 = word >> 16, (word >> 8) & 0xFF, word & 0xFF
    if word == 0:
        return 'nop'
    if 0x80 <= op <= 0xBF:
        tgt = word & 0xFFF
        if op == 0x83 and b1 == 0xA0:
            return 'ret?'
        return 'jmp?   0x%03x  cond=%02x.%x' % (tgt, op, b1 >> 4)
    if 0x44 <= op <= 0x4F:
        return 'imm    r%x, 0x%04x' % (op & 0xF, word & 0xFFFF)
    if 0xC0 <= op <= 0xDF:
        return 'mov?   r%d -> d%d.%d  low=%02x' % (op & 0x1F, b1 >> 3, b1 & 7, b2)
    return 'op%02x   0x%04x' % (op, word & 0xFFFF)


def imm_writes(words, reg, lo, hi):
    """Addresses in [lo, hi) that load an immediate into pointer register reg."""
    op = 0x40 | reg
    return [(a, words[a] & 0xFFFF) for a in range(lo, min(hi, len(words))) if words[a] >> 16 == op]


def _int(s):
    return int(s, 0)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('u', help='microcode listing (.u)')
    ap.add_argument('--bin', help='raw instruction image (.bin); required to disassemble')
    ap.add_argument('--range', help='LO:HI microcode address range to disassemble')
    ap.add_argument('--dispatch', action='store_true', help='print non-default token entries')
    ap.add_argument('--imm', type=_int, metavar='REG', help='list immediate loads into pointer register REG in --range')
    args = ap.parse_args(argv)
    with open(args.u, 'rb') as f:
        uc = parse_u(f.read())
    print('banner: %s' % uc.banner.replace('\n', ' | '))
    if args.dispatch:
        for tok, a in enumerate(uc.dispatch):
            print('token 0x%03x -> 0x%03x' % (tok, a))
    if args.bin:
        with open(args.bin, 'rb') as f:
            words = parse_bin(f.read())
        lo, hi = (0, len(words))
        if args.range:
            lo, hi = (_int(x) for x in args.range.split(':'))
        if args.imm is not None:
            for a, v in imm_writes(words, args.imm, lo, hi):
                print('0x%03x  r%x <- 0x%04x' % (a, args.imm, v))
        else:
            for a in range(lo, min(hi, len(words))):
                src = uc.lines.get(a)
                print('%03x  %06x  %-28s %s' % (a, words[a], disasm(words[a], a),
                                                  '%s:%d' % src if src else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
