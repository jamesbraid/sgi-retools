"""Pair the IR diagnostic's engine instruction test with its expected results.

Usage: ge_inst_results.py [IRSAUDIT] [DIAG_UCODE_DIR] [OUT_TSV]
       defaults: diags/IR/bin/irsaudit diags/IR/ucode ucode/ge_inst_results.tsv

TEST_ge_instTest in irsaudit (IRIX 6.5.30m) starts the diagnostic engine
program, has the engine send its results to host memory, and compares 172
words, one by one, with the 172-word array `expected_token` (a dynamic
symbol of irsaudit, 688 bytes). The engine code that produces them is the
source file ge_inst.s of the diagnostic program diags/IR/ucode/ge.hex and
ge.u. It is straight-line code: every result leaves the engine through one
output instruction, a form-10 or form-12 word with record field r213
(R213-212) = 3 and B (R186-182) = 9, 10 or 11, and there are exactly 172
of them in address order, none inside a loop.

This script lists them in address order beside the expected word with the
same index, and writes one row per result:

  index, engine address, ge_inst.s line, form, M, r110, r148 of the output
  word, the expected word, and the word read as an IEEE single.

Fields and forms are those of ucode/ge_isa.md (scripts/ge_disasm.py).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ge_disasm import field, form, is_padding, load_hex, load_u  # noqa: E402

N = 172


def elf_symbol(path, name):
    """Return the bytes of a dynamic symbol of a big-endian 32-bit ELF."""
    b = open(path, 'rb').read()
    shoff, = struct.unpack('>I', b[0x20:0x24])
    shnum, = struct.unpack('>H', b[0x30:0x32])
    secs = [struct.unpack('>10I', b[shoff + 40 * i:shoff + 40 * i + 40]) for i in range(shnum)]
    dynsym = next(s for s in secs if s[1] == 11)
    strtab = secs[dynsym[6]]
    for i in range(dynsym[5] // 16):
        n, v, size = struct.unpack('>III', b[dynsym[4] + 16 * i:dynsym[4] + 16 * i + 12])
        s = strtab[4] + n
        if b[s:b.index(b'\0', s)].decode() != name:
            continue
        for sec in secs:
            if sec[1] != 8 and sec[3] and sec[3] <= v < sec[3] + sec[5]:
                o = v - sec[3] + sec[4]
                return b[o:o + size]
    raise SystemExit('%s: no symbol %s' % (path, name))


def main():
    irsaudit = sys.argv[1] if len(sys.argv) > 1 else 'diags/IR/bin/irsaudit'
    src = sys.argv[2] if len(sys.argv) > 2 else 'diags/IR/ucode'
    out = sys.argv[3] if len(sys.argv) > 3 else 'ucode/ge_inst_results.tsv'

    raw = elf_symbol(irsaudit, 'expected_token')
    expected = struct.unpack('>%dI' % (len(raw) // 4), raw)
    if len(expected) != N:
        raise SystemExit('expected_token has %d words, not %d' % (len(expected), N))

    words = load_hex(os.path.join(src, 'ge.hex'))
    recs, lines = load_u(os.path.join(src, 'ge.u'))
    outputs = []
    current = None
    for a in sorted(words):
        w, r = words[a], recs[a]
        if is_padding(w, r):
            continue
        if a in lines:
            current = lines[a]
        if current is None or current[0] != 'ge_inst.s':
            continue
        if form(w) in (10, 12) and field(r, 213, 212) == 3 and field(r, 186, 182) in (9, 10, 11):
            outputs.append((a, current[1], form(w), field(r, 121, 111), field(r, 110, 100),
                            field(r, 148, 139)))
    if len(outputs) != N:
        raise SystemExit('found %d output instructions in ge_inst.s, not %d' % (len(outputs), N))

    with open(out, 'w') as fh:
        fh.write('# The IR diagnostic engine test (ge_inst.s in diags/IR/ucode/ge.u) and the words\n')
        fh.write('# irsaudit expects from it (expected_token, IRIX 6.5.30m); scripts/ge_inst_results.py.\n')
        fh.write('# One row per output instruction, in address order; see ucode/ge_ops.md.\n')
        fh.write('index\taddress\tline\tform\tM\tr110\tr148\texpected\tas_float\n')
        for i, (a, ln, f, m, r110, r148) in enumerate(outputs):
            e = expected[i]
            fl = struct.unpack('>f', struct.pack('>I', e))[0]
            fs = '%.9g' % fl if 1e-30 < abs(fl) < 1e30 else ''
            fh.write('%d\t%04x\t%d\t%d\t%x\t%x\t%x\t%08x\t%s\n' % (i, a, ln, f, m, r110, r148, e, fs))


if __name__ == '__main__':
    main()
