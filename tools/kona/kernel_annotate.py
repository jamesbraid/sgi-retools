"""Disassemble a kernel object with its string and global references resolved.

Usage: kernel_annotate.py OBJECT [FUNCTION ...] > listing_disasm.txt

The IRIX 64-bit compiler reaches string literals and small globals through
the $gp-relative small-data sections: a `ld rX,imm($gp)` relocated against
.srdata loads a pointer slot that itself points at .rodata (or .data), and a
following `daddiu rY,rX,off` adds the string's offset. objdump shows the
relocation but not the string. This walks objdump -dr output in text order,
tracks which register holds which slot, and appends the string (or the
section and offset) to the instruction that forms the address. Direct
$gp-relative loads of .sbss/.sdata words are annotated with their offset in
that section. With FUNCTION names, only those functions are printed.

The register tracking is text-order and does not follow branches, so an
annotation can be stale after a join; read it as a hint and check the code.
"""
import os
import re
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

OBJDUMP = os.environ.get('MIPS_OBJDUMP', 'mips64-linux-gnuabi64-objdump')


def gp0_of(elf):
    sec = elf.get_section_by_name('.MIPS.options')
    if sec is None:
        return 0
    data = sec.data()
    i = 0
    while i + 8 <= len(data):
        kind, size = data[i], data[i + 1]
        if size == 0:
            break
        if kind == 1:  # ODK_REGINFO: masks then the 64-bit gp value
            return struct.unpack('>q', data[i + 8 + 24:i + 8 + 32])[0]
        i += size
    return 0


def slot_targets(elf, secname):
    """Map slot offset in a pointer section to (target section, addend)."""
    out = {}
    sec = elf.get_section_by_name(secname)
    if sec is None:
        return out
    symtab = elf.get_section_by_name('.symtab')
    raw = sec.data()
    for rs in elf.iter_sections():
        if not isinstance(rs, RelocationSection):
            continue
        if elf.get_section(rs['sh_info']).name != secname:
            continue
        for r in rs.iter_relocations():
            sym = symtab.get_symbol(r['r_info_sym'])
            name = sym.name or elf.get_section(sym['st_shndx']).name
            off = r['r_offset']
            add = r['r_addend'] if r.is_RELA() else struct.unpack('>q', raw[off:off + 8])[0]
            out[off] = (name, add)
    return out


def cstring(elf, secname, off):
    sec = elf.get_section_by_name(secname)
    if sec is None or off < 0 or off >= sec['sh_size']:
        return None
    data = sec.data()
    end = data.find(b'\0', off)
    if end < 0 or end - off > 200:
        return None
    s = data[off:end]
    if not s or any(c < 9 or c > 126 for c in s):
        return None
    return s.decode('ascii').replace('\n', '\\n').replace('\t', '\\t')


def main():
    obj = sys.argv[1]
    want = set(sys.argv[2:])
    elf = ELFFile(open(obj, 'rb'))
    gp0 = gp0_of(elf)
    slots = slot_targets(elf, '.srdata')
    text = subprocess.run([OBJDUMP, '-dr', '--no-show-raw-insn', obj],
                          capture_output=True, text=True).stdout.splitlines()
    insn = re.compile(r'\s+([0-9a-f]+):\t(\S+)\t?(.*)')
    reloc = re.compile(r'\s+([0-9a-f]+): (R_MIPS_\w+)\s+(\S+)')
    func = re.compile(r'[0-9a-f]+ <(\w+)>:')
    regs = {}
    cur = None
    pending = None  # (index in out, mnemonic, operands)
    out = []
    keep = not want
    for line in text:
        m = func.match(line)
        if m:
            cur = m.group(1)
            keep = not want or cur in want
            regs = {}
            if keep:
                out.append('')
                out.append(line)
            continue
        m = reloc.match(line)
        if m and pending is not None:
            kind, target = m.group(2), m.group(3)
            idx, op, args = pending
            if kind == 'R_MIPS_GPREL16' and op in ('ld', 'lw', 'lwu', 'sd', 'sw', 'daddiu'):
                mm = re.match(r'(\w+),(-?\d+)\(gp\)', args)
                if mm:
                    rd, imm = mm.group(1), int(mm.group(2))
                    slot = imm + gp0
                    if target == '.srdata' and op == 'ld' and slot in slots:
                        regs[rd] = slots[slot]
                        note = '%s+0x%x' % slots[slot]
                        s = cstring(elf, slots[slot][0], slots[slot][1])
                        if s is not None:
                            note += ' "%s"' % s
                        if idx is not None:
                            out[idx] += '\t# ' + note
                    else:
                        regs.pop(rd, None)
                        if idx is not None:
                            out[idx] += ('\t# %s+0x%x' % (target, slot)
                                         if target.startswith('.') else '\t# ' + target)
            elif kind == 'R_MIPS_26' and idx is not None and keep:
                out[idx] = re.sub(r'\t(jal|j)\t.*', r'\t\1\t' + target, out[idx])
            continue
        m = insn.match(line)
        if not m:
            continue
        addr, op, args = m.groups()
        s = '%6s:\t%s\t%s' % (addr, op, args)
        note = None
        mm = re.match(r'(\w+),(\w+),(-?\d+)$', args)
        if op in ('daddiu', 'addiu') and mm and mm.group(2) in regs:
            sec, add = regs[mm.group(2)]
            t = (sec, add + int(mm.group(3)))
            st = cstring(elf, t[0], t[1])
            note = '%s+0x%x' % t + (' "%s"' % st if st is not None else '')
            regs[mm.group(1)] = t
        else:
            dst = args.split(',')[0] if args else ''
            if dst in regs and op not in ('sd', 'sw', 'sh', 'sb', 'beq', 'bne', 'beqz', 'bnez', 'jalr', 'jr'):
                regs.pop(dst, None)
        if note:
            s += '\t# ' + note
        if keep:
            out.append(s)
            pending = (len(out) - 1, op, args)
        else:
            pending = (None, op, args)
    print('\n'.join(out))


if __name__ == '__main__':
    main()
