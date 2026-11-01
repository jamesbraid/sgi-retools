#!/usr/bin/env python3
"""Annotated PowerPC listing of one L2 user-space ELF (executable or library).

usage: l2_list.py ELF [--out FILE]

Disassembles .text with capstone. Calls into the lazy PLT are named from
.rela.plt (a 32-bit PowerPC PLT slot is code the loader writes, and its
address is the relocation offset). Exported symbols label routine starts;
every other branch target gets sub_<addr>. Loads of a 32-bit constant built
with lis plus addi/ori and of gp-relative small-data words are resolved, and
a result that lands in .rodata or .data and looks like text is shown as a
string. Nothing here is copied from a vendor listing.
"""
import re
import sys

import capstone
from elftools.elf.elffile import ELFFile


def main():
    path = sys.argv[1]
    out = sys.stdout
    if "--out" in sys.argv:
        out = open(sys.argv[sys.argv.index("--out") + 1], "w")
    f = ELFFile(open(path, "rb"))
    ds = f.get_section_by_name(".dynsym")
    names = {}
    plt = {}
    for s in ds.iter_symbols():
        if s.name and s["st_shndx"] != "SHN_UNDEF" and s["st_info"]["type"] == "STT_FUNC":
            names[s["st_value"]] = s.name
    rp = f.get_section_by_name(".rela.plt")
    if rp is not None:
        for r in rp.iter_relocations():
            plt[r["r_offset"]] = ds.get_symbol(r["r_info_sym"]).name
    # Shared objects here carry text relocations: the instruction words hold
    # zero and the loader patches them, so the target comes from .rela.text.
    relocs = {}
    rt = f.get_section_by_name(".rela.text")
    syms = list(ds.iter_symbols())
    if rt is not None:
        for r in rt.iter_relocations():
            sy = syms[r["r_info_sym"]]
            name = sy.name
            val = sy["st_value"] if sy["st_shndx"] != "SHN_UNDEF" else None
            relocs[r["r_offset"]] = (r["r_info_type"], name, r["r_addend"], val)
    objs = sorted((s["st_value"], s["st_size"], s.name) for s in ds.iter_symbols()
                  if s.name and s["st_shndx"] != "SHN_UNDEF" and s["st_info"]["type"] == "STT_OBJECT")

    def objname(a):
        for v, z, n in objs:
            if v <= a < v + max(z, 1):
                return n
        return None

    secs = [(s["sh_addr"], s["sh_addr"] + s["sh_size"], s.data(), s.name)
            for s in f.iter_sections() if s["sh_type"] == "SHT_PROGBITS" and s["sh_addr"]]

    def rd(addr, n):
        for a, e, d, _ in secs:
            if a <= addr < e:
                return d[addr - a:addr - a + n]
        return b""

    def text(addr):
        b = rd(addr, 80)
        m = re.match(rb"[\x20-\x7e\n\t]{3,}\x00", b)
        if m:
            return m.group(0)[:-1].decode().replace("\n", "\\n")
        return None

    t = f.get_section_by_name(".text")
    code = t.data()
    base = t["sh_addr"]
    md = capstone.Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
    md.detail = False
    insns = list(md.disasm(code, base))
    targets = set(names)
    for i in insns:
        if i.mnemonic in ("bl", "b") and i.op_str.startswith("0x"):
            tg = int(i.op_str, 16)
            if tg not in plt and base <= tg < base + len(code) and i.mnemonic == "bl":
                targets.add(tg)
    # r13 and r2 hold the small-data bases in an EABI binary
    sda = {}
    for s in ds.iter_symbols():
        if s.name in ("_SDA_BASE_", "_SDA2_BASE_"):
            sda[s.name] = s["st_value"]
    regs = {}
    for i in insns:
        if i.address in targets:
            out.write("\n%08x <%s>:\n" % (i.address, names.get(i.address, "sub_%x" % i.address)))
            regs = {}
        note = ""
        rl = relocs.get(i.address) or relocs.get(i.address + 2)
        if rl:
            ty, nm, ad, val = rl
            if ty == 10:  # R_PPC_REL24
                note = "  ; call %s" % (nm or "sub")
            elif ty in (4, 5, 6, 7, 9) or ty == 109:
                tv = (((val or 0) if nm else 0) + ad) & 0xffffffff
                st = text(tv) if (val is not None or not nm) else None
                label = nm or objname(tv)
                note = "  ; %s0x%x%s" % ((nm + "+") if nm else "", tv if not nm else ad, (' "%s"' % st) if st else (" (%s)" % label if label and not nm else ""))
        ops = [o.strip() for o in i.op_str.split(",")]
        if (ops and ops[0].startswith("r") and not i.mnemonic.startswith(("st", "cmp", "b", "mt", "tw", "sync", "isync"))
                and i.mnemonic not in ("lis", "addi", "ori")):
            regs.pop(ops[0], None)
        if i.mnemonic in ("addi", "ori") and len(ops) == 3 and ops[1] not in regs:
            regs.pop(ops[0], None)
        if rl and i.mnemonic in ("lis", "addi", "ori", "lwz", "lbz", "stw", "stb", "lhz", "sth", "bl", "b"):
            pass
        elif i.mnemonic == "lis" and len(ops) == 2:
            regs[ops[0]] = (int(ops[1], 0) & 0xffff) << 16
        elif i.mnemonic in ("addi", "ori") and len(ops) == 3 and ops[1] in regs:
            v = (regs[ops[1]] + (int(ops[2], 0) if i.mnemonic == "addi" else int(ops[2], 0))) & 0xffffffff
            if i.mnemonic == "addi" and int(ops[2], 0) < 0:
                v = (regs[ops[1]] + int(ops[2], 0)) & 0xffffffff
            regs[ops[0]] = v
            s = text(v)
            note = "  ; 0x%x%s" % (v, (' "%s"' % s) if s else "")
        elif i.mnemonic == "addi" and len(ops) == 3 and ops[1] == "r13" and "_SDA_BASE_" in sda:
            v = (sda["_SDA_BASE_"] + int(ops[2], 0)) & 0xffffffff
            s = text(v)
            note = "  ; 0x%x%s" % (v, (' "%s"' % s) if s else "")
        elif i.mnemonic == "addi" and len(ops) == 3 and ops[1] == "r2" and "_SDA2_BASE_" in sda:
            v = (sda["_SDA2_BASE_"] + int(ops[2], 0)) & 0xffffffff
            s = text(v)
            note = "  ; 0x%x%s" % (v, (' "%s"' % s) if s else "")
        elif i.mnemonic in ("bl", "b") and i.op_str.startswith("0x"):
            tg = int(i.op_str, 16)
            if tg in plt:
                note = "  ; %s" % plt[tg]
            elif tg in targets:
                note = "  ; %s" % names.get(tg, "sub_%x" % tg)
        out.write("  %08x  %s %s%s\n" % (i.address, i.mnemonic, i.op_str, note))


if __name__ == "__main__":
    main()
