#!/usr/bin/env python3
"""Write data/languages/kona_ge.slaspec, the SLEIGH spec of the KONA (and
IMPACT GE11) geometry-engine microcode.

Usage: gen_slaspec.py [OUT]   (default: ../data/languages/kona_ge.slaspec)

The spec is generated because most of it is tables: one display constructor
per decoded group, one semantic constructor per operation code and one per
condition code. Every meaning below comes from ucode/ge_isa.md and
ucode/ge_ops.md; the comments in the output carry their labels.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, '..', 'data', 'languages', 'kona_ge.slaspec')

# Context fields: the decoded record groups of ge.u (scripts/ge_disasm.py
# GROUPS), split where a group is wider than 32 bits or where the semantics
# test a part of it. (name, start, end, attributes). Every field sits inside
# one 32-bit context word, and fields are set by name by the loader, so the
# bit order inside a word never matters.
CTX = [
    # word 0
    ('fimm', 0, 31, ''), ('fsimm', 0, 31, 'signed'),
    # word 1
    ('fw71', 32, 32, ''), ('f222', 33, 33, ''), ('f221', 34, 34, ''), ('f220', 35, 35, ''),
    ('f219', 36, 37, ''), ('f217', 38, 39, ''), ('f215', 40, 41, ''), ('f213', 42, 43, ''),
    ('f211', 44, 45, ''), ('fcc', 46, 56, ''), ('f198', 57, 63, ''),
    # word 2
    ('fA', 64, 68, ''), ('fAr', 64, 68, ''), ('fB', 69, 73, ''), ('fBr', 69, 73, ''),
    ('fC', 74, 78, ''), ('fCr', 74, 78, ''), ('f176', 79, 80, ''), ('fD', 81, 86, ''),
    ('fE', 87, 92, ''), ('f162', 93, 95, ''),
    # word 3
    ('fF', 96, 101, ''), ('fG', 102, 106, ''), ('fGr', 102, 106, ''),
    ('f148h', 107, 111, ''), ('f148hr', 107, 111, ''), ('f148l', 112, 116, ''), ('f148lr', 112, 116, ''),
    ('fP', 117, 121, ''), ('fPr', 117, 121, ''), ('fQ', 122, 126, ''), ('fQr', 122, 126, ''),
    ('fvalid', 127, 127, ''),
    # word 4
    ('f128', 128, 134, ''), ('f128p1', 129, 131, ''), ('f128p2', 132, 134, ''), ('fMk', 135, 138, ''), ('fMu', 139, 145, ''), ('f110', 146, 156, ''), ('f110b10', 146, 146, ''), ('f110s1', 147, 148, ''), ('f110s2', 149, 150, ''),
    ('f110u1', 151, 152, ''), ('f110u2', 153, 154, ''), ('f110sd', 155, 155, ''),
    # word 5
    ('f99h', 160, 160, ''), ('f99l', 161, 163, ''), ('f99b2', 161, 161, ''), ('f95', 164, 170, ''),
    ('fsind', 171, 171, ''), ('fsrel', 172, 172, ''), ('fsop', 173, 175, 'dec'),
    ('fsmid', 176, 182, ''), ('fsgrp', 183, 187, 'dec'),
    # word 6
    ('f71', 192, 200, ''), ('f62h', 201, 205, ''), ('fwtop', 206, 213, ''), ('fdly', 214, 217, ''), ('fform', 218, 221, ''),
    # word 7
    ('f62l', 224, 255, ''),
    # word 8
    ('f25', 256, 281, ''),
]

# Display groups in scripts/ge_disasm.py order: (label, [fields], nop value,
# value expression). A group whose fields hold the value of the canonical
# no-op record prints nothing, as ge_disasm.py leaves it out.
NOP = dict(imm=0, w71=0, r222=0, r221=0, r220=0, r219=0, r217=0, r215=0, r213=0, r211=0,
           cc=0x11, r198=0x14, A=0, B=0, C=0, r176=3, D=0, E=0, r162=0, F=0x1f, G=0x1f,
           r148=0, P=0x1f, Q=0x1f, r128=0x2d, M=0x6ff, r110=0x6bd, r99=0, r95=0,
           seq=0x6fe4, r71=0, r62=0x1ffc000170, r25=0x3e29c00)
SIMPLE = dict(imm='fimm', w71='fw71', r222='f222', r221='f221', r220='f220', r219='f219',
              r217='f217', r215='f215', r213='f213', r211='f211', cc='fcc', r198='f198',
              A='fA', B='fB', C='fC', r176='f176', D='fD', E='fE', r162='f162', F='fF',
              G='fG', P='fP', Q='fQ', r128='f128', r110='f110', r95='f95', r71='f71', r25='f25')
# Groups stored as several fields: (label, [(field, width)] high part first).
SPLIT = dict(r148=[('f148h', 5), ('f148l', 5)], M=[('fMk', 4), ('fMu', 7)],
             r99=[('f99h', 1), ('f99l', 3)],
             seq=[('fsind', 1), ('fsrel', 1), ('fsop', 3), ('fsmid', 7), ('fsgrp', 5)],
             r62=[('f62h', 5), ('f62l', 32)])
ORDER = ['imm', 'w71', 'r222', 'r221', 'r220', 'r219', 'r217', 'r215', 'r213', 'r211', 'cc',
         'r198', 'A', 'B', 'C', 'r176', 'D', 'E', 'r162', 'F', 'G', 'r148', 'P', 'Q', 'r128',
         'M', 'r110', 'r99', 'r95', 'seq', 'r71', 'r62', 'r25']

# Unit-1 operations, M[6:0] (ucode/ge_ops.md "Operation table", GE.h).
# (code, mnemonic, p-code with OPAV/OPBV in, U1V out, result kind for the
# flags: 'i' integer, 'f' float, None unknown, label).
U1 = [
    (0x20, 'dadd', 'U1V = dadd(P1V, P2V);', None,
     'double add, ESTABLISHED (ge_inst.s 3829); the two-word pairing is not mapped, so a pcodeop'),
    (0x22, 'dsub', 'U1V = dsub(P1V, P2V);', None,
     'double subtract, ESTABLISHED (ge_inst.s 3858); two-word pairing not mapped, pcodeop'),
    (0x40, 'iadd', 'U1V = iadd_sat(P1V, P2V);', 'i',
     'integer add, ESTABLISHED; saturates at the signed limit, ESTABLISHED for the GE11 (iadd test)'),
    (0x42, 'isub', 'U1V = isub_sat(P1V, P2V);', 'i',
     'integer subtract A - B, ESTABLISHED not wrapping; saturating INFERRED'),
    (0x4a, 'mov', 'U1V = P1V;', 'i', 'move of the first operand, ESTABLISHED'),
    (0x4b, 'movb', 'U1V = P2V;', 'i', 'move of the second operand, ESTABLISHED'),
    (0x50, 'and', 'U1V = P1V & P2V;', 'i', 'AND, INFERRED by intent (test ties AND/NOR)'),
    (0x54, 'or', 'U1V = P1V | P2V;', 'i', 'OR, INFERRED by function (test ties OR/XOR/NAND)'),
    (0x56, 'xor', 'U1V = P1V ^ P2V;', 'i', 'XOR, INFERRED by function'),
    (0x58, 'not', 'U1V = ~P1V;', 'i', 'bitwise NOT of the first operand, ESTABLISHED'),
    (0x5b, 'sra', 'U1V = P1V s>> P2V;', 'i', 'arithmetic shift right by the second operand, INFERRED'),
    (0x5d, 'srl', 'U1V = P1V >> P2V;', 'i', 'logical shift right by the second operand, INFERRED'),
    (0x5f, 'sll', 'U1V = P1V << P2V;', 'i', 'shift left by the second operand, INFERRED'),
    (0x60, 'fadd', 'U1V = P1V f+ P2V;', 'f', 'single add, ESTABLISHED'),
    (0x62, 'fsub', 'U1V = P1V f- P2V;', 'f',
     'single subtract first - second, ESTABLISHED for two registers (ge_inst.s 3774)'),
    (0x66, 'fmin', 'U1V = fmin(P1V, P2V);', 'f', 'minimum, INFERRED (mmo_Minmax)'),
    (0x68, 'fmax', 'U1V = fmax(P1V, P2V);', 'f', 'maximum, INFERRED (mmo_Minmax)'),
    (0x71, 'ftoi', 'U1V = ftoi(P1V);', 'i',
     'float to integer, INFERRED (mmo_FloatToInt); rounding UNKNOWN, so a pcodeop'),
    (0x73, 'itof', 'U1V = int2float(P1V);', 'f', 'integer to single, ESTABLISHED'),
    (0x7c, 'clamp', 'U1V = clamp01(P1V);', 'f',
     'clamp to [0, 1]: below at 0 ESTABLISHED, above at 1.0 INFERRED; NaN UNKNOWN, so a pcodeop'),
]
# Unit-2 operations, k = M[10:7], code = k << 3 | 7 (k = 0xd idle).
U2 = [
    (0x0, 'dmul', 'U2V = dmul(OPAV, OPBV);', None,
     'double multiply 0x07, ESTABLISHED; two-word pairing not mapped, pcodeop'),
    (0x1, 'imul', 'U2V = OPAV * OPBV;', 'i', 'integer multiply 0x0f, low 32 bits, INFERRED (GE11 imul)'),
    (0x4, 'fmov', 'U2V = OPAV;', 'f', 'unit-2 move of the first operand 0x27, ESTABLISHED'),
    (0x6, 'dmov', 'U2V = OPAV;', 'f', 'double move of the first pair 0x37, ESTABLISHED (one word of it)'),
    (0x8, 'fmul', 'U2V = OPAV f* OPBV;', 'f', 'single multiply 0x47, ESTABLISHED bit for bit'),
    (0x9, 'rcpstep', 'U2V = int2float(2:4) f- (OPAV f* OPBV);', 'f',
     '2 - a*b 0x4f, Newton-Raphson reciprocal step, ESTABLISHED bit for bit'),
    (0xa, 'rsqstep', 'U2V = (int2float(3:4) f- (OPAV f* OPBV)) f/ int2float(2:4);', 'f',
     '(3 - a*b)/2 0x57, Newton-Raphson reciprocal-square-root step, ESTABLISHED bit for bit'),
]


def emit(out):
    w = out.append
    w('# KONA / IMPACT GE11 geometry-engine microcode: SLEIGH specification.')
    w('# GENERATED by sleigh/kona-ge/tools/gen_slaspec.py; edit that, not this.')
    w('#')
    w('# Sources: ucode/ge_isa.md (word layout, forms, fields, transfers, delay')
    w('# slots), ucode/ge_ops.md (operation codes, conditions, flag register),')
    w('# GE.h (operation ids). Labels: ESTABLISHED, INFERRED and UNKNOWN as there.')
    w('#')
    w('# How the decode works. The chip stores a 72-bit word W. The assembler also')
    w('# shipped each word decoded to a 256-bit control record (ge.u); 205 of its')
    w('# bits vary and most are not plain slices of W, so the decode from W is not')
    w('# known as logic. The loader (ghidra_scripts/KonaGEImport.java) therefore')
    w('# puts W[63:0] in code memory (one 8-byte address unit per word, so code')
    w('# addresses are word addresses) and the record groups in the context')
    w('# register at each word. Every field below is a record group of')
    w('# scripts/ge_disasm.py, and the display reproduces that script field for')
    w('# field after a mnemonic.')
    w('#')
    w('# Semantics modelled (each with its label below): the unit-1 and unit-2')
    w('# operations, the seeds, the address unit, stores, the flag word and its')
    w('# twelve-word latency, and transfers with their delay slots. Not modelled,')
    w('# because no document maps them: r128, r176, r162, r198, r217, r71, r62,')
    w('# r25, most of r95 and r110, and the latency of unit results (code that is')
    w('# software-pipelined decompiles as if each result were ready at once).')
    w('')
    w('define endian=big;')
    w('# Alignment is in bytes and must be a multiple of the 8-byte address unit.')
    w('define alignment=8;')
    w('')
    w('# Code: one 8-byte unit per microcode word (W[63:0]); W[71:64] is fwtop.')
    w('define space code type=ram_space size=4 wordsize=8 default;')
    w('# The engine address space reached through address registers. Which of')
    w('# WRAM, ERAM, the special-register window (0xfffe0000) or the output window')
    w('# (0xffff0000) an address selects is UNKNOWN, so it gets its own space.')
    w('define space dmem type=ram_space size=4 wordsize=4;')
    w('# The three engine memories of the GE11 test description (INFERRED for KONA):')
    w('# WRAM (2K words, command FIFO and scratch), CRAM (512 words, shared),')
    w('# ERAM (external SRAM).')
    w('define space wram type=ram_space size=2 wordsize=4;')
    w('define space cram type=ram_space size=2 wordsize=4;')
    w('define space eram type=ram_space size=4 wordsize=4;')
    w('define space register type=register_space size=4;')
    w('')
    w('# Arithmetic registers (r148 operands, P and Q destinations).')
    w('define register offset=0x0 size=4 [ %s ];' % ' '.join('R%d' % i for i in range(32)))
    w('# Address registers (A, B, C, G); 18 bits wide on the chip, modelled as 32.')
    w('define register offset=0x100 size=4 [ %s ];' % ' '.join('AR%d' % i for i in range(32)))
    w('# SEED: the seed result unit 2 reads through selector 0, the seed of the')
    w('# operand two words back (ESTABLISHED, ge_isa.md "Unit-2 and seed-unit')
    w('# operands"); SEED0 and SEED1 hold this word\'s and the last word\'s seeds.')
    w('# LR: return address the hardware keeps (INFERRED stack, modelled as one register).')
    w('# NEXTCMD: the next handler the dispatch hardware supplies (INFERRED).')
    w('define register offset=0x200 size=4 [ SEED LR NEXTCMD PC SP SEED0 SEED1 SDOP ];')
    w('# Per-word scratch: operands, unit results, address-unit result, store data.')
    w('define register offset=0x300 size=4 [ OPAV OPBV U1V U2V AUV CSRC STV LDV LDL P1V P2V ];')
    w('# U1H0..U1H7, U2H0..U2H7: each unit\'s result 0..7 words ago, the window')
    w('# result forwarding reads (ESTABLISHED, ge_isa.md "Operand ports").')
    w('define register offset=0x380 size=4 [ %s %s ];' % (' '.join('U1H%d' % i for i in range(8)),
                                                           ' '.join('U2H%d' % i for i in range(8))))
    w('# FL: the condition word FPU_COND_A, low nibble unit 1, high nibble unit 2,')
    w('# each bit 3 <= 0, bit 2 zero, bit 1 negative, bit 0 second operand passed.')
    w('# FLD1..FLD12: FL as it was 1..12 words ago (the twelve-word flag latency).')
    w('# AZ/AGT: address-unit zero and greater-than; AZD*/AGTD*: one and two')
    w('# words ago (address-unit conditions arrive after two words, ESTABLISHED).')
    w('define register offset=0x400 size=1 [ FL %s AZ AGT AZD1 AGTD1 AZD2 AGTD2 ];' % ' '.join('FLD%d' % i for i in range(1, 13)))
    w('define register offset=0x1000 size=36 [ contextreg ];')
    w('define context contextreg')
    for name, s, e, attr in CTX:
        w('  %s=(%d,%d) %s noflow' % (name, s, e, attr))
    w(';')
    w('define token word(64) wlo=(0,63);')
    w('')
    regs = ' '.join('R%d' % i for i in range(32))
    aregs = ' '.join('AR%d' % i for i in range(32))
    w('attach variables [ f148hr f148lr fPr fQr ] [ %s ];' % regs)
    w('attach variables [ fAr fBr fCr fGr ] [ %s ];' % aregs)
    w('')
    for op in ('dadd', 'dsub', 'dmul', 'iadd_sat', 'isub_sat', 'fmin', 'fmax', 'ftoi', 'clamp01',
               'u1_op', 'u2_op', 'rcp_seed', 'rsqrt_seed', 'seed_op', 'aalu', 'cond_test',
               'abort_requested', 'store_predicate', 'next_command', 'seq_unknown', 'passb'):
        w('define pcodeop %s;' % op)
    w('define pcodeop read_r95_14;')
    w('')

    # ---- display groups
    w('# ---- Display: one subtable per record group, empty at its no-op value.')
    for g in ORDER:
        t = 'G_' + g
        if g in SIMPLE:
            f = SIMPLE[g]
            w('%s: is %s=0x%x { }' % (t, f, NOP[g]))
            w('%s: "%s="^%s is %s { }' % (t, g, f, f))
        elif g == 'r62':
            # Wider than the 32 bits a display value keeps: high:low.
            w('G_r62: is f62h=0x1f & f62l=0xfc000170 { }')
            w('G_r62: "r62="^f62h^":"^f62l is f62h & f62l { }')
        else:
            parts = SPLIT[g]
            nopv, vals, sh = NOP[g], [], 0
            for f, width in reversed(parts):
                vals.append(('%s' % f, sh, (nopv >> sh) & ((1 << width) - 1)))
                sh += width
            w('%s: is %s { }' % (t, ' & '.join('%s=0x%x' % (f, v) for f, _, v in vals)))
            expr = ' | '.join('(%s << %d)' % (f, s) if s else f for f, s, _ in vals)
            w('%s: "%s="^v is %s [ v = %s; ] { }' % (t, g, ' & '.join(f for f, _, _ in vals), expr))
    w('XREL: is fsrel=0 { }')
    w('XREL: ".rel" is fsrel=1 { }')
    w('# Transfer target: the immediate, or the word\'s own address plus the signed')
    w('# immediate when R87 (fsrel) is set (INFERRED, ge_isa.md "Transfers").')
    w('XT: dst is fsrel=0 & fimm [ dst = fimm & 0xffff; ] { export *[code]:8 dst; }')
    w('XT: dst is fsrel=1 & fsimm [ dst = (inst_start + fsimm) & 0xffff; ] { export *[code]:8 dst; }')
    w('XF: is fsop=6 { }')
    w('# The target shown is a number: an address operand in the display would')
    w('# make Ghidra add a data reference for the transfers it cannot follow.')
    w('XTD: dst is fsrel=0 & fimm [ dst = fimm & 0xffff; ] { }')
    w('XTD: dst is fsrel=1 & fsimm [ dst = (inst_start + fsimm) & 0xffff; ] { }')
    w('XF: "xfer"^fsop^XREL " c"^fsgrp " cc="^fcc " -> "^XTD is fsop & XREL & fsgrp & fcc & XTD { }')
    w('FIELDS: XF %s is XF & %s { }' % (' '.join('G_' + g for g in ORDER), ' & '.join('G_' + g for g in ORDER)))
    w('')

    # ---- mnemonic for words without a transfer
    w('# ---- Mnemonic of a word without a transfer: its unit operations, else its')
    w('# seed, store or address-unit action, else nop (every group at its no-op')
    w('# value) or ctl (something else set that no document names).')
    for code, mn, _, _, _ in U1:
        w('U1N: "%s" is fMu=0x%x { }' % (mn, code))
    w('U1N: "u1_"^fMu is fMu { }')
    for k, mn, _, _, _ in U2:
        w('U2N: "%s" is fMk=0x%x { }' % (mn, k))
    w('U2N: "u2_"^fMk is fMk { }')
    w('U1D: is fMu=0x7f { }')
    for code, mn, _, _, _ in U1:
        w('U1D: ".%s" is fMu=0x%x { }' % (mn, code))
    w('U1D: ".u1_"^fMu is fMu { }')
    nopc = ' & '.join('%s=0x%x' % (f, v) for f, v in nop_constraints())
    w('LASTN: "nop" is %s { }' % nopc)
    w('LASTN: "ctl" is epsilon { }')
    w('AUN: "aop" is f219=1 { }')
    w('AUN: "aop" is f219=2 { }')
    w('AUN: "aop" is f219=3 { }')
    w('AUN: "atest" is f219=0 & f222=1 { }')
    w('AUN: LASTN is f219=0 & f222=0 & LASTN { }')
    w('STN: "st" is f213=3 { }')
    w('STN: "stp" is f213=2 { }')
    w('STN: "sti" is f213=0 & f215=3 { }')
    w('STN: AUN is f213=0 & f215=0 & AUN { }')
    w('STN: AUN is f213=0 & f215=1 & AUN { }')
    w('STN: AUN is f213=0 & f215=2 & AUN { }')
    w('STN: AUN is f213=1 & AUN { }')
    w('SDN: "rcpseed" is f110=0x6bf { }')
    w('SDN: "rsqseed" is f110=0x2bf { }')
    w('SDN: STN is f110 & STN { }')
    w('MN: U1N is fMk=0xd & U1N { }')
    w('MN: SDN is fMk=0xd & fMu=0x7f & SDN { }')
    w('MN: U2N^U1D is fMk & U2N & U1D { }')
    w('')

    # ---- semantics
    w('# ---- Semantics')
    w('macro flagshift() {')
    for i in range(12, 1, -1):
        w('  FLD%d = FLD%d;' % (i, i - 1))
    w('  FLD1 = FL;')
    for u in (1, 2):
        for i in range(7, 0, -1):
            w('  U%dH%d = U%dH%d;' % (u, i, u, i - 1))
    w('  AZD2 = AZD1; AGTD2 = AGTD1; AZD1 = AZ; AGTD1 = AGT;')
    w('  SEED = SEED1; SEED1 = SEED0;')
    w('}')
    w('# One nibble of the condition word from a result (ge_ops.md, "Branch')
    w('# conditions"): bit 3 <= 0, bit 2 zero, bit 1 negative, ESTABLISHED for the')
    w('# test cases; bit 0 "passed its second operand" INFERRED from the GE11 labels')
    w('# and approximated here as result == second operand.')
    w('macro inib(n, r, b) { n = ((r s<= 0) << 3) | ((r == 0) << 2) | ((r s< 0) << 1) | (r == b); }')
    w('macro fnib(n, r, b) { local z:4 = int2float(0:4); n = ((r f<= z) << 3) | ((r f== z) << 2) | ((r f< z) << 1) | (r == b); }')
    w('')
    w('# Memory reads. Through A and D (INFERRED reading of A/D, ge_isa.md')
    w('# "Fields"): A = 0x1f is word D of the command, read where it arrived')
    w('# (INFERRED); its WRAM base is UNKNOWN, so D is used alone. r99 bit 3')
    w('# brings that word to the operand ports as "the word the instruction')
    w('# reads" (LDV); r99 bit 2 makes it a read with no destination, whose word')
    w('# a later port takes as "the loaded word" (LDL) (ge_isa.md "Operand ports",')
    w('# 0x7281 and the diagnostic 0x0988).')
    w('ADR: is fA=0x1f & fD { export *[wram]:4 fD; }')
    w('ADR: is fAr & fD { local a:4 = fAr + fD; export *[dmem]:4 a; }')
    w('LDR: is f99h=0 & f99b2=0 { }')
    w('LDR: is f99h=1 & f99b2=0 & ADR { LDV = ADR; }')
    w('LDR: is f99h=0 & f99b2=1 & ADR { LDL = ADR; }')
    w('LDR: is f99h=1 & f99b2=1 & ADR { LDV = ADR; LDL = LDV; }')
    w('# Reads through C also load LDL. r95 = 0x13 reads CRAM: at the immediate')
    w('# in form 5 and, in form 14, with C = 0x1e (ESTABLISHED, ge_ops.md')
    w('# "Control-memory addresses in immediates"); at address register C plus')
    w('# 0x1f - F otherwise (INFERRED from mMatrixCopyCC, ge_compute.md).')
    w('# r95 = 0x17 reads ERAM: at the immediate with C = 0x1e (INFERRED,')
    w('# mmo_CopyFifoLine); through C with the same 0x1f - F offset (INFERRED here:')
    w('# mmo_Clamp reads its parameter block with F = 0x1a down to 0xf through one')
    w('# C). r95 = 0x14 with C = 0x1e is a read with no destination (0xa7e8, the')
    w('# raster position); its memory is UNKNOWN, so a pcodeop. A read in the')
    w('# word that consumes it is seen by that word (uMatrixMultCCC 0xe72-0xe75).')
    w('CR13R: is fC=0x1e & fimm { LDL = *[cram]:4 fimm:2; }')
    w('CR13R: is fCr & fF { local a:4 = fCr + (0x1f - fF); LDL = *[cram]:4 a:2; }')
    w('CR13: is fform=5 & fimm { LDL = *[cram]:4 fimm:2; }')
    w('CR13: is CR13R { build CR13R; }')
    w('CR17: is fC=0x1e & fimm { LDL = *[eram]:4 fimm:4; }')
    w('CR17: is fCr & fF { local a:4 = fCr + (0x1f - fF); LDL = *[eram]:4 a; }')
    w('CRD: is f95=0x13 & CR13 { build CR13; }')
    w('CRD: is f95=0x17 & CR17 { build CR17; }')
    w('CRD: is f95=0x14 & fC=0x1e & fimm { LDL = read_r95_14(fimm:4); }')
    w('CRD: is f95 { }')
    w('# Forwarded results (ESTABLISHED): r128 code k = 0-3 is the unit-1 result')
    w('# 4 + k words back, 4-7 the unit-2 result 4 + (k - 4) words back.')
    for p in (1, 2):
        for k in range(8):
            src = 'U1H%d' % (4 + k) if k < 4 else 'U2H%d' % k
            w('FW%d: is f128p%d=%d { P%dV = %s; }' % (p, p, k, p, src))
    w('# Unit-1 ports (ESTABLISHED selectors 0 and 1, INFERRED 2 and 3): r110')
    w('# bits 9-8 pick port 1, 7-6 port 2; 0 a register named in r148, 1 a')
    w('# forwarded result named in r128, 2 the word the instruction reads (LDV),')
    w('# 3 the loaded word (LDL). A subtract returns port 1 minus port 2.')
    w('PT1: is f110s1=0 & f148hr { P1V = f148hr; }')
    w('PT1: is f110s1=1 & FW1 { build FW1; }')
    w('PT1: is f110s1=2 { P1V = LDV; }')
    w('PT1: is f110s1=3 { P1V = LDL; }')
    w('PT2: is f110s2=0 & f148lr { P2V = f148lr; }')
    w('PT2: is f110s2=1 & FW2 { build FW2; }')
    w('PT2: is f110s2=2 { P2V = LDV; }')
    w('PT2: is f110s2=3 { P2V = LDL; }')
    w('# Unit-2 ports (ESTABLISHED selectors 0-2, INFERRED 3; ge_isa.md "Unit-2')
    w('# and seed-unit operands"): r110 bits 5-4 pick port 1 (OPAV), 3-2 port 2')
    w('# (OPBV); 0 the seed result two words back, 1 a register named in r148')
    w('# (bits 9-5, 4-0), 2 a forwarded result named in r128 (bits 5-3, 2-0) by')
    w('# the unit-1 rule, 3 a memory word: port 1 the word read through A and D')
    w('# (LDV, which keeps the last word read when a word reads nothing), port 2')
    w('# the loaded word (LDL) (INFERRED, the matrix multiply-adds).')
    for p, f128, opv in ((1, 'f128p1', 'OPAV'), (2, 'f128p2', 'OPBV')):
        for k in range(8):
            src = 'U1H%d' % (4 + k) if k < 4 else 'U2H%d' % k
            w('FU%d: is %s=%d { %s = %s; }' % (p, f128, k, opv, src))
    w('OP2A: is f110u1=0 { OPAV = SEED; }')
    w('OP2A: is f110u1=1 & f148hr { OPAV = f148hr; }')
    w('OP2A: is f110u1=2 & FU1 { build FU1; }')
    w('OP2A: is f110u1=3 { OPAV = LDV; }')
    w('OP2B: is f110u2=0 { OPBV = SEED; }')
    w('OP2B: is f110u2=1 & f148lr { OPBV = f148lr; }')
    w('OP2B: is f110u2=2 & FU2 { build FU2; }')
    w('OP2B: is f110u2=3 { OPBV = LDL; }')
    w('# Seed operand (ESTABLISHED): r110 bit 1 set takes the register in r148')
    w('# bits 9-5, clear the forwarded result in r128 bits 5-3.')
    for k in range(8):
        src = 'U1H%d' % (4 + k) if k < 4 else 'U2H%d' % k
        w('FSD: is f128p1=%d { SDOP = %s; }' % (k, src))
    w('SDO: is f110sd=1 & f148hr { SDOP = f148hr; }')
    w('SDO: is f110sd=0 & FSD { build FSD; }')
    w('OPS: is LDR & CRD & PT1 & PT2 & OP2A & OP2B & SDO { build LDR; build CRD; build PT1; build PT2; build OP2A; build OP2B; build SDO; }')
    w('')
    w('U1S: is fMu=0x7f { }')
    for code, mn, pc, kind, label in U1:
        w('# 0x%02x %s: %s' % (code, mn, label))
        w('U1S: is fMu=0x%x { %s STV = U1V; U1H0 = U1V; }' % (code, pc))
    w('# Unit-1 codes no document identifies: named, not given a meaning.')
    w('U1S: is fMu { U1V = u1_op(fMu:1, P1V, P2V); STV = U1V; U1H0 = U1V; }')
    w('U2S: is fMk=0xd { }')
    for k, mn, pc, kind, label in U2:
        w('# k=0x%x (code 0x%02x) %s: %s' % (k, (k << 3) | 7, mn, label))
        w('U2S: is fMk=0x%x { %s STV = U2V; U2H0 = U2V; }' % (k, pc))
    w('# k = 5 (0x2f: move of B or minimum), 7 (0x3f) and the rest: UNKNOWN.')
    w('U2S: is fMk { U2V = u2_op(fMk:1, OPAV, OPBV); STV = U2V; U2H0 = U2V; }')
    w('')
    w('# Seed unit (ESTABLISHED, ge_isa.md "Unit-2 and seed-unit operands"): it')
    w('# runs in every word on SDOP; r110 bit 10 set gives the reciprocal seed,')
    w('# clear the reciprocal-square-root seed, and unit 2 reads it two words')
    w('# later. APPROXIMATION: the seeds are within 0.4%% with 7 fraction bits')
    w('# (ESTABLISHED) but the table is UNKNOWN, so the exact 1/x and 1/sqrt(x)')
    w('# stand in; a seed nothing reads is dead code the decompiler drops.')
    w('SDS: is f110b10=1 { SEED0 = int2float(1:4) f/ SDOP; }')
    w('SDS: is f110b10=0 { SEED0 = int2float(1:4) f/ sqrt(SDOP); }')
    w('')
    w('# Destinations: unit 1 writes Q, unit 2 writes P; 0x1f is the idle value')
    w('# (ESTABLISHED as the no-op value; "no register write" INFERRED: stores of a')
    w('# unit result carry it).')
    w('WQ: is fQ=0x1f { }')
    w('WQ: is fQr { fQr = U1V; }')
    w('WP: is fP=0x1f { }')
    w('WP: is fPr { fPr = U2V; }')
    w('')
    w('# Address unit. Source C: the immediate when C = 0x1e (INFERRED), else an')
    w('# address register. F = 0x3f adds A and C (ESTABLISHED for the GE11 aalu3')
    w('# test, KONA areg.s agrees); F = 0x1f (idle value) and F = 0 pass C through')
    w('# (INFERRED: pointer copies in uxform.s, loop-count loads, areg.s loads);')
    w('# F = 0x20 and 0x25 step C down by one (INFERRED: GE11 eram_Databus, the')
    w('# counted loops). Other F values are UNKNOWN.')
    w('CSR: is fC=0x1e & fimm { CSRC = fimm; }')
    w('CSR: is fCr { CSRC = fCr; }')
    w('AOP: is fF=0x3f & fAr { AUV = fAr + CSRC; }')
    w('AOP: is fF=0x1f { AUV = CSRC; }')
    w('AOP: is fF=0x0 { AUV = CSRC; }')
    w('AOP: is fF=0x20 { AUV = CSRC - 1; }')
    w('AOP: is fF=0x25 { AUV = CSRC - 1; }')
    w('AOP: is fF & fAr { AUV = aalu(fF:1, fAr, CSRC); }')
    w('AUS: is f219=0 & f222=0 { }')
    w('AUS: is CSR & AOP { build CSR; build AOP; }')
    w('# r219 != 0 writes G (ESTABLISHED by areg.s for loads, INFERRED otherwise).')
    w('WG: is f219=0 { }')
    w('WG: is fGr { fGr = AUV; }')
    w('# r222: the address-unit result sets the address conditions (ESTABLISHED).')
    w('FLA: is f222=0 { }')
    w('FLA: is f222=1 { AZ = (AUV == 0); AGT = (AUV s> 0); }')
    w('')
    w('# Stores. r213 = 3: the unit result to B + E (ESTABLISHED for the')
    w('# diagnostic output words), or to CRAM at the immediate when B = 0x1e and')
    w('# r95 = 0x13 (ESTABLISHED). r213 = 2 is the predicated form (INFERRED); the')
    w('# predicate is UNKNOWN. r215 = 3: the immediate to B + E (form 15 constant')
    w('# loads, INFERRED from ge_inst.s). r211 = 3 with r95 = 4: the unit result to')
    w('# CRAM through C (INFERRED, load-matrix handlers and mMatrixCopyCC).')
    w('SADDR: a is fB=0x1e & f95=0x13 & fimm [ a = fimm & 0xffff; ] { export *[cram]:4 a; }')
    w('SADDR: is fBr & fE { local a:4 = fBr + fE; export *[dmem]:4 a; }')
    w('ST3: is f213=0 { }')
    w('ST3: is f213=1 { }')
    w('ST3: is f213=3 & SADDR { SADDR = STV; }')
    w('ST3: is f213=2 & SADDR { local p:1 = store_predicate(); if (p == 0) goto <skip>; SADDR = STV; <skip> }')
    w('ST5: is f215=0 { }')
    w('ST5: is f215=1 { }')
    w('ST5: is f215=3 & fBr & fE & fimm { local a:4 = fBr + fE; *[dmem]:4 a = fimm:4; }')
    w('ST5: is f215=2 & fBr & fE & fimm { local a:4 = fBr + fE; local p:1 = store_predicate(); if (p == 0) goto <skip>; *[dmem]:4 a = fimm:4; <skip> }')
    w('ST1R: is fC=0x1e & fimm { *[cram]:4 fimm:2 = STV; }')
    w('ST1R: is fCr & fF { local a:4 = fCr + (0x1f - fF); *[cram]:4 a:2 = STV; }')
    w('ST1A: is fform=5 & fimm { *[cram]:4 fimm:2 = STV; }')
    w('ST1A: is ST1R { build ST1R; }')
    w('ST1: is f211=3 & f95=4 & ST1A { build ST1A; }')
    w('ST1: is epsilon { }')
    w('')
    w('# Flags: r220 sets the low nibble from unit 1, r221 the high nibble from')
    w('# unit 2 (INFERRED split by unit, ge_ops.md).')
    w('FK1: is fMu=0x7f { }')
    for code, mn, pc, kind, label in U1:
        if kind == 'i':
            w('FK1: is fMu=0x%x { local n:1; inib(n, U1V, P2V); FL = (FL & 0xf0) | n; }' % code)
        elif kind == 'f':
            w('FK1: is fMu=0x%x { local n:1; fnib(n, U1V, P2V); FL = (FL & 0xf0) | n; }' % code)
    w('FK1: is fMu { local n:1 = passb(fMu:1, U1V, P2V); FL = (FL & 0xf0) | n; }')
    w('FK2: is fMk=0xd { }')
    for k, mn, pc, kind, label in U2:
        if kind == 'i':
            w('FK2: is fMk=0x%x { local n:1; inib(n, U2V, OPBV); FL = (FL & 0x0f) | (n << 4); }' % k)
        elif kind == 'f':
            w('FK2: is fMk=0x%x { local n:1; fnib(n, U2V, OPBV); FL = (FL & 0x0f) | (n << 4); }' % k)
    w('FK2: is fMk { local n:1 = passb(fMk:1, U2V, OPBV); FL = (FL & 0x0f) | (n << 4); }')
    w('FL1: is f220=0 { }')
    w('FL1: is f220=1 & FK1 { build FK1; }')
    w('FL2: is f221=0 { }')
    w('FL2: is f221=1 & FK2 { build FK2; }')
    w('')
    w('# A word\'s own work: operands are read before anything is written, so the')
    w('# units, the address unit and the stores all see the values from before it.')
    w('BODY: is OPS & U1S & U2S & SDS & AUS & WQ & WP & WG & FLA & ST3 & ST5 & ST1 & FL1 & FL2 {')
    w('  flagshift();')
    w('  build OPS; build U1S; build U2S; build SDS; build AUS;')
    w('  build ST3; build ST5; build ST1;')
    w('  build WQ; build WP; build WG;')
    w('  build FLA; build FL1; build FL2;')
    w('}')
    w('')
    w('# Conditions (ge_ops.md). cc 0-15 test the condition word as it was twelve')
    w('# words earlier (ESTABLISHED for KONA, "The twelve-word flag delay"): cc')
    w('# 0-7 the low nibble, 8-15 the high; address conditions are two words')
    w('# late (ESTABLISHED);')
    w('# cc bits 2-1 pick <= 0, zero, negative, second-operand-passed and bit 0')
    w('# inverts (ESTABLISHED for the test cases). cc 0x10/0x11 address result')
    w('# zero/not zero, 0x14/0x15 > 0 / <= 0 (ESTABLISHED by the GE11 labels).')
    w('# cc 0x10 in group 31 is an abort request from outside (INFERRED). Others')
    w('# (0x72 and 0x76 dirty flags, 0x60-0x7f dispatch tests) are UNKNOWN.')
    for cc in range(16):
        nib = 4 if cc >= 8 else 0
        bit = nib + 3 - ((cc >> 1) & 3)
        inv = cc & 1
        expr = '((FLD12 >> %d) & 1)' % bit
        if inv:
            w('COND: is fcc=0x%x { local c:1 = %s == 0; export c; }' % (cc, expr))
        else:
            w('COND: is fcc=0x%x { local c:1 = %s != 0; export c; }' % (cc, expr))
    w('COND: is fcc=0x10 & fsgrp=31 { local c:1 = abort_requested(); export c; }')
    w('COND: is fcc=0x10 & fsgrp { local c:1 = AZD2; export c; }')
    w('COND: is fcc=0x11 { local c:1 = !AZD2; export c; }')
    w('COND: is fcc=0x14 { local c:1 = AGTD2; export c; }')
    w('COND: is fcc=0x15 { local c:1 = !AGTD2; export c; }')
    w('COND: is fcc { local c:1 = cond_test(fcc:2); export c; }')
    w('')
    w('# ---- Instructions')
    w('# Words without a transfer (sequencer code 6, ESTABLISHED as the common case).')
    w(':^MN FIELDS is fvalid=1 & fsop=6 & MN & FIELDS & BODY & wlo { build BODY; }')
    w('# Delay slots: a transfer takes effect after four words (INFERRED from the')
    w('# GE11 microcode latency four and the call sites resuming at call + 5); a')
    w('# return after eight (ESTABLISHED for the GE11, MemRegInit writes them out).')
    w('# Ghidra cannot nest delay slots, and dispatch chains put transfers in each')
    w('# other\'s window, so the loader sets fdly to the words before the next')
    w('# transfer (at most 4 or 8) and those are the delay slots modelled. A')
    w('# transfer inside another\'s window is thus modelled as taking effect')
    w('# after the earlier one: an approximation of how the two overlap, which')
    w('# no document describes.')
    w('# Group 0 code 4: call (ESTABLISHED). Code 5 in group 0: conditional call')
    w('# (INFERRED: the transform modules\' cc 0x72/0x76 calls). Code 4 without')
    w('# R88: jump; code 5: conditional jump (INFERRED); code 3: the loop form,')
    w('# conditional (INFERRED, mainloop/epilogue targets). R88 in group 31: end')
    w('# of command, on to the next handler the dispatch hardware supplies')
    w('# (INFERRED). R88 in other groups: return (ESTABLISHED for the GE11,')
    w('# INFERRED for KONA groups 4 and 5).')
    kinds = [
        ('call', 'fsop=4 & fsind=0 & fsgrp=0', 'XT', '', 'LR = inst_start + @K@; call XT;', 4),
        ('callc', 'fsop=5 & fsind=0 & fsgrp=0', 'XT & COND', 'build COND; local c:1 = COND;',
         'if (!c) goto <skip>; LR = inst_start + @K@; call XT; <skip>', 4),
        ('jmp', 'fsop=4 & fsind=0', 'XT', '', 'goto XT;', 4),
        ('bc', 'fsop=5 & fsind=0', 'XT & COND', 'build COND; local c:1 = COND;', 'if (c) goto XT;', 4),
        ('loop', 'fsop=3 & fsind=0', 'XT & COND', 'build COND; local c:1 = COND;', 'if (c) goto XT;', 4),
        ('endcmd', 'fsop=4 & fsind=1 & fsgrp=31', '', '', 'NEXTCMD = next_command(); return [NEXTCMD];', 4),
        ('endcmdc', 'fsop=5 & fsind=1 & fsgrp=31', 'COND', 'build COND; local c:1 = COND;',
         'if (!c) goto <skip>; NEXTCMD = next_command(); return [NEXTCMD]; <skip>', 4),
        ('ret', 'fsop=4 & fsind=1', '', '', 'return [LR];', 8),
        ('retc', 'fsop=5 & fsind=1', 'COND', 'build COND; local c:1 = COND;',
         'if (!c) goto <skip>; return [LR]; <skip>', 8),
    ]
    for mn, cons, ops, pre, post, nmax in kinds:
        for k in range(nmax + 1):
            pat = 'fvalid=1 & %s & fdly=%d & FIELDS & BODY%s & wlo' % (cons, k, (' & ' + ops) if ops else '')
            ds = ' delayslot(%d);' % (8 * k) if k else ''
            # inst_next would make Ghidra decode the delay slots to build
            # p-code before the disassembler has committed them.
            w(':%s FIELDS is %s { build BODY; %s%s %s }' % (mn, pat, pre, ds, post.replace('@K@', str(k + 1))))
    w('# Sequencer codes 0, 1, 2, 7 and code 3 with R88: UNKNOWN (rare); no flow.')
    w(':xfer FIELDS is fvalid=1 & fsop & FIELDS & BODY & wlo { build BODY; seq_unknown(fsop:1); }')


def nop_constraints():
    res = []
    for g in ORDER:
        if g in SIMPLE:
            res.append((SIMPLE[g], NOP[g]))
        else:
            sh = 0
            for f, width in reversed(SPLIT[g]):
                res.append((f, (NOP[g] >> sh) & ((1 << width) - 1)))
                sh += width
    return res


def main():
    out = []
    emit(out)
    with open(OUT, 'w') as fh:
        fh.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
