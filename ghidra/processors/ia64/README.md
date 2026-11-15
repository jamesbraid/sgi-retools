# IA-64 (Itanium) processor module

A Ghidra processor for IA-64, written to read the SGI Altix and Prism system firmware
(the SN2 PROM: PAL, SAL_A, SAL_B) in Ghidra instead of objdump scripts. Language id
`IA64:LE:64:default`.

## How a bundle becomes instructions

An IA-64 bundle is 128 bits: a 5-bit template, then three 41-bit slots. Each slot is
its own Ghidra instruction, at the address `ia64-linux-gnu-objdump` prints for it:

| Slot | Address | Length |
|---|---|---|
| 0 | bundle + 0 | 6 |
| 1 | bundle + 6 | 6 |
| 2 | bundle + 0xc | 4 |
| L+X of MLX | bundle + 6 | 10 |

So an address in an objdump listing, or in notes written from one (`0xffc4e096` is slot 1
of the bundle at `0xffc4e090`), is the same address in Ghidra. Branch targets and call
return addresses are bundle addresses (slot 0), as on the hardware; a call's return
address is the next bundle, whichever slot the call is in.

Slots 1 and 2 do not start on byte boundaries, so the instruction before each one hands
over what it needs in noflow context fields: the template (`tmpl`), and the slot's low
bits (`ca` for slot 1, two bits; `cb` for slot 2, nine bits). Disassembly therefore has to
reach a bundle at slot 0; started at +6 or +0xc without that context, Ghidra decodes the
bytes as a slot 0. Flow never does that: every branch target is a bundle.

The template decides each slot's unit (M, I, F, B, or L+X) and its stops. Stops print as
`;;` after the instruction. A qualifying predicate other than p0 prints as the first
operand, `(p6)`, so the mnemonic column holds only the mnemonic and its completers.
Numbers print in Ghidra's hexadecimal.

## Files

- `tools/ia64_isa.py`: the instruction table (encodings from the Intel Itanium Architecture
  Software Developer's Manual rev 2.3, vol 3, 323207, chapter 4; GNU assembler syntax), with
  a reference decoder.
- `tools/gen_slaspec.py`: writes `ia64.slaspec` from the table. The `.slaspec` is not committed:
  the Ghidra image builds it (a throwaway stage runs the generator), and `tools/re-run` tags the
  image with a hash of the generator and tables. To try it by hand: `python3 tools/gen_slaspec.py OUT`.
- `tests/run-ghidra.sh`: installs the module and the image's generated slaspec (or `IA64_SLASPEC=FILE`) and disassembles a flat
  image, every bundle (`DumpSlots.java`, which also decodes slots after a branch that is
  always taken).
- `tests/check.py`: compares that listing with `ia64-linux-gnu-objdump` over the code
  regions an SN2 PROM's FIT names.
- `tests/synthetic.py`: hand-encoded bundles with their expected text, for the reference
  decoder (no arguments) or for Ghidra (`write`, then `check`). `write` also writes `emu.tsv`:
  short sequences that `EmuSynthetic.java` runs in Ghidra's emulator and `check-emu` compares
  with the SDM (signed `extr` with pos+len over 64, `ld` post-incrementing by its own target).
  It also lays out a status function for `DecompileAt.java` that must not decompile as `void`
  (`check-dec`).
- `tests/test_generated.py`: the generator runs and writes a file with the expected landmarks.

## Running

From a workspace whose `root/` holds the SN2 images (chips), with retools as `retools/`:

```sh
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64 root/sn2/snprom-10.54-70399/boot/efi/efi/sgi/snprom/shub1snprom.bin 0xffa00000
retools/tools/re-run python3 retools/ghidra/processors/ia64/tests/check.py \
    .cache/ia64/slots.tsv root/sn2/snprom-10.54-70399/boot/efi/efi/sgi/snprom/shub1snprom.bin
```

Where the image is absent (a workspace without a PROM root), `check.py` prints that it
skipped and exits 0. The synthetic test needs no image:

```sh
python3 retools/ghidra/processors/ia64/tests/synthetic.py
python3 retools/ghidra/processors/ia64/tests/synthetic.py write .cache/ia64-syn
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64-syn .cache/ia64-syn/synthetic.bin 0x80000
python3 retools/ghidra/processors/ia64/tests/synthetic.py check .cache/ia64-syn/slots.tsv
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64-syn .cache/ia64-syn/synthetic.bin 0x80000 EmuSynthetic.java \
    .cache/ia64-syn/emu.tsv .cache/ia64-syn/emu.out
python3 retools/ghidra/processors/ia64/tests/synthetic.py check-emu .cache/ia64-syn/emu.out
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64-syn .cache/ia64-syn/synthetic.bin 0x80000 DecompileAt.java .cache/ia64-syn 0x80130
python3 retools/ghidra/processors/ia64/tests/synthetic.py check-dec .cache/ia64-syn/0x80130.c
```

## Agreement with objdump

Measured with binutils 2.44 on `shub1snprom.bin` (SAL 5.04, sha256 `51ccf9ad...3a34617`):
over PAL_B 7.79, 5.73 and 2.25, the three processor-specific PAL_A images, SAL_A, SAL_B
and the generic PAL_A, objdump decodes 731,511 slots and Ghidra gives the same mnemonic,
completers, operands, predicate and stop for all of them.

objdump cannot decode 105,508 slots there (it prints `data8`). Most are data between
code, and a reserved template makes all three slots of its bundle undecodable. Ghidra shows
each of those slots as `unknown`, `unknown.m`, `.i`, `.f`, `.b` or `.x` with the slot's 41
raw bits, and gives it no semantics beyond an `unknown_insn` call. Two encodings occur in
real code and are left that way on purpose, because no public document assigns them:
M-unit opcode 0 with x3 0, x4 1, x2 2 (slot bits 32:27 = 33), right after `srlz` at
`0xFFFF82F6`; and B-unit opcode 0 with x6 9 at `0xffe0905c`, `0xffe0912c`, `0xffe0917c`
and `0xffe091bc`.

## P-code

Enough to read SAL and PAL as C. What is modelled and what is approximated:

- Registers. r0 reads as 0, p0 as 1, f0 and f1 as 0.0 and 1.0; writes to them go nowhere.
  A qualifying predicate makes the instruction a no-op when false.
- Compares and tests write their predicate pair by compare type: normal, `unc` (both
  cleared when the qualifying predicate is false), `and`, `or` and `or.andcm`.
  `mov pr=r,mask`, `mov r=pr` and `mov pr.rot` act on the 63 single predicates.
- Loads and stores, with post-increment by register or immediate. Acquire and release
  forms are plain accesses; the module keeps their order only for uncached addresses
  (bit 63 set, declared volatile in the pspec), which is where SAL's device registers are.
  Speculative, advanced and check loads load; `chk.a` asks a `chk_a` op whether to branch.
- Branches: conditional, indirect, `br.call` (return address in b1 is the next bundle),
  `br.ret`, `br.cloop` on ar.lc, and the modulo-scheduled `br.ctop`, `br.cexit`,
  `br.wtop`, `br.wexit` on ar.lc, ar.ec and p63.
- Application, control and branch registers are named registers (`ar.lc`, `cr.lid`,
  `b0`). `msr`, `cpuid`, `pmc`, `pmd`, `rr`, `dbr`, `ibr`, `pkr` and `dahr` are address
  spaces indexed by the general register, so `mov r9=msr[r10]` with r10 known shows as
  `msr:0xd4`.
- Floating-point registers hold 64 bits: the significand for the integer forms
  (`setf.sig`, `getf.sig`, `xma`, which compilers use for multiplication, so it decompiles
  as `*`), a double for arithmetic. The 82-bit register format is not modelled;
  `ldf.fill` and `stf.spill` move 8 of their 16 bytes.
- `rfi` restores psr from cr.ipsr and returns to cr.iip.
- What the architecture leaves to the implementation, or depends on state the module
  does not keep, is a named p-code op and never a guess: `frcpa`, `frsqrta` and their
  parallel forms, `nat` (NaT bits are not tracked, so `tnat` and `chk.s` ask it), `tf_bit`,
  `fclass`, `probe_*`, `thash`, `ttag`, `tpa`, `tak`, TLB and cache maintenance,
  `rotate_regs`, the multimedia instructions, and `unknown_insn` for an unassigned
  encoding.

The register stack is approximated. r32..r127 are fixed registers: `alloc` renames
nothing, `br.call` does not save the frame and `br.ret` does not restore it, rotation is
the `rotate_regs` op without effect, and `flushrs`, `loadrs` and `cover` are ops. To keep
call arguments right, `alloc` records the frame's locals (sol) and outputs (sof - sol) in
flowing context, and each call copies up to eight output registers r(32+sol).. into
r32.. before it and puts the caller's r32.. back after it. The callee therefore sees its
arguments where its own code reads them, r32..r39, and the cspec passes arguments there
and returns them in r8. A call reached before any `alloc` in its function copies nothing.

r8 is also listed as a ninth input register. The decompiler decides what a function returns
before it can prove that two predicated writes (`(p6) mov r8=0` / `(p7) mov r8=-33`) are
complementary, and rejects r8 because the path where neither runs leaves the function's input
r8; an input that could be a parameter is accepted. Without this such a function came out
`void`. The cost is a function that reads r8 before writing it can get a ninth parameter.
