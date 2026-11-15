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
- `tools/gen_slaspec.py`: writes `data/languages/ia64.slaspec` from the table. Edit the
  table or the generator and regenerate; do not edit the `.slaspec`.
- `tests/run-ghidra.sh`: builds the module in the Ghidra image and disassembles a flat
  image, every bundle (`DumpSlots.java`, which also decodes slots after a branch that is
  always taken).
- `tests/check.py`: compares that listing with `ia64-linux-gnu-objdump` over the code
  regions an SN2 PROM's FIT names.
- `tests/synthetic.py`: hand-encoded bundles with their expected text, for the reference
  decoder (no arguments) or for Ghidra (`write`, then `check`).
- `tests/test_generated.py`: the committed `.slaspec` matches the generator.

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
