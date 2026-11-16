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
  with the SDM (signed `extr` with pos+len over 64, `ld` post-incrementing by its own target),
  and three register stack programs run until a given address: nested calls with different
  frames, a software-pipelined loop and `clrrrb`, and `cover`, `flushrs`, `loadrs` and `rfi`.
  It also lays out functions for `DecompileAt.java`: a status function that must not
  decompile as `void` (`check-dec`), a call that must pass one argument, not the gp beside it
  (`check-call`), and the register stack programs' functions (`frames`, `check-frames`).
  A `br.ia` function checks the flagged form (`pal=ADDRESS` argument to `DecompileAt.java`; `check-pal`) and
  the plain one (`check-plain`). A loop that saves the predicates with `mov r=pr` and restores them with
  `mov pr=r,mask` must decompile (`predloop`, `check-predloop`). Three functions run `break.m 0`,
  `break.m` with a system call's immediate and `(p6) break.m 0`, then set r8: only the first loses the code behind it
  (`breaks`, `check-breaks`). `DecompileAt.java` with `sigs` first runs `IA64Signatures.java`: a store function
  and its caller must come out `void`, a function that sets r8 must not (`voids`, `check-voids`).
- `tests/DecompileAt.java`: makes a function at each address it is given in a flat image and writes its C and
  listing. The synthetic tests and a quick look at one function of a PROM use it; for a whole ELF or PROM
  go through `tools/ghidra-export.py` (`tools/README-analysis.md`).
- `tests/test_generated.py`: the generator runs and writes a file with the expected landmarks.

## Running

From a workspace whose `root/` holds the SN2 images (chips), with retools as `retools/`:

```sh
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64 root/sn2/snprom-10.54-70399/boot/efi/efi/sgi/snprom/shub1snprom.bin 0xffa00000
retools/tools/re-run python3 retools/ghidra/processors/ia64/tests/check.py \
    .cache/ia64/slots.tsv root/sn2/snprom-10.54-70399/boot/efi/efi/sgi/snprom/shub1snprom.bin
```

An IA-64 ELF object, such as an SN2 Linux kernel, loads through Ghidra's ELF loader
(`data/languages/ia64.opinion` maps EM_IA_64 to this language) and is read the same way as a
MIPS one: `retools/tools/re-run --ghidra-export vmlinux --decompile-symbol sn_setup`. The
kernel is linked, so nothing is relocated; calls through function descriptors stay indirect.

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
    .cache/ia64-syn .cache/ia64-syn/synthetic.bin 0x80000 DecompileAt.java .cache/ia64-syn r1=1000 0x80130 0x80150
python3 retools/ghidra/processors/ia64/tests/synthetic.py check-dec .cache/ia64-syn/0x80130.c
python3 retools/ghidra/processors/ia64/tests/synthetic.py check-call .cache/ia64-syn/0x80150.c
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64-syn .cache/ia64-syn/synthetic.bin 0x80000 DecompileAt.java .cache/ia64-syn \
    $(python3 retools/ghidra/processors/ia64/tests/synthetic.py frames)
python3 retools/ghidra/processors/ia64/tests/synthetic.py check-frames .cache/ia64-syn
retools/tools/re-run --ghidra -- sh retools/ghidra/processors/ia64/tests/run-ghidra.sh \
    .cache/ia64-syn .cache/ia64-syn/synthetic.bin 0x80000 DecompileAt.java .cache/ia64-syn \
    $(python3 retools/ghidra/processors/ia64/tests/synthetic.py predloop)
python3 retools/ghidra/processors/ia64/tests/synthetic.py check-predloop \
    .cache/ia64-syn/$(python3 retools/ghidra/processors/ia64/tests/synthetic.py predloop).c
```

## Agreement with objdump

Measured with binutils 2.44 on `shub1snprom.bin` (SAL 5.04, sha256 `51ccf9ad...3a34617`):
over PAL_B 7.79, 5.73 and 2.25, the three processor-specific PAL_A images, SAL_A, SAL_B
and the generic PAL_A, objdump decodes 731,511 slots and Ghidra gives the same mnemonic,
completers, operands, predicate and stop for all of them. The same check on `shub2snprom.bin` of that
release (914,540 slots) and on the older SAL 4.43 `snprom.bin` (694,790) also finds 0 mismatches; the
p-code changes do not touch the decoded text.

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
- `mov r=pr` builds the 64-bit value as one OR expression of the predicates, not as 63 writes to the
  register: a loop that saved the predicates with it and restored them with `mov pr=r,mask` (the PAL's FIT
  walk) made the decompiler stop with "Unable to find unique hash for varnode".
- Loads and stores, with post-increment by register or immediate. Acquire and release
  forms are plain accesses; the module keeps their order only for uncached addresses
  (bit 63 set, declared volatile in the pspec), which is where SAL's device registers are.
  Speculative, advanced and check loads load; `chk.a` asks a `chk_a` op whether to branch.
- Branches: conditional, indirect, `br.call` (return address in b1 is the next bundle),
  `br.ret`, `br.cloop` on ar.lc, and the modulo-scheduled `br.ctop`, `br.cexit`,
  `br.wtop`, `br.wexit` on ar.lc, ar.ec and p63.
- `break` with an immediate of 0 and no qualifying predicate (Linux's `BUG()`) never falls through: its
  p-code is a jump to itself, so flow, and the function, end there. A nonzero immediate (a system call) and a
  predicated `break` fall through as before.
- Application, control and branch registers are named registers (`ar.lc`, `cr.lid`,
  `b0`). `msr`, `cpuid`, `pmc`, `pmd`, `rr`, `dbr`, `ibr`, `pkr` and `dahr` are address
  spaces indexed by the general register, so `mov r9=msr[r10]` with r10 known shows as
  `msr:0xd4`.
- Floating-point registers hold 64 bits: the significand for the integer forms
  (`setf.sig`, `getf.sig`, `xma`, which compilers use for multiplication, so it decompiles
  as `*`), a double for arithmetic. The 82-bit register format (sign, 17-bit exponent,
  64-bit significand; SDM vol 1 5.1.2, 1:85) is not modelled, because Ghidra has no float format
  for it (its 10-byte format is x87's, with a 15-bit exponent) and the decompiler's float
  operations need one. Firmware and kernels use the FP registers for integer multiply and
  divide and for saving context, neither of which needs the exponent. `ldf.fill` and
  `stf.spill` move 8 of their 16 bytes: the half with the sign and exponent is not kept.
- NaT bits are not stored. `tnat` and `chk.s` ask the `nat` op, which the decompiler
  keeps opaque, so both paths of a NaT test stay in the C. A speculative load is a plain
  load (no fault is deferred, so the NaT it would set is clear), `st8.spill` and
  `ld8.fill` move the value and leave `ar.unat` alone, and the register stack does not
  collect NaT bits in `ar.rnat`. The emulator has no `nat`: emulated code stops at a NaT
  test.
- `br.ia` is a plain jump to an IA-32 entry (an opaque `br_ia` op, then a branch to b2), except where the
  `pal` context bit is set: there it is `r1 = pal_special_service(r5, r2, r3)` and execution continues at the
  next bundle. `SN2PromImport.java` sets the bit at every `br.ia` in the PAL_A components, where the PAL
  code sets msr[1225], passes an image and its size in r2 and r3, and reads r1 afterwards. Inferred, not shown:
  no document names the service, and the PAL_A sites' b0 is the next bundle (the reset site's b0 is data).
- What the architecture leaves to the implementation, or depends on state the module
  does not keep, is a named p-code op and never a guess: `frcpa`, `frsqrta` and their
  parallel forms, `nat` (NaT bits are not tracked, so `tnat` and `chk.s` ask it), `tf_bit`,
  `fclass`, `probe_*`, `thash`, `ttag`, `tpa`, `tak`, TLB and cache maintenance,
  the multimedia instructions, and `unknown_insn` for an unassigned encoding.

## Register stack

The register stack and the register stack engine (SDM vol 2 chapter 6, 2:133-2:150) are
modelled by moving values, not by renaming registers, so each function's p-code reads its
own frame as r32..r127, which is what the decompiler and the emulator both need. CFM is
kept by field (`cfm_sof`, `cfm_sol`, `cfm_sor`, `rrb_gr`, `rrb_fr`, `rrb_pr`). The frames
below the current one live in an address space of their own, `rse`, from `bof`: the
physical stacked registers, without the hardware's limit, so the model never needs to
spill to the backing store.

- `alloc` sets CFM, and records sol, sof - sol and sor in flowing context.
- `br.call` saves CFM, `ar.ec` and psr.cpl in `ar.pfs`, moves the caller's locals to `rse`,
  moves its outputs down to r32.., where the callee reads them, gives the rest of r32..r39
  `noarg` (a register nothing writes, unaffected in the cspec, so a saved gp or other stale
  local is never an argument), and advances `ar.bsp` as the hardware does, with a NaT
  collection slot every 63 registers (vol 2 table 6-2).
- `br.ret` puts the callee's frame where the caller's outputs are, takes the caller's locals
  back from `rse`, and restores CFM, `ar.ec` and `ar.bsp` from `ar.pfs`. So after a call
  the caller's outputs hold what the callee left in its inputs, as on the hardware.
- `cover` moves the whole frame to `rse`, copies CFM to `cr.ifs` with the valid bit when
  psr.ic is 0, and starts an empty frame. `rfi` restores psr from `cr.ipsr`, takes the
  covered frame back when `cr.ifs` is valid, and resumes at slot psr.ri of `cr.iip`.
- `flushrs` sets `ar.bspstore` to `ar.bsp`. `loadrs` sets it to `ar.bsp` less RSC.loadrs.
  Writing `ar.bspstore` moves `ar.bsp` with it, keeping the dirty registers (table 6-4).
- `br.ctop`, `br.cexit`, `br.wtop` and `br.wexit` rotate r32..r(32+sor-1), f32..f127 and
  p16..p63 one place up when the hardware would, so p63 lands in p16, and count the rrb's
  down (vol 1 4.5.1, 1:76). `clrrrb` and `clrrrb.pr` rotate on round to rrb 0.

The decompiler sees the same p-code. Its copies into `rse` are dead because `rse` is not
global memory and `bof` is a constant in every function: the cspec sets it, and the rrb's,
to 0 on entry, as `br.call` leaves them. A call also copies r32.. to fs0..fs95 before it and
back after it, which stands in for the callee's `br.ret`. Under emulation that copy back
never runs, because the emulator continues at the return address; `br.ret` restores the
frame instead. The cspec lists r40..r127 as unaffected: the register stack preserves the
caller's locals.

A call reached before any `alloc` in its function passes r32.. as they are, since the
frame's size is not known.

Limits:

- The backing store in memory is never written or read. Code that reads spilled
  registers from memory after `flushrs` sees memory as it was.
- `cover` keeps all 96 stacked registers whatever the frame's size, so `rfi` takes back
  what a matching `cover` saved. An `rfi` with a `cr.ifs` that software built takes back
  whatever is in `rse` below.
- `br.call` does not un-rotate f32..f127 and p16..p63 for the callee. Only a callee that
  reads rotating registers its caller had rotated could tell.
- A software-pipelined loop reads rotating registers before any iteration writes them
  (the stage predicates keep those reads from mattering), so the decompiler can show them
  as parameters.

A call's arguments are the callee's parameters when the callee's signature is known.
`ghidra/scripts/IA64Signatures.java` sets one from each function's own body, callees first;
`tools/ghidra-export.py` runs it for IA-64. Without it, every output register the caller's
frame declares counts, and one set on only some paths shows up as an argument (`in_r40`). It also gives a
function that never writes r8, and calls and jumps only to functions it has made void, a `void` return.
Any other function keeps its return open, because a caller that returns through complementary predicated
writes still needs a possible r8 from the call.

Call limits. A decompiled caller does not see what a callee does to the callee's own input registers: the
copy of r32.. back after the call restores the caller's values, although emulation, where the callee's
`br.ret` restores the frame, does show them. An indirect call, a call to a function with no committed
signature and the arguments a varargs callee takes beyond its fixed ones are not known, so a call can show
arguments the callee never reads or miss ones it does.

Banked registers: r16..r31 are one set here, so code that runs between `bsw.0` and `bsw.1` (PAL, interruption
handlers) reads the other bank's values as `in_r*` or `extraout_r*`. `psr.bn` is not tracked in context.

Limits that matter when reading PAL and SAL. A PAL procedure called with the static register convention
(index in r28, arguments r29 to r31, status in r8 to r11) is an indirect call with no arguments: the
index is visible only in the r28 write before it, and the status branches after it test whatever the decompiler
last saw in r8. No convention for it is modelled. A routine entered by a branch rather than `br.call` has no
caller's frame, so which of r32..r127 it reads before writing (the FIT walk at the generic PAL_A,
`pale_reset_fit_walk`, which decompiles in full with the `pal_special_service` call and the test of its
result) shows as unwritten locals (`in_r*`).

r8 is also listed as a ninth input register. The decompiler decides what a function returns
before it can prove that two predicated writes (`(p6) mov r8=0` / `(p7) mov r8=-33`) are
complementary, and rejects r8 because the path where neither runs leaves the function's input
r8; an input that could be a parameter is accepted. Without this such a function came out
`void`. The cost is a function that reads r8 before writing it can get a ninth parameter.

## PE32+ images

An IA-64 PE32+ file (machine 0x200: an EFI driver or application, `elilo.efi`) loads through Ghidra's PE loader,
which `ia64.opinion` maps to this language. `ghidra/scripts/IA64Pe.java` runs before analysis and:

- applies the DIR64 base relocations when the image is not at its preferred base (`base=ADDR` moves it first);
- resolves the entry point and each export through its function descriptor, `{entry, gp}`: the function is named
  `entry` or the export's name and the descriptor `entry_descriptor` or `<name>_descriptor`;
- sets r1 over the executable blocks to the entry descriptor's gp (the GLOBALPTR directory's RVA when the entry is
  plain code). A descriptor with another gp is not given its own r1;
- makes a function at every other descriptor in the data (two relocated words, the first into code) and at each
  `.pdata` entry (begin RVA).

Read one with `tools/re-run --ghidra-export IMAGE.efi --decompile-symbol entry`. An EFI driver in a PROM
(`drv_fpswa.efi`, `drv_lsisas.efi`, `drv_b57undi64.efi` in SAL 5.04) is in a tar archive inside the FIT's type 0x22
component, which is gzip packed; extract the PE file first. Not done: a separate r1 for a descriptor whose gp differs from the entry's.

## Checks

Each runs in the Ghidra image through `retools/tools/re-run --ghidra --` unless it is marked Python.

| Check | Command (from the workspace, retools as `retools/`) | Passes when |
|---|---|---|
| Table and decoder (Python) | `python3 retools/ghidra/processors/ia64/tests/synthetic.py` and `tests/test_generated.py` | every hand-encoded slot gives its expected text; the generator writes the landmarks (CI runs both) |
| Agreement with objdump | `run-ghidra.sh .cache/ia64 IMAGE BASE`, then `python3 retools/ghidra/processors/ia64/tests/check.py .cache/ia64/slots.tsv IMAGE` | the summary line reads `mismatches: 0` (see below) |
| Ghidra on the synthetic image | `synthetic.py write DIR`, `run-ghidra.sh DIR DIR/synthetic.bin 0x80000`, then `synthetic.py check DIR/slots.tsv` | every slot in the listing is as expected |
| Emulator | `run-ghidra.sh ... EmuSynthetic.java DIR/emu.tsv DIR/emu.out`, then `synthetic.py check-emu DIR/emu.out` | each short sequence and register stack program ends as the SDM says |
| Decompiler | `run-ghidra.sh ... DecompileAt.java DIR ADDRESS...`, then `synthetic.py check-dec`, `check-call`, `check-frames`, `check-pal`, `check-plain`, `check-predloop`, `check-breaks` or `check-voids` | the C is as each check describes; `synthetic.py` with a function name prints the addresses (see Running) |
| PE32+ import | `tests/pe_synthetic.py write DIR`, `run-ghidra.sh` with `PE=1` and `PRESCRIPT=IA64Pe.java` (and `PRESCRIPT_ARGS=base=0x20000000` for the moved image), `DumpSymbols.java`, then `pe_synthetic.py check SYMS BASE` | the entry, the export and the `.pdata`-only function are functions, the descriptors are labelled, r1 is the gp at both bases |
| SN2 PROM import | `ghidra/import/sn2-prom/tests/run-ghidra.sh IMAGE DIR` and `check.py DIR/symbols.tsv IMAGE` | `0 failures` (`ghidra/import/sn2-prom/README.md`) |

A check that needs an image skips, with a message, where the workspace has no PROM root.
