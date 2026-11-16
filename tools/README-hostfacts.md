# hostfacts: routine facts without containers

`tools/facts.py` needs the MIPS objdump from the toolchain container, so an agent whose
sandbox cannot run Podman has had to read raw disassembly, and that is where offsets, branch
directions and call arguments go wrong. `tools/hostfacts.py` gives the same facts on the host. It
runs facts.py's analysis with a Capstone decoder in place of objdump, so a run needs only
Python with `capstone` and `pyelftools`:

```sh
uv run --with capstone --with pyelftools \
    python -I retools/tools/hostfacts.py BINARY[:MEMBER] ROUTINE [--size N] [--flat --load ADDR] [--json]
```

Run it from the workspace root (a clone of this repository elsewhere works too, given by its path) with the same arguments as `facts.py` (ROUTINE is a symbol or
`0xADDR`; an archive member follows a colon). The text names, for the one routine:

- range, size, ELF class, ABI and ISA;
- every load and store with its width, base register, the displacement as written and the resolved
  target, `abs 0xADDR` or `ORIGIN +/-0xOFF`. A displacement from a `lui`-built base keeps its sign,
  so `lui t0,1; lw t1,-0x6954(t0)` reads as 0x96ac from the origin, not 0x6954;
- every call with its callee and the argument registers as the callee sees them, after the delay
  slot (`?` is a register the tool could not follow);
- basic blocks, each conditional branch with when it is taken and when it falls through, the
  instruction in its delay slot and whether a branch-likely annuls it, and which blocks reach each
  return and what v0 holds on the way in;
- the constants and immediates the routine uses.

Base every offset, condition and argument claim on this output, not on a hand reading of the
listing. `--json` prints the sheet `facts.py` prints. Its sections match a container run of
`tools/re-run python3 tools/facts.py` on the same routine, except where objdump prints a
64-bit constant load as the pseudo-instruction `dli` (N64 code): facts.py does not follow `dli`, so
the Capstone run, which decodes it as `ori`, shows constants and call arguments the container
run lacks. `tools/test_hostfacts.py` holds the hand-assembled checks (run it with the same
`uv run --with` line); it skips itself when Capstone is missing.

## Flat controller firmware

The same `hostfacts.py` entry point also accepts `--arch coldfire`, `m68k`,
`arm`, `thumb`, `x86-16` and `x86-32`. These modes require `--load ADDR`.
For raw images, supply `--size N`. The tool does not infer a routine boundary
from a linear decoder. `--offset N` skips a container header before mapping
the payload at the load address.

```sh
uv run --with capstone --with pyelftools python -I tools/hostfacts.py \
    firmware.bin 0xffe10400 --arch coldfire --flat --load 0xffe00000 --size 0x40
uv run --with capstone --with pyelftools python -I tools/hostfacts.py \
    mmscfw.bin _sysNvRamGet --arch x86-32 --load 0x108000
```

MMSC a.out images use `tools/sysco/mmsc_aout.py` for their text/data map and
nlist names. Their routine sizes come from the next symbol and are labelled
inferred. Headers, symbols and bss are not treated as mapped file contents.
An explicit load address that disagrees with the a.out header is rejected.

The non-MIPS sections report accesses, calls, control flow, returns,
constants and an instruction listing. Register values are merged across all
predecessors. Unsupported effects invalidate affected values and produce
warnings. Predicated ARM accesses carry their execution condition. There are
no delay slots in these modes.

The default calling conventions are M68K stack arguments, ARM AAPCS registers
and x86 cdecl32 stack arguments. Argument counts are unknown: the printed
locations are candidates, not a declaration that the callee accepts them.
Use `--abi unknown` when the convention is not established, or `--abi cdecl16`
for a known 16-bit near-call convention. The default x86-16 ABI is unknown.
Its addresses are segment offsets, with no inferred segment base. ColdFire
uses Capstone's 68040 decoder for the common instruction subset. This does
not establish that every decoded opcode is legal on a ColdFire part.

`--arch ppc32` decodes big-endian 32-bit PowerPC with Capstone and uses the
System V register convention (arguments in r3 to r10, result in r3). It models
address and constant building (`li`, `lis`, `addi`, `addis`, `ori`, `oris`,
`mr`), D-form loads and stores, `cmpwi`/`cmpw`, the link and count registers
and the branch family. Everything else invalidates what it writes and warns.
Compares through a CR field other than cr0, unsigned compares and indexed
loads and stores are not tracked.

Run the synthetic regression tests on the host:

```sh
uv run --with capstone --with pyelftools python -I tools/test_hostfacts.py
uv run --with capstone --with pyelftools python -I tools/test_hostfacts_firmware.py
```

The [real-image validation table](tools/hostfacts-firmware-validation.tsv)
records five routines per extracted image: 60 ColdFire bodies, 20 executable
ARM segments and 11 MMSC carriers. It preserves the input hashes and mappings.
These checks compare decoded bytes, emitted locators and required fact-sheet
sections. The synthetic tests and independent review cover modeled instruction
effects. Warnings and unknown values remain part of the output.

The CPU families and MMSC mapping follow sysco's `docs/controllers.md` and
`docs/mmsc/load-map.md`. ColdFire body mappings come from each package header,
with the layout described in `docs/l1/coldfire-package-sections.md`. ARM
packages have no load address in their outer headers. The ARM checks use
executable segments from their userland ELF images and take `p_vaddr` from
each ELF program header. No outer ARM package load address is assumed.

