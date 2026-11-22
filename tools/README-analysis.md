# Analysis tools shared by the workspaces

Three tools beyond the decompile export. All run through `tools/re-run`, in the toolchain or Ghidra
image, and never write outside `.cache/` unless you give `--out`. Their output is derived from the
binary you point them at; public lists named below are used only to check numbering.

## Evidence order

This is the order every RE tool and agent uses for a register or behaviour fact. Take the fact from the
highest source that states it, and grade it by that source. The grade words are the ones the tools check:
`established`, `inferred`, `unknown`.

1. **IRIX source**: the public `irix-657m-src` tree, with its SN0/SN1 and graphics headers, PROM code and
   kernel code. Read it, learn the fact, and write it in your own words. Never copy source text into a commit
   or a datasheet. Cite the file path within that public tree. A fact the source defines is `established`.
2. **Shipped binaries**: the PROMs, kernels and libraries we disassemble. Confirm that the source matches
   what shipped, and note the release differences (6.5.7 source against 6.5.22 and 6.5.30 binaries).
3. **Public OS headers and drivers**: Linux, OpenBSD and NetBSD. They are mostly derived from SGI's own, so
   they rank below it. A fact from them becomes `established` when the IRIX source confirms it.
4. **Published SGI and vendor manuals.**
5. **Notes from other projects**: other projects' datasheets, manual pages and emulator code. They may confirm or
   contradict a fact and never supply one. A fact that rests only on one of them stays `unknown`, with the
   note named in `from`.

Machines with no IRIX source (the SN2 Altix and Prism, IA-64 on the SN1 Bedrock, and the Altix UV) put SGI's
own Linux platform code in step 1: the SN code under `arch/ia64/sn/`, its headers under `include/asm-ia64/sn/`
and `arch/ia64/include/asm/sn/`, and the UV code under `arch/x86/platform/uv/` and `arch/x86/include/asm/uv/`.
So is SGI-written Linux code for these platforms wherever it lives in the tree: `drivers/misc/ioc4.c` and its
headers, `drivers/char/snsc.c` and `snsc_event.c`, `drivers/char/mmtimer.c`, `drivers/misc/sgi-xp/`,
`drivers/misc/sgi-gru/`, `drivers/sn/`, and the SN-specific PCI providers. A fact it defines is `established`,
cited by tree, tag and path. SGI's shipped ProPack kernels and modules take
step 2.

Emulator runs show what the model does. They are never hardware evidence, and a reading must not call one
"observed" or "measured".

### Reset values

- `established`: the source states a power-on default, or PROM code relies on a reset state. Give
  `reset_from`.
- `inferred`: the PROM depends on a value before its first write. Cite the PROM address in `reset_from`.
- A register read after firmware initialisation is not a reset value. It can only rule values out.
- Otherwise `unknown`.
- A read on physical hardware is the last resort. It needs the repository owner's approval, and it counts as a reset value
  only for a register that firmware provably never writes.

### What the tools check

- `defs-check` fails when a numeric reset is graded `established` (its own `reset_grade`, else the register's)
  and has no `reset_from`.
- `defs-check` prints `WARN` when a register, or its reset value, is graded `established` and every source in
  `from` (or `reset_from`) names an emulator or another project's notes. The warning does not change the exit
  status. A source list that also names a real source passes.
- `grade_readings.py --check-doc` reports an entry sentence that says "observed", "measured" or
  "measurement" and names an emulator, a simulator or a model run.

The tools cannot judge the rest, such as whether the source really states a power-on default. A reviewer
checks that. Repos point here from their `AGENTS.md` with `tools/templates/AGENTS-evidence.md`.

## .mdebug import for Ghidra

MIPSpro objects built for o32 and N32 carry an ECOFF-style `.mdebug` symbol table that Ghidra's ELF
loader ignores. `ghidra-scripts/ReMdebugImport.java` reads it and applies:

- procedure names and addresses, local labels and named data, before analysis (a name Ghidra already
  holds from `.symtab` or `.dynsym` is kept);
- source files and line numbers as Ghidra source-map entries;
- for objects compiled with `-g`: structs, unions, enums and typedefs in the category
  `/mdebug/<object name>`, each procedure's signature, and its stack variables.

Run it through the export wrapper:

    tools/re-run --ghidra-export root/usr/lib/SOMETHING.so --mdebug --decompile-symbol NAME

An object without `.mdebug`, or a 64-bit object (those carry DWARF, which Ghidra reads itself), is reported
and left alone. A routine compiled without `-g` gets its name, address and lines but no signature, because
the table holds no type records for it. `tools/mdebug.py` decodes the same table in Python (`--procs`,
`--types`, `--signatures`) and is the reference for the format tests in `tools/test_mdebug.py`.
Limits: no parameter types for a pointer to function, `long` is 4 bytes, bit fields that straddle their
storage unit are dropped, and aggregates with the same tag are merged (the first definition with members wins).

## x86 Windows PE with a separate .dbg

Windows NT drivers and DLLs from the 1990s ship stripped, with the symbols in a `.dbg` file (an
`IMAGE_SEPARATE_DEBUG_HEADER`, then COFF symbols) and sometimes a `.pdb`. The recipe:

1. Unpack the installer: `7z x` for self-extracting executables, `unshield x` for InstallShield 5 and later
   cabinets (`cabextract` and `innoextract` are in the image too). InstallShield 3 archives (a `.Z` file
   starting `13 5D 65 8C`, as in 1990s driver disks) need `unshieldv3 list ARCHIVE.Z` and
   `unshieldv3 extract ARCHIVE.Z DESTDIR`; 7z and unshield cannot open them. A `data1.cab` starting `ISc(` is
   IS5 and later: use `unshield`.
2. Import and apply the symbols, in the workspace:

       tools/re-run --ghidra-export path/driver.dll --dbg path/driver.dbg --decompile-symbol @0xADDR

`ghidra/scripts/ReDbgImport.java` runs before analysis. Symbol values are RVAs from the image base (a COFF
file whose values fit their sections only as virtual addresses is rebased as a whole, never value by value:
an NT4 display driver's ImageBase is 0x10000, below many of its own RVAs). A
`.dbg` that has no COFF table but a CodeView NB09 record (a 1999 driver's symbols, publics only) is read
from its sstGlobalPub subsection instead: each S_PUB32 or S_PUB16 offset is in segment N, taken as the
N-th section of the `.dbg`. A public has no type, so one in a code section is called a function, except a
`??_C@_` string literal or an import descriptor (`__IMPORT_DESCRIPTOR_x`, `__NULL_IMPORT_DESCRIPTOR`, which sit in the executable INIT section). That is an approximation; check names against the disassembly. An NB10 or NB11
record points at a `.pdb` (use `--pdb`) and is refused with that message. The counting rule, which the
script prints as its last line:

- a COFF auxiliary record is skipped and never counted;
- a function-typed symbol in the section named `.text` is a function, counted by distinct address, so an
  alias of the same address adds none;
- any other named symbol in a section is a label, also counted by distinct address;
- a name beginning with `.` is a section record (the per-object `.text` and `.data` entries) and is
  skipped, counted apart, so it never becomes the name of a function or label;
- a symbol with no section (undefined, absolute) or outside the image is ignored, and a name Ghidra
  rejects (the `\x7f..._NULL_THUNK_DATA` import markers) is counted and skipped;
- a name Ghidra already holds at an address, such as `entry`, is kept;
- functions are named before labels, highest address first, so a label never takes a function's name
  and a function's flow stops at the next one's entry. A function symbol that lies inside another
  function's body cannot become a function; it keeps its name as a label and is counted as "functions
  not created".

Count symbols the same way before comparing totals, or two readers will differ by the aliases and
auxiliary records. `pefile` is in the image for reading headers. `ghidra/scripts/tests/dbg_synthetic.py` is
the test, on a generated image (`ghidra/scripts/tests/dbg-check.sh` runs it through Ghidra).

## Decompile export

    tools/re-run --ghidra-export OBJECT OPTIONS

Ghidra analyses OBJECT and writes decompiled C per function as JSON under `.cache/ghidra-export/` (the
file is named on stdout; decompiler output is navigation, not evidence). It reads ELF objects for
big-endian MIPS, little-endian ARM (language `ARM:LE:32:v4`, for example the SN2 L1 controller firmware) and
IA-64 (an SN2 Linux kernel, linked or compressed as `vmlinuz`, which is inflated first); the language and
calling convention come from the ELF header. A PE32+ IA-64 image and a 32-bit x86 PE image (below) are read too. A flat image, such as a PROM, has no
header, so say what it is with `--flat` or `--sn2-prom`. `python3 retools/tools/ghidra-export.py prepare --help`
lists the options, and the top of `tools/ghidra-export.py` explains each.

| Option | What it does |
|---|---|
| `--decompile-symbol NAME\|GLOB\|@0xADDR\|@0xLO-0xHI` | one function by name, those matching a glob, the function at an address, or every function entered in an address range; repeatable. For a flat image the address is the machine address (`--load`) |
| `--decompile-component GLOB` | every function in the program-tree fragment named GLOB; an SN2 PROM has one per FIT component (`SAL_B_5_04`, `PAL_A_generic_7_31`, ...) |
| `--decompile-list FILE` | one name, glob, `@address` or `@range` per line |
| `--decompile-all` | every function Ghidra found |
| `--decompile-timeout SECONDS` | per function (60); a function that times out is tried once more with four times as long, and its JSON row says so (`timeout_retried_s`) |
| `--types SPEC.json` | structure types to apply first (`ghidra/README.md`) |
| `--mdebug` | import the `.mdebug` table of a 32-bit MIPSpro object (next section) |
| `--dbg FILE.dbg` | apply the COFF symbols, or the CodeView NB09 publics, of a Windows NT separate debug file to an x86 PE image (next section) |
| `--pdb FILE.pdb` | apply a PDB 2.0 or 7.0 file to an x86 PE image: types, function names, parameters. Needs analysis, so not with `--no-analysis` |
| `--returning NAME[,NAME]` | after analysis, clear the no-return flag on these functions (a name or `@0xADDR`, repeatable), re-disassemble each call to them so the code after it is reached, and rebuild the callers; for a routine analysis wrongly marked non-returning, which cuts every caller at the call ("Subroutine does not return") |
| `--callconv CONV:GLOB[,GLOB]`, `--callconv-file FILE` | after analysis, give each function named GLOB (`*` wildcards, or `@0xADDR`) the calling convention CONV of the compiler spec (`fastcall`, `stdcall`, `thiscall`, `cdecl`); repeatable. The file holds one `CONV:GLOB[,GLOB]` per line. Worked example in `ghidra/README.md` |
| `--param-type GLOB:INDEX:TYPE` | set the type of parameter INDEX (from 0) of the functions named GLOB to a type already in the program (`"__GLCOcontextRec *"`); repeatable, applied after the calling conventions |
| `--bsim-db NAME --bsim-label LABEL`, `--bsim-dir DIR`, `--bsim-min S` | match against a BSim database, then add under the label (default directory `.cache/ghidra-bsim`, lowest similarity 0.7) |
| `--flat`, `--load ADDR`, `--header N`, `--processor LANG`, `--window ADDR` | read OBJECT as raw bytes: the address of the first byte after N header bytes, the Ghidra language (default MIPS 64-bit) and, for a 64-bit MIPS language, the upper address bits of the window it runs in |
| `--sn2-prom` | OBJECT is an SN2 PROM: IA-64, loaded to end at 4 GiB, laid out by `SN2PromImport.java` (below) |
| `--sal-runtime` | with `--sn2-prom`, also map the SAL runtime ELF (below) |
| `--gzip-elfs` | with `--sn2-prom`, also map the other gzip ELF components, FIT types 0x13 and 0x1f, at `0x200000000` and `0x300000000` |
| `--timeout SECONDS`, `--cpus N` | analysis limits (3600, 2) |
| `--heap SIZE` | the Java heap of Ghidra, such as `14G`. Default 2G for an ELF object; for a flat image 2G plus 1G per MiB of it, at most 14G (a 2G heap did not run out on the 12 MiB SHub 2 PROM, see the SN2 section). The container's memory cap is `RE_GHIDRA_MEMORY` (16g), so raise that for a larger heap |
| `--no-analysis` | skip Ghidra's automatic analysis. Only what the import lays out (an SN2 PROM's entries and labels, an ELF's symbols) and each `@0xADDR` asked for are functions, and callee signatures come only from those; it is the fast way to read known addresses (the SHub 2 PROM's `SALE_ENTRY` and FIT walk take under a minute) |

For IA-64 the export first runs `IA64Elf.java` (an ELF object: r1 from `__gp`) or `IA64Pe.java` (a PE32+ EFI image: relocations, entry and exports through their descriptors, r1 from the entry's gp) and `IA64Signatures.java` (the
parameters and return each function's body shows, callees first), so a call passes exactly its callee's
arguments. `ghidra/processors/ia64/tests/DecompileAt.java` is the test helper that makes and decompiles
functions at addresses in a small flat image; it is not part of the export.

## SN2 PROM (IA-64) in Ghidra

The SGI Altix and Prism system firmware is an IA-64 flash image. The Ghidra image carries the IA-64
processor from `ghidra/processors/ia64/` (language `IA64:LE:64:default`) and the layout script
`SN2PromImport.java`, so either of these reads one:

    tools/re-run --ghidra-export root/sn2/snprom-10.54-70399/boot/efi/efi/sgi/snprom/shub1snprom.bin \
        --sn2-prom --decompile-symbol SALE_ENTRY --decompile-symbol @0xffc4e970
    tools/re-run --ghidra analyzeHeadless /tmp/ghidra-projects p -import IMAGE -loader BinaryLoader \
        -loader-baseAddr 0xffa00000 -processor IA64:LE:64:default \
        -scriptPath /opt/re-scripts -preScript SN2PromImport.java

The script places the image to end at 4 GiB and adds an uncached alias of it at bit 63; parses the
FIT and labels it and every component (`PAL_B_7_79`, `SAL_A_5_04`, ...), giving the packed data ones (SAL runtime, EFI, OEM)
non-executable blocks so analysis does not disassemble them; disassembles and names the
generic PAL_A vectors (`PALE_RESET` at `0xffffffb0`), each processor-specific PAL_A entry (image +
`0x300`), `SALE_ENTRY` and the three SAL_B entries; finds the physical-mode SAL dispatch table in
SAL_B by its shape, makes each handler a function named `sal_<id>`, and sets r1 over SAL_B to the
global pointer the table's descriptors carry. Full analysis of a 6 MiB image took 118 s; the 12 MiB SHub 2 PROM
took 108 s with its default 14G heap and 173 s with `--heap 2G` (one run, under more load), which completed without running out of memory.
Wall times are from the container start to the end of Ghidra, one `--decompile-symbol SALE_ENTRY` export of
`shub1snprom.bin` and `shub2snprom.bin` of snprom 10.54, on a 224-thread AMD EPYC 7663 host (kernel
7.2.11) with a load average of 45 to 90, Ghidra 12.1.3 in the `re-ghidra` image built from retools `e0f4a4f`
(first runs of 130 s and 114 s agreed). Heap use is from the JVM's GC log: at most 1.7 GiB in use before a collection, 0.26 GiB live after
one, 2.4 to 2.6 GiB committed, with the default heaps (8G and 14G). A report that full analysis ran out of heap at 16G and 24G did not reproduce (cause unknown): with the default `--heap`,
`--decompile-all` of `shub1snprom.bin` took 10.5 minutes (2709 functions, 1.3 GiB used at most) and of `shub2snprom.bin` with
`--sal-runtime --gzip-elfs` 10.5 minutes (6684 functions, 2.0 GiB used, 2.9 GiB committed). `ghidra/import/sn2-prom/README.md` lists everything it seeds and labels.

With `--sal-runtime` it also inflates the gzip SAL runtime component (FIT type 0x12) and maps its IA-64 ELF at
`0x100000000` with its dynamic symbols as functions under their own names (1032 in SAL 5.04):

    tools/re-run --ghidra-export root/sn2/snprom-10.54-70399/boot/efi/efi/sgi/snprom/shub1snprom.bin \
        --sn2-prom --sal-runtime --decompile-symbol strcpy --decompile-symbol cpu_halt

A runtime address is the ELF's link address plus `0x100000000`; the gzip stream itself is at image offset
`0x252000` in SAL 5.04. SAL allocates the real address at run time, and relocations are not applied.

What the processor does not do, in short (its README has the detail): the register stack is
modelled by moving values (frames, rotation and the RSE's cover, flushrs, loadrs and rfi; no backing store in
memory), NaT bits are not tracked, floating-point registers hold 64 bits, and instructions the architecture leaves to
the implementation are named p-code ops. Slot addresses
are objdump's (bundle + 0, 6, 0xc), so objdump-based notes and Ghidra agree on every address.

## System call table

    tools/re-run --syscalls root/6.5.30/unix.IP35 --out .cache/syscalls.tsv [--cross-check DIR --report FILE]

`tools/syscall_table.py` finds each table of 24-byte entries (argument count and flags, handler, argument
table) by shape, ties it to the dispatcher's pointer-and-count pair, confirms the layout from the dispatcher
code, and writes one row per entry with the handler named from the kernel's own symbol table. The call-number
base is read from the dispatcher. `--cross-check DIR` compares numbering with copies of public lists
(see the top of the script for the file names); disagreements go to `--report`.

## syssgi selectors

    tools/re-run --syssgi root/6.5.30/unix.IP35 --out .cache/selectors.tsv [--cross-check DIR --report FILE]

`tools/syssgi_selectors.py` explores the `syssgi` function with the selector as a symbolic value, reading
jump tables and following compare trees, and writes the code address each selector reaches and the first
routine that code calls. Selectors that share a target are flagged. Selectors that never narrow to a single
value are not listed. Tests for the walker and the list parsers: `tools/test_syssgi_selectors.py`.

## Where the tools look

Every tool that names a workspace path asks `tools/_layout.py`.

| Item | Path |
|---|---|
| inventory config, root manifest, sibling pins, scope list | `tools/config/inventory-config.json`, `inventory-root.sha256`, `inventory-siblings.json`, `scope.json` |
| binaries manifest (`map_binaries.py`) | `tools/config/binaries_manifest.json` |
| inventory tables, `functions.tsv`, `audits.tsv` | `generated/inventory/` |
| coverage page | `COVERAGE.md` |
| lists of what the repository holds (`irix-files.md`, binaries, firmware versions) | `references/` |
| version and personality diffs, userland symbol tables | `generated/version-diffs/`, `generated/personality-diffs/`, `generated/userland-symbols/` |
| routine role and reading pages (`reading_round.py`, `rerender_mismatches.py`) | `<subject>/readings/<binary>.md` |
| census tables (`chips/`) | `devices/<chip>/census/` (`chips/<chip>/census/` in a repository with the old register-map shape) |
| register maps, their output and settings (`defs/`) | see [defs/README.md](defs/README.md); a repository with only `defs/` keeps the old `defs/`, `gen/` shape |
| submodules `setup-clone.sh` initialises | `references/code/<name>` |

A sibling workspace is read at its pinned commit on whichever layout it had then, so a repository that
has moved can still be compared with one that has not. The workspace itself is `--repo DIR`, else
`$RETOOLS_WORKSPACE`, else the git work tree around the current directory.

## Where readings are filed

Per-routine readings live beside the subject they explain: `<subject>/readings/<binary>.md`, with the subject
a `devices/<chip>/`, `platforms/<board>/`, `formats/<name>/` or `software/<area>/` directory and the file
named for the binary (`IP27-pcibr.o.md`, `IP27-unix.md`). `tools/config/readings-subjects.json` says which
subject a binary belongs to: ordered rules of a regular expression on the binary path and a directory, and a
default (`{1}` is the first group of the rule, lower-cased). `reading_round.py` files each entry there as it
writes it; for a hand-written entry use `_readings.file_entries` or add it to the page by hand, in address
order. Entries are never copied or reworded when a binary changes subject; move the page.

## Routine role entries

`tools/reading_round.py` and the readers that write readings pages state what a routine does, in
the author's own words, so that `tools/inventory.py` can move its row from located to understood. The
inventory credits an entry only for the build it names, so the entry must say which build and where.

The canonical entry is a list item whose first line is the header and whose indented lines are the role:

    - `fsio_mount` in `b100-ip30-a/var/sysgen/boot/fsdrv.o` at 0x1f80
      **Inferred.** Copies a 12-byte block in at 0x1f9c and calls `swf_mount_fs` at 0x2080. The
      return is the constant 0xe or the mount result at 0x2084.

- The header is `` `routine` in `path/of/binary` at 0xADDR ``: the routine, the binary written as its path
  under `root/` (the full path when other builds have a file of the same name), and the exact address of
  the routine in that binary. `reading_round.py` writes this header and `grade_readings.py` reads it.
- The role lines carry an `Established.` or `Inferred.` label, state what the routine does in words that
  do not just repeat its name, and cite the addresses, callees or constants they come from. A statement
  that says the role or purpose is unknown, open, not derived or not shown, or that what the routine does
  or what its result means is, holds the entry at located; one that cites nothing is a mention. A sub-fact marked unknown
  ("the stored value is unknown") is an open sub-fact and leaves the role understood.
- A bare file name (`fsdrv.o`) in the header credits a build only when every build that has the routine at
  that address runs the same code there. When the routine's code differs between builds the entry is held
  at located: write the full path.

Two other shapes are accepted, because they cannot be mistaken for prose: a heading (`###` or deeper)
that gives the exact address and the binary (`` ### `routine` in `path` at 0xADDR ``, or a heading with
the binary and address that is followed by a paragraph starting with the routine in backticks), whose
paragraphs up to the next heading, list or table are its role; and a header-only list item followed by an
indented paragraph after a blank line. A heading without an address and binary is a section title, and a
paragraph under it is not an entry.

`grade_readings.py` reads all three shapes with the inventory's own entry grouping (`--review-pack`,
`--apply-verdicts` and `--check-facts` included). `--apply-verdicts` keeps an entry's shape: a bullet keeps its
indented lines, a header-only bullet takes the corrected text as indented paragraphs, and a heading keeps its
heading line and takes the corrected text as its paragraphs. The `Reviewed: DATE` line goes last, indented under
a bullet and as a paragraph of its own under a heading.

    tools/re-run python3 retools/tools/grade_readings.py PAGE.md --check-doc

lints one file the way the inventory reads it and exits 1 when it reports anything. For each entry that will
not credit its routine it prints the line and the reason: no routine named, a heading with no address or no
binary, no citation, too few role words or items, a header that is not a row of `generated/inventory/functions.tsv`
(`--inventory PATH` selects another table), or a bare file name that cannot pick between builds. Entries
held at located by their own wording are listed as notes and do not change the exit status.

### Review cap

A reader that writes many entries quickly gets some of them wrong, and the mechanical fact check below
sees only a small share of the wrong ones. A workspace can therefore ask for a second reading before an
entry counts as understood. `tools/config/inventory-config.json` takes a top-level list of globs:

    "review_required": ["evidence/routines/t2-*.md", "evidence/routines/r3-*.md"]

The paths are relative to the repository root. The cap works on whole files, so it applies only to a
workspace that still files readings by batch; once readings are filed by binary a file mixes both kinds and
the key is dropped (every routine entry already carries the marker). An entry in a matching file earns at most located unless
it carries a review marker, a line (or sentence) of the form

    Reviewed: 2026-11-12

with an ISO date. The list defaults to empty, so a workspace that does not set it is unaffected.
`grade_readings.py --check-doc` reads the same list and reports an unreviewed entry that would otherwise
be understood as a note. `grade_readings.py --apply-verdicts` writes the marker after a review.

Review does not lift every cap. An entry with a sentence that starts `Role (from name):` states a role
that comes from the routine's name, not from its facts, and earns at most located however it is reviewed.

### Checking an entry's claims against its facts

    tools/re-run python3 retools/tools/grade_readings.py PAGE.md --check-doc --check-facts

adds a mechanical check of what each entry claims. It renders the routine's facts the way
`reading_round.py` and `render_reading.py` do (once per binary and address), pulls the checkable claims out
of the prose with fixed patterns, and reports every claim the facts contradict, with the rule and the
reason. It reports a contradiction, never a missing detail, and it skips a claim it cannot place on one
call, branch or access. It needs `root/`; the size of a routine the header does not give comes from
`generated/inventory/functions.tsv`. PowerPC and ColdFire (m68k) firmware entries are rendered too, from the segment
the config's `layout` group cuts out of the container (the same `firmware_layout.py` the inventory uses); the
architecture comes from the entry's `Architecture:` line or, without one, the table's `abi` column. PowerPC
passes arguments in r3-r10, so `arg-slot`, `arg-register` and their cited forms read `r4 = 0x10` and
"second argument (r4)"; ColdFire and m68k pass arguments on the stack, so those rules and `enable-only` skip
there. The other rules apply unchanged. Entries it cannot render (ARM and x86 images, a binary not under
`root/`, a firmware key in no layout group) are counted and skipped. The check is opt-in: `--check-doc` alone does not run it, and `--check-facts` without
`--check-doc` is an error. The rules are in `tools/fact_check.py`:

| Rule | Claim | Reported when |
|---|---|---|
| `arg-slot` | "0xb4 as its fourth argument", "a1 of 1", "a0 = 0x2e" | the call named puts the value in another slot. The reason says the convention: n32 and n64 pass eight arguments in a0-a7, so the fifth is a4; o32 passes four in a0-a3 |
| `arg-register` | "fifth argument (a3)" | the ordinal and the register disagree |
| `branch-direction` | "calls X when the flag is clear", "unless", "only when ... is set", "skips X when ... is zero" | the branch that decides the call compares the word with zero the other way round. A condition on a call's result, a compound condition, or a word the branch does not compare is left alone |
| `call-order` | "A, then B", "A after B", "A before B" between two named calls | every path runs B before A and none runs A before B. A panic call and a value named as `ret(callee)` are not calls |
| `access-kind` | "reads ... +0xd8", "stores to +0x4", "reads q (0xADDR)" | the facts only show a store at that offset, or only a load, or the cited instruction is the other kind |
| `return-value` | "returns the cursor address" | the facts merge that value with a call result at the return and the sentence names only one. Sentences that name a path or an alternative are left alone |
| `conditional-wording` | "unconditionally", "otherwise ... at ADDR", a flat "frees X (ADDR)" | the cited call or store is skipped by a branch (or runs on every path, for "otherwise"). A flat release is reported only when one or two branches skip it, no other sentence cites them and it is the only site cited |
| `enable-only` | "enables 0xb60 through f" | the same callee is also called with that constant and a1 of 0 |
| `role-word` | "non-rational", "the float fields suggest a colour move" | the qualifier is a negation the facts never mention, or a role is pinned on the facts instead of the routine's name |

The rules were written from an audit that found a quarter of forty round 4 entries wrong or overclaimed:
reversed branch direction, an argument slot off by one, a read that is a store, an unconditional claim over a
guard, call order, and roles taken from a routine's name. They are narrow on purpose. A report is a reason to
look at the entry against its facts, and the role-word rule in particular flags wording a reviewer may accept.
`tools/test_fact_check.py` pins each rule and the ten kona entries the audit corrected: the text before the
correction fails, the text after it passes.

### Cited entries

The patterns above find about one wrong claim in thirty, because most of what is wrong in an entry (which side
of a branch a call is on, whether an argument is the fifth, what a routine's role is) cannot be pulled out of
free prose. A cited entry puts a citation after each claim, so `fact_check.check_cited` tests the claim against
the one fact it names instead of guessing which fact the prose means.

    - `gl_c_depthcue` in `usr/gfx/arch/IGLOO32/libgl.so` at 0xec43df0
      **Inferred.** Tests the word at 0xecdda34 [@0xec43e10]. When it is zero [@0xec43e10 taken zero] it calls
      gl_intrptab_insert with a0 = 0xecd72c0 [call 2, @0xec43e10 taken], then calls gl_compile with a0 = 0x4
      [call 1]. When it is nonzero [@0xec43e10 fall nonzero] it makes the gl_compile call alone [call 1]. It
      returns the result of gl_compile [@0xec43e40].
      Role (from facts): registers a record before compiling on the zero path [call 2, @0xec43e10 taken].

Citations:

| Form | Names | Checked |
|---|---|---|
| `[@0x10a4]` | the instruction at that address | it is a call, branch, return or load or store the facts list. The verb before it must fit: calls a call, stores or writes a store, loads or reads a load, returns a return |
| `[call 3]` | the third call of the facts, counting from 1 in address order | the callee the sentence names (by name or target) is that call's; argument claims written before the citation (`a0 = 0x4`, `0xb4 as its fifth argument`, `a1 at entry`) match that call's argument registers; a value in a slot the facts leave as `?` is reported |
| `[@0x10a0 taken]`, `[@0x10a0 fall]` | one side of a branch | the branch exists. `zero` or `nonzero` after the side (`[@0x10a0 fall nonzero]`) must match that side's condition, and the condition must compare with zero |
| `[call 4, @0x10a0 fall]` | a group in one bracket | the call (or store) runs on that side of that branch and the branch decides it. A call that runs on both sides is accepted under either unless the sentence says only, alone or unless |

Rules, each reported with the sentence it came from:

- `uncited`: a sentence that states a fact (a hex address, a named callee, or a verb such as calls, stores,
  returns, tests) and carries no citation. A sentence that says the facts do not show something is not a claim
  and needs none.
- `cite-address`: a citation to an address or call number the facts do not list, or one that does not parse.
- `cite-callee`, `cite-arg`, `access-kind`, `cite-kind`, `cite-return`, `cite-value`: the call, argument, load
  or store, instruction kind, return value or stored value does not match. The facts list that a store
  happened, not what it stored, so a claim of the stored value (`stores zero`, `clears`) is reported.
  `passes its arguments through` is reported too; name each register (`a1 at entry`).
- `cite-branch`: the side or the zero/nonzero sense of a branch does not match its condition, or the branch does
  not decide the call grouped with it.
- `condition-missing`: a call that a branch skips on some path is stated with no branch citation, and
  `condition-uncited`: a sentence says when or unless and cites no branch. `cite-conditional`: a sentence says
  unconditionally, always or on every path about a call that a branch skips.
- `cite-loop`: a sentence describes a loop and cites no branch whose taken side goes back to an earlier address.
- `cite-count`: `three calls` against the facts' number of calls, and any `about` or `up to` count.
- `cite-order`: `A, then B`, `A before B` or `A after B` between two cited calls that the facts reach in the
  other order.
- `role-missing`, `role-uncited`, `role-unmarked`, `role-from-name`: see below.

The rules of the previous section also run, on the prose with its citations removed, except the two argument
rules, which the citation check replaces.

    tools/re-run python3 retools/tools/grade_readings.py PAGE.md --check-doc --check-facts --strict-citations

reads every entry of the file as a cited entry. It prints each finding as `FILE:LINE: routine [rule]` with the
reason and the sentence, counts an entry once however many findings it has, and exits 1 when any entry has one.
`role-from-name` is printed as a note and does not count. Without the flag nothing changes: an entry is read by the
prose rules, and a citation in it is ordinary text. The flag needs `--check-doc --check-facts` and `root/`.

The role is the claim the most errors turned up in, so it is the one sentence that must be labelled. An entry
has a sentence that starts `Role (from facts):` and cites the facts it rests on, or one that starts
`Role (from name):`. The second admits that the role is a guess from the routine's name or its neighbours; it is
reported as the note `role-from-name` and the inventory holds the entry at located. A role taken from the name
anywhere else (the name suggests, by its name, looks like) is `role-unmarked`. An entry with neither sentence is
`role-missing`. A line that starts `Reviewed:` is not a sentence of the entry.

### Review pack

    tools/re-run python3 retools/tools/grade_readings.py PAGE.md --review-pack OUT.md [--unreviewed] [--batch 2/6] [--routine NAME...]

writes what a reviewer reads. For each entry of the file: its key (`routine@0xADDR@binary`, the key a verdict file
uses), then the entry as written beside the facts rendered for its routine (`fact_check.fact_index`: calls
numbered the way `[call N]` counts them, branches with both conditions, returns, loads and stores), then the
findings of the checker, a cited-entry check when the entry has citations and the prose rules otherwise. A
finding is a reason to look at a sentence against the facts, not a verdict. `--unreviewed` leaves out entries that
have a Reviewed line, `--batch K/M` takes the Kth of M equal slices of what is left, and an entry whose facts
cannot be rendered says so in place of the facts. It needs `root/`, as `--check-facts` does.

### Applying a review

    tools/re-run python3 retools/tools/grade_readings.py PAGE.md --apply-verdicts VERDICTS.json [--review-date 2026-11-12]

reads a reviewer's verdicts, a JSON object from entry key (the `routine@0xADDR@binary` of the review pack) to

    {"verdict": "ok" | "fixed" | "reject", "text": "corrected lines under the header", "reviewer": "ignored"}

`ok` keeps the entry as written, `fixed` replaces the lines under its header with `text`, and both add
`Reviewed: DATE` (no reviewer name; a `reviewer` key is accepted and ignored) as the entry's last line, replacing an older marker. `reject` changes nothing and
leaves the entry unreviewed, so the inventory still holds it at located. A key that is not in the file, an unknown
verdict or a `fixed` with no text stops the run before the file is written. The date defaults to today.

## Directory indexes

    tools/re-run python3 retools/tools/docs-index [--repo DIR] [--check]

writes a `README.md` into each of `devices/`, `platforms/`, `formats/`, `software/`, `questions/` that exists, so a workspace's top-level README does not list documents by hand. The index has
one table row for each Markdown page and each unit subdirectory: a link, the page's own title (its first
heading) and a one-line summary (the first sentence of its first prose paragraph, cut to about 120
characters). A subdirectory with a `README.md`, `registers.md` or `format.md` is one row that links to that
page. Any other subdirectory, such as `software/kernel/`, gets a heading over a table of its pages. Tables,
lists, quotes and code are skipped when looking for the summary, so a page that opens with one has an empty
summary cell.

The first line of a generated file marks it, and a run rewrites only files that carry the mark. A
`README.md` containing `<!-- keep -->` is hand-written and skipped. A README with neither is left alone and
the run fails, so no one's text is overwritten. An index whose directory has no pages left is removed.

`--check` writes nothing and exits 1 for a missing or stale index. `tools/defs/ci-check` runs it, so a page added,
retitled or removed without a rerun fails the workspace's check. The fix is to run the tool and commit the
result. Tests: `tools/test_docs_index.py`.
