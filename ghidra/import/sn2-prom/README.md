# SN2 PROM import

`ghidra_scripts/SN2PromImport.java` lays out an SGI SN2 (Altix, Prism) flash PROM that Ghidra has read as a
flat IA-64 image (language `IA64:LE:64:default`). It runs as a pre-script on a `BinaryLoader` import; an image
loaded anywhere is moved so that it ends at 4 GiB, where the processor finds it. The instruction set comes
from [`ghidra/processors/ia64/`](../../processors/ia64/README.md).

## Reaching it

    retools/tools/re-run --ghidra-export IMAGE --sn2-prom --decompile-symbol SALE_ENTRY
    retools/tools/re-run --ghidra-export IMAGE --sn2-prom --decompile-component 'SAL_B_*'
    retools/tools/re-run --ghidra-export IMAGE --sn2-prom --decompile-symbol @0xffff8470
    retools/tools/re-run --ghidra-export IMAGE --sn2-prom --sal-runtime --decompile-symbol strcpy

`IMAGE` is a PROM such as `shub1snprom.bin`. The exporter analyses the whole 6 MiB image, which takes about
fifteen minutes. `--decompile-symbol` takes a label (below), a glob, `@0xADDR` or `@0xLO-0xHI`;
`--decompile-component` takes a program-tree fragment name (below). `tools/README-analysis.md` has the other
options.

## What it lays out

- The top of flash: `ia32_reset_vector`, `fit_pointer`, `sale_entry_pointer`, `alternate_fit_pointer`, and the
  image as the blocks `flash` and `flash_uc`, an uncached alias at bit 63 that SAL_A reads the FIT through.
- The Firmware Interface Table, as `FIT` and one `FIT_<n>_<component>` label per entry, and a label and a
  comment at each component. Components are named `<type>_<major>_<minor>`, the version as the table
  gives it: `PAL_B_7_79`, `PAL_A_7_31`, `SAL_A_5_04`, `SAL_B_5_04`, `SAL_runtime_5_04`, `EFI_...`; other types
  are `OEM_<type>`. The generic PAL_A (`PAL_A_generic_7_31`), which the entry just below the top-of-flash
  pointers describes, holds the hardware entry vectors.
- A program-tree fragment for each code component (PAL_B, PAL_A, SAL_A, SAL_B), named like its label, for
  `--decompile-component`. A component that is packed data (SAL runtime, EFI, OEM) gets its own block that is
  not executable, and analysis does not disassemble it.
- The generic PAL_A vectors: `PALE_RESET` at `0xffffffb0`, `PALE_INIT`, `PALE_CHECK` and the
  `pal_a_vector_<address>` bundles, with the branch target of each hand-off a function
  (`pale_reset_handler`, `pale_init_handler`, `pale_check_handler`), and `pale_reset_fit_walk` at
  `0xffff8470`, the code `PALE_RESET` leaves to through an `rfi` that flow cannot follow. The `PALE_INIT` and
  `PALE_CHECK` roles are inferred from PAL_B's hand-offs.
- Each `br.ia` in a PAL_A component, flagged with the processor's `pal` context bit so that it reads as a PAL
  service call (the processor README gives the evidence grade).
- Each processor-specific PAL_A entered at image + `0x300` (`<name>_entry`); PAL_B's run of entry bundles
  at image + `0x10000` and the bodies they branch to (`<name>_entry_<offset>`, `_init_entry`, `_check_entry`);
  and the PAL procedure table, found by its shape (24-byte entries ended by -1, then one handler link address
  per entry), as `pal_proc_table`, `pal_proc_handlers` and `pal_proc_<index>` functions. PAL_B links at
  `0xfff00000` whatever its address in flash; the table is accepted only if the dispatch code loads the link
  address of it. SHub 2's PAL_B has no such table and gets none.
- SAL_B's reset entry and the entries SAL_A takes for reasons 2 and 1; the physical-mode SAL dispatch table,
  found by its shape (pairs of function id and descriptor), as `sal_dispatch_table`, a `sal_desc_<id>` label
  per descriptor and a `sal_<id>` function per handler; r1 over SAL_B set to the one global pointer
  the descriptors carry; and `SALE_ENTRY`, an external entry point.

## The SAL runtime

The SAL runtime component (FIT type 0x12) is a gzip stream. Inflated it is an IA-64 shared object (ET_DYN)
with one PT_LOAD at link address 0 and about a thousand dynamic function symbols. With `--sal-runtime`
(`sal-runtime` as the script's argument) the import inflates it, maps it in the block
`SAL_runtime_<version>_elf` at `0x100000000`, makes each function symbol a function under its own name,
labels each object symbol, and sets r1 over the block to `DT_PLTGOT`, the global pointer the linker gives
such an object. In SAL 5.04 `shub1snprom.bin` that is 1032 functions.

- Runtime address = ELF link address + `0x100000000`. The image offset of the gzip stream is the component's
  address less the image base (`0x252000` for SAL 5.04, whose component is at `0xffc52000` in an image based at
  `0xffa00000`).
- SAL_B inflates the stream into a buffer it allocates at run time, so no fixed address is the real one.
- Relocations are not applied: a function-pointer table in the runtime's data holds link-time values, and
  calls through function descriptors stay indirect.
- The other gzip components (FIT types 0x13, 0x1f and 0x22 in SAL 5.04) are left packed. 0x13 and 0x1f
  inflate to IA-64 ELF files too; 0x22 holds a PE32+ EFI driver (`drv_fpswa.efi`), which no tool here imports.

## Checking it

    retools/tools/re-run --ghidra -- sh retools/ghidra/import/sn2-prom/tests/run-ghidra.sh IMAGE .cache/sn2-prom
    retools/tools/re-run python3 retools/ghidra/import/sn2-prom/tests/check.py .cache/sn2-prom/symbols.tsv IMAGE

`run-ghidra.sh` loads the image at 0 (the script has to move it), imports it without analysis and writes
`symbols.tsv`. `check.py` parses the FIT, the top-of-flash words and the SAL dispatch table again in Python
and fails unless every component, entry and table has its label, every entry is a function, every `br.ia` is
flagged and SAL_B has its global pointer. With `SAL_RUNTIME=1` in the environment of `run-ghidra.sh` and
`--runtime` after the image for `check.py`, it also inflates the runtime itself and requires each of its
dynamic functions at its mapped address. `check.py` prints that it skipped when the image is absent.
