# Analysis tools shared by the workspaces

Three tools beyond the decompile export. All run through `tools/re-run`, in the toolchain or Ghidra
image, and never write outside `.cache/` unless you give `--out`. Their output is derived from the
binary you point them at; public lists named below are used only to check numbering.

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
the table holds no type records for it. `scripts/mdebug.py` decodes the same table in Python (`--procs`,
`--types`, `--signatures`) and is the reference for the format tests in `scripts/test_mdebug.py`.
Limits: no parameter types for a pointer to function, `long` is 4 bytes, bit fields that straddle their
storage unit are dropped, and aggregates with the same tag are merged (the first definition with members wins).

## System call table

    tools/re-run --syscalls root/6.5.30/unix.IP35 --out .cache/syscalls.tsv [--cross-check DIR --report FILE]

`scripts/syscall_table.py` finds each table of 24-byte entries (argument count and flags, handler, argument
table) by shape, ties it to the dispatcher's pointer-and-count pair, confirms the layout from the dispatcher
code, and writes one row per entry with the handler named from the kernel's own symbol table. The call-number
base is read from the dispatcher. `--cross-check DIR` compares numbering with copies of public lists
(see the top of the script for the file names); disagreements go to `--report`.

## syssgi selectors

    tools/re-run --syssgi root/6.5.30/unix.IP35 --out .cache/selectors.tsv [--cross-check DIR --report FILE]

`scripts/syssgi_selectors.py` explores the `syssgi` function with the selector as a symbolic value, reading
jump tables and following compare trees, and writes the code address each selector reaches and the first
routine that code calls. Selectors that share a target are flagged. Selectors that never narrow to a single
value are not listed. Tests for the walker and the list parsers: `scripts/test_syssgi_selectors.py`.
