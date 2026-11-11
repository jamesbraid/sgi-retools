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
the table holds no type records for it. `tools/mdebug.py` decodes the same table in Python (`--procs`,
`--types`, `--signatures`) and is the reference for the format tests in `tools/test_mdebug.py`.
Limits: no parameter types for a pointer to function, `long` is 4 bytes, bit fields that straddle their
storage unit are dropped, and aggregates with the same tag are merged (the first definition with members wins).

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

## Routine role entries

`tools/reading_round.py` and the readers that write `docs/routines/*.md` state what a routine does, in
the author's own words, so that `tools/inventory.py` can move its row from located to understood. The
inventory credits an entry only for the build it names, so the entry must say which build and where.

The canonical entry is a list item whose first line is the header and whose indented lines are the role:

    - `swfio_mount` in `sw22_474-ip30-flame834/var/sysgen/boot/swfs.o` at 0x1f80
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
- A bare file name (`swfs.o`) in the header credits a build only when every build that has the routine at
  that address runs the same code there. When the routine's code differs between builds the entry is held
  at located: write the full path.

Two other shapes are accepted, because they cannot be mistaken for prose: a heading (`###` or deeper)
that gives the exact address and the binary (`` ### `routine` in `path` at 0xADDR ``, or a heading with
the binary and address that is followed by a paragraph starting with the routine in backticks), whose
paragraphs up to the next heading, list or table are its role; and a header-only list item followed by an
indented paragraph after a blank line. A heading without an address and binary is a section title, and a
paragraph under it is not an entry.

    tools/re-run python3 retools/tools/grade_readings.py docs/routines/FILE.md --check-doc

lints one file the way the inventory reads it and exits 1 when it reports anything. For each entry that will
not credit its routine it prints the line and the reason: no routine named, a heading with no address or no
binary, no citation, too few role words or items, a header that is not a row of `docs/inventory/functions.tsv`
(`--inventory PATH` selects another table), or a bare file name that cannot pick between builds. Entries
held at located by their own wording are listed as notes and do not change the exit status.
