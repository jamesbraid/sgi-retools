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

### Review cap

A reader that writes many entries quickly gets some of them wrong, and the mechanical fact check below
sees only a small share of the wrong ones. A workspace can therefore ask for a second reading before an
entry counts as understood. `scripts/inventory-config.json` takes a top-level list of globs:

    "review_required": ["docs/routines/t2-*.md", "docs/routines/r3-*.md"]

The paths are relative to the repository root. An entry in a matching file earns at most located unless
it carries a review marker, a line (or sentence) of the form

    Reviewed: 2026-11-12

with an ISO date. The list defaults to empty, so a workspace that does not set it is unaffected.
`grade_readings.py --check-doc` reads the same list and reports an unreviewed entry that would otherwise
be understood as a note.

Review does not lift every cap. An entry with a sentence that starts `Role (from name):` states a role
that comes from the routine's name, not from its facts, and earns at most located however it is reviewed.

### Checking an entry's claims against its facts

    tools/re-run python3 retools/tools/grade_readings.py docs/routines/FILE.md --check-doc --check-facts

adds a mechanical check of what each entry claims. It renders the routine's facts the way
`reading_round.py` and `render_reading.py` do (once per binary and address), pulls the checkable claims out
of the prose with fixed patterns, and reports every claim the facts contradict, with the rule and the
reason. It reports a contradiction, never a missing detail, and it skips a claim it cannot place on one
call, branch or access. It needs `root/`; the size of a routine the header does not give comes from
`docs/inventory/functions.tsv`. Entries it cannot render (non-MIPS images, a binary not under `root/`) are
counted and skipped. The check is opt-in: `--check-doc` alone does not run it, and `--check-facts` without
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
