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
be understood as a note. `grade_readings.py --apply-verdicts` writes the marker after a review.

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

    tools/re-run python3 retools/tools/grade_readings.py docs/routines/FILE.md --check-doc --check-facts --strict-citations

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

    tools/re-run python3 retools/tools/grade_readings.py docs/routines/FILE.md --review-pack OUT.md [--unreviewed] [--batch 2/6] [--routine NAME...]

writes what a reviewer reads. For each entry of the file: its key (`routine@0xADDR@binary`, the key a verdict file
uses), then the entry as written beside the facts rendered for its routine (`fact_check.fact_index`: calls
numbered the way `[call N]` counts them, branches with both conditions, returns, loads and stores), then the
findings of the checker, a cited-entry check when the entry has citations and the prose rules otherwise. A
finding is a reason to look at a sentence against the facts, not a verdict. `--unreviewed` leaves out entries that
have a Reviewed line, `--batch K/M` takes the Kth of M equal slices of what is left, and an entry whose facts
cannot be rendered says so in place of the facts. It needs `root/`, as `--check-facts` does.

### Applying a review

    tools/re-run python3 retools/tools/grade_readings.py docs/routines/FILE.md --apply-verdicts VERDICTS.json [--review-date 2026-11-12]

reads a reviewer's verdicts, a JSON object from entry key (the `routine@0xADDR@binary` of the review pack) to

    {"verdict": "ok" | "fixed" | "reject", "text": "corrected lines under the header", "reviewer": "optional"}

`ok` keeps the entry as written, `fixed` replaces the lines under its header with `text`, and both add
`Reviewed: DATE (reviewer)` as the entry's last line, replacing an older marker. `reject` changes nothing and
leaves the entry unreviewed, so the inventory still holds it at located. A key that is not in the file, an unknown
verdict or a `fixed` with no text stops the run before the file is written. The date defaults to today.
