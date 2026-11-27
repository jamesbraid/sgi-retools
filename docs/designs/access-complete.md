# Access-complete RE repositories: cross-reference tables, register contracts and lookup

Status: direction approved, nothing built. `generated/xref/`, `--xref`, `--xref-all` and `questions/lookups.tsv`
are adopted, as are the other names below.

Read against sgi-retools `main` at `6cd5399` and the RE repositories at their 2026-11-27 heads: chips
`abd0a17`, cobalt `add9b42`, crime `a3dadaf`, gr2 `8775b07`, kona `9472c6c`, kudzu `c9a5672`, newport
`fb008fe`, odsy `96ee7d1`, sysco `43f80db`, voyager `b36b925`, plus gr4 on its `origami-re` branch at `b42c8ef`
and one private repository that this page does not name. All but the private one pin sgi-retools at `6cd5399`.

Scope is every RE repository above and every IRIX release each one holds, not a primary release per board.
Committing all of them is the pressure test of the design: if the tables, their size or their run time do not
hold up across every release, the design is wrong, and the first work unit measures exactly that.

## The goal

Someone asking a hardware question should get the answer by looking it up, not by asking for a trace. The
questions that reach the RE repositories today come in four forms:

- who writes this RAM word or register, and with what value
- what calls the routine that does the store, back to an entry point
- what register sequence follows a given access
- what a value read from a register is compared, masked or added against.

Three questions answered on 2026-11-27 show the cost. The IP12 PROM's delay divisor at physical `0x3809d4`
and the INT2 timer writes at `0x1fb801f0` (chips `platforms/ip12/README.md`). The SHub 2 PROM's store to
`0x3_8000` and the memory-test sequence around it (chips `devices/shub/shub2-memory-test.md`). The RTC year
base each IRIX platform uses (chips `devices/ds1286/`, `devices/ds1685/`). Each took a hand trace of the
binary. None of the tables the repositories carry could have answered them.

"Done" here means *access-complete*, not "every function understood":

1. Every held binary that touches hardware has machine-generated cross-reference tables: calls, every load and
   store to a constant address with its width, value and routine, the accesses whose address is only partly
   known, the constants a loaded value meets, and the strings each routine references.
2. Every register those tables reach has a graded contract: readers and writers, sequences, the values software
   needs, side effects, reset value.
3. Code that touches no hardware is credited by family or identical-code matching, or counted as named and
   located and left out of scope.
4. The tables are plain TSV files that any text or code search can index, so one query by address, register,
   routine or string finds them. Addresses are written in one canonical form inside the tables, so the search
   needs no knowledge of address formats.
5. Every incoming question is recorded. A question the lookup could not answer adds the missing table column
   or contract.

## What exists

### Cross-reference tables

- `ReCallWalk` writes one record per call site: direct, constant, table or unresolved, with tail jumps.
  `DumpCallEdges.java sites` writes them.
- `ReAccessWalk` writes one record per load or store to a constant address outside the image, with physical
  address, width, `load`/`store`/`rmw`, and `absolute` or `base+offset` addressing. `FindWindowStores.java`
  writes them. Constant folding stops at a basic block boundary, which `ReBlockEval` keeps on purpose so a walk
  loses an address rather than reporting a wrong one.
- `re-run --ghidra-export` drives Ghidra headless in the pinned image, with hand function boundaries, a
  work-bounded decompile budget and a run-twice check in CI.
- `tools/facts.py` writes a symbolic fact sheet for one MIPS routine: stored values, immediates, branches,
  exits, literals and `mmio`.
- sgi-retools `tools/chips/scan.py` writes committed per-site register tables,
  `devices/<chip>/census/census-sites.tsv` (13 chips, 8,038 rows): a path-sensitive data flow over objdump
  text, MIPS only, seeded per chip. `tools/chips/callargs.py` finds the constant register numbers passed to
  named accessor routines, straight-line within one routine.
- `tools/kona/ge_catalogue.py` writes kona `software/ucode/ge_xref.tsv` (1,100 rows), the only true
  cross-reference table in any repository. Its header cites a path that is not where the script lives.
- Partial call-site tables for one purpose each: sysco `console-messages.tsv`, kudzu `panics.tsv`,
  `hwgraph-adds.tsv`, `tunable-sites.tsv` and `selectors.tsv`.
- The inventory's `mmio.tsv` holds one row per register offset in a configured window, with a site count, the
  first six functions and one example. It has no binary column and lists no sites. It reaches only the windows
  a repository configured: chips configures seven (CRIME, RE, GBE, two MACE regions, Hub, HEART), so Bridge,
  Xbow, IOC3, SHub, Bedrock, INT2 and HPC1 accesses are not counted. The linked IP27 kernel shows 5 access
  sites.
- The hardening design ([re-toolchain-hardening.md](re-toolchain-hardening.md)) specifies a committed
  `code.json` per PROM and a device map per family, `devices/address-map.toml`. Its export commit waits for the
  promkit Ghidra loader. The `prom/promkit-code` branch writes a code file for a flat segment from Python,
  first for the IP27 PROM.

What no table gives today:

- Committed output of the two walks for any binary, and any caller and callee table.
- Stored values, the constants a loaded value is compared, masked or offset against, and strings to routines
  outside the console-sink and panic tables.
- Accesses made through an accessor routine whose address is an argument. The SHub 2 store is one: sixteen
  stores go through one write-64 leaf. Finding them takes a named accessor or a hand read.
- Accesses whose base is a run-time value, and stores in a loop over a constant range.
- Any device map. No repository has `devices/address-map.toml`.

### Register contracts

`registers.toml` per unit is loaded strictly by `tools/defs`. Every item is graded. A register carries `reset`,
`reset_grade`, `reset_from`, the `ro`, `w1c`, `cor` and `rsvd` masks, prose and decode vectors. Counts at the
heads above: chips 3,378 registers in 106 units, crime 384, voyager 362, kona 141, cobalt 68, sysco 59,
gr2 58, newport 50, odsy 48. kudzu's 12 units are formats with no registers. The inventory grades each
`mmio.tsv` and `spec-registers.tsv` row from the documents that mention it.

Across the register-type tables (`mmio`, `spec-registers`, `tokens`, `ucode`, sysco `io-registers`) there are
31,224 rows, measured on 2026-11-27. sysco's `mmio.tsv` is 23,575 of them, and its 20,077 undocumented rows
are 64% of the total, mostly L1 firmware offsets in its own flash and SRAM repeated across releases. The other
7,649 rows are 72% understood, 20% located, 6% named-only and 1% undocumented.

Missing:

- A generated per-register list of who reads and writes, the values written and the constants compared.
  Readers and writers appear only as `mmio.tsv`'s six function names, and sequences and side effects are in
  prose pages written per question.
- A measure of how many access sites land on a register with a finished contract.
- Any distinction between a device register and firmware's own memory, so firmware RAM and flash inflate the
  register gap.

### Generic code, addresses and questions

- Generic code: `code_sha` in `functions.tsv` (identical bytes across binaries), family blocks
  (`families.tsv`), the cross-workspace role check, the `scope` column with `out:N` and the
  `no-software-dependency` status exist. No rule puts a routine out of scope because it touches no hardware,
  and without a call graph the inventory cannot tell a string routine from a driver helper.
- Addresses: pages and tables write `0x3_8000`, `0x38000`, `0xa03809d4` and `0x3809d4`, and a text search
  cannot tell that the last two name the same word. Today's `functions.tsv` files are 2 to 60 MB (chips
  15.8 MB, odsy 30 MB, kudzu 60 MB), larger than code-search indexers usually read in full.
- Questions: every repository has `questions/README.md`, with routes tried, the next route and a route tag. An
  answered entry moves to its owning page and is deleted. Nothing records which lookup would have answered it,
  so a miss tells the tooling nothing.

### Repositories with no inventory

cobalt, gr2 and newport have no `generated/inventory/`, no root manifest and no inventory config. cobalt's
binaries are x86 Windows drivers. gr2 and newport hold their inputs in the repository or not at all. gr4's
`origami-re` branch and the private repository have an inventory from an older sgi-retools, with no inventory
README and no audits.

## The design

One export, one directory of tables per binary, one measure in the inventory, one device map per family, one
canonical address form and one log. Each extends something that exists.

### Tables

Tables live in each RE repository under `generated/xref/`, one directory per distinct binary content, named by
its path key as `binaries.tsv` writes it: `generated/xref/IP27/unix/`,
`generated/xref/IP32/usr/cpu/sysgen/IP32boot/crime.a(crime_init.o)/`. An archive member keeps the
`archive(member)` form. Firmware segments use the inventory's `l1.bin(l1#2)` key, parentheses kept. The files
are TSV with a header row, like every other generated table, so a line search returns a whole fact.

Addresses are written one way everywhere: lowercase hex, `0x` prefix, no underscores, no leading zeros, each in
a cell of its own. A whole-word search for `0x38000` then finds every row that names the word, and never
`0x380000`. `address` keeps the form the code builds, such as kseg1 `0xa03809d4`, and `physical` holds the
canonical physical address, `0x3809d4`, so a search by either form finds the row. Prose that cites an address
in another form is not changed. The normalisation lives in the tables, not in a search service.

No generated table passes 1 MiB: the per-binary tables, `registers.tsv`, `manifest.tsv` and
`questions/lookups.tsv`. A larger table is split into numbered files at a row boundary that keeps a unit
together (a function, or a register), so a code-search indexer reads every file in full. `registers.tsv` is
written by `inventory.py` into `generated/xref/`, not by the export.

`manifest.tsv` has one row per binary: `binary`, `sha256`, `arch`, `status` (`complete`, `partial` or
`failed`, with the reason), `ghidra`, `retools`, the analysis options, the row count of each table and the
count of partial and range rows. `generated/xref/README.md` defines every column, as
`generated/inventory/README.md` does for the inventory.

Per binary:

- `functions.tsv`: `entry`, `end`, `name`, `name_source`, `callers`, `callees`, `hardware`, `constants`.
  - `hardware` is `access` for a routine with an access row of any form, `calls-access` for its direct
    callers, `indirect` for a routine with an unresolved or table call and no access row, empty otherwise.
  - `callers` and `callees` list entry addresses, so a search for a routine's address finds its own row and
    every row that calls it. Repeated searches walk a caller chain back to an entry point.
  - `constants`, on a `hardware` routine, lists the immediates the routine uses, as `facts.py` reports them.
  - `name` comes from the binary's own symbols, or from a seed whose provenance is a shipped binary, and
    `name_source` says which. A hand-assigned name of any other origin and a Ghidra placeholder are never
    written.
- `sites.tsv`: one row per access and per call site inside a `hardware` routine, sorted by function and then
  site. Columns: `function`, `site`, `kind` (`load`, `store`, `rmw`, `call`), `form`, `address` (as the code
  forms it), `physical`, `base`, `offset`, `end`, `width`, `value`, `uses`, `target`, `via`, `pair`, `region`,
  `register`, `grade`. Reading the lines after a hit gives the static order of accesses and calls in that
  routine, which answers "what follows".
  - `form`, on an access: `constant` (a known address), `partial` or `range`, described below.
  - `value`, on a store: a constant, or where the value came from: `arg0`, `load@0xSITE`, `ret(0xENTRY)`, or
    `?`.
  - `uses`, on a load: the operations within the block that meet the loaded value with a constant, such as
    `and 0xff`, `beq 0x3`, `add 0x7b2`, `sltiu 0x10`. This is where the 1970 year base and the "compared after
    the read" answers show up.
  - `target`, on a call: the callee entry and how it was resolved, from `ReCallWalk`.
  - `via`, on an access found through an accessor: the call site and the accessor's entry.
  - `pair`, on a store to an index port: the site of the data-port access that follows it, and on that access
    the site of the store. The index value is then the paired store's `value`.
  - `region` and `register`: the device-map region and the register name, joined after export.
- `strings.tsv`: `string`, `text`, `function`, `site`. One row per reference from code to a string.

Two of the questions above would have been answered directly:

- IP12: search `0x3809d4`. The `store` rows in the calibration routine and the `load` row in the delay routine
  come back. The INT2 rows at `0x1fb801f0` show values `0x2`, `0x42`, `0x42` in one routine, in order.
- SHub 2: search `0x38000`. The row in the port loader carries `via` with the write-64 leaf, `value`
  `0x80000000000`, and the routine's following rows give the sequence. Its `functions.tsv` row gives callers
  to walk back to the memory test.

The RTC year base needs the `uses` column on the calendar loads, plus the function-scope values below, because
the constant is formed in a different block from the read.

#### Partial and range rows

A `partial` row is an access whose base is only known at run time, such as the SHub node window built from a
read of `V`. `address` and `physical` are empty. `base` holds the base expression (`load@0xSITE`, `arg0`,
`ret(0xENTRY)`, or a symbol) and `offset` the constant added to it. The join matches `offset` against
`registers.toml` and fills `register`.

The export emits a partial row only in a routine that also reaches a known window, or whose offsets match a
register map, so ordinary pointer traffic does not flood the table. The manifest reports each binary's volume.

A `range` row is a store through a pointer that starts from a constant and is bounded by a constant, such as a
clear loop. `address` is the start, `end` the bound, and `physical` is filled when both fall in one region.

### Producing them

One Ghidra post-script, `ReXrefExport.java`, run by `re-run --ghidra-export OBJECT --xref DIR`. It writes JSON
lines from the walks, and `ghidra-export.py finish` turns them into the TSVs. The Python step does the register
join and the sorting, following the hardening design's pattern where Java writes records and Python writes the
file. `--xref` never runs `ReDecompileExport`: `ReXrefExport` calls `ReAccessWalk` directly, so a run costs no
decompile budget. When the PROM code export lands it should read the same records rather than walk the program
again, so `code.json` and the xref tables cannot disagree.

Changes to the walks, each with a fixture in `mips_synthetic.py` and the IA-64 `synthetic.py`:

1. `ReAccessWalk` gains `value` on stores and `uses` on loads, inside the block, graded `established`. It also
   stops excluding image blocks that the device map marks `ram` or `flash`, so firmware's own RAM and flash
   sites are tabled.
2. A function-scope pass follows values and addresses across blocks within one function, using Ghidra's
   `SymbolicPropogator`, with no decompiler. Rows it adds or changes are graded `inferred`, and `grade` says
   which pass produced them. Block-only stays the default for anything called `established`. This pass also
   finds `range` rows.
3. Call-argument and return tracking in `ReBlockEval`, through a per-architecture ABI model: MIPS o32, n32 and
   n64, and IA-64 with register-stack renaming. This is its own work unit. It gives `arg` and `ret` bases and
   values, and the constant arguments accessor propagation needs.
4. Accessor propagation. A routine whose accesses take their address from an argument plus a constant is an
   accessor. At every call of it, an argument that is constant at the call site gives a derived access row with
   `via` set. Wrappers are followed to a fixed depth. Accessor seeds come from the binary's own symbols and
   from seeds whose provenance is a shipped binary, such as the named-accessor lists in chips' `call_census`
   configs. `callargs.py` becomes a check on the export, not a second source.
5. `partial` rows, as above.
6. A string walk: constants that point into a defined string, found with `ReBlockEval`, give `strings.tsv`
   rows.

The run is per binary and incremental. `re-run --ghidra-export --xref-all` reads
`generated/inventory/binaries.tsv`, keeps the hardware roles (`kernel`, `kernel-object`, `x-module`,
`x-server`, GL `library`, `diagnostic`, `firmware`, `microcode` where a processor module exists), skips any
binary whose manifest row already matches its sha256, the sgi-retools revision and the Ghidra version, and runs
the rest one at a time under the image's memory cap. Committed tables use `--cpus 1`, the setting the hardening
design reserves for a run-twice mismatch, so two runs give the same bytes. Kernel objects are skipped when the
same board and release has a linked kernel held and every function in the object matches a kernel function by
name and size. The manifest records them as `covered-by` that kernel.

`binaries.tsv` lists only what each repository's inventory root manifest names, so those manifests are extended
first to every held binary, including the IP12 PROMs, the IRIX 5.3 IP12 objects, the SHub 2 PROM and the IP22
and IP28 kernels.

The binaries are not in the repositories and CI has no `root/`, so the tables are generated on a host that
holds the inputs, like the inventory. CI checks what it can without them (below).

Two cross-checks keep the export honest:

- chips `census-sites.tsv` (from `scan.py`), `callargs.py` output and inventory `mmio.tsv` sites are compared
  with `sites.tsv`. A site one finds and the other misses is reported. This follows the rule that Ghidra reads
  and objdump-based tools check. The census tools stay the source for base-plus-offset accesses until the
  `partial` rows match them. After that they run only as CI cross-checks against the Ghidra tables.
- `facts.py` stays the per-routine reader for MIPS. Its stored values must agree with `value` on the rows they
  share.

Architectures: MIPS and IA-64 work in the walks today. ColdFire and m68k (sysco L1), ARM (kona L1, SN2 L1),
PowerPC and x86 PE (cobalt) go through the same p-code walks. `RePhysical` needs a rule for each, and x86 adds
port I/O (`in`, `out`) as an access with its own address space. Each architecture is enabled when its fixture
passes.

### Device maps

The device map from the hardening design becomes the one place that says where each unit sits in a machine:
`devices/address-map.toml`, or `devices/address-map.<family>.toml` where a repository covers several machines.
Each region has a name, physical base, length, the `registers.toml` unit it maps (or none), a grade and a
source. It also gets `kind`: `registers`, `ram`, `flash` or `rom`.

`kind` separates firmware's own memory from device registers. Accesses to `ram`, `flash` and `rom` regions are
still tabled, so "who writes RAM word `0x3809d4`" is answered. They need no register contract and are not
counted in the register gap. We expect most of sysco's 20,077 undocumented rows to move there once its map
exists.

A region inside a run-time window uses the existing `space = "node-local"` with `base_formula`, already in the
address-map-loader branch (`c2512df9`). The join matches `partial` rows by `offset` within that space.

The inventory's `windows` config already lists physical bases for some windows. Each repository moves those
into the map once, and the inventory reads its windows from the map when one exists, so the two cannot drift.

### Contracts and the coverage measure

A register's contract is three things:

1. Its `registers.toml` entry, graded, with a reset value or an `unknown` reset and its reason.
2. Its generated software-use row in `generated/xref/registers.tsv`: unit, register, readers and writers by
   binary and routine, distinct values written with counts, constants met after reads. The inventory writes
   this from `sites.tsv` and the device map, so nobody types it.
3. A documented entry at `understood` or `no-software-dependency` under the inventory's existing rules, which
   states the side effects and the sequence software uses, or says none is seen.

Parts 1 and 3 already exist. Part 2 is new, and it hands the entry writer the facts the question-answerers had
to trace.

`inventory.py` gains one table in `summary.tsv`, `accesses`, counting access sites in `sites.tsv`:

- placed: the physical address falls in a device-map region, or a `partial` row's offset matches a register in
  a `node-local` region
- unplaced: anything else
- on a register: placed in a `registers` region and inside a named register
- with a contract: on a register whose contract is complete as above
- memory: placed in a `ram`, `flash` or `rom` region.

`pct_done` for `accesses` is sites with a contract over sites in `registers` regions. COVERAGE.md shows it
beside the existing headline. Unplaced is a per-binary count with a listed sample of its sites, in COVERAGE.md
and the manifest. A repository is access-complete when every hardware binary's manifest row is `complete` or
carries a stated failure, each binary's unplaced sample has been read, and `pct_done` for `accesses` is 100.

The same pass applies the generic-code rule. A routine is out of scope only if it has no access rows of any
form (constant, partial or range) and no unresolved or table calls, which is an empty `hardware` cell in
`functions.tsv`. Such a routine is counted as named and located and left out of the done ratio. Identical-code
and family credit work as now. Generic routines stay in the tables, so a question about one still has rows to
find.

### Lookup

The tables are the lookup. Any text or code search over a clone finds them: `git grep -w 0x3809d4
generated/xref` answers the IP12 question in one command, and an indexed code search does the same across
repositories. A result line is a whole row, and the lines after it follow a sequence or the next caller.
Register names, routine names and string text are plain text in the same rows.

A search that finds nothing proves nothing on its own. A negative answer ("no routine writes this word") needs:

- the binary's manifest row is `complete`
- the search covered the repository
- a check of the binary's `range` rows, because a word search misses a range whose span holds the address, and
  of its `partial` rows by `offset`
- the answer names the walk's limits, such as block-only folding or run-time bases.

Search services that index these repositories are configured outside them. The repositories do not name one,
and the lookup log records the address or term, never a command.

### Questions log

Each RE repository gains `questions/lookups.tsv`, kept by hand, one row per question answered:

| Column | Meaning |
|---|---|
| `date` | when it was answered |
| `question` | the question in one line, in our words |
| `class` | `writers`, `callers`, `sequence`, `read-use`, `string`, `contract` or `other` |
| `term` | the address, register, routine or string that should find the answer |
| `answer` | the page and anchor that holds the answer |
| `result` | `lookup` (the tables answered it), `added-column`, `added-table`, `added-contract`, or `hand` |
| `change` | the sgi-retools or repository commit that closed the miss |

A `hand` row is a miss. It stays open until a change lets the lookup answer it, and then its `result` records
which kind of change did it. The inventory checks each row with an address `term` against the repository's own
`sites.tsv` and `strings.tsv`: a row marked `lookup` whose term no table holds fails. That check needs no
search service and runs in CI. `summary.tsv` counts rows by `result`, so the trend of misses is visible.

The asker is not recorded. The repositories are mirrored publicly, and the people and sessions that ask are not
hardware facts.

### CI

The RE repositories' CI runs `defs/ci-check` in a plain container. It gains a pure-Python check of
`generated/xref/`: column headers, address form, every generated table under the 1 MiB limit, every hardware
binary in `binaries.tsv` present in `manifest.tsv` or listed as covered or excluded, and the `lookups.tsv`
check. It reads files only. Its run time is measured in unit 1.

sgi-retools' `ghidra-check.yml` `re-scripts` job gains the new fixtures, including the run-twice comparison of
`--xref` output. That is the only CI cost that grows with this design, and it grows by the fixtures, not by the
corpus. Ghidra never runs on held binaries in CI.

## Work units

In order. Each unit lands as its own pull request in the repository named. "Mechanical" work is transcription,
runs and pin bumps. "Review-grade" work is Ghidra and inventory code, and review of it.

1. **Measure.** sgi-retools, review-grade, because it changes `ReAccessWalk` and needs reading Ghidra p-code.
   Add `value` and `uses` to the walk with fixtures, relax the image exclusion, add `ReXrefExport.java` and
   `--xref`, and run it on three reference binaries: the linked IP27 kernel, the SHub 2 PROM and one libGLcore.
   Record rows, bytes and run time per table. The IP27 kernel has 68,071 call instructions and 325,604 loads
   and stores among 960,044 instructions (objdump count), which suggests its `sites.tsv` alone may pass a few
   megabytes. Then project the totals for every held release in every repository from the per-binary numbers:
   committed bytes, files, and a full corpus run's time. That projection is the test of the every-release
   scope (see Risks).
2. **Device maps.** One pull request per repository that has register maps, mechanical, transcribing the
   existing `windows` configs and register-map sources and marking unsure regions rather than guessing.
   sgi-retools: the `tools/defs` loader for `address-map.toml` with `kind`, review-grade. A review-grade
   reviewer checks each map against its cited sources, because a wrong base misplaces every site under it.
3. **Function-scope values and strings.** sgi-retools, review-grade: the `SymbolicPropogator` pass and the
   string walk. The fixtures include a value formed in one block and stored in another.
4. **Call arguments and returns.** sgi-retools, review-grade: the ABI model for `ReBlockEval` for MIPS and
   IA-64, with fixtures for each calling convention.
5. **Accessors, partial rows and range rows.** sgi-retools, review-grade, after 3 and 4. The fixtures include a
   write through a leaf accessor, a store through a run-time base, a clear loop and an index-port and
   data-port pair.
6. **Corpus driver.** sgi-retools, review-grade: `--xref-all`, the manifest, kernel-object covering, the shard
   writer, the register join in the finish step and the pure-Python CI check.
7. **Inventory roots.** Per repository, mechanical: extend each repo's inventory root manifest to all held
   binaries.
8. **Generate.** Per repository, mechanical: run `--xref-all` on a host that holds the inputs, check the
   manifest, commit `generated/xref/`. Start with chips, since today's questions came from it, then the rest.
   Failures go back to units 3 to 6 as tool fixes, never as hand edits to the tables.
9. **Coverage.** sgi-retools `inventory.py`, review-grade: the `accesses` summary table, `registers.tsv`, the
   generic-code rule, windows from the device map, the census and `mmio.tsv` cross-check, and the
   `lookups.tsv` check, all in `test_inventory.py`. Then a mechanical pin bump and inventory regeneration in
   every repository.
10. **Search.** Make the repositories searchable where the project's search runs. That work is outside these
    repositories and is designed separately. Nothing here depends on it: `git grep` over a clone answers the same questions.
11. **Backfill the log.** Per repository, mechanical: enter the questions answered so far, starting with the
    three above, and confirm each `term` now finds its rows. A term that does not is a miss and goes to a tool
    unit or to 9.
12. **Contracts.** Per family, ranked by access-site count. Mechanical work drafts each entry from
    `registers.tsv` (readers, writers, values), marking anything unsure. Review-grade work writes side effects
    and sequences, and reviews the drafts against the rows. This continues until `accesses` reaches 100 in
    each repository.
13. **The remaining repositories.** cobalt, gr2 and newport: mechanical for the inventory config and root
    manifest, review-grade for the x86 port-I/O walk cobalt needs. gr4 (`origami-re`) and the private
    repository: mechanical for the pin bump and an inventory on the current sgi-retools. They follow unit 9.

Units 1 and 2 can run together, as can 3 and 4. Unit 7 can start at once. Unit 8 needs 1, 5, 6 and 7. Unit 9
needs 2 and 8. Unit 10 needs 8 only. Units 11 and 12 need 9.

## Risks

- **Size.** One kernel's tables may run to several megabytes, and kudzu, chips and sysco hold the same binaries
  across many releases. Splitting keeps every file searchable, but the repository total and the public mirrors
  grow, and each sgi-retools change to the export rewrites the tables. The scope stays every held release.
  Unit 1's projection is the test: a size or run time that does not fit means the table design changes (fewer
  columns, a more compact call graph, rows shared between identical releases), not that releases are dropped.
- **Restricted source.** The tables are generated from shipped binaries only and never read IRIX source, so
  they contain no source-derived facts. That keeps them safe for the public mirrors and readable by
  implementers. Two things need a check. Strings in shipped binaries can carry source file names and internal
  names, so `strings.tsv` runs through `leakcheck.py` with the repository's own term list before it is
  written, and a string that fails keeps its address and routine and has its text withheld. Symbol names from
  shipped symbol tables are allowed in committed outputs (the hardening design's decision), and the
  decompiler-identifier denylist applies to `name`.
- **Submodules.** Some RE repositories carry submodules of other projects, and gr2's include vendor source. The
  tables never read them, and a clone used for lookup initialises `retools/` alone.
- **Wrong facts that look mechanical.** A wrong function boundary or a misread base gives a confident wrong
  row. Block-only folding stays `established`. Function-scope rows are `inferred`. The census cross-check
  reports disagreement. Run-time bases become `partial` rows, never a guessed address.
- **Host load.** A full corpus run is heavy. It runs one binary at a time per repository under the Ghidra
  image's memory cap, with at most four repositories at once, and incrementally after the first pass.

CI time grows only by the sgi-retools fixtures and a file-reading check in each repository.

## Open questions

- Whether `facts.py` should later write its MIPS stored values into `sites.tsv`, or stay a separate reader.
- Where an index-port and data-port pair is declared: in `registers.toml` beside the registers, or in the
  device map.

## Out of scope

- Understanding every function. Generic code stays named and located.
- Emulator design. The tables describe the hardware and the software that drives it.
- Physical hardware reads.
- A new search service, index or viewer.
