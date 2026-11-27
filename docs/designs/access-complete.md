# Access-complete RE repositories: cross-reference tables, register contracts and lookup

Status: direction approved. `generated/xref/`, `--xref`, `--xref-all` and `questions/lookups.tsv` are adopted, as
are the other names below. Only unit 1 (the measurement, below) is built.

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

## Unit 1: what was built and what it measured

Measured 2026-11-27 on the shared build host, one run per input, `--cpus 1`, Ghidra 12.1.3 in the pinned image,
container capped at 8 GiB. Times are wall clock on a host with other jobs running, so read them to within a
factor of about 1.3. Peak memory is the container's cgroup `memory.peak`.

### Choices where the design was silent

- `--xref DIR` writes `DIR/<install path>/`, the object path without a leading `root/`. It runs no decompile and
  needs no decompile option. `ReXrefExport` calls `ReCallWalk`, `ReAccessWalk` and `ReBlockEval` directly.
- `functions.tsv` takes the design's columns. `end` is the exclusive end (maximum address plus one). A function
  Ghidra named itself has an empty `name` and `name_source`. `name_source` is the lower-cased Ghidra source type
  (`imported` for a symbol-table name, `analysis`, `user`).
- `sites.tsv` omits `via`, `region` and `register` until the passes that fill them exist, and has no
  `addressing` column. Its `grade` is `established` for every row. A call row's `target` is `ENTRY RESOLVED_BY`,
  where `RESOLVED_BY` is `direct`, `constant`, `table` or `unresolved`, with `@0xSOURCE` after `constant` and
  `table` and ` tail` after a tail jump, and `?` for ENTRY when the call does not resolve. At one site an access
  row sorts before the call row, because a delay-slot access is reported at its branch.
- `hardware` follows the design: `access` for a routine with an access row, `calls-access` for its direct callers.
  `sites.tsv` holds the accesses and every call site of both kinds.
- `value`: `0xHEX`, `load@0xSITE[,load@0xSITE]` (up to four loads of the same block that the stored value depends
  on, the lowest addresses first, image and stack loads included, so a site need not have a row), or `?`. A word read
  through a loaded pointer names its own load, not the pointer's. There is no `arg0` or `ret(...)` form yet, because an argument is only a
  value that is unknown in the block.
- `uses`: operations in the same block that meet the loaded value, or a value derived from it, with a constant.
  Names: `and or xor shl shr sar add sub mul eq ne lt le gt ge ltu leu gtu geu`, the loaded value on the left, so
  `ltu 0x10` is value < 0x10 and `gtu 0x3` is 3 < value. An add of a negative constant is a `sub`. Moves
  (`+ 0`, `| 0`) are not uses. Each load keeps at most eight distinct uses, in order of first occurrence, joined by `;`.
  The add of an addressing mode (`lw t, 8(p)`) is not a use, and a word read through a loaded pointer is a new
  load, so a test of a structure field is not a use of the pointer. A register add (`addiu t, p, 8`) still is,
  because nothing says it is address arithmetic. The first run listed both kinds: on libGLcore `add` was 1,521 of
  5,241 entries and is now 99 of 3,146, and on the kernel 6,612 entries on 2,954 loads fell to 1,493 on 1,162.
- `strings.tsv`: only strings in initialised, loaded, non-overlay memory. A reference is a constant the block
  walk builds that equals a string's first byte, or a reference Ghidra's own analysis recorded from an
  instruction. Text is escaped (`\t`, `\n`, `\\`, `\xNN`) and cut at 200 characters with `...`. The `leakcheck.py` pass
  the risks section calls for is not applied yet.
- Addresses of a flat image placed under a window are written without the window.

### Results

| Input | Size | Functions | Hardware routines | Access rows | Call rows | Strings with a reference |
|---|---|---|---|---|---|---|
| IP27 linked kernel (`unix`, 6.5.30 build, sha256 `56747467`) | 11.1 MB ELF | 12,274 | 4,773 | 4,107 | 40,203 | 5,361 rows |
| SHub 2 PROM `shub2snprom.bin` (sha256 `3ea83318`) | 12.6 MB flat | 2,714 | 1,182 | 27,430 | 8,281 | 4,693 rows |
| `libGLcore.so` (IP27KONA) | 2.9 MB ELF | 4,962 | 2,896 | 5,793 | 6,479 | 88 rows |
| `acl.o` (smallest kernel object, for the fixed cost) | 20 KB | 35 | 2 | 4 | 28 | 0 |

| Input | functions.tsv | sites.tsv | strings.tsv | Total | gzip -9 | xz -9 |
|---|---|---|---|---|---|---|
| kernel | 2.19 MB | 3.85 MB | 0.46 MB | 6.49 MB | 0.70 MB | 0.52 MB |
| SHub 2 PROM | 0.23 MB | 2.42 MB | 0.34 MB | 2.99 MB | 0.24 MB | 0.14 MB |
| libGLcore | 0.29 MB | 0.74 MB | 0.005 MB | 1.03 MB | 0.12 MB | 0.07 MB |
| acl.o | 2.1 KB | 2.0 KB | 0.03 KB | 4.1 KB | 0.9 KB | 0.9 KB |

| Input | Wall | Import, analysis and start-up | Walks | Strings | Peak memory |
|---|---|---|---|---|---|
| kernel (5 GiB Java heap) | 234 s | 187 s | 25 s | 18 s | 1.9 GiB (2.2 GiB on a first run) |
| SHub 2 PROM (4 GiB heap) | 338 s | 273 s | 40 s | 21 s | 1.9 GiB |
| libGLcore | 91 s | 78 s | 6 s | 3 s | 1.1 GiB |
| acl.o | 27 s | 24 s | 0 s | 0 s | 0.46 GiB |

The kernel and PROM runs also ran a throwaway counting script, which took 18 s and 55 s. Those are subtracted
above. Two runs of libGLcore gave byte-identical tables. The fixtures compare two runs of the whole export.
The size rows for the kernel and libGLcore are from the final scripts. The SHub 2 PROM and `acl.o` rows, the
times and the extrapolation below were taken before the pointer and addressing-add change, which only shortens
`value` and `uses` (the kernel's `sites.tsv` by 1.2%) and leaves every row and every other table as it was.

Findings that change the design:

- **Fixed cost per file.** The smallest object costs 24 s before any walk, which is Podman, the JVM and the
  project import. Time is about `24 s + 21 s per MB`. A corpus of thousands of objects is dominated by the fixed
  part, so `--xref-all` has to open many files in one headless session, not start one container per file.
- **The `hardware` flag is polluted in the kernel.** 4,031 of the kernel's 4,107 access rows are loads and stores
  at `0xffffffffffffc000` to `0xffffffffffffdfff`, the per-CPU private page, and 55 more are at addresses below `0x10000`. Only
  21 are anywhere a device window could be. That makes 1,538 routines `access` and 3,235 `calls-access`, and call
  rows are 88% of `sites.tsv` (3.4 of 3.9 MB). A region test before the flag (unit 2, the device map) takes the
  kernel's `sites.tsv` to well under 1 MB. In the SHub 2 PROM the walk's addresses are mostly real: 21,208 are
  above `0x10000`, 6,002 below it and 220 are `0x0`.
- **Block-only string references are weak.** The block walk finds 87 string references in the kernel and 0 in the
  PROM and libGLcore, where Ghidra's own references find 5,274, 4,693 and 88. The IA-64 PROM builds addresses from
  `gp`, which is not a constant in the block. Both sources are kept.
- **Function counts differ from the inventory.** Ghidra finds 12,274 functions in the kernel, the inventory's
  `functions.tsv` 13,484. Not investigated.

### Run-time base plus a constant

`ReAccessWalk` drops a load or store whose address is a known constant added to an unknown base. Counted over
the same two programs with a throwaway script, with "register offsets" meaning the `offset` of every row in the
chips `generated/json` for the Hub, Bridge, Xbow and IOC3 units (kernel, 375 offsets) or SHub 2 (PROM, 357):

| Rows | IP27 kernel | SHub 2 PROM |
|---|---|---|
| all run-time base plus constant | 286,289 (11,111 routines) | 676,234 (2,429 routines) |
| in a routine that also has a known access above `0x10000` and below `0xffffffffffff0000` | 243 (11) | 135,610 (326) |
| constant equals a register offset | 182,870 (10,849) | 42,448 (2,332) |
| constant equals a register offset of at least `0x100` | 13,266 (2,199) | 20,607 (24) |
| equals a register offset, in a routine with such a known access | 166 (10) | 25,468 (317) |
| fully unknown address, no constant | 255 | 45,459 |

At about 50 bytes a row before value and uses, the kernel's unrestricted set is 15 MB and the PROM's 24 MB.
99% of the PROM's rows are 8 bytes wide: they are `gp`-relative and stack accesses, not registers. In the kernel
they are every structure field. The restriction to a known device-window access is the only one that holds the
volume down on both, and it finds almost nothing in the kernel because the kernel reaches its devices through
bases the walk cannot fold. Check against the chips census: the kernel's census lists 1,382 sites, 3 of which
are constant-address rows and 990 of which appear as run-time base plus constant rows (442 with the same offset).
So the new row kind is the kernel's main source of accesses.

### Spot checks

- **SHub 2 store at `0xff420850` through the helper `0xff420840`.** The helper's store address is its first
  argument, so the walk emits no access row for it. What it emits: a `functions.tsv` row for `0xff420840` (end
  `0xff420890`, no name, `hardware` empty) with 103 callers, among them `0xff4886c0` and `0xff47bf60`. In
  `0xff4886c0`, whose own accesses make it a hardware routine, `sites.tsv` has the call row
  `0xff488dcc call 0xff420840 direct`, and its callers `0xff481b20` and `0xff482c60` match the memory-init page.
  `0xff47bf60`, the port loader with sixteen stores through the helper, has no access row and calls only
  routines without one, so it is not a hardware routine and none of its call rows are written. Searching
  `0x38000` finds nothing. That is unit 3 (accessor propagation), as designed, and it also shows that an
  accessor's callers must be treated as hardware routines.
- **A kernel register access in the chips census.** Census row `ip27-unix update_ust 0xc0000000000236b8 ld r 8
  0x30100` has `sites.tsv` row `0xc0000000000236a0 0xc0000000000236b8 load 0x9200000001030100 0x1030100 8` (function
  `update_ust`, then site): same
  site, direction and width, offset `0x30100` in the `0x1000000` window. Two more match, `start` at
  `0xc00000000001a780` and `bootstrap` at `0xc000000000043764`, both loads of offset `0x600000`, where the
  read-use column adds `and 0x1ff00;shr 0x8` (and in `bootstrap` `shl 0x20;or 0xa8000000000021d0`), the field extraction
  the census does not carry.

### What call-argument and return tracking would take

Not built. The walks clear their state at a call, and an argument is only a value that is unknown in the block.
Three pieces are needed.

1. An argument value: a symbolic "incoming argument N plus a constant" in `ReBlockEval`, so a leaf accessor
   `st [arg0+k] = arg1` shows as an accessor with its address and value arguments. MIPS names the argument
   registers by ABI (o32 `a0`-`a3` with the rest on the stack, n32 and n64 `a0`-`a7`), so the register to argument
   mapping needs the object's ABI, which `ghidra-export.py` already derives. A routine's accessor summary is
   built from its first block only, so it covers leaves and the single-block wrappers, not a wrapper that
   calls first.
2. The caller's side: the state at each call, which today is discarded. The call hook needs the constants of the
   argument registers, and the result is one derived row per call site with a constant argument (for the SHub 2
   PROM, the four leaf routines have 378 calling routines between them, and how many of their call sites pass a
   constant is only known by building it).
3. Return values: `v0` and `v1` after a call are unknown unless the callee summary says it returns a constant or
   an argument. That needs a per-routine summary and an order (callees first, a fixed depth for recursion).
   On IA-64 the arguments sit in the caller's output registers, which the register stack renames to the
   callee's `r32` onward at the call, so the caller's `alloc` (inputs, locals, outputs) is needed to map them,
   and a return value is in `r8` to `r11`, which are not renamed. `IA64Signatures.java` already derives
   callee parameter lists and is the starting point. Predicated calls and `br.call` through `b6` need the same
   care as predicated writes now get.

### Extrapolation

Corpus (the RE repositories' `generated/inventory/binaries.tsv`, hardware roles, deduplicated by sha256 across
repositories): 8,443 binaries, 472,000 functions, 704 MB. By repository, unique binaries: chips 3,092 (98,000
functions), kudzu 4,481 (151,000), kona 508 (50,000), odsy 181 (93,000), voyager 43 (64,000), crime 31
(15,000), sysco 107 (900). The root manifests hold two kernel releases, 6.5.22 and 6.5.30 (kudzu: 4,013 and 3,443
binaries with 179,000 and 174,000 functions); the media inventory lists 6.5-base and a 6.5.29 tarball set as well,
which no root manifest holds yet. Each further release costs about what 6.5.30 does.

Rates used: raw table bytes per function 117 (`acl.o`, the only object), 208 (libGLcore), 533 (kernel) and
1,100 (PROM); gzip about 1/8 of raw and xz about 1/12 for the large inputs. Git stores deflate, so the gzip
column is the repository growth for one generation.

| Part | Count | Raw | gzip | Time, one stream |
|---|---|---|---|---|
| 6 linked kernels (IP27, IP30, IP35, two releases), taken as the IP27 kernel | 6 | 39 MB | 4.2 MB | 25 min |
| kernel objects, both releases | about 7,570 | 29 to 133 MB | 4 to 17 MB | 52 h, nearly all fixed cost |
| graphics libraries, X modules, diagnostics, firmware | 870 | 46 to 119 MB | 6 to 15 MB | 8 h |
| all | 8,443 | 114 to 291 MB | 14 to 36 MB | 60 h; about 15 h with four runs at once |

Memory stays under 2.5 GiB per run, so four at once fit the 8 GiB cap each with room to spare on this host. One
more release adds roughly 40 to 110 MB raw, 5 to 14 MB gzip and about 24 hours of one stream.

Is committing full tables for everything feasible? Once, yes. Every regeneration is the problem: any new column or
changed value rewrites every line, so each full generation adds the whole gzip figure (14 to 36 MB) to each
mirrored repository, and the 1 MiB shard limit makes the kernel alone 4 `sites.tsv` and 3 `functions.tsv`
files, about 25,000 files for the corpus. What would make it so:

- A region test before the `hardware` flag and a rule for which run-time-base rows are kept (a known window in the
  routine, or an offset of at least `0x100` that equals a register offset). By estimate, not run, that takes the kernel's `sites.tsv`
  from 3.9 MB to about 1 MB, and its tables from 6.5 MB to about 3.5 MB, because `functions.tsv` (2.2 MB) has a
  row per function whatever is kept. The PROM's partial rows stay near 1 MB.
- Not tabulating kernel objects that a linked kernel covers. That holds for IP27 and IP30, which have linked kernels
  held. IP35 and IP32 do not, so their objects (353 and 230 per release) must be run.
- Batching objects into one headless session, which removes the 24 s fixed cost. The 52 hours go to a few.
- Deduplicating by function, not by binary. No kernel object is byte-identical across 6.5.22 and 6.5.30 (0 of
  3,141 at the same path), but 43% of 6.5.30's function rows have code that also occurs in 6.5.22, and 38% of a
  release's functions repeat inside it (111,000 distinct code hashes in 179,000). Tables keyed by code hash with
  routine-relative addresses would hold each once.
- Regenerating only when the manifest's sgi-retools revision or the input changes, never per commit.

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
