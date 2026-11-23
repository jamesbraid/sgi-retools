# Hardening the shared reverse-engineering toolchain

Status: decided, being built. Every name in it is adopted. [Implementation](#implementation) lays out the work
and its two pull requests.

## Decisions

- Upgrade the shared Ghidra scripts in `ghidra/scripts/` properly, rather than writing PROM-only copies.
- Make m2c and spimdisasm work in the toolchain image. m2c is pinned at the `techomancer/m2c` fork commit
  `9dc1bd4b`.
- The new script that writes code files is `SgiPromCodeExport.java`. Every other name in
  [Names](#names) is adopted as proposed.
- Drop pycparser from the toolchain image. Nothing imports it: `git grep` finds it only in
  `tools/Containerfile` in sgi-retools, and in none of the eight RE workspaces at their current heads.
- Debug-symbol names from shipped binaries may reach committed code files. Names from shipped binaries and
  their debug information are fine in RE outputs. Only IRIX source names are barred. `--debug-symbol-names`
  stays an option.
- `SgiPromCodeExport.java` writes the records. The Python finish step writes the code file.
- The device map lives in the RE repository that defines the registers, as hardware facts beside the units.
  The `tools/prom` family plug-in reads it.
- Jump tables go in the committed code file. They are structural facts, not decompiled text.
- Calls and device accesses keep their grades.
- SN2 PROMs get no code kind yet. That is later work.
- The budget defaults are Ghidra's suggested limits: 100,000 instructions, 50 MB of payload and 1,024
  jump-table entries. The code export's wall-clock guard is 3,600 s.
- Per-site `DumpCallEdges` rows stay opt-in. Making them the default is a later decision.
- If the run-twice check shows analysis differs at `--cpus 2`, the code export defaults to `--cpus 1`.
- chips pins sgi-retools as a submodule like the other workspaces.

Read against sgi-retools `main` at `022bbbc`, the PROM-to-Rust pipeline design in Origami (branch
`emdash/sgint-c89ux`, `docs/designs/prom-rust-pipeline.md`), its second promkit-boundary review, and the RE
workspaces at their 2026-11-22 heads: chips `bdbf144`, cobalt `9925373`, crime `dd0c93c`, gr4 `origami-re`
`390b3e0`, kona `653fd5b`, odsy `aa56039`, stonewire `46604d3`, sysco `e83d547`.

## The problems

The PROM-to-Rust pipeline needs a committed `<image>.code.json` (the `code` kind of the `sgi-prom` schema)
listing functions, call edges and device accesses. The scripts that would feed it were written for reading
IRIX objects by hand and are not fit to produce a committed file:

- `DumpCallEdges.java` writes `program, caller, callee, kind`. It records no call-site address, keeps one row
  per callee name per function, and does not say how an indirect call was resolved. It has no test.
- `FindWindowStores.java` runs the decompiler on every function, so a function that fails to decompile
  yields no accesses. It has no read-modify-write class and no register names. An access through a base
  register loaded from a table is tagged `field` or `chain`, never `window`, so it is missed by a window
  search. It has no test.
- Every decompiler call in the scripts passes a wall-clock timeout (60 s in `FindWindowStores`,
  `IA64Signatures` and `ReDecompileExport`, 120 s in `DecompileFunctions`). Whether a function decompiles
  depends on host load, so two identical runs can differ. `IA64Signatures` applies parameter lists from
  those decompiles, so a timeout there changes the program every later step reads.
- Only hand-curated modules survive a re-run. A function boundary or name set by hand is lost.
- m2c is not in the toolchain image. The workspaces run it from a submodule. No extractor calls spimdisasm,
  so disassembling a flat PROM segment for m2c is new work.
- m2c's known failures are a jump table it cannot see, a whole file failing on one rejected branch, static
  functions with no symbol, and one-function files that lose their callee labels.
- Nothing stops decompiler identifiers from reaching a published repository. The pipeline design lists some
  patterns but none are enforced.

## Who uses the scripts

Every workspace pins sgi-retools as its `retools/` submodule: chips at `a851fc4` (its head `bdbf144`), the
others at `b6db4a8`. No workspace has its own copy
of a shared script, and no workspace calls `DumpCallEdges` or `FindWindowStores` from code. The scripts are
named in documentation and run by hand.

| Workspace | What it calls | What reads the output |
|---|---|---|
| chips | `--ghidra-export` for SN2 PROMs (IA-64), Linux kernels, EFI drivers and the Visual Workstation HAL (x86 PE). `tools/ghidra/README.md` names `FindWindowStores`, `IrixGp`, `IrixJumpTables` | `tools/visws-hal/build.sh`, `scan.py` and `stats.py` read `decompile.json` fields `address`, `end`, `name`, `name_source`, `complete` |
| cobalt | nothing found | |
| crime | `--ghidra-export`, `FindWindowStores`, `IrixGp`, `IrixJumpTables`, `MarkVolatileWindows` (README). m2c from its submodule in `software/opengl/decompile_libglcore.sh` and `software/xsgi/decompile_ddx.sh` | m2c output committed under `software/*/decomp/` |
| gr4 | `ApplyStruct`, `DecompileFunctions`, `DumpCallEdges`, `FindWindowStores`, `IrixGp`, `IrixJumpTables` (`AGENTS.md`). m2c in four `decompile_*.sh` runners | none in code |
| kona | every IRIX script (`tools/ghidra/README.md`, `tools/tooling-bakeoff.md`). m2c in two runners | m2c output committed under `software/*/decomp/` |
| odsy | every IRIX script, cited throughout its readings. m2c in two runners | m2c output committed under `software/*/decomp/` |
| stonewire | `--ghidra-export` (one reading) | none in code |
| sysco | `--ghidra-export` for the L1 controller firmware (ARM flat image) | none in code |
| sgi-retools | `tools/re-run --ghidra-export` drives `ReDecompileExport`, `ReMipsGp`, `IA64Elf`, `IA64Pe`, `IA64Signatures`, `ReBSimAdd` and the others. the SN2 import. the IA-64 and `.dbg` checks in `ghidra-check.yml` | `tools/ghidra-export.py` `finish` |

crime, kona and odsy pin m2c at `techomancer/m2c` branch `irixn32` commit `9dc1bd4b`. gr4 pins `b3e0876a` on
the same branch. All four pin spimdisasm `4b5d4c68` but none of their runners call it.

## Rules for every change

- **Additive output.** Existing outputs gain fields or trailing columns. Nothing is renamed, removed or
  reordered, and a script called with its current arguments writes the same rows. Where a fix would change
  existing rows, the new behaviour is behind a new argument.
- **No wall-clock in results.** A recorded result must not depend on how long something took. Timings may be
  recorded, but they are named as timings and excluded from every determinism comparison.
- **Stable order.** Every list is written sorted by a stated key. Hex is lowercase with no leading zeros,
  matching the schema's `^0x[0-9a-f]+$`.
- **One resolver.** Converting between a Ghidra address, a `(segment, address)` pair and a file offset is
  promkit's job, because promkit owns regions. It is written once in `tools/prom/` and called by everything
  else.

## A deterministic decompile budget

Ghidra 12.1.3's `DecompileOptions` has three limits that count work rather than time. Their suggested
defaults, read from the class constants in the Ghidra image, are:

| Option | Suggested default | Effect |
|---|---|---|
| `setMaxInstructions` | 100,000 | the decompiler stops when flow from the entry reaches more instructions than this |
| `setMaxPayloadMBytes` | 50 | the decompiler stops when its result exceeds this size |
| `setMaxJumpTableEntries` | 1,024 | a switch table with more entries is not recovered |

The budget is these three numbers. Every script that decompiles sets them through one helper class,
`ReDecompBudget`, in `ghidra/scripts/`. The timeout argument to `decompileFunction` stays
but becomes a ceiling that guards against a hung decompiler. It is not a limit on normal work. The largest
measured case in `ghidra/scripts/README.md` (a 17 KB routine that took 121 s) has about 4,300 instructions,
well inside the instruction limit, so with a generous ceiling it completes on every run.

Each decompile result gets a status:

- `complete`: the decompiler finished and its C has no flow-losing warning.
- `partial`: it finished, but the C carries a warning from a fixed list that means part of the body is
  missing or wrong: an unrecovered jump table, bad instruction data, unreachable blocks removed, an
  unimplemented instruction. The list lives in the helper, beside the existing `WARNING` pattern in
  `ReDecompileExport`.
- `failed`: the decompiler stopped. The reason is `budget` (one of the three limits, from the decompiler's
  own message, recorded verbatim), `ceiling` (the wall-clock guard fired) or `error`.

A `ceiling` failure is the only status that depends on time. Navigation output records it and prints how
many functions hit it. The code export refuses to write a code file when any function hit the ceiling, so a
committed file never depends on host load. It also makes one attempt only, with a default ceiling of
3,600 s, where `ReDecompileExport` retries a timed-out function at four times the timeout.

Two of Ghidra's own analyzers, switch analysis and parameter identification, run the decompiler during
auto-analysis with their own timeouts. For a code export, a pre-script raises those timeouts to the ceiling
before analysis. The option names are read from Ghidra 12.1.3's analyzer list when the change is written,
and the run-twice check below shows whether analysis is deterministic at the default `--cpus 2`. If it is
not, the code export defaults to `--cpus 1`.

The budget values in force are written into every output: a top-level `budget` object in `decompile.json`
and `analysis.budget` in a code file. A budget change is then a visible change, not a silent one.

## Shared helper classes

The walks the code export needs are written once, as plain Java classes in `ghidra/scripts/` that the
scripts call. Ghidra builds each script directory as one bundle, so a script should be able to use another class in
its directory. The first fixture run confirms this in headless mode. If it fails, each script carries its own
copy of the budget constants and the walks move into `SgiPromCodeExport.java` alone.

| Class | Does |
|---|---|
| `ReDecompBudget` | applies the budget and the ceiling, classifies a result as `complete`, `partial` or `failed` |
| `ReCallWalk` | one record per call site: site, containing function, target or none, resolution kind |
| `ReAccessWalk` | one record per load or store whose address resolves to a device: site, physical address, width, operation, addressing |
| `ReBlockEval` | the block-local evaluator the two walks share |
| `RePhysical` | maps a virtual address to a physical one per processor: MIPS kseg0, kseg1 and XKPHYS (the rule in `FindWindowStores.phys()` today), IA-64 regions 6 and 7 and the bit-63 uncached alias |

`ReCallWalk` and `ReAccessWalk` work on instructions and their raw p-code. They do not need the decompiler, so a
function the decompiler fails on still yields its calls and accesses, and the result does not depend on the
budget. Both read register values from one small evaluator, `ReBlockEval`, which follows constants through
copies, adds, shifts and ors, and through loads from read-only memory, within one basic block. It replaces
Ghidra's constant propagator, whose reach into read-only memory would have had to be probed and whose
behaviour the scripts do not control. A constant built in one block and used in another is not followed. That
is a stated limitation, and the fixtures include it.

## Script by script

### DumpCallEdges.java

Called with one argument, it writes the same rows as today. A second argument, `sites`,
switches to one row per call site with three columns appended:

```
program  caller  callee  kind  site  target  resolved_by
```

`callee` and `kind` keep their meaning (`direct`, or `indirect` with callee `?`). `site` is the call
instruction's address, `target` the callee's entry or empty, `resolved_by` one of the kinds below. Rows come
from `ReCallWalk`, sorted by site and then target. One site with several targets (a call through a handler
table) gives one row per target.

### FindWindowStores.java

Rows and their first ten columns stay as they are. Access mode gains trailing columns:

```
... note  physical  op  addressing  load_site
```

- `physical`: the physical address from `RePhysical`, when the address resolves. This is where a
  base-register access gains its device address: a base loaded from read-only memory folds to a constant,
  and the row keeps its `field` or `chain` tag. The tag column does not change, because changing a value
  would break the additive rule.
- `op`: `load`, `store` or `rmw`. The existing `r`/`w` column stays.
- `addressing`: `absolute` or `base+offset`, defined under the device-access record.
- `load_site`: for `rmw`, the address of the load it pairs with.

The decompiler call moves to `ReDecompBudget`. A function that fails now prints its status and reason in the
existing `decompile failed` row, after the existing text. Register names are not joined here. That join is
Python's (see the code export), and this script stays independent of any workspace's register definitions.

### ReDecompileExport.java and tools/ghidra-export.py

`functions.jsonl` rows, and so `decompile.json` functions, keep every field, including the inclusive `end`
and the Ghidra `SourceType` string in `name_source` that chips' HAL tools read. Each row gains:

- `decompile_status`: `complete`, `partial` or `failed`.
- `failure`: `{"reason": "budget" | "ceiling" | "error", "message": ...}` when failed.

`decompile.json` gains a top-level `budget`. `export.json`, the request file `ghidra-export.py` writes,
gains a `budget` object. New options set the limits: `--decompile-max-instructions`,
`--decompile-max-payload`, `--decompile-max-jumptable`. `--decompile-timeout` keeps its
meaning and its retry. `decompile_ms` and `timeout_retried_s` are still written and are timings.

### DecompileFunctions.java and IA64Signatures.java

Both take the budget through `ReDecompBudget`. `DecompileFunctions` adds the status to its `ok=` line, after
the existing text. `IA64Signatures` applies a parameter list only from a `complete` or `partial` result and
prints how many functions hit the ceiling. A code export over an IA-64 image refuses to finish if any did.

### The other scripts

`IrixGp`, `IrixJumpTables`, `MarkVolatileWindows`, `ApplyStruct`, the importers and `ReBSimAdd` do not
change. `tools/re-run` already hashes `ghidra/scripts/*` into the Ghidra image tag, so the new classes
rebuild the image.

## The call-edge record

One record per call site and target. In a code file:

| Field | Value |
|---|---|
| `site` | address of the call instruction, `{segment, address}` |
| `from` | entry of the function containing the site, `{segment, address}` |
| `to` | entry of the callee, `{segment, address}`, or `null` |
| `resolved_by` | `direct`, `constant`, `table`, `trace` or `unresolved` |
| `tail` | optional, `true` for a jump to another function's entry that is not a call instruction |
| `table` | optional, for `table`: the `prom.json` table entry the target was read from, `{kind, name, address}` |
| `grade` | one of the six ratings |

How each kind is decided:

- `direct`: the target is in the instruction (`jal`, `bal`, IA-64 `br.call` with an immediate). Grade
  established.
- `constant`: the register the call goes through holds a constant at the site, by constant propagation over
  the function (`lui`/`addiu` into `t9`, then `jalr t9`). Grade established.
- `table`: the register was loaded from a word inside a `prom.json` table entry, such as a firmware vector
  or a command table. Every entry of the table that the index can reach is a target. The grade is the
  table entry's grade.
- `trace`: a target seen in a run. The export has no run data, so it never writes this kind. A curator adds
  such records by hand and the merge keeps them (see Hand edits). Grade observed.
- `unresolved`: none of the above. `to` is `null`. Grade unknown.

The kinds come from `ReCallWalk`, not from Ghidra's computed-call references. Those references are an
analysis result, and their absence says nothing about why.

## The device-access record

One record per load or store whose address resolves to a physical address that the family's device map
covers.

| Field | Value |
|---|---|
| `site` | the instruction, `{segment, address}` |
| `function` | entry of the containing function, `{segment, address}` |
| `physical` | physical address, hex. It may lie outside every segment |
| `width` | 1, 2, 4 or 8 bytes |
| `op` | `load`, `store` or `rmw` |
| `addressing` | `absolute` or `base+offset` |
| `base` | optional, for `base+offset`: the read-only word the base was loaded from, `{segment, address}` |
| `load_site` | optional, for `rmw`: the load's instruction, `{segment, address}` |
| `register` | the register's name in the generated `tools/defs` output, or `null` |
| `grade` | established when every input is read from the bytes, otherwise inferred |

`absolute` means the address is a constant built in the function's own instructions. `base+offset` means the
base came from a load, such as a pointer table in read-only data, and the instruction's displacement selects
the register. That is the case `FindWindowStores` tags `field` or `chain` today.

`rmw` is decided on raw p-code inside one basic block. A load from address A, then operations on the loaded
value, then a store to A of the same width whose value depends on the load, with no call between them,
becomes one `rmw` record at the store with `load_site` set. The separate load record is not written. A
modify that crosses a branch stays as two records. That is a stated limitation, and the fixtures include it.

The register-name join runs in Python, in the export's finishing step, because the definitions are Python
data. A defs unit gives offsets from its own `base`, which is 0 for the O2 units (crime's
`generated/json/crime.json`, profile `defs-flat/1`). Nothing in the definitions says where a unit sits in a
machine's physical address space. The join therefore needs a device map per family: for each unit, its
name, physical base and length, with a grade and source like any other hardware fact. The map lives in the
RE repository that defines the units, beside them, because where a block sits in the machine is a hardware
fact. For the O2 that is crime. Its file name is `devices/address-map.toml`, or `devices/address-map.<family>.toml` where one repository covers
several machines. The `tools/prom`
family plug-in names the repository and reads the map as `devices`, through the existing `--sibling`
mechanism, which also finds the generated JSON. The join rule: an access
names a register when it lies wholly inside one register, with `count` and `stride` expanded and the index
written as `name[i]`, and the register is in the unit's default space. Anything else is `null`, so a
partial-width access never borrows a name it does not cover.

## Hand edits and re-runs

A code file is both an input and an output of the export. The run reads the previous file, applies its
curated parts to the program, and writes a new file in which the curated parts are unchanged and everything
else is regenerated. Only a file for the same `image.sha256` is read. Any other file is refused.

Curated, and kept as they are:

- A function with `boundary: hand`. Its `entry`, `end`, `name`, `name_source` and `grade` are the curator's.
  Its `decompiled` and `decompiler` are regenerated.
- A name with `name_source.kind: hand` on an automatic boundary. The name is kept and the boundary is
  regenerated.
- `modules`, copied unchanged.
- Calls with `resolved_by: trace`, and matches with `method: hand`.

Hand boundaries reach Ghidra through a new shared pre-script, `ReHandFunctions.java`, which
reads a list of `{entry, end, name}` and creates each function with exactly that body before auto-analysis.
After analysis the export checks every hand body again and restores it if analysis moved it, so the
decompile and the walks see the curator's boundaries. An automatic function that overlaps a hand one is
dropped and reported. The pre-script is useful outside PROMs too, so `--ghidra-export` gains
`--hand-functions FILE` for any image.

The export's check reports curated data that no longer fits: a module listing an entry that is not a
function, or a hand function whose entry does not decode. It reports these and does not fix them.

## SgiPromCodeExport.java and the code kind

### How a code file is produced

One run: `re-run --ghidra-export IMAGE --sgi-prom PROM.json --code CODE.json`. It
follows the SN2 import pattern, where Python finds, a Ghidra script applies and a Python check re-parses.

1. `ghidra-export.py prepare` reads `prom.json` and the previous code file, writes the hand-function list for
   `ReHandFunctions.java` and records the sgi-retools revision.
2. `SgiPromImport.java` lays out the image, as the [promkit design](prom-toolkit.md) describes. `ReHandFunctions.java` applies
   the curated boundaries and names. Ghidra analyses.
3. `SgiPromCodeExport.java` runs as a post-script. It reads the analysed program and writes the generated
   records into the job directory: functions with Ghidra addresses, decompile status from
   `ReDecompBudget`, calls from `ReCallWalk`, accesses from `ReAccessWalk`, and jump tables.
4. `ghidra-export.py finish` turns Ghidra addresses into `(segment, address)` pairs with promkit's resolver,
   joins register names, merges the curated parts of the previous file, adds an optional m2c status file,
   sorts, validates the result against the schema and writes `CODE.json`.

The split matches how `decompile.json` is produced today, where the Java script writes `functions.jsonl` and
Python writes the file. It keeps the address resolver and the register join in Python, which owns both.
`SgiPromCodeExport.java` writes the records and the finish step writes the file.

`SgiPromCodeExport.java` writes a function name only when it can name the source: a `prom.json` table entry
(`table`), a fact name the facts step built (`neutral`), a curated name (`hand`) or, with
`--debug-symbol-names`, a payload's symbol table or debug information (`debug-symbol`). It works the source out from `prom.json` and the hand list,
not from Ghidra's `SourceType`. A Ghidra placeholder name (`FUN_...`) is never written.

### Fields

The target is the field list settled for the PROM-to-Rust pipeline. The table gives the field list as this
design writes it. The next section lists every difference.

| Section | Fields |
|---|---|
| top level | `schema`, `version` (1), `kind` (`code`), `tool`, `image`, `analysis`, `functions`, `calls`, `device_accesses`, `jump_tables`, `modules`, `matches` |
| `image` | `sha256`, optional `file`, optional `segments` (segment name to sha256) |
| `analysis` | `ghidra` (version), `scripts` (sgi-retools revision), `budget` (`max_instructions`, `max_payload_mb`, `max_jumptable_entries`, `ceiling_s`), optional `m2c` and `spimdisasm` versions when an m2c status was merged |
| `functions[]` | `segment`, `entry`, `end` (exclusive), optional `ranges`, `name` or `null`, `name_source` (`kind`: `table`, `debug-symbol`, `neutral` or `hand`. optional `table` `{kind, name}`. optional `address`), `boundary` (`auto` or `hand`), `decompiled` (`complete`, `partial` or `failed`), `decompiler` (`ghidra` or `m2c`), `grade` |
| `calls[]` | as in the call-edge record |
| `device_accesses[]` | as in the device-access record |
| `jump_tables[]` | `site` (the indirect jump), `function`, `table` (address of the first entry), `targets[]` (addresses in entry order), `grade` |
| `modules[]` | `id`, `segment`, `start`, `end`, `functions[]` (entries), `spec` (chips page path). curated |
| `matches[]` | `entry`, `other_image` (sha256), `other_entry`, `method` (`bsim`, `exact-bytes` or `hand`), `score` |

Not in the file: decompiled text, trace data and m2c output files.

Sort keys: `functions` by entry, `calls` by site then target, `device_accesses` by site, `jump_tables` by
site, `modules` by start, `matches` by entry. Addresses sort by numeric value, then by segment name. A
`null` target sorts after every address.

`decompiled` and `decompiler` describe one reading. The export writes `ghidra` and Ghidra's status. When an
m2c status file is given and Ghidra's status is `partial` or `failed` while m2c's is `complete`, it writes
`m2c` and `complete`.

`end` is exclusive here. `decompile.json` keeps its inclusive `end`. The two files are separate and each
keeps its own meaning.

### Differences from the settled field list

Each item below departs from the PROM-to-Rust pipeline's field list. Each one says why.

1. **`tool` is kept** beside `analysis`. The schema's shared header requires `tool` in both kinds, and
   promkit writes it.
2. **Addresses in `calls`, `device_accesses`, `jump_tables` and `matches` are `{segment, address}`
   objects**, not bare hex. A call can cross segments (the O2's `sloader` calls into `post1`), so a bare
   target cannot be resolved. `functions` stays flat (`segment`, `entry`, `end`) as settled.
   `physical` stays bare hex, because a device address has no segment.
3. **`grade` stays required on `calls`, `device_accesses` and `jump_tables`.** The promkit design decided
   that every entry carries a grade, and the export can grade each record by the rules above. `matches` do
   not carry one, because `method` and `score` are their measure.
4. **`functions[].ranges`** is optional. It is written only when Ghidra's body for the
   function is not one contiguous range. `end` is then the end of the range that holds the entry.
5. **`name_source.kind: debug-symbol` is written only with `--debug-symbol-names`.** Such names are allowed
   in committed files, because they come from shipped binaries. The option exists so a run can leave them
   out. The pipeline design's statement that payload symbol names stay in the private Ghidra project is
   superseded by that ruling.
6. **`calls[].tail` and `calls[].table`** are optional additions. Translators need tail calls, and a
   `table` call has to cite the table entry that resolved it.
7. **`resolved_by: trace` is never generated.** The settled list excludes trace data, and the export has
   none. Trace-resolved calls exist only as curated records, which the merge keeps.
8. **`device_accesses[].base` and `.load_site`** are optional additions, for checking a `base+offset`
   access and for finding the load an `rmw` record folds in.
9. **`jump_tables[]` is a new section.** m2c refuses a function whose `jr` has no table in its input, and
   a call record cannot carry a switch. Ghidra has recovered the table by this point, so the export writes
   it into the committed file. A table's base and targets are read from the bytes, not from decompiled text.
10. **`modules[].segment`** is added. `start` and `end` are addresses, and an address needs a segment.
11. **`image.segments`** is optional. It catches a code file written against a promkit revision whose
    regions have since been corrected for the same image, which `image.sha256` alone cannot catch.

### Schema changes

All within version 1. The code kind has no producer yet, so its entry shapes can change.

- Replace the five placeholder item shapes in `code_file` with the shapes above. Every item gets
  `additionalProperties: false` so a typo fails, as the `prom` kind's items already do.
- Add `analysis` and `jump_tables` to the top-level `required` list and `properties`.
- `calls[].to` becomes `address` or `null`. `functions[]` loses its `address` field and gains `segment`,
  `entry` and `end`.
- `schema.py` gains the JSON `number` type, for `score`, and its `enum` check stops accepting a boolean for an
  integer (`True in [1, 2, 4, 8]` is true in Python, so `width: true` passes today).
- The `address` description gains the resolver rule: the address falls in one region of its segment, the
  offset in the segment is the region's `offset` plus the distance from the region's `address`, and an
  address in a zero-filled region is rejected for a function. An address uses the same segment form as the
  segment's `load` or region `address` (kseg0 or kseg1, not both).

Additions after this land as optional fields. A reader validates against its own revision of the schema, so
a file from a newer sgi-retools may fail an older validator. Consumers pin sgi-retools and update the pin.

### Matches between revisions

A match is written only into the newer image's file. Newer is a numeric comparison of dotted versions
(`4.18` is newer than `4.8`), made per segment on the segment's own `version`. When the two versions are
equal, as with the O2 `sloader` at `1.0` in both images, the comparison falls back to the family's
version-bearing segment (`firmware` for the O2), which the family plug-in names. When neither image has a
version (IO4 flat images, `raw`, the IP27 PROM), the run must name the other image with `--against`
, and the file the command writes holds the matches. The newer file's matches need the older
image analysed into the BSim database first. That database lives under the workspace's ignored `.cache/`.

### Checks

- `promkit validate` checks format contracts, which need promkit's knowledge: the schema, every address in a
  region of its named segment, `image.sha256` and `image.segments` matching a `prom.json`. A code file finds
  its `prom.json` through `--prom FILE`, or through the sibling `<image>.prom.json`
  named by `image.file`.
- The export's own check, `ghidra/scripts/tests/code_check.py`, checks analysis
  semantics: every call endpoint is a function entry or `null`, every function is in at most one module,
  every jump-table target is inside its function, curated entries survived. It also re-parses the image
  independently: it decodes each function's instructions with the toolkit's MIPS decoder and requires a
  `direct` call record for every `jal`, and an `absolute` access record for every kseg1 load or store whose
  base is built by a `lui` within the same block.
- The Origami cross-checks the pipeline design names stay manual first-run checks. They are not a dependency
  of sgi-retools CI.

## m2c and spimdisasm

### Versions in the image

`tools/Containerfile` pins Python packages exactly and fetches source archives by URL with a sha256 check.
The new entries follow that convention:

- **spimdisasm 1.42.4**, already installed. It is the latest release on PyPI (uploaded 2026-08-06).
- **rabbitizer 1.16.2**, pinned explicitly. It is the latest release and is what the image already gets
  transitively through spimdisasm's `rabbitizer>=1.14.0,<2.0.0`.
- **m2c from source at a commit.** Upstream m2c has no releases. The PyPI package named `m2c` (0.4.7, 2021)
  is an unrelated project from another author, so a plain `pip install m2c` installs the wrong program. The
  image fetches `https://github.com/techomancer/m2c/archive/9dc1bd4bcd96fc343274df2799d18e287d29fb71.tar.gz`
  (sha256 `5e690478f97fa53944b5acd982949ea157ed6f9da3cff7ae40c5cf2df9c6c4db`, identical on two fetches),
  unpacks it to `/opt/m2c` and puts an `m2c` wrapper on `PATH`. A build step runs `m2c --help` and fails if
  it does not run. m2c needs nothing beyond the standard library: it carries its own C parser
  (`m2c_pycparser`) and imports `graphviz` only for `--visualize`.

The fork is pinned rather than upstream because crime, kona and odsy already pin it, so their committed
outputs come from it. It carries IRIX N32 fixes, MIPS III float-to-integer conversions and a 64-bit shift fix
that the PROM path will meet. Measured against upstream `master` (`c632946b`, 2026-10-22), it is six commits
ahead and three behind. One of the six commits maps GR2 graphics apertures into m2c's evaluator, which is
device-specific.

The image's comment says pycparser is "what m2c parses C with". It is not, at this m2c revision, and
nothing in sgi-retools or the workspaces imports `pycparser`. It is dropped from the image, with its entry in
the import check that ends the `pip install` step.

### From a promkit segment to spimdisasm input

The extractor, `tools/m2c_flat.py`, runs in the toolchain image. It takes a `prom.json`, a
code file and a segment name.

The spimdisasm command line does not handle a PROM segment as it is. In a synthetic test on the current
image (spimdisasm 1.42.4, one run), `singleFileDisasm` with `--start 0x0 --end 0x80 --vram 0x81000000
--data-start 0x100 --data-end 0x10c` placed the data at `0x81000080`, the end of the text, not at
`0x81000100`. It recognised the jump table but wrote it in `.data` as plain words, and put no case labels in
the text. The O2 firmware's three regions run at addresses that are not their offsets in the segment, so the
command line would misplace them.

The extractor therefore drives spimdisasm through its Python API, as splat does:

- One `SectionText` per `code` region and one `SectionRodata` per `readonly` region, each at its region's
  `address`, with bytes taken from the region's `offset` through promkit's resolver.
- Every function in the code file is registered with `addFunction` and named by its code-file name, or
  `fn_<entry>` when it has none. Every jump table is registered with `addJumpTable`, and
  every target with `addJumpTableLabel`.
- ABI and architecture level come from the family plug-in: O32 and MIPS III for the O2, n64 for the 64-bit
  families. m2c's target follows them (`-t mips` for O32, `-t mipsn32` where the workspaces already use it).
  In the synthetic run, m2c with `-t mips` gave the dispatch function a second parameter (`arg5`) that its
  code never reads. The trial checks the target on one real O2 function before relying on it, as the review
  asked.

### One function per file, without losing context

spimdisasm's `--split-functions` writes one file per function. The extractor writes each function's file
with what m2c needs to read it alone:

- the function's own text, with `jlabel` at every jump-table target inside it
- the `.rodata` holding each of its jump tables, as `dlabel` plus `.word` entries naming those labels
- no other function's code, so a branch m2c rejects fails one function and nothing else
- names for every call target, taken from the code file, so a `jal` never takes the name of the nearest
  preceding symbol. Static functions in a flat image are found by Ghidra and listed in the code file, so they
  have entries and names here
- a generated context file declaring every callee as `extern`, with the parameter count Ghidra inferred, so
  a one-function file keeps its callee names and argument counts.

Each function runs in its own `m2c` process with a per-process limit on CPU seconds (`ulimit -t`), which
varies far less with host load than wall time but is not exact. A function that hits it is recorded as
`failed` with reason `limit`, and the code export ignores m2c status for such functions, so the committed file does not depend
on it. A failure records the exit status and m2c's first error line. The
function's output and status are written whatever happens to the others.

In the synthetic test, m2c refused the dispatch function as spimdisasm's command line wrote it ("Found jr
instruction ... but the corresponding jump table is not provided"). With `jlabel` at each target and the table
added as `.rodata`, the same function decompiled to a `switch`. This is one synthetic function, and it shows
the input shape the extractor must produce. It says nothing yet about real PROM code.

### Where output goes

Everything m2c and spimdisasm write goes under the workspace's `.cache/m2c/<image sha256 prefix>/`,
which every RE workspace's `.gitignore` already excludes: assembly, C, context files and
logs. Nothing is committed or published, and the extractor refuses an `--out` inside the git work tree that
is not ignored.

The only thing that leaves the cache is the status file, `<image>.m2c-status.json`. Per
function it holds entry, status (`complete`, `partial` when m2c's output contains `M2C_ERROR` or "Read from
unset register", `failed`), m2c commit and spimdisasm version. It carries no C. The code export reads it with
`--m2c-status FILE` on its next run. The export is then still the only producer of the code
file, and the run-twice check compares runs with the same inputs. m2c depends on the code file for function
starts, and the code file depends on m2c only through a status file. Boundaries do not move between the two
runs, so the cycle settles after one round.

### The identifier denylist

The patterns go in one file, `tools/decompiler-identifiers.txt`, one regular expression
per line with a label. `leakcheck.py` reads it when given `--decompiler-names`. A
publishing repository such as shoji, or a chips page set, reads the same file through its `retools/`
submodule rather than keeping a copy. The check is off by default, because crime, kona, odsy and gr4 commit
m2c trees on purpose and must keep passing their checks.

m2c patterns. Counts are from the 148 committed m2c files in crime, kona and odsy at the heads above
(fork `9dc1bd4b`, 597,315 lines):

| Pattern | Occurrences |
|---|---|
| `\btemp_[a-z][a-z0-9]{0,3}(_\d+)?\b` | 273,617 (`temp_` prefix) |
| `\bvar_(v\|a\|t\|s\|f)[0-9a-z]*(_\d+)?\b` | 140,038 (`var_` prefix, all forms) |
| `\bunk_?[0-9A-F]+\b` | 125,821 |
| `\bsp[0-9A-F]*[0-9][0-9A-F]*\b` | 89,534 |
| `\bM2C_[A-Z0-9_]+\b` | 15,250 (`M2C_ERROR` 11,003, `M2C_FIELD` 2,644, `M2C_TRAP_IF` 870, `M2C_UNK` 730) |
| `\bunksp[0-9A-F]+\b` | 8,052 |
| `Read from unset register` | 5,585 |
| `\bsaved_reg_\w+` | 5,462 |
| `\bphi_\w+` | 104 |
| `Decompilation failure in function` | seen in the synthetic run |

The `var_` row counts every name with that prefix. The denylist keeps only register-shaped names, so a Rust
variable such as `var_count` passes. `arg0` to `arg7` appear 87,232 times but are also ordinary names, so
they are left out.

spimdisasm symbol forms, seen in the synthetic run: `\b(func|D|jtbl|T)_[0-9A-F]{8}\b`,
`\.L[0-9A-F]{8}\b`, and the directives `\b(glabel|jlabel|dlabel|alabel|endlabel|enddlabel|nonmatching)\b`.

Ghidra default names, from Ghidra's naming conventions. None were checked against a committed Ghidra corpus,
because none is committed: `\b(FUN|DAT|LAB|PTR|SUB|switchD|caseD)_[0-9a-f]{4,16}\b`,
`\b[a-z]{1,3}Var\d+\b`, `\bparam_\d+\b`, `\blocal_[0-9a-f]+\b`, `\bauStack_[0-9a-f]+\b`,
`\bextraout_\w+`, `\bunaff_\w+`, `\bin_(v[01]|a[0-7]|t[0-9]|s[0-8]|gp|sp|ra|r\d+)\b`,
`\b(CONCAT|ZEXT|SEXT|SUB)\d{2}\b`, `\bhalt_baddata\b`, `\bs_\w+_[0-9a-f]{8}\b`.

The list is not left to grow from experience. The m2c extractor's test runs m2c over its synthetic input and
fails if any identifier in the output is neither from the input's symbols nor matched by a pattern. The Ghidra
fixture does the same over `ReDecompileExport`'s output. The list is confirmed before any translator sees m2c
output, and a new m2c or Ghidra pin that invents a new name fails the test.

## Tests

### Fixtures built in code

No fixture contains SGI bytes. Each generator builds its image from hand-encoded instruction words, as
`ghidra/processors/ia64/tests/synthetic.py` does for IA-64, and computes the expected records from what it
built.

MIPS, big-endian, `ghidra/scripts/tests/mips_synthetic.py`. Two segments, the second with
a region at an address that is not its offset, plus a `prom.json` describing them, a three-entry handler
table in read-only data, and a small defs JSON and device map. The code covers:

- calls: `jal`, `lui`/`addiu` into `t9` then `jalr t9`, `jalr` through the handler table, `jalr` through
  an argument (unresolved), a tail `j` to another function, and a call from one segment into the other
- a switch through a jump table with a bound check
- accesses: kseg1 `lw` and `sw` built by `lui`, an `sb` and an `sd`, a base loaded from a read-only pointer
  table plus a displacement, `lw`/`ori`/`sw` in one block (one `rmw`), the same split by a branch (a load and
  a store), and a partial-width read of a 64-bit register (`register: null`)
- a function with no return that falls into the next, so Ghidra merges them and a hand boundary splits them
- a long straight-line function above a test budget of a few hundred instructions, which must fail with
  `budget` on every run
- a previous code file with a hand boundary, a hand name, a module, a `trace` call and a `hand` match, all of
  which must survive.

IA-64, an extension of the existing `synthetic.py`: a `br.call` with an immediate target, a call through
`b6` loaded from a `movl` constant, and `ld8`/`st8` to a region-6 address and a bit-63 uncached address. It
exercises `ReCallWalk`, `ReAccessWalk` and `RePhysical` on the second processor that chips and sysco use.
SN2 PROMs are not in the `sgi-prom` schema, so this fixture checks the shared scripts' outputs, not a code
file.

Each fixture runs the scripts with the current arguments and with the new ones. The current-argument output
of `DumpCallEdges` and `FindWindowStores` is compared with a golden captured from the scripts at `022bbbc`
on the same fixture. That is the additive-output test.

### Run twice

The check runs the whole export twice on each fixture, each time in a fresh Ghidra project. It compares the
code file, both TSV outputs and `decompile.json` byte for byte, with `decompile_ms` and `timeout_retried_s`
removed. Any other difference fails the check. A failure is investigated as a bug in analysis or in the
scripts, and the comparison is never widened to make it pass. When the workspace holds the real O2 images,
the same check runs on them, as `tools/prom/tests/test_real_images.py` does, and skips with the sha256 when
they are absent.

### m2c path

`tools/test_m2c_flat.py` builds the synthetic MIPS image, writes a `prom.json` and a code
file by hand (it does not need Ghidra), runs the extractor and m2c in the toolchain image, and checks:
one file per function, the switch decompiled, one deliberately bad function failing alone, callee names
present in a one-function file, the denylist completeness rule, and that nothing was written outside the
output directory.

## CI

- `ghidra-check.yml` gains a job, `re-scripts`, that builds the Ghidra image and runs both
  fixtures, the additive-output test and the run-twice check. Its trigger paths gain `tools/prom/**`,
  `tools/ghidra-export.py`, `tools/re-run` and `tools/leakcheck.py`, so a schema or resolver change runs it.
- `re-check.yml` runs in a plain Debian container without the toolchain image, so it cannot run m2c. It
  gains the schema and resolver unit tests, which need only Python. A new job, `toolchain`,
  builds `tools/Containerfile` and runs `test_m2c_flat.py`. It triggers on `tools/Containerfile`,
  `tools/m2c_flat.py`, `tools/prom/**` and `tools/decompiler-identifiers.txt`.

## Implementation

### Two pull requests, one commit per logical change

The work lands as two sgi-retools pull requests, each opened with the `hold` label. The first carries commits
1 to 4 and 6 to 9. The second carries commit 5, which needs `SgiPromImport.java` and promkit's address resolver
and so waits for them on `main`. The first pull request's `re-scripts` job covers the fixtures that exist; the
second adds the code-file checks to it. Each commit builds and passes
its own tests, and each carries the tests and README changes for what it adds (`ghidra/scripts/README.md`,
`tools/README-analysis.md`). The last commit adds the CI wiring, because a CI job needs every fixture to
exist first.

1. **Shared walks.** `ReCallWalk`, `ReAccessWalk` and `RePhysical`, with the MIPS fixture generator
   (`mips_synthetic.py`), the IA-64 additions to `synthetic.py`, and a test post-script that checks each
   walk's records against what the generator built. This commit also shows that a script can call a helper
   class in its directory under headless Ghidra. If it cannot, the plan falls back as
   [Shared helper classes](#shared-helper-classes) describes, before any later commit is written.
2. **`DumpCallEdges` and `FindWindowStores`.** The `sites` mode and the trailing columns, built on the walks.
   A committed golden of both scripts' current-argument output on the fixtures, taken at `022bbbc`, checks
   the additive rule.
3. **The budget.** `ReDecompBudget`, used by `ReDecompileExport`, `FindWindowStores`, `DecompileFunctions` and
   `IA64Signatures`. The status and budget fields, the three `ghidra-export.py` options, planner tests in
   `test_ghidra_export.py`, and the fixture's over-budget function.
4. **The hand-edit pre-script.** `ReHandFunctions.java` and `--hand-functions`, tested on the fixture's
   merged pair.
5. **`SgiPromCodeExport.java`, the Python finish step and the schema.** The code-kind entry shapes,
   `schema.py`'s `number` type and boolean fix, the merge of curated parts, the register join through
   `devices`, `promkit validate --prom`, and `code_check.py`. It needs `SgiPromImport.java`, `--sgi-prom` and
   promkit's address resolver, which the [promkit design](prom-toolkit.md) owns. This is the second pull
   request. It waits for them on `main` and rebases onto them.
6. **Drop pycparser** from `tools/Containerfile` and its import check.
7. **m2c and spimdisasm.** The m2c archive, the explicit rabbitizer pin and the `m2c` wrapper in
   `tools/Containerfile`, `tools/m2c_flat.py`, the status file, the export's `--m2c-status`, and
   `tools/test_m2c_flat.py`.
8. **The denylist.** `tools/decompiler-identifiers.txt`, `leakcheck.py --decompiler-names` with its tests, and
   the completeness rule in the m2c test and the Ghidra fixture.
9. **CI.** The `re-scripts` job in `ghidra-check.yml`, with the run-twice comparison and the wider trigger
   paths, and the `toolchain` job in `re-check.yml`.

An independent reviewer builds both images, runs every fixture and the run-twice check, and reads the diff
against this design. The hold is released after review clearance and after the migration comparisons below
pass on the pull request's head.

### Migration, per workspace

The goal is to show that every workspace's existing output only gains fields. Each workspace's inputs live
outside its repository, so these runs happen on a host that holds them. For each workspace:

1. Run its documented invocations at its current pin and keep the outputs in private storage.
2. Run them again at the pull request's head, with the same arguments.
3. Compare with `tools/compare_exports.py`. For JSON, every old field is present with an equal value. For
   TSV, every old row is present with identical leading columns. The comparison allows exactly these
   differences and counts each:
   - new fields and trailing columns
   - timing fields
   - functions whose old result timed out, at either attempt, which may now decompile
   - on IA-64 images, decompiled text of functions whose callee signatures changed because
     `IA64Signatures` no longer lost a callee to a timeout.

   Any other difference blocks the pull request.
4. Record the counts in the pull request.
5. After it lands, move the workspace's `retools` pin in its own change, with any README that describes the
   scripts' columns.

The invocations, by workspace:

| Workspace | Pin today | Runs |
|---|---|---|
| chips | `a851fc4` | the SN2 PROM export (`--sn2-prom`, one component, then `--decompile-all`), and one HAL build through `tools/visws-hal/build.sh`, whose `scan.py` and `stats.py` must still read `decompile.json` |
| crime | `b6db4a8` | `--ghidra-export --decompile-all` on one graphics library, with `DumpCallEdges` and `FindWindowStores` in access mode as post-scripts |
| kona | `b6db4a8` | the same, on its graphics library |
| odsy | `b6db4a8` | the same, on its graphics library |
| gr4 | `b6db4a8` | the same, on its graphics library. `AGENTS.md` names the scripts and is checked for column descriptions |
| sysco | `b6db4a8` | the L1 controller flat-image export its reading records |
| stonewire | `b6db4a8` | the one export its reading records |
| cobalt | `b6db4a8` | none. It calls no script, so only the pin moves |

The workspaces' m2c runners stay as they are. Their `decompile_*.sh` keep calling their submodule m2c. The
image's m2c is the same commit as crime's, kona's and odsy's, so switching is a path change they may make
later. gr4 pins an older commit (`b3e0876a`) and would regenerate its trees before switching. That is gr4's
call.

## Names

| What | Name |
|---|---|
| Budget helper class | `ReDecompBudget` |
| Call walk class | `ReCallWalk` |
| Access walk class | `ReAccessWalk` |
| Physical-address class | `RePhysical` |
| Block-local evaluator the walks share | `ReBlockEval` |
| Hand-function pre-script | `ReHandFunctions.java` |
| Export option for it | `--hand-functions FILE` |
| Budget options | `--decompile-max-instructions`, `--decompile-max-payload`, `--decompile-max-jumptable` |
| `DumpCallEdges` mode argument | `sites` |
| New `FindWindowStores` columns | `physical`, `op`, `addressing`, `load_site` |
| New `decompile.json` fields | `decompile_status`, `failure`, `budget` |
| Code export options | `--code FILE`, `--m2c-status FILE`, `--against IMAGE`, `--debug-symbol-names` |
| `promkit validate` option | `--prom FILE` |
| New code-file fields | `analysis`, `jump_tables`, `ranges`, `tail`, `table`, `base`, `load_site`, `image.segments`, `modules[].segment` |
| Family device map, as the plug-in reads it | `devices` |
| Neutral function name form | `fn_<entry>` |
| m2c extractor | `tools/m2c_flat.py` |
| m2c status file | `<image>.m2c-status.json` |
| m2c output directory | `.cache/m2c/` |
| Denylist file and flag | `tools/decompiler-identifiers.txt`, `--decompiler-names` |
| Code check | `ghidra/scripts/tests/code_check.py` |
| MIPS fixture | `ghidra/scripts/tests/mips_synthetic.py` |
| m2c test | `tools/test_m2c_flat.py` |
| Migration comparer | `tools/compare_exports.py` |
| CI jobs | `re-scripts` (ghidra-check), `toolchain` (re-check) |

## Out of scope

- A code kind for SN2 PROMs. It is later work, through the FIT import.
- `SgiPromImport.java`, the facts finders and `--sgi-prom` itself, which the promkit design owns. This design
  depends on them and on promkit's address resolver.
- The workspaces' committed m2c trees and their runners.
- Running a PROM, and trace data of any kind.
