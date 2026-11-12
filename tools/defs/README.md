# Hardware definitions: sources, checks and generated outputs

A repo describes its hardware once, in TOML, and everything else is generated from
that: C headers, a Rust crate, Python decode helpers, flat JSON, an export in the
Intel/Mesa genxml dialect and a reference page per unit. The tools here load the
sources, check them, write the outputs and prove the outputs build.

| Tool | Does |
|---|---|
| `defs-check [--build]` | loads `defs/`, runs every check, confirms `gen/` is fresh; `--build` also compiles and runs the outputs |
| `defs-gen [--check]` | writes `gen/` and the forwarding headers; `--check` writes nothing and fails on a stale tree |
| `defs-import` | converts a repo's annotated headers (`*_DECODE.h`, census headers) to `defs/` sources |
| `defs-compare` | compares an old header with its replacement macro by macro with the C compiler |
| `ci-check` | the one command CI runs: `defs-check --build` when `defs/` exists, the older decode-header path otherwise |
| `forgejo-workflow.yml` | template for `.forgejo/workflows/re-check.yml` |
| `test_defslib_*.py`, `test_defs.py` | tests (`python3 -m unittest discover -s retools/tools/defs -p 'test_*.py'`) |

Needs Python 3.11 or newer (`tomllib`) and nothing else for loading, checking and
generating. Building the outputs needs a C compiler; the Rust crate builds with
`rustc` alone, with or without cargo. Run from the repo root:

```sh
retools/tools/defs/defs-check [--root DIR] [--unit U ...] [--no-fresh] [--build] [--verbose]
retools/tools/defs/defs-gen   [--root DIR] [--check]
```

Exit status: 0 clean, 1 a check failed (each offending item printed), 2 a setup
problem (a source file does not load, a prose document or plugin is missing).

## Layout of a repo

```
defs/
  <unit>.toml          one hardware block, word family or table of constants
  <unit>.<rev>.toml    optional revision overlay on <unit>
  <unit>_helpers.h     optional hand-written C helpers the generated header includes
  check.toml           the repo's check settings
  legacy-dropped.txt   during a migration: old macros dropped on purpose (NAME, tab, reason)
gen/                   generated and committed; CI fails when it is stale
  c/<unit>.h           gen/rust/ (Cargo.toml, src/)      py/<unit>.py
  json/<unit>.json     genxml/<unit>.xml                 docs/<unit>.md
<old header path>      a forwarding header, for each unit that names one
```

Generated files carry a banner naming their source and are never edited. Output is
deterministic, so staleness is a byte comparison.

## A unit file

```toml
unit = "uart"                       # matches the file name
prefix = "UART"                     # macro prefix
# block = "UART"                    # register block name when it differs from the prefix
title = "made-up UART"
doc = "One or two sentences."
from = "vendor register guide"      # default source for every item in the file
public_from = ["vendor register guide"]   # sources that may appear in public output

[spaces.hq]                         # an address space; unit = "byte" (default) or "reg"
unit = "reg"                        # offsets are register indexes, one per 32-bit register

[enums.parity]                      # an enum several fields can share
values = { none = { value = 0, grade = "established" }, odd = { value = 1, grade = "inferred" } }

[registers.ctl]
offset = 0x10
access = "rw"                       # r, w or rw
width = 32                          # 8, 16, 32 or 64
reset = 0x0                         # or "unknown" (default)
count = 1                           # array of registers; stride defaults to the register size
space = "hq"                        # default: the unit's own default space
grade = "established"
from = "vendor register guide p.12" # only when it differs from the file's
doc = "Prose for the reference page and the C comment."

[registers.ctl.fields]
enable  = { bits = [0, 0],   grade = "established" }
parity  = { bits = [3, 1],   grade = "inferred", enum = "parity" }     # or enums = { ... } inline
divisor = { bits = [31, 16], grade = "established" }

[[registers.ctl.tests]]             # a vector: a value recorded from a source
value = 0x00040003
expect = { enable = 1, parity = 1, divisor = 4 }     # a value may be "@register" for that register's offset
# kind = "example" shows a layout only; it is decoded for consistency and never asserted elsewhere

[words.FRAME]                       # a non-register word: a command, descriptor or on-disk structure
width = 32
grade = "established"
[words.FRAME.fields]
payload = { bits = [8, 1], grade = "established" }

[constants]                         # opcodes, sizes, table entries
FIFO_DEPTH = { value = 16, grade = "established" }
# macro = "OTHER_NAME" names the C macro in full when the prefix rule does not fit
```

Every register, word, field, enum value and constant needs a grade: `established`,
`inferred` or `unknown`. A grade says how the item was derived from its source, not
that it was measured on silicon. `from` is free text naming the source; it defaults
from the file to the register or word, and an item sets its own only when it
differs. The loader is strict: an unknown key, a wrong type, a missing grade or a
misspelt grade is an error with the path of the key, and a duplicate key is a parse
error.

### Revision overlays

`defs/<unit>.<rev>.toml` builds a second unit from the first without copying it.
The result is named `<unit>_<rev>` with prefix `<PREFIX>_<REV>` unless `override`
says otherwise, and it does not inherit the base's old header path or old names.

```toml
[override]                          # top-level keys: unit, prefix, block, title, doc, from, public_from, c
title = "UART, revision 2"
[patch."registers.ctl.fields.divisor"]   # change properties of an item
grade = "inferred"
[add.registers.irq_mask]            # add items (to change an existing one, patch it)
offset = 0x18
access = "rw"
width = 32
grade = "inferred"
# remove = ["registers.status"]     # delete items
# import = "other_unit"             # overlay a unit other than <unit> (a base from another file)
```

A base file stays untouched, so a layer of corrections (for example, what a driver
shows about a register a vendor guide documents) lives in its own file.

## defs/check.toml

What `defs.toml` held, minus the header list. Everything is optional but `[project]`.

```toml
[project]
name = "odsy"
plugin = "scripts/odsy_checks.py"   # repo-specific checks, see Plugins

[gen]
profile = "public"                  # or "internal": see Profiles
forwarding = "on"                   # "off" stops writing forwarding headers
rust_crate = "hwdefs"               # crate name; never derived from the project name

[checks]
address_bits = 14                   # a register may not lie beyond this address space
max_reg_offset = 0xffff

[banned]                            # leak rules; see What the checks do
allow_includes = ["stdint.h"]
[[banned.extra]]
label = "driver routine prefix"
regex = '\b(?:gfP_|ody_)\w*'

[allowlists]                        # NAME<TAB>REASON per line
# source_names = "scripts/source-names-allow.txt"
# copy = "scripts/copy-check-allow.txt"
# leak = "scripts/leak-allow.txt"

# [docs_scan]
# paths = ["docs/*.md"]

[units.display]                     # per-unit settings
group = "display"                   # units sharing a group share a claims namespace (default: the unit name)
notes_corpus = ["docs/display.md"]  # every vector value must appear as a hex literal here
# no_addresses = true               # a descriptor that must carry no address value
# size_limit_macro = "DMA_ENTRY_MAX_BYTES"
# address_field_prefix = "addr"
# prose_offsets = false             # skip the "no register offset spelled out in prose" rule
# plugin_form = "legacy"            # give plugins vectors as the old {(value, word): {...}} dictionary

[[claims]]                          # a regular expression over a prose document, bound to the model
group = "display"
label = "colour map channels"
doc = "docs/display.md"
regex = 'R in bits (\d+):(\d+), G in (\d+):(\d+)'
binds = [["F", "DISPLAY.cmap.r", 1, 2], ["F", "DISPLAY.cmap.g", 3, 4]]
```

Claim binds are the ones in the older form below, over the same keys: a register is
`BLOCK.name`, a register field `BLOCK.name.field`, a plain word's field `WORD.field`,
an enum value `(field key, label)`, and a macro is a generated C macro name or an
old name from `[c.aliases]`.

## What the checks do

`defs-check` runs, in order, and reports every failure it finds:

1. Layout of each unit: field overlap and width, register overlap per address space
   (an array occupies `count` elements at its stride; a `reg` space counts in
   registers; a named space is shared by every unit that names it), enum values that
   fit their field, vectors that decode as stated, a grade on every item, a `from`
   that reaches every item, the `[checks]` address bounds.
2. Leaks. The built-in rules of the older form below (vendor paths, file and routine
   names, board tokens, binary offsets, tool names, ...) plus `[[banned.extra]]` are
   run over the public rendering of every generated file and over every
   `defs/<unit>_helpers.h`. Generated Rust must not name the project at all.
3. Prose: `[[claims]]`, vectors against `notes_corpus`, `no_addresses`, and (for a
   unit with registers) no register offset spelled out in `doc` text.
4. Plugins.
5. Freshness: `gen/` and the forwarding headers are what `defs-gen` would write, with
   no file missing and none left over.

`--build` then builds what is committed: every C header and forwarding header
compiles with `-Wall -Wextra -Werror` and a generated program decodes each vector
with the header's own macros; each Python module runs its self-test; every genxml
export goes through the vendored upstream pack generator, and each vector unpacks and
repacks through the C it writes; the Rust crate builds with warnings denied and its
tests pass (skipped with a note when there is no `rustc`).

### Plugins

A repo plugin still works. It may define `CLAIMS`, `check_header(ctx, hdr)`,
`check_group(ctx, group, hdrs)` and `check_final(ctx)` as in the older form. `ctx` and
`hdr` have the old shapes, built from the model: `hdr.file` is the old header path
(or `gen/c/<unit>.h`), `hdr.text` is the generated C, then the unit's helpers, then the unit
regenerated in the old comment grammar (`/* REG: ... */`, `FIELD`, `ENUM`, `WORD`, and
` * TESTVEC:` lines), so a plugin that reads those lines keeps working,
`hdr.regs`, `hdr.fields`, `hdr.widths`, `hdr.enums`, `hdr.defs` (every generated
macro and every alias that evaluates) and `hdr.vecs` are the dictionaries the old
checker built, and `hdr.unit` is the loaded unit. A plugin that reads other annotations or the
layout of the old comments (a command table, say) needs them to survive the migration: the
importer keeps comment lines like ` * CALC: ...` verbatim in the helpers file, but it cannot
carry free-form comments, so such a plugin is ported to read the model (`hdr.regs`,
`hdr.fields`, `hdr.defs`, `hdr.vecs`) instead of the header text.

## Profiles

`[gen] profile` chooses what the committed outputs carry. `public` keeps a `from`
only when it starts with one of the unit's `public_from` prefixes and drops notes.
`internal` keeps every `from` and note, for a repo that is not published. The leak
check always runs on the public rendering, so switching profiles needs no new fixes.

## The generated outputs

| Output | Contents |
|---|---|
| `gen/c/<unit>.h` | `<BLOCK>_<REG>_OFFSET`, `_COUNT`, `_STRIDE`; `<BLOCK>_<REG>_<FIELD>_SHIFT`, `_MASK`, `_INPLACE`; `<PREFIX>_<WORD>_WIDTH` and word fields the same way; `<field macro>_<LABEL>` for a field's own enum values and `<PREFIX>_<ENUM>_<LABEL>` for shared ones; `<PREFIX>_<NAME>` for constants. Every macro carries its grade. `[c] offset_macro = "bare"` drops `_OFFSET`. |
| `gen/rust/` | a crate (`Cargo.toml`, `src/lib.rs`, a module per unit): typed field accessors, an enum with an `Other` variant per field that has values, constants, a test per vector |
| `gen/py/<unit>.py` | the layout as tables plus `decode`, `encode`, `describe` and `selftest`, no imports |
| `gen/json/<unit>.json` | one flat row per register, word, field, enum value and constant |
| `gen/genxml/<unit>.xml` | the genxml dialect Asahi and Panfrost use: `<struct>` per word and register, `<field start size type>`, top-level `<enum>`; grade, source, offset, access, test vectors and constants ride in extra attributes and elements |
| `gen/docs/<unit>.md` | a reference page: every register, word, field, enum value, constant and vector with its grade and source |

The genxml export is proved by `tools/defs/vendor/genxml/gen_pack.py`, an unmodified
copy of Mesa's Asahi pack generator (MIT; see `vendor/genxml/SOURCE` and `LICENSE`).
It is never edited: if the dialect needs the export to change, the export changes.
`genxml_prelude.h` stands in for Mesa's own prelude header.

### Forwarding headers and helpers

A unit that replaces an old header names it:

```toml
[c]
legacy_header = "BUZZ_DECODE.h"
legacy_guard = "BUZZ_DECODE_H"
[c.aliases]                         # old macro name = a C expression over the new names
BUZZ_HDR_W4_SIZEFLD_SHIFT = "BUZZ_HDR_W4_SIZE_FIELD_SHIFT"
```

`defs-gen` writes a header at that path that includes `gen/c/<unit>.h` and defines
the aliases, so QEMU and iris keep building unchanged for one transition period.
Remove `legacy_header` (and the file) when the consumers use the new path.

Helper macros and any C that is code rather than data (a table, a `static inline`
function) go in `defs/<unit>_helpers.h`; the generated header includes it last.
Hand-written code may use the generated names but not the old aliases, which are
defined after it.

## Migrating a repo

One repo at a time, in one change. From the repo root, with this repository checked
out as `retools/`:

```sh
retools/tools/defs/defs-import                      # writes defs/, never edits a header; prints the report
# read the report (also in defs/import-report.txt) and settle each item in defs/*.toml:
#   constants with no grade   -> give each a grade, or list it in defs/legacy-dropped.txt
#   old macros with no counterpart -> add a field or constant, alias it under [c.aliases], or drop it
#   grades defaulted          -> confirm, or correct
#   set the real source in `from` (the importer wrote a placeholder, dropped from public output)
retools/tools/defs/defs-gen                         # writes gen/ and overwrites each old header with its forwarding header
retools/tools/defs/defs-compare                     # old headers from git HEAD against the forwarding headers: must report 0 different, 0 missing
retools/tools/defs/defs-check --build               # layout, leaks, claims, plugin, freshness, builds
git rm defs.toml generated/ ...                     # the old config and Rust output, once defs/check.toml and gen/ replace them
rm defs/import-report.txt
```

Commit `defs/`, `gen/`, the forwarding headers and the removals together, add the
workflow (below), and switch QEMU and iris to `gen/c/` paths in their own changes.
`defs-compare --old-rev REV` compares against another revision; `defs-compare --old
FILE --new FILE` compares two files.

What the importer reads: REG, WORD, FIELD, ENUM and TESTVEC lines; the older
FIELD-only form with `macro_pairs` and `inplace`; census headers
(`#define PFX_NAME 0xOFF /* [E] width N byte(s), access rw; ... */`, where the label is
the grade and `through the <name> window` makes an address space); and tables of graded
`#define` constants. A header that names several register blocks without configuring one
becomes a block-less unit whose block-colliding registers get an address space each; a
constant that the register layout already generates (`<REG>_COUNT`) is dropped as
redundant, or reported when its value differs; a graded macro that does not start with the
unit's prefix keeps its full name (`macro =`). It carries function-like macros, C code
outside the `#define`s and unknown annotation comments to the helpers file. It never invents: a word's grade is
the weakest of its fields, enum values without a grade inherit their field's and say
so, and a bare numeric expression is never turned into an alias.

What `defs-compare` does not see: C code in the old header that is not a macro (a
table or inline function). The build step compiles the helpers that carry it, but
nothing compares their contents with the old text.

## Adopting it in CI

Copy `forgejo-workflow.yml` to `.forgejo/workflows/re-check.yml`. The job runs on
`ubuntu-latest` in a public Debian image, installs `python3`, `gcc` and `rustc` from
Debian (rustc 1.63 builds the crate; cargo is not needed), and initialises only the
retools submodule (`git submodule update --init --depth 1 retools`). Never use
`--recursive`: some workspaces carry vendor-source submodules that must not be
fetched. The workflow uses no secrets beyond the read-only retools token.

`ci-check` runs `defs-check --build` when a `defs/` directory exists. With only a
`defs.toml` it takes the older path below, so repos move one at a time. With neither
it prints `no decode headers`.

# Older form: decode headers and defs.toml

Repos that have not migrated keep their `*_DECODE.h` headers, `defs.toml`,
`check-publish-safe.py` and `gen_decode_rust.py`, described here. They go away when the
last repo has moved.

A decode header (`*_DECODE.h`) is a small C header that states a hardware
contract in a form a public project can consume: register offsets, bit ranges,
enum values and worked examples, with no vendor source, symbol or address. This
directory holds the two tools every workspace shares for them:

| Tool | Does |
|---|---|
| `check-publish-safe.py --config defs.toml` | refuses leaks, checks the header against itself, checks it against the workspace's prose notes |
| `gen_decode_rust.py --config defs.toml` | writes one plain Rust module per header; `--check` fails when the checked-in output is stale |
| `test_defs.py` | tests for both, over `testdata/mini/` |
| `ci-check` | the one command a workspace's CI runs: full check, staleness, C and Rust compile |
| `forgejo-workflow.yml` | template for the workspace's `.forgejo/workflows/re-check.yml` |

Needs Python 3.11 or newer (for `tomllib`) and nothing else. Run them from the
workspace:

```sh
retools/tools/defs/check-publish-safe.py --config defs.toml [--header FILE ...] [--rust] [--verbose]
retools/tools/defs/gen_decode_rust.py    --config defs.toml [--check] [--commit C] [-o OUTDIR]
python3 retools/tools/defs/test_defs.py
```

Exit status: 0 clean, 1 a check failed (each offending line printed), 2 a setup
problem (config, header or prose document missing).

### Header grammar

Annotations sit in C comments, one per line, and must not be reformatted. `<hi>:<lo>`
is an inclusive bit range, `n:n` is one bit. A grade is `established`,
`inferred` or `unknown`: it says how the layout was derived, not that silicon
was measured.

```
REG:   <BLOCK>.<name> <offset> <acc><width> [count=<n>] [space=<s>] reset=<v> <grade>
WORD:  <WORD> <32|64>                               width of a non-register word (default 32)
FIELD: <BLOCK>.<name>.<field> <hi>:<lo> <grade>     a field of a register
FIELD: <WORD>.<field> <hi>:<lo> <grade>             a field of a non-register word
ENUM:  <target> <value> <label> <grade>             target is a FIELD key
TESTVEC: <value> as <WORD or BLOCK.name> => field=val, ...
EXAMPLE (unverified): <value> as <...> => ...       layout only, never asserted
```

- `REG`: `<acc>` is `r`, `w` or `rw`; `<width>` 8, 16, 32 or 64; `reset=` is a
  number or `unknown`. The offset is 1 to 4 lowercase hex digits. An offset of
  0x100 or more (including every address of a `count=` block up to 64) may appear
  only inside its REG line; elsewhere write the register name. A TESTVEC names an
  address as `@BLOCK.name`. `count=n` marks n consecutive registers.
  `space=<s>` names the address space the offset belongs to (see below).
- Word width: a word is 32 bits wide, or 64 for a word declared with `WORD:`
  or a `rw64` register with a field above bit 31. Field ranges go up to bit 63 in a 64-bit word and the
  generated Rust uses `u64` for it. A `#define` value may carry a `u`, `ul` or `ull` suffix.
- `FIELD`: block names are upper case, register and field names lower case; a
  non-register word name is upper case (`FRAME`, `HDR_W7`). Fields of one word
  must not overlap; a field must fit the register width (32 for plain words).
- `ENUM`: the value must fit the field.
- `TESTVEC`: decoded with the header's own ranges and must come out as stated.
  Put it on a ` * ` line inside a block comment so the value list is not followed
  by `*/`. Values the notes record are TESTVECs; values invented to show a layout
  are `EXAMPLE (unverified)` lines (decoded for consistency, never compared with
  the notes, never emitted as Rust tests).
- Lines containing `<` are grammar illustrations in the header preamble and are skipped.
- Macros. Each FIELD needs `<PREFIX>_<REG>_<FIELD>_SHIFT` and `_MASK` defines
  (`PREFIX` is the `prefix` key, default the REG block; for a plain word the
  macro is `<PREFIX>_<WORD>_<FIELD>`); each ENUM needs `<field macro>_<LABEL>`
  with the same value. Plain numeric `#define`s with a trailing grade comment
  become Rust constants.

Address spaces. Register offsets collide only inside one space. A REG takes
its space from its own `space=` attribute, else from the header's `space` key,
else it is in the unnamed default space, so headers that declare none are
checked together as before. Use it where two register windows reuse offsets.

A second, older form (`form = "legacy"`) has `FIELD: WORD.name hi:lo grade` on
32-bit words and a hand-listed macro table; use it only for a header that
already has one. odsy's `BUZZ_DECODE.h` is the example.

### What the check does

1. Publish safety. Built-in rules refuse a vendor source path, an install path,
   a source or object file name, an include of any header but the repo's own and
   `stdint.h`, mixed-case calls, a vendor release cite, an `IPnn` board token,
   an RE tool name, N32 or kernel virtual addresses, a binary offset (`+0x...`,
   `at 0x...`), a record offset and a source-line cite. A repo adds its own
   rules under `[[banned.extra]]`.
2. Consistency. Field overlap and ranges, macros against FIELD lines, enum
   values against macros, TESTVEC decodes, register overlap (within one address space) across all REG
   headers, and the REG-offsets-only-in-REG-lines rule (with `[checks]`
   `address_bits`, default 14, bounding a 4-digit hex value as an address).
3. Prose. Each `[[claims]]` entry binds a regular expression over a notes file
   to header facts. If the passage no longer matches, the check fails, so drift
   in either direction is caught.
4. Optional per header: `notes_corpus` (every TESTVEC value must appear as a hex
   literal in those files), `no_addresses` (see below).
5. Generated Rust (when `[rust]` is set and no `--header` is given, or with
   `--rust`): every `.rs` file is one of the configured modules, has the
   generator banner naming a real commit (no `-dirty`), names the project
   nowhere else, points at no note file or URL, carries no 5-digit hex literal
   that is neither in its header nor a contiguous mask and no 7-digit decimal,
   and is not stale against the headers.
6. Optional `[docs_scan]`: the source-path and file-name rules over prose files.

`no_addresses = true` (for descriptors that must carry no address value): a
decimal literal of 7 or more digits fails; a hex literal of 5 or more digits is
allowed only as a contiguous mask in a `*_MASK` macro or in the one
`size_limit_macro`; a macro with `ADDR` in its name must be `_SHIFT`, `_MASK` or
`_BITS`; no vector may set bits in, or name, a field whose name starts with
`address_field_prefix` (default `addr`).

### defs.toml

Paths are relative to `[project] root` (default: the directory holding the
file). A minimal, working one is `testdata/mini/defs.toml`.

```toml
[project]
name = "odsy"                       # required; banner text and a leak word in the Rust
# root = "."
# plugin = "scripts/odsy_checks.py" # repo-specific checks, see below
# regenerate = "..."                # hint printed when generated Rust is stale

[rust]
out_dir = "generated/odyssey-regs"
# [[rust.banned_extra]] label = "..." regex = "..."

[checks]
# address_bits = 14                 # REG address space; a REG may not exceed it
# max_reg_offset = 0xffff

[banned]
# skip = ["source line cite"]       # drop a built-in rule by label
# allow_includes = ["stdint.h"]     # headers a decode header may include
[[banned.extra]]
label = "driver routine prefix"
regex = '\b(?:gfP_|ody_)\w*'

[allowlists]                        # optional; NAME<TAB>REASON per line, '#' comments
# source_names = "scripts/source-names-allow.txt"  # exempt these exact names from the file-name rules
# copy = "scripts/copy-check-allow.txt"            # same exemption
# leak = "scripts/leak-allow.txt"                  # exempt any match containing the term

# [docs_scan]
# paths = ["docs/*.md"]             # globs; rules = labels (default: path and file-name rules)

[[headers]]
file = "DISPLAY_DECODE.h"
block = "DISPLAY"                   # REG block; omit for a header with plain words only
# space = "cpu"                     # address space of this header's REGs; default none
# prefix = "DISPLAY"                # macro prefix for plain words; default the block
# group = "display"                 # headers sharing a group share one claims namespace
# form = "regs"                     # or "legacy"
# notes_corpus = ["docs/display.md"]
# no_addresses = true
# size_limit_macro = "DMA_ENTRY_MAX_BYTES"
# macro_pairs = [["HDR_W4.class", "BUZZ_HDR_W4_CLASS_SHIFT", "BUZZ_HDR_W4_CLASS_MASK"]]  # legacy
# inplace = [["HDR_W7.type", "BUZZ_HDR_W7_TYPE_INPLACE"]]                                 # legacy
# Rust generation (a header without `module` is checked but not generated):
module = "display"
rust_prefix = "DISPLAY_"            # stripped from #define names for the Rust constants
register_doc = "Display-space register"
description = ["Two lines of module", "documentation."]
# words = { HDR_W4 = ["ReadHeader", "Doc line."] }      # nicer type names for plain words
# [[headers.enum_families]]         # #define families standing in for ENUM lines
# prefix = "FMT"
# type = "WriteFormat"
# doc = "Write header format code (bits 4:0)."
# digit_prefix = "Format"           # added to a variant name that starts with a digit
# fields = ["HDR_W7.format"]

[[claims]]
group = "display"                   # a group name; default group of a header is its file name
label = "colour map channels"
doc = "docs/display.md"
regex = 'R in bits (\d+):(\d+), G in (\d+):(\d+)'
binds = [["F", "DISPLAY.cmap.r", 1, 2], ["F", "DISPLAY.cmap.g", 3, 4]]
```

Claim binds (the first element is the kind; the numbers are regex group
indexes; `re.S`, case-sensitive):

| Bind | Meaning |
|---|---|
| `["F", field, hi, lo]` | field range equals the prose; omit `lo` for one bit, omit both to require only that the field exists |
| `["O", reg, g]` / `["E", reg, g]` | register offset / last register equals the prose (hex or decimal) |
| `["C", reg, g, mult]` / `["CDEC", reg, g, add]` | register count times `mult` equals the prose / count equals the prose plus `add` |
| `["LO", field, g, add]` | field's low bit is the prose number plus `add` |
| `["WHEX", field, g]` | field is four bits wide per hex digit of the prose |
| `["IN", [fields], hi, lo]` / `["M", [fields], g]` | fields lie inside the prose range / single-bit fields make the prose mask |
| `["EN", field, label, g]` | enum value |
| `["DEF", macro, g]` / `["DEFN", macro, g]` / `["DEFL", macro, g]` | macro equals the prose (decimal / 32-bit hex or decimal / low 16 bits) |
| `["FW", field, hi, lo]` / `["FWD", field, g]` | field width from a range / from a number |
| `["WDEC", "", hi, lo, bits]`, `["EQ", value, g]` | prose range is `bits` wide; prose number equals a constant |

A claim whose group matches no header is a setup error (exit 2).

#### Plugins

Anything that does not fit a regular expression and a bind (odsy's texel format
table, its C-compile check of the helpers, claims that evaluate arithmetic)
goes in a Python file named by `plugin`. It may define any of:

```python
CLAIMS = [{"group": ..., "label": ..., "doc": ..., "regex": ..., "binds": [...]}]
def check_header(ctx, hdr): ...        # after the generic checks, for each selected header
def check_group(ctx, group, hdrs): ... # once per group with a selected header
def check_final(ctx): ...
```

`ctx.rep.fail(where, message)` records a failure, `ctx.read(path)` and
`ctx.read_doc(path)` read workspace files (the second exits 2 when missing),
`ctx.allregs` is every REG of every block header, `ctx.lib` is the
`publish_check` module (parsers, `check_banned`, `HEXLIT_RE`, ...). A `hdr`
has `file`, `name`, `text`, `regs`, `fields`, `defs`, `enums`, `vecs`, `cfg`.
Keep plugin code to what the declarative form cannot say.

### What the generator emits

Per header with a `module`: a typed accessor per FIELD (range and grade in the
doc comment), an enum with an `Other` variant per ENUM target, a constant per
REG line (`REG_<NAME>`, `_WIDTH`, `_COUNT`), a constant per plain numeric
`#define` (excluding `_SHIFT`/`_MASK`), `name(i)` functions for
`#define NAME(i) (0x... + (i))` opcodes, and one `#[test]` per TESTVEC. It
refuses a TESTVEC that disagrees with the header and any output that would carry
a note-file pointer or the project name. The first line is
`// generated from <project> <12-hex commit> <header> - do not edit, regenerate in <project>`;
the commit is the last one that touched the header, `-dirty` if it has
uncommitted edits (which the check refuses). `--check` compares everything but
that commit, and also fails on a missing or extra `.rs` file.

### Adopting it in a workspace

1. Write the decode headers (`*_DECODE.h`) at the workspace root following the
   grammar, with a derivation paragraph in each.
2. Add `defs.toml` with the `[[headers]]`, banned extras for the workspace's own
   identifiers, `notes_corpus` where TESTVECs must trace to notes, and the
   `[[claims]]` that tie header bits to the prose.
3. Run `retools/tools/defs/check-publish-safe.py --config defs.toml`, then the
   generator, commit the `.rs` output, and run the check again.
4. Wire the check into the workspace's pre-push or CI step beside its existing
   leak check (`retools/tools/defs/test_defs.py` covers the framework).

### Running it in CI

`ci-check` runs from the workspace root with this repository checked out as
`retools/`. With no `defs.toml` it prints `no decode headers` and exits 0.
Otherwise it runs, in order:

1. `check-publish-safe.py --config defs.toml` (every check: leaks, header self-consistency,
   prose claims, generated Rust)
2. `gen_decode_rust.py --config defs.toml --check` (never writes files)
3. `cc -fsyntax-only -Wall -Werror` over each header listed in `defs.toml`
4. `rustc --edition 2021 --crate-type lib --emit=metadata` over each generated
   module; if `rustc` is missing it says so on stderr and skips this step

Each failure prints one `FAIL <reason>` line and the exit status is 1. It needs
Python 3.11 or newer and a C compiler.

To adopt it, copy `forgejo-workflow.yml` to `.forgejo/workflows/re-check.yml`.
The job runs on `ubuntu-latest` in a public Debian image, installs `python3`,
`gcc` and `rustc` from Debian, and initialises only the retools submodule
(`git submodule update --init --depth 1 retools`). Never use `--recursive`:
some workspaces carry vendor-source submodules that must not be fetched.
The workflow uses no secrets.
