# Decode headers: publish-safe check and Rust generator

A decode header (`*_DECODE.h`) is a small C header that states a hardware
contract in a form a public project can consume: register offsets, bit ranges,
enum values and worked examples, with no vendor source, symbol or address. This
directory holds the two tools every workspace shares for them:

| Tool | Does |
|---|---|
| `check-publish-safe.py --config defs.toml` | refuses leaks, checks the header against itself, checks it against the workspace's prose notes |
| `gen_decode_rust.py --config defs.toml` | writes one plain Rust module per header; `--check` fails when the checked-in output is stale |
| `test_defs.py` | tests for both, over `testdata/mini/` |
| `ci-check` | the one command a workspace's CI runs: check, staleness, C and Rust compile |
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

## Header grammar

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

## What the check does

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

## defs.toml

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

### Plugins

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

## What the generator emits

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

## Adopting it in a workspace

1. Write the decode headers (`*_DECODE.h`) at the workspace root following the
   grammar, with a derivation paragraph in each.
2. Add `defs.toml` with the `[[headers]]`, banned extras for the workspace's own
   identifiers, `notes_corpus` where TESTVECs must trace to notes, and the
   `[[claims]]` that tie header bits to the prose.
3. Run `retools/tools/defs/check-publish-safe.py --config defs.toml`, then the
   generator, commit the `.rs` output, and run the check again.
4. Wire the check into the workspace's pre-push or CI step beside its existing
   leak check (`retools/tools/defs/test_defs.py` covers the framework).

## Running it in CI

`ci-check` runs from the workspace root with this repository checked out as
`retools/`. With no `defs.toml` it prints `no decode headers` and exits 0.
Otherwise it runs, in order:

1. `check-publish-safe.py --config defs.toml --rust`
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
