# A toolkit for SGI PROM images: identify, unpack, facts, assets and Ghidra loading

Status: design, for decision. Nothing here is built. Every new name in this page is a proposal for the
repository owner to decide; each one is marked *(proposed name)* where it first appears and collected in
[Proposed names](#proposed-names).

## What it is for

The reverse-engineering repositories read SGI boot PROMs constantly, and each reading starts the same way:
work out which image this is, cut it out of its container, find its load address, load it into Ghidra by
hand, then find the ARCS system parameter block, the firmware vector, the command table and the
environment table by searching for constants. The container formats are now written up in the chips
repository (the O2 flash segments, the Challenge and Onyx IO4 containers, the byte-order survey, the
per-board PROM pages), but each write-up ends in a "how to reproduce" paragraph rather than a tool.

A second consumer has arrived. shoji, the Windows NT for MIPS effort, is building its own O2 firmware in
Rust as a faithful clone of the SGI PROM. It must look and behave like SGI's down to the boot screen and
menus, and the owner has ruled that SGI's own logo, icons, fonts, palettes and sounds may be used for it.
shoji needs those assets and the PROM's tables (environment defaults, command list, menu layout) as data
it can build from.

The toolkit turns the written formats into one tool with five steps:

1. **Identify**: hash an image, look it up in the PROM catalogue, and report board, version, revision,
   byte order and container.
2. **Unpack**: cut out every segment, verify each against its own checksums, and write a manifest of
   segments with load addresses.
3. **Facts**: find the PROM's tables and export them as structured data for the chips pages and shoji.
4. **Assets**: write the PROM's bitmaps, fonts, palettes, layout constants and sounds as PNG, a font
   description and WAV.
5. **Ghidra**: load an unpacked image with its memory map, and label the tables the facts step found.

## Summary of the recommendations

- Build it in **Python, inside sgi-retools**, as one package of per-format and per-family plug-ins, run
  through the existing container runner. Extend the existing Ghidra export rather than adding a second
  launcher. Absorb sgi-retools' own promgen64 unpacker into it. Do not grow it from iris's Rust PROM tool;
  the reasons are in [Language and home](#language-and-home).
- Keep **one catalogue of image identity: the provenance catalogue in the Origami repository**, read by
  every other repository through the JSON index that its publishing tool already writes beside the
  images. The four other lists become selections or views keyed by sha256. Details in
  [One catalogue](#one-catalogue).
- The toolkit's code and synthetic fixtures live in sgi-retools; the chips repository holds the format
  write-ups and the committed facts exports; shoji takes sgi-retools as a submodule and consumes files,
  not code.
- Asset formats inside the O2 PROM are not yet known. The asset step is designed as an output contract
  plus a research step; no extractor is written until a chips page establishes each format.

## What already exists

This audit read the current trunks of sgi-retools, chips, Origami, iris, the QEMU `sgi-origami` branch,
toolchest, sgi-emulator and shoji, and searched their tools for PROM, ARCS, ECOFF, promgen and segment-header
code. The result is that container decoding has been written several times and table discovery never has.

### Container decoders

| Code | Repository, language | Does | Disposition |
|---|---|---|---|
| `tools/chips/promgen64.py` | sgi-retools, Python | Unpacks the 64-bit promgen container (magic `JFKSWCSM` at 0x40, records from 0x80, gzip payloads, byte-sum check) to one file per segment; called by the census script `disasm.sh` | Becomes the toolkit's promgen64 plug-in; the script is removed once `disasm.sh` calls the toolkit |
| `tools/firmware_layout.py` | sgi-retools, Python | Cuts a controller container into `(member, body, load)` segments for the inventory and reading tools; knows `flat`, `sysco-l1`, `sysco-l2` | Extended: gains one layout that delegates to the toolkit, so inventory rows can be keyed by PROM segment |
| `ghidra/import/sn2-prom/` | sgi-retools, Java | Lays out an SN2 (Altix, Prism) flash: FIT components, PAL and SAL entries, dispatch tables; maps the gzip ELF components | Kept as is; it is the pattern the new MIPS import follows (Python finds, a Ghidra script applies, a Python `check.py` re-parses) |
| `tools/ghidra-export.py`, `tools/re-run --ghidra-export` | sgi-retools, Python and shell | Ghidra decompile export; `--flat --load --header --processor --window` for a raw image | Extended with one option that takes a toolkit manifest |
| `tools/hostfacts.py`, `tools/facts.py` | sgi-retools, Python | Capstone decode and register tracking for one MIPS routine, flat images included | Used by the facts step to resolve table addresses from code |
| `tools/envscan.py` | sgi-retools, Python | Lists environment variables an IRIX ELF reads, from `getenv` call sites | Not extended: PROM environment tables are data records, not calls; reusing its ELF-only walk would not fit |
| `tools/defs/` | sgi-retools, Python | One TOML per unit becomes C, Rust, Python, JSON; `formats/<name>/format.toml` holds software structures | Not used for parsing (it would make sgi-retools depend on chips); an optional later use is in [Open questions](#open-questions) |
| `tools/extract-irix` (`promgen_info`, `promgen_payload`, `describe`) | Origami, Python | Decodes the promgen64 header from IRIX media; recognises a four-byte `JKSW` magic, calls it "promgen32" and decodes no segments; identifies ECOFF by magic | Left alone. `JKSW` is the same magic as the IO4 segmented container the chips page decodes in full |
| `tools/promgen-unpack` | Origami, Python | Finds a promgen64 header part-way through a payload (the IP35 PROM's nested BaseIO segment) and checks it | Its search is folded into the promgen64 plug-in as nested-segment discovery |
| `tools/prom-banner` | Origami, Python | Finds version banners in plain, gzip, `compress` and 16-bit-pair-swapped bytes | Its banner rules are ported into identify |
| `tools/origami_lib/objects.py` | Origami, Python | Reads ELF and big-endian MIPS ECOFF objects with their symbol tables and ISA | Its ECOFF reader is the model for the toolkit's ECOFF plug-in |
| `src/dev/prom_image.rs`, `iris-prom` | iris, Rust | Emulator-side decoder (installer header, promgen64 container, nested records, banners); `iris-prom download`, `pack`, `show`, `extract --segment` | Left alone; an emulator needs its own runtime decoder. Hand-run agreement checks are described under [Tests](#tests) |
| `hw/mips/sgi/prom-image.c` | QEMU, C | The decoder iris's was ported from; its manual page is `docs/system/mips/sgi/prom-image.rst` | Left alone, same reason |
| `src/coffdump.rs` | iris, Rust | ECOFF header and symbolic-header dumper | Left alone |
| `ESTFBINR` readers (`tools/sysco/`, `objects.py est_layout`) | sgi-retools, Origami | System-controller firmware containers | Out of scope; already served by `firmware_layout.py` |

So the 64-bit promgen container has four implementations (QEMU in C, iris in Rust, sgi-retools and
Origami in Python), banner scanning two, and ECOFF reading three. The O2 flash segments (`SHDR`), the IO4
flat (`JFK4`) and segmented (`JKSW`, `SEG2`, `_LZW`) containers, the IP32 firmware load map, and every
table-discovery method in the chips pages exist only as prose.

### ARCS clients and other related code

- iris's `cpu-tests/harness/arcs.c` and toolchest's ARCS network probe are original standalone programs
  that call a running PROM through the parameter block at physical `0x1000`. They confirm, on a live
  machine, the block layout the facts step reports. Neither is reusable code for reading an image.
- iris's `tools/gen-screen-font.py` reads SGI's Screen bitmap font from the X11 PCF files SGI shipped. If a
  PROM font turns out to match a shipped X11 font, that is a second source to compare against; it does not
  replace reading the PROM.
- Origami's `docs/analysis/<image>/` holds Ghidra, angr, capstone, radare2 and rizin passes over the IP27,
  IP35 and IO6 payloads and sashARCS, produced by its own disassembly tools. They are prior navigation
  output, not inputs this toolkit depends on.

### Five lists of images

| List | Repository | Rows | Holds | Role |
|---|---|---|---|---|
| `assets/prom-catalog.toml` | Origami | 170 | board, version, rev, part, banner, shipped or dumped, origin, size, sha256 of the published file, publish flag | Provenance and publication; checked nightly against the published checksums; its publishing tool writes a JSON copy beside the images |
| `references/prom-images.md` | chips | 36 | board, machine, part, version, size, sha256, whether a boot capture is held | Holdings view for readers |
| `data/proms/proms.toml` | iris | 8 | board, version, URL, size, sha256, unwrap flag | Which images iris embeds |
| `resources/proms.toml` | sgi-emulator | 3 | machine profiles, version, path, size, sha256 | Which image each profile boots |
| `hw/mips/sgi/models/references.yaml` | QEMU | (citation registry) | title, version, banner, distribution path, sha256 of the payload | Citation keys for manual pages |

Compared by sha256 on the current trunks: all 8 of iris's rows are catalogue rows. Four of chips' 36 are
not in the catalogue: the IP20 4.0.5G image, the IP30 Rev 4.9 dump, the 16-bit-swapped IP24 dump and the
raw O2 4.18 flash dump. sgi-emulator's IP27 and IP35 rows, and QEMU's registry entries for the same
images, hash the unpacked payload rather than the published file, so they match no catalogue row
directly (QEMU's IP35 entry also records the container's hash, which is a catalogue row). The IP30 row in
both is the published file and matches.

## Language and home

Three options were weighed.

**A. Grow iris's `iris-prom`.** It already reads the promgen64 container and the O2 installer header, and
shoji is Rust. Against it: `iris-prom` is an emulator packaging tool that links the whole `iris` crate; it is
part of a repository maintained with its upstream author, so every format and every Ghidra-facing change
would go through that project's review for a purpose it does not have; and the RE pipeline that must
consume the manifest (the inventory, the reading tools, `facts.py`, the Ghidra export) is Python. shoji
would take the emulator as a dependency to read a bitmap.

**B. A shared Rust crate**, split out of iris's `prom_image`, used by iris, shoji and a new tool. Against
it: a cross-repository code dependency between three projects that are each meant to stand alone, a
second build system inside sgi-retools for one tool, and Python callers still need a process boundary.
It would also not remove QEMU's C decoder, so the count of implementations does not fall.

**C. Python in sgi-retools** (recommended). It matches the repository: every tool is Python run through
`tools/re-run`, tests are standard-library `unittest`, and CI runs them with `python3` and the packages
its job already installs.
It plugs into `firmware_layout.py`, `hostfacts.py`, `facts.py` and `ghidra-export.py` directly. It replaces
sgi-retools' own promgen64 script rather than adding a fifth implementation, and the porting sources for
banners, nested segments and ECOFF are already Python.

The shoji rule that its code is written in Rust is about what shoji ships: the firmware, HALs and drivers.
shoji's own repository already builds with Python tools (`elf2coff.py` and `peinfo.py` in its toolchain).
The toolkit is a build-time input, consumed through files with a fixed schema, so shoji's Rust build reads
JSON, PNG and WAV and never runs toolkit code inside the firmware. If the owner reads the rule as covering
build tooling too, option B is the one to take, and [Open questions](#open-questions) asks.

The emulator decoders stay where they are. They decode at run time inside an emulator and must not
depend on an RE toolbox.

## One catalogue

The Origami catalogue is the single source of truth for image identity and provenance. It is the most
complete list, it already has a checker and a publisher, its rows are immutable and append-only, and its
publisher writes a JSON copy of it (the PROM index) beside the published images, which any repository can
read without depending on Origami's source.

- **Identity lives only in the catalogue.** Board, version, revision, part, banner, origin, size and file
  sha256 are written there and nowhere else.
- **Other lists hold selections, keyed by sha256.** iris (what it embeds and whether to unwrap) and
  sgi-emulator (which profile boots which image) keep their own small files, because they say what a
  product uses, not what an image is. Each row's hash must name a catalogue row or a payload the toolkit
  derives from one.
- **chips' `prom-images.md` becomes a holdings view**: the sha256 and the columns only chips knows (boot
  capture held, which page read the image). Identity columns are dropped or generated from the PROM index.
  The four uncatalogued images go to the catalogue as new rows; a dump whose public origin is unknown takes
  `publish = false`, as the catalogue's rules already require. Adding rows is a catalogue change with
  publication consequences, so it is listed as an open question.
- **QEMU's registry stays a citation registry.** Its entries cite the payload a manual page describes. The
  toolkit's manifests record both the file hash and each derived payload hash, so a payload hash resolves
  to its catalogue row by looking it up in the committed golden manifests.
- **The toolkit reads the PROM index**, cached under `.cache/`, or a local copy given with `--catalog`. It
  never reads the TOML from another repository's checkout.

If the Origami repository is retired, the catalogue and its publisher move together and the PROM index
keeps its address; no consumer changes. Where the catalogue should live in that case is an open question.

## Architecture

### Pipeline

```
image bytes
  -> transforms      (byte-pair swap, if detected)
  -> container       (installer header, O2 flash, IO4 flat or segmented, promgen64, ...)
  -> payloads        (ELF, ECOFF, gzip, compress, flat)
  -> manifest        (segments, load addresses, checks, hashes)
  -> family          (memory map, facts, assets, Ghidra program grouping)
```

Each arrow is a plug-in boundary. Every step after identify reads the manifest, so facts, assets and
Ghidra loading never re-derive the layout.

### Package layout

```
tools/prom/                  (proposed name)
  promkit                    entry point, argparse subcommands       (proposed name)
  model.py                   Segment, Check, Manifest, Fact dataclasses; JSON writers
  catalog.py                 PROM index lookup
  identify.py                hashing, banners, byte-order and container detection
  transforms/                swap16.py
  containers/                installer.py ip32_flash.py io4_flat.py io4_segmented.py promgen64.py raw.py
  payloads/                  elf.py ecoff.py gzip.py lzw.py
  families/                  ip32.py ip22.py ip20.py ip17.py everest.py ...
  facts/                     spb.py vectors.py commands.py environment.py config_tree.py strings.py
  assets/                    png.py wav.py font.py  (writers only; readers live in each family)
  tests/                     test_*.py, golden/, fixtures built at run time
ghidra/import/sgi-prom/      (proposed name)
  ghidra_scripts/SgiPromImport.java                                   (proposed name)
  tests/run-ghidra.sh, tests/check.py, README.md
```

Everything is standard-library Python 3.11. Capstone and pyelftools, already in the toolchain image, are
used only where `hostfacts.py` already uses them. PNG is written with `zlib`, WAV with `wave`; there is no
imaging dependency. `compress`-format LZW has no standard-library decoder, so `payloads/lzw.py` is a small
one.

### Plug-in boundary

There are four kinds of plug-in. Each is one module that registers itself in a list in its package's
`__init__.py`; adding a board family or format is a new module, a registry line, a fixture builder and its
tests, with no change elsewhere.

- **Transform**: `probe(data) -> Probe | None` and `apply(data) -> bytes`. A probe returns a confidence and
  its evidence. `swap16` probes the way the byte-order survey in chips did it: the count of big-endian
  `jr ra` words, read both straight and pair-swapped, and the reset-vector branch pattern.
- **Container**: `probe(data) -> Probe | None` and `unpack(data, ctx) -> list[Segment]`. A container yields
  segments with their stored bytes, decoded bytes, load and entry addresses and the result of every check
  the format defines. A container that recognises its magic but fails a structural check raises, as the
  QEMU and iris decoders do, rather than falling back to a raw reading.
- **Payload**: `probe(segment) -> bool` and `expand(segment, ctx) -> list[Segment]`. ELF and ECOFF payloads
  yield their loadable sections or program headers as regions and their symbol tables as names; gzip and
  `compress` yield one decoded child; a promgen64 payload may yield nested segments found by search.
- **Family**: chosen from the catalogue's board field, or from the container and banner when the image is
  uncatalogued. It supplies: the Ghidra language and address window; the memory map (which segment runs
  where, with any split such as the O2 firmware's text, read-only data, data and zero-initialised ranges);
  which segments form one Ghidra program; the facts finders that apply; and the asset readers.

A `Segment` is the unit everything passes around: name, id, parent, container offset, stored length,
compression, decoded length, decoded sha256, load, entry, format, regions, checks and an output file name.
`firmware_layout.firmware_segments` keeps returning `(member, body, load)` tuples, built from segments.

### Formats covered first

| Plug-in | Source of the format | Checks |
|---|---|---|
| `raw` | none | none |
| `swap16` | chips byte-order page | reported, not checked |
| `installer` (256-byte `PROM` header, the O2's `.image` files) | chips O2 PROM page; iris and QEMU decoders | header length equals the file |
| `ip32-flash` (five `SHDR` segments) | chips O2 PROM page | header words sum to zero; body ends in a balance word; firmware segment type 3 and its load map sum to zero |
| `io4-flat` (`JFK4`) | chips IO4 payload page | halfword-sum checksum |
| `io4-segmented` (`JKSW`, `SEG2`, `_LZW`) | chips IO4 payload page | record halfword sums; decoded length and byte sum; the `0xce0` offset bias is applied and recorded, not hidden |
| `promgen64` | QEMU manual page; existing sgi-retools and Origami scripts | decoded length and additive byte sum; nested segments found by magic search |
| `elf`, `ecoff`, `gzip`, `lzw` | public formats | ELF and ECOFF header consistency; gzip CRC; decoded length |

The SN2 FIT is already handled by its own Ghidra import and is not repeated.

## Command-line interface

Run through the container, from a workspace, like every sgi-retools tool:

```sh
retools/tools/re-run python3 retools/tools/prom/promkit identify IMAGE... [--catalog FILE] [--json]
retools/tools/re-run python3 retools/tools/prom/promkit unpack IMAGE [--out DIR] [--catalog FILE]
retools/tools/re-run python3 retools/tools/prom/promkit facts MANIFEST [--segment NAME] [--out FILE]
retools/tools/re-run python3 retools/tools/prom/promkit assets MANIFEST [--out DIR] [--only KIND,...]
retools/tools/re-run --ghidra-export IMAGE --sgi-prom MANIFEST [--program NAME] [--facts FILE] [OPTIONS]
```

- `identify` prints one line per image (or one JSON object with `--json`): sha256, catalogue row or
  `uncatalogued`, byte order and any transform, container, banners with where each was found. It reads
  only the image and the catalogue and writes nothing.
- `unpack` writes `DIR/manifest.json` and one file per segment under `DIR/segments/`, then prints the
  manifest path. `DIR` defaults to `.cache/prom/<sha256 prefix>/`. It exits 1 when any check fails, after
  writing everything it could, so a damaged image is still readable.
- `facts` reads a manifest and writes the facts document for one segment or for every segment the family
  covers.
- `assets` writes the asset index and the PNG, WAV and font files. `--only` limits it to `logo`, `icon`,
  `font`, `palette`, `layout` or `audio`.
- `--sgi-prom` (proposed name) joins the existing `--ghidra-export` options. It takes the layout from the
  manifest, so `--flat`, `--load`, `--header`, `--processor` and `--window` are refused beside it, as they
  are beside `--sn2-prom`. `--program` picks one of the manifest's Ghidra programs when there are several
  (each CPU payload of an IO4 container is its own program). `--facts` defaults to the facts file next to
  the manifest.

Exit status follows the repository: 0 clean, 1 a check failed, 2 a usage or setup problem. Output is
deterministic: the same image and tool revision give byte-identical manifests and facts.

## Output schemas

Addresses and sha256 values are strings (`"0x81000000"`), as in Origami's analysis records, so 64-bit
addresses survive any JSON reader. Every document carries a schema id and the tool revision; a reader
refuses a major schema it does not know.

### Manifest

```json
{
  "schema": "prom-manifest/1",
  "tool": {"name": "promkit", "revision": "b6db4a8"},
  "image": {
    "file": "ip32prom.image",
    "sha256": "11230c35...",
    "size": 431872,
    "catalog": {"board": "ip32", "version": "4.18", "rev": "", "part": "", "kind": "shipped"},
    "banners": [{"text": "...", "where": "segment version +0x40"}],
    "byte_order": "big",
    "transforms": [],
    "container": "installer"
  },
  "family": "ip32",
  "segments": [
    {
      "name": "firmware", "id": null, "parent": "flash",
      "offset": "0x9200", "stored_length": "0x5fffc", "compression": "none",
      "length": "0x5fffc", "sha256": "...", "format": "flat",
      "load": "0x81000000", "entry": "0x81000048",
      "regions": [
        {"name": "text", "address": "0x81000000", "length": "0x48e70", "kind": "code"},
        {"name": "rodata", "address": "0x81048e70", "length": "0xb290", "kind": "readonly"},
        {"name": "data", "address": "0x81054100", "length": "0xbee0", "kind": "data"},
        {"name": "bss", "address": "0x8105ffe0", "length": null, "kind": "zero"}
      ],
      "checks": [
        {"rule": "shdr-header-zero-sum", "ok": true},
        {"rule": "shdr-body-balance", "ok": true},
        {"rule": "ip32-load-map-zero-sum", "ok": true}
      ],
      "file": "segments/firmware.bin"
    }
  ],
  "programs": [
    {"name": "flash", "language": "MIPS:BE:32:default", "segments": ["flash"], "base": "0xbfc00000"},
    {"name": "firmware", "language": "MIPS:BE:32:default", "segments": ["firmware"]}
  ]
}
```

The figures above are the O2 4.18 layout from the chips O2 PROM page, used to show the shape; the
manifest is what the tool computes, and the golden test for that image checks it against those figures.
A length the tool cannot determine is `null`, never a guess.

### Facts

One document per segment. Each fact carries its address, the rule that found it, and a grade in the words
the chips repository uses. The tool grades only what the bytes show: a table read in full whose shape was
verified is `established`; a role name taken from the published ARC slot order, or a meaning taken from a
string, is `inferred`; anything else is `unknown`. Chips pages may grade higher from other sources; the
facts file never claims more than the bytes.

```json
{
  "schema": "prom-facts/1",
  "tool": {"name": "promkit", "revision": "b6db4a8"},
  "image": {"sha256": "11230c35...", "segment": "firmware", "segment_sha256": "..."},
  "spb": {
    "builder": "0x810174d8", "address": "0xa0001000", "signature": "0x53435241",
    "fields": {"length": "0x48", "version": 1, "revision": 10, "firmware_vector_length": "0x8c",
               "firmware_vector": "0xa0001800", "private_vector_length": "0x34",
               "private_vector": "0xa0001c00", "adapter_count": 0},
    "rule": "spb-builder", "grade": "established"
  },
  "vectors": {
    "firmware": {"source": "0x81058840", "entries": [
      {"index": 0, "target": "0x81014858", "role": "Load", "role_grade": "inferred"}]},
    "private": {"source": "0x810588cc", "entries": [{"index": 0, "target": "0x81016ebc"}]},
    "patched": [{"index": 3, "target": "0xbfc0161c", "by": "0x81000530"}]
  },
  "commands": {"table": "0x81054100", "record": ["name", "handler", "usage"], "entries": [
    {"name": "boot", "handler": "0x81047a00", "usage": "...", "hidden": false}]},
  "environment": {
    "defaults": {"table": "0x810552f4", "record": ["name", "default", "flags"], "entries": [
      {"name": "console", "default": "g"}]},
    "special": {"table": "0x81055438", "entries": [{"name": "DEBUG", "cell": "0x810720d0", "flags": 2}]},
    "nvram_records": null
  },
  "config_tree": {"builders": [
    {"record": "0x81054280", "install": "0x81003a54", "parent_tag": 1, "identifiers": ["SGI-IP32"]}]},
  "menus": [{"table": "0x81060c50", "entries": [{"label": "Start System", "handler": "0x81012528",
             "image": "0x..."}]}],
  "strings": [{"address": "0x8104a998", "text": "1.0", "referenced_by": ["0x8100ad14"]}]
}
```

`nvram_records` holds the byte-addressed record tables of the Indigo, Indigo2 and Indy PROMs (name, NVRAM
offset, length, default); `defaults` holds the O2's name-and-default table. A family that has neither
leaves both `null`. Strings are exported only when some exported fact refers to them, not as a dump of
the image.

### Asset index

```json
{
  "schema": "prom-assets/1",
  "image": {"sha256": "...", "segment": "firmware"},
  "assets": [
    {"kind": "logo", "name": "logo-0x81070000", "address": "0x81070000", "encoding": "unknown",
     "width": 0, "height": 0, "file": "logo-0x81070000.png", "sha256": "...", "drawn_by": "0x8103caa0",
     "grade": "inferred"},
    {"kind": "font", "name": "font-0x...", "file": "font-0x....json", "bdf": "font-0x....bdf",
     "cell": [8, 16], "ascent": 13, "descent": 3, "first": 32, "last": 126, "proportional": false},
    {"kind": "palette", "file": "palette-0x....json", "entries": 16},
    {"kind": "layout", "file": "layout.json"},
    {"kind": "audio", "file": "chime-0x....wav", "rate": null, "rate_from": "unknown",
     "bits": 16, "channels": 2}
  ]
}
```

Asset names use the address where the data sits, because a descriptive name would be a guess until a
chips page settles what each one is. The values in the example are placeholders for the shape only.

The font description is JSON (cell size, ascent, descent, glyph range, and for each glyph its advance,
bounding box and rows as hex), with a BDF copy written beside it so ordinary font tools can open it. A
palette is a JSON list of RGB triples in table order. `layout.json` holds the menu geometry the PROM's
drawing code uses (positions, spacing, colours by palette index), each value with the address it was read
from. Audio is WAV at the rate the PROM programs, when the facts step can read it from the playback code;
otherwise `rate` is `null` and the asset says so rather than picking a rate.

## Facts discovery

Discovery runs in Python on the unpacked segments, before Ghidra, so it is testable without Ghidra and
the Ghidra script only applies what it is given. Each finder states its rule in the facts file.

- **System parameter block**: find the signature `0x53435241` built by `lui` and `ori` within a window of
  instructions (the chips survey found that adjacent-only matching misses the IP22, IP24 and IP30
  builders), or as a data word. From the builder, track the stores relative to the block's base with
  `facts.py` to read the length, version, vector lengths and vector addresses.
- **Firmware and private vectors**: find the copy into the vector address and its source table, using the
  register tracking to resolve the copy's arguments; then read the table. Patches applied later (the O2's
  five flash routines) are found as stores into the vector after the copy. Slot roles come from the
  published ARC 1.2 order and are graded `inferred`.
- **Command table**: candidate arrays of `{string pointer, code pointer, string pointer}` records in
  read-only data, accepted when the record stride is regular, every name pointer points at a printable
  string, every handler is the start of code, and the array is the argument of the interpreter call the
  family names. Hidden commands (a leading `.`) are reported as a flag, matching what the chips pages
  established of the `help` handler.
- **Environment**: the family plug-in names the record shape (the O2's `{name, default, flags}`, the
  Indigo2's 44-byte NVRAM record). The finder locates the table from a variable-name anchor, checks the
  shape across every record, and reads it.
- **Configuration tree builders**: the family plug-in names the walker's record table; the finder reads
  each `{install routine, parent tag, display hook}` record and lists the identifier strings each install
  routine refers to.
- **Menus**: on the O2, the menu records named in the chips O2 page, including each entry's image pointer,
  which is where the asset step starts.

What each finder may not do: it never names a routine from anything but the binary's own symbol tables,
the published ARC names, or a neutral name built from the address and the fact (`arcs_fv_23`,
`cmd_boot`). It never takes a name from vendor source.

## Ghidra loading

A new import component, `ghidra/import/sgi-prom/` (proposed name), follows the rule in
[ghidra/README.md](../../ghidra/README.md): its own README, a `tests/run-ghidra.sh` that runs it in the
Ghidra image, and a `tests/check.py` that checks the result with plain Python.

`SgiPromImport.java` (proposed name) runs as a pre-script on a raw import, as `SN2PromImport.java` does. It
reads the manifest and the facts file and:

- creates one memory block per region of each segment in the chosen program, at its load address and
  under the family's window; marks code regions executable and read-only data read-only; creates the
  zero-initialised range uninitialised;
- for the O2, maps the flash at `0xbfc00000` for the first-stage loader and `post1`, and the firmware
  segment's load-map chunks at their run-time addresses, in the same program;
- labels and types the parameter block, both vectors (each entry a pointer, each target a function), the
  command table (each handler a function named from its command), the environment tables, the walker
  records and the menu records, with a plate comment naming the rule and grade from the facts file;
- applies any names the payload carries (ELF or ECOFF symbol tables).

`re-run` already includes the SN2 import script in the Ghidra image's tag hash; the new component's
scripts join that list so a change rebuilds the image. The existing rule stands: decompiler output is
navigation, not evidence.

## Assets

None of the O2 PROM's asset formats is written up yet. The chips O2 pages give the entry points: the menu
records carry an image pointer per button; the `sgilogo` variable is read at the logo-drawing site; the
`pagecolor` and `volume` variables and the hidden `.play` command lead to the palette and the audio path;
the console's text output leads to the font. The asset step therefore has two stages:

1. **Research, in chips.** A reading of each drawing or playback routine establishes the encoding (bit
   depth, run-length or plain, palette indexing, glyph layout, sample format) and records it in a chips
   page with addresses and grades. The facts step exports the pointers and sizes it can find mechanically.
2. **Extractor, in the toolkit.** Each family's asset reader implements only formats a chips page has
   established, and its test builds a synthetic asset in that format.

The deliverable for shoji is fidelity, so every asset carries the address it came from and the routine
that draws it, and the reader refuses an asset whose decoded size disagrees with the size the drawing code
uses. Which PROM revisions shoji clones decides which images the asset tests cover.

## Fitting the existing tools

- `firmware_layout.py` gains `layout = "sgi-prom"` (proposed name), which calls the toolkit's unpack and
  returns its segments. A chips inventory group with that layout keys its rows `ip32prom.image(firmware)`,
  so `inventory.py`, `reading_round.py` and `facts.py` read a PROM segment by key, as they read
  system-controller segments today.
- `tools/chips/promgen64.py` has one caller: the census disassembly script `tools/chips/disasm.sh`, for
  inventory items of kind `promgen64` (the IP27 PROM in the chips hub census config). Two other chips
  tools name its output files in their usage text. The promgen64 plug-in keeps that output naming
  (`LABEL.<segment>.bin`), `disasm.sh` calls the toolkit, and the script is then removed.
- `ghidra-export.py` gains `--sgi-prom`; its planner reads the manifest for language, base and window
  instead of taking them as options.
- CI's existing `re-check` job gains one step per test module; the `ghidra-check` job gains the import's
  synthetic check.
- Nothing in Origami, iris, QEMU or sgi-emulator changes as part of this design. Whether Origami's own
  Python copies are later replaced by calls into the toolkit is an open question.

## Tests

### Committed fixtures: generated, never SGI bytes

Every binary fixture is built by test code at run time, as `test_firmware_layout.py` builds its controller
containers today. No committed file holds bytes copied from SGI firmware.

- The O2 flash: five synthetic `SHDR` segments with invented names and versions and computed zero sums;
  a firmware segment with a type-3 load map of invented chunks; one case with a broken body sum and one
  with a broken load-map sum.
- IO4: a `JFK4` image with a computed halfword checksum; a `JKSW` image with a `SEG2` table of four records,
  biased offsets, and `_LZW` payloads produced by a small LZW encoder in the test helpers. The decoder is
  also compared with the host's `gzip -d` (which reads `compress` streams) when present.
- promgen64: the cases the current script handles, plus a nested header part-way through a payload,
  which is the IP35 shape.
- ELF and ECOFF: minimal headers built with `struct`; one ECOFF with a small symbolic header.
- Byte order: a synthetic flat image of `jr ra` words and a branch at offset 0, then the same pair-swapped.
- Facts: synthetic MIPS code built from hand-assembled words (as the existing tests do for ColdFire and
  PowerPC) that builds a parameter block with `lui`/`ori` split by other instructions, copies a vector
  table, and passes an invented command table to an invented interpreter.
- Assets: once a format is established, a synthetic bitmap, glyph set or sample in that format, with the
  expected PNG, BDF and WAV bytes computed by the test.
- Ghidra: a synthetic O2-shaped image whose `check.py` asserts every block and label the manifest and
  facts call for.

### Real images, when present

A second set of tests runs against catalogue images found by sha256, in the workspace's `root/firmware/`
or a directory named by `RETOOLS_PROM_IMAGES` (proposed name). An absent image prints a skip with its
sha256, as the SN2 import's check does. The expected results are committed **golden manifests and facts**
under `tools/prom/tests/golden/<sha256 prefix>.json`: offsets, lengths, load addresses, check results,
segment hashes and table addresses, all derived numbers, no image bytes. The first goldens come from what
chips has already established, so they test the pages as much as the tool:

- the 13 IO4 images: container kind, segment count, and the payload sha256 table in the chips IO4 page;
- the O2 4.8 and 4.18 images: the segment table, the load map, the parameter block and vector targets and
  the 28-entry command table in the chips O2 page;
- the IP20, IP22 and IP24 images: parameter block fields, vector lengths and the Indigo2 environment
  records;
- the swapped IP24 dump: swapping it back gives the catalogued image's sha256, as the chips holdings page
  records;
- the IP27 and IP35 payloads: their payload hashes equal the hashes sgi-emulator and QEMU cite.

These run by hand and on any runner that holds the images; CI runners hold none. Optional hand-run
agreement checks compare `identify` and `unpack` with `iris-prom show` on the eight images iris embeds.

## How shoji consumes it

shoji adds sgi-retools as its `retools/` submodule, pinned to a commit, as the RE repositories do. Its
build container runs:

```sh
retools/tools/re-run python3 retools/tools/prom/promkit unpack IMAGE --out build/prom
retools/tools/re-run python3 retools/tools/prom/promkit facts build/prom/manifest.json --out build/prom/facts.json
retools/tools/re-run python3 retools/tools/prom/promkit assets build/prom/manifest.json --out build/prom/assets
```

- The image is fetched from the published distribution by the sha256 shoji pins, or given as a path.
- shoji commits a lock file, `prom-assets.lock.json` (proposed name), listing the image sha256, the
  toolkit commit and the sha256 of every output it uses. The build fails when an output changes, so a
  toolkit update that alters an asset is a visible change in shoji.
- shoji's Rust build step reads `facts.json` (environment defaults, command names, menu layout) and the
  PNG, BDF or JSON font and WAV files, and emits Rust tables for the firmware. The toolkit never writes Rust.
- Whether shoji commits the derived assets, or regenerates them on every build, is the owner's call (see
  below).

## Clean-room and publication constraints

- The toolkit reads only shipped binaries: catalogued PROM images and shipped standalone programs. Its
  inputs never include the IRIX source tree, restricted Library documents, or notes written by an author
  exposed to vendor source. Chips pages that mix readings of shipped binaries with facts graded from the
  public IRIX source are usable references for the formats, as the owner has ruled.
- Labels and names come from the binary's own tables and strings, the published ARC specification, public
  OS headers (Linux and NetBSD ARCS definitions), or neutral address-based names. No vendor-source
  identifier enters code, labels, fixtures or commits.
- sgi-retools is public. No SGI firmware bytes are committed: not in fixtures, not in goldens, not as
  extracted assets. Extracted segments and assets go to `.cache/` or a caller's `--out`, which RE
  workspaces ignore. Manifests and facts are derived data and may be committed, as chips commits its
  tables today.
- Extracted SGI assets are usable in shoji by the owner's ruling. That ruling covers shoji, not
  publication of the assets from sgi-retools or chips.
- Decompiler output stays navigation. A committed fact rests on the bytes and the disassembly.

## Which repository owns what

| Repository | Owns |
|---|---|
| Origami | The PROM catalogue (identity and provenance), its checker and publisher, the published PROM index |
| sgi-retools | The toolkit, its schemas, plug-ins, synthetic fixtures, golden manifests and facts, the Ghidra import |
| chips | The format write-ups and per-board PROM pages, the holdings view, committed facts exports under `generated/prom/` (proposed name) that the pages cite |
| shoji | Its pin of sgi-retools, its lock file, the conversion of toolkit outputs into Rust tables |
| iris, QEMU, sgi-emulator | Their runtime decoders and selection lists, unchanged; selection rows cite catalogue rows by sha256 |

## Proposed names

Every name below is a proposal. None is used until the owner picks.

| What | Proposal | Alternatives |
|---|---|---|
| The package directory | `tools/prom/` | `tools/sgiprom/` |
| The entry point | `promkit` | `prom-tool`, `sgiprom` |
| Subcommands | `identify`, `unpack`, `facts`, `assets` | `id`, `split`, `tables`, `media` |
| Container plug-ins | `installer`, `ip32-flash`, `io4-flat`, `io4-segmented`, `promgen64`, `raw` | `shdr`, `jfk4`, `jksw` (after the magics) |
| Transform plug-in | `swap16` | `pairswap` |
| Ghidra import directory and script | `ghidra/import/sgi-prom/`, `SgiPromImport.java` | `mips-prom`, `MipsPromImport.java` |
| Ghidra export option | `--sgi-prom MANIFEST` | `--prom-manifest` |
| `firmware_layout.py` layout | `sgi-prom` | `prom` |
| Schema ids | `prom-manifest/1`, `prom-facts/1`, `prom-assets/1` | |
| Image directory variable | `RETOOLS_PROM_IMAGES` | `PROM_IMAGES` |
| Golden directory | `tools/prom/tests/golden/` | |
| Chips facts directory | `generated/prom/<board>/` | `platforms/<board>/generated/` |
| shoji lock file | `prom-assets.lock.json` | `assets.lock` |
| This page's directory | `docs/designs/` (sgi-retools has no design directory yet) | `ghidra/` or `tools/` README sections |

## Open questions

1. **Names.** Every entry in the table above.
2. **Language.** Does shoji's Rust rule cover build tooling? The recommendation assumes it covers what
   shoji ships, which is how shoji's own Python toolchain scripts read. If it covers tooling, the toolkit
   becomes a shared Rust crate split from iris's decoder, with the costs listed under option B.
3. **Catalogue home.** The catalogue stays in Origami for now. If Origami is retired, should the catalogue
   and its publisher move to sgi-retools, chips, or a repository of their own?
4. **Holdings and missing rows.** Should chips' `prom-images.md` be cut to holdings-only columns or
   generated from the PROM index? Should the four images it lists that the catalogue lacks become catalogue
   rows, with `publish = false` for the dumps of unknown origin?
5. **Payload hashes.** Should the catalogue gain an optional payload sha256 per row so that sgi-emulator's
   and QEMU's payload hashes resolve without the golden manifests, or do the goldens suffice?
6. **shoji's copy of the assets.** Commit the extracted assets in shoji (shoji is private), or regenerate
   them on every build from the pinned image?
7. **Which O2 PROM shoji clones.** 4.18 only, or 4.8 as well? That sets which images the asset goldens cover.
8. **Origami's Python copies.** Replace `extract-irix`'s promgen code, `promgen-unpack` and `prom-banner`
   with calls into the toolkit, or leave them as they are while Origami winds down?
9. **Container record layouts as defs units.** Should chips also describe the `SHDR`, `SEG2`, `_LZW` and
   promgen64 records as `formats/<name>/format.toml` units, so the defs tooling generates Rust structures
   for shoji and the emulators from the same graded source? The toolkit would not depend on them.
10. **First families after the O2.** The order assumed is IP32, then IP22 and IP24, IP20, IP17, then the
    Challenge and Onyx IO4 payloads. The owner may reorder.

## Out of scope

- Writing, repacking or flashing images. The toolkit reads only.
- The SN2 FIT, already handled by its own import, and system-controller firmware, already handled by
  `firmware_layout.py`.
- Running a PROM. Emulators already do that, and their runs are model behaviour, not evidence of what an
  image contains.
