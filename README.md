# sgi-retools

Tooling shared by the SGI reverse-engineering workspaces: container definitions, the
wrappers that drive them, Ghidra scripts, processors and importers, the inventory and
claim checker, the pre-push hook, and the extractors that are specific to one device
family. A workspace holds the findings, tables and configuration; the tools live here.

A workspace pulls this repository in as the `retools/` submodule, pinned to a commit, and
links the paths it has always used (`tools/re-run`, `scripts/inventory.py`,
`ghidra/scripts/*.java`) into it. Update the pin with
`git -C retools checkout COMMIT && git add retools`.

```sh
git clone --recurse-submodules URL/WORKSPACE.git    # or: git submodule update --init retools
tools/setup-clone.sh --root DIR                      # siblings, public submodules, root/
tools/check-shared                                   # the pin matches, nothing local, no dangling links
```

## Layout

| Path | Contents |
|---|---|
| `tools/` | `Containerfile` and `Containerfile.ghidra`, `re-run`, `setup-clone.sh`, `check-shared`, `refresh-union-root`, `ghidra-export.py`, `README-analysis.md` |
| `tools/chips/` | the register-access census tools (scan, join, report, header generation) |
| `scripts/` | the code every workspace runs the same way: `inventory.py`, `facts.py`, `hostfacts.py`, `check_claims.py`, `mdebug.py`, `syscall_table.py`, `syssgi_selectors.py`, `capability_tree.py`, `mips_shim.py`, `reading_round.py`, `toolchain.py`, `populate-root`, `pre-push`, `check-leaks.sh` and their tests |
| `scripts/<device>/` | extractors, disassemblers and analysis scripts for one device family (`kona`, `odsy`, `crime`, `chips`, `voyager`, `sysco`, `kudzu`, `gr4`); a script two families share sits in the first family's directory and the other links to it |
| `ghidra/scripts/` | the Ghidra scripts for IRIX MIPS objects and the export helpers (`Re*.java`) |
| `ghidra/processors/<name>/` | Ghidra processor extensions with their generators and tests (`kona-ge`, `kona-ged`, `odsy-buzz`, `ge11`) |
| `ghidra/import/<name>/`, `ghidra/types/<name>/` | firmware importers and data-type scripts (`kona-arm`, `kona-types`, `mmsc-aout`) |

Tools that name paths of their workspace (`docs/`, `root/`, `scripts/inventory-config.json`)
find the workspace through the link they were started by, not through this repository, so
they must be run by the workspace's path.

## For agents without containers

`scripts/facts.py` needs the MIPS objdump from the toolchain container, so an agent whose
sandbox cannot run Podman has had to read raw disassembly, and that is where offsets, branch
directions and call arguments go wrong. `scripts/hostfacts.py` gives the same facts on the host. It
runs facts.py's analysis with a Capstone decoder in place of objdump, so a run needs only
Python with `capstone` and `pyelftools`:

```sh
uv run --with capstone --with pyelftools \
    python -I retools/scripts/hostfacts.py BINARY[:MEMBER] ROUTINE [--size N] [--flat --load ADDR] [--json]
```

Run it from the workspace root (a clone of this repository elsewhere works too, given by its path) with the same arguments as `facts.py` (ROUTINE is a symbol or
`0xADDR`; an archive member follows a colon). The text names, for the one routine:

- range, size, ELF class, ABI and ISA;
- every load and store with its width, base register, the displacement as written and the resolved
  target, `abs 0xADDR` or `ORIGIN +/-0xOFF`. A displacement from a `lui`-built base keeps its sign,
  so `lui t0,1; lw t1,-0x6954(t0)` reads as 0x96ac from the origin, not 0x6954;
- every call with its callee and the argument registers as the callee sees them, after the delay
  slot (`?` is a register the tool could not follow);
- basic blocks, each conditional branch with when it is taken and when it falls through, the
  instruction in its delay slot and whether a branch-likely annuls it, and which blocks reach each
  return and what v0 holds on the way in;
- the constants and immediates the routine uses.

Base every offset, condition and argument claim on this output, not on a hand reading of the
listing. `--json` prints the sheet `facts.py` prints. Its sections match a container run of
`tools/re-run python3 scripts/facts.py` on the same routine, except where objdump prints a
64-bit constant load as the pseudo-instruction `dli` (N64 code): facts.py does not follow `dli`, so
the Capstone run, which decodes it as `ori`, shows constants and call arguments the container
run lacks. `scripts/test_hostfacts.py` holds the hand-assembled checks (run it with the same
`uv run --with` line); it skips itself when Capstone is missing.

## What stays in a workspace

Content and configuration: documents, findings and generated tables, the inventory and its
config, root manifests other than the union store's (see below), the list of IRIX files, `scripts/copy-check-allow.txt`, the per-chip
`tools/configs/`, and the forbidden-term list described next.

## The leak check

`scripts/check-leaks.sh` checks what a push adds: the lines of the range and its commit messages
(`--all` audits the whole tree). The base patterns are in
[scripts/leak-patterns.txt](scripts/leak-patterns.txt), one regular expression per line, a single
file other tools (a server-side hook) can read too. Terms that must not be written into a shared
tool are read from the workspace's `.re-leak-terms` (git-ignored) or the host's
`~/.config/re-leak-terms`; with neither the check warns and uses the base patterns. A string that
matches but is fine goes in the workspace's `scripts/leak-allow.txt` as `STRING<TAB>REASON`,
exact text only. Exit status is 0 clean, 1 hit, 2 tool error; `check-leaks.sh --self-test` runs it
against planted hits.

## Pushing

`tools/setup-clone.sh` sets the clone's push URL to a placeholder, so a plain `git push` fails at
once (`--no-verify` too) and names `retools/re-push`. `re-push` runs the stages of
`scripts/pre-push` (leak check, claim checker on the changed entries, copy check) on
`origin/main..HEAD`, refuses on any failure or tool error, and pushes with the real URL given for
that one command. It has no option to skip a stage, and the copy check fails closed: no
tool, a missing `root/`, an unavailable container engine or image, missing indexes and a tool
error all refuse the push with a message naming the cause and the fix. A missing or stale symbol
baseline (the per-repository index of names the shipped binaries carry, keyed by the digest of
`scripts/inventory-root.sha256`) is built with the tool's build option and the check
runs again; if the build fails, or the tool is still not ready, the push is refused. Only the bare
hook keeps `COPY_CHECK=off` and `CHECK_CLAIMS=off`, as emergency overrides that print a warning
that the push is unchecked; `re-push` ignores both. `retools/re-push --install [DIR...]` prepares
existing clones. The pre-push hook stays as the early warning for anything else.

### Graded entries must be testable

The claim checker can only test an entry that names a routine and a binary it finds in `root/`.
`re-push` (through `scripts/pre-push`, which passes `--block-unresolved` to
`scripts/check_claims.py`) refuses a push when an entry carrying a grade, Established or
Inferred, is added or edited by the pushed range and cannot be resolved: no routine, no binary, or
a routine the binary does not have. The message gives the `doc:line`, the routine and binary as
read, the reason and the fix: name the routine in backticks and the binary by its full build path,
with the address and size, or write the note as Unverified or plain prose.

The rule is judged on the range alone (`git diff -U0` against the remote tip, pure deletions
ignored), so there is no baseline file and no list of entry ids: a graded note nobody touches stays
allowed however old, and touching one makes it testable or ungraded. Unverified entries, prose with
no grade and tables without a routine, function, name or symbol column are exempt, as are the
register tables of `chips/*/README.md`, which the chip checker reads by its own rules.

## The union root

`scripts/inventory-root.sha256` is the manifest of a union root store: every workspace's
`root/` tree, hardlinked under one directory with a subdirectory per workspace. The union
root exists only so the pre-push copy check has a reference. The check reads the shipped
binaries from the clone's `root/` and keys its symbol baseline by this manifest's digest, so
every clone with the same manifest shares one baseline.

```sh
tools/refresh-union-root RE_ROOTS STORE
ln -s STORE root            # or: tools/setup-clone.sh --root STORE
```

`RE_ROOTS` is the directory holding one folder per workspace, each with a `root/` tree. The
script rebuilds `STORE` from scratch as hardlinks, drops links that do not resolve inside their
own workspace and dangling links, and rewrites the manifest. Run it when a workspace's root
changes, commit the new manifest so the baseline key follows, and rebuild the copy-check
symbol baseline with the copy-check tool's build step (its help lists the option). `STORE` holds links only,
so it must sit on the same filesystem as `RE_ROOTS`.

## Licence

The code written for these workspaces is BSD 3-Clause, see [LICENSE](LICENSE). The scripts
descended from the gr4 project keep that project's notice, [scripts/LICENSE-gr4](scripts/LICENSE-gr4)
(BSD 3-Clause, copyright Dominik Behr): the adaptations carry a header naming it and the
original script they derive from. `scripts/gr4/` and `ghidra/processors/ge11/` come from the gr4
repository under that notice. Keep those headers and that file with any copy of them.

### Flat controller firmware

The same `hostfacts.py` entry point also accepts `--arch coldfire`, `m68k`,
`arm`, `thumb`, `x86-16` and `x86-32`. These modes require `--load ADDR`.
For raw images, supply `--size N`. The tool does not infer a routine boundary
from a linear decoder. `--offset N` skips a container header before mapping
the payload at the load address.

```sh
uv run --with capstone --with pyelftools python -I scripts/hostfacts.py \
    firmware.bin 0xffe10400 --arch coldfire --flat --load 0xffe00000 --size 0x40
uv run --with capstone --with pyelftools python -I scripts/hostfacts.py \
    mmscfw.bin _sysNvRamGet --arch x86-32 --load 0x108000
```

MMSC a.out images use `scripts/sysco/mmsc_aout.py` for their text/data map and
nlist names. Their routine sizes come from the next symbol and are labelled
inferred. Headers, symbols and bss are not treated as mapped file contents.
An explicit load address that disagrees with the a.out header is rejected.

The non-MIPS sections report accesses, calls, control flow, returns,
constants and an instruction listing. Register values are merged across all
predecessors. Unsupported effects invalidate affected values and produce
warnings. Predicated ARM accesses carry their execution condition. There are
no delay slots in these modes.

The default calling conventions are M68K stack arguments, ARM AAPCS registers
and x86 cdecl32 stack arguments. Argument counts are unknown: the printed
locations are candidates, not a declaration that the callee accepts them.
Use `--abi unknown` when the convention is not established, or `--abi cdecl16`
for a known 16-bit near-call convention. The default x86-16 ABI is unknown.
Its addresses are segment offsets, with no inferred segment base. ColdFire
uses Capstone's 68040 decoder for the common instruction subset. This does
not establish that every decoded opcode is legal on a ColdFire part.

Run the synthetic regression tests on the host:

```sh
uv run --with capstone --with pyelftools python -I scripts/test_hostfacts.py
uv run --with capstone --with pyelftools python -I scripts/test_hostfacts_firmware.py
```

The [real-image validation table](scripts/hostfacts-firmware-validation.tsv)
records five routines per extracted image: 60 ColdFire bodies, 20 executable
ARM segments and 11 MMSC carriers. It preserves the input hashes and mappings.
These checks compare decoded bytes, emitted locators and required fact-sheet
sections. The synthetic tests and independent review cover modeled instruction
effects. Warnings and unknown values remain part of the output.

The CPU families and MMSC mapping follow sysco's `docs/controllers.md` and
`docs/mmsc/load-map.md`. ColdFire body mappings come from each package header,
with the layout described in `docs/l1/coldfire-package-sections.md`. ARM
packages have no load address in their outer headers. The ARM checks use
executable segments from their userland ELF images and take `p_vaddr` from
each ELF program header. No outer ARM package load address is assumed.
