# Ghidra in the graphics workspaces: index

This directory holds the Ghidra code every workspace shares. Each workspace
(odsy, gr4, kona, crime, chips) also keeps a `ghidra/` directory of its own with
its own README and conventions. This page points at all of them and does not
repeat them; read the README of the workspace you are in for how to build and
run its components.

## What lives here

| Path | What it is | Documented in |
|---|---|---|
| [scripts/](scripts/) | Ghidra scripts for IRIX MIPS objects (`IrixGp`, `IrixJumpTables`, `FindWindowStores`, `MarkVolatileWindows`, `DumpCallEdges`, `DecompileFunctions`, `ApplyStruct`, the GOT import workaround, the `Re*.java` export helpers) | [scripts/README.md](scripts/README.md): when to use Ghidra versus the assembly-to-C pipeline, failure modes of both, per-script use |
| [processors/ge11/](processors/ge11/) | geometry-engine processor extension for the IMPACT GE11 | gr4 `ghidra/README.md` |
| [processors/kona-ge/](processors/kona-ge/), [processors/kona-ged/](processors/kona-ged/) | geometry-engine microcode processor and its decoder variant | kona `ghidra/README.md` and `docs/tooling.md` |
| [processors/odsy-buzz/](processors/odsy-buzz/) | BUZZ transform-microcode processor and its import script | odsy `ghidra/README.md` |
| [import/kona-arm/](import/kona-arm/), [import/mmsc-aout/](import/mmsc-aout/) | firmware loaders | kona `ghidra/README.md` |
| [types/kona-types/](types/kona-types/) | data-type scripts and tables | kona `ghidra/README.md` |

Every processor or importer has `tests/run-ghidra.sh` (runs in the Ghidra image
and writes a dump) and `tests/check.py` (checks the dump with plain Python 3).

## Per-workspace conventions

All five use the same layout: `ghidra/processors/<name>/`,
`ghidra/import/<name>/`, `ghidra/types/<name>/`. They differ in what they hold
and in how they reach the shared scripts.

| Workspace | Its `ghidra/` holds | Shared scripts | Run commands |
|---|---|---|---|
| odsy | `processors/odsy-buzz` (a link into this repository, kept as a link because its test script locates the module by that path); the README also documents `re-run --ghidra-export` (decompiled C as JSON, typed structures, BSim similarity, flat PROM images) | used directly from `retools/ghidra/scripts/` | `retools/tools/re-run --ghidra ghidra/processors/odsy-buzz/tests/run-ghidra.sh .cache/odsy-buzz` |
| gr4 | `processors/ge11` (the gr4 project's, kept in this repository), empty `import/` and `types/` | its README says `ghidra/scripts/` is linked from the submodule | `re-run --workspace . --ghidra -- ghidra/processors/NAME/tests/run-ghidra.sh .cache/NAME` |
| kona | `processors/kona-ge`, `processors/kona-ged`, `import/kona-arm`, `types/kona-types`; `docs/tooling.md` holds the Ghidra versus pipeline comparison | `retools/ghidra/scripts/`, not linked | `retools/tools/re-run --ghidra ghidra/processors/kona-ge/tests/run-ghidra.sh .cache/kona-ge` |
| crime | layout only (`.gitkeep` directories, no component yet) | `retools/ghidra/scripts/`, not linked | `retools/tools/re-run --ghidra ghidra/processors/NAME/tests/run-ghidra.sh .cache/NAME` |
| chips | layout only (`.gitkeep` directories, no component yet) | `retools/ghidra/scripts/`; `re-run --ghidra-export` reads them from there | `retools/tools/re-run --ghidra -- ghidra/processors/NAME/tests/run-ghidra.sh .cache/NAME` |

The README of each workspace is `ghidra/README.md` at its root. The run commands
differ only in how they spell the workspace flag; `retools/tools/re-run` mounts
the workspace at `/work` and picks the Ghidra image with `--ghidra`, the
toolchain image without it.

## Adding a component

Put a processor, importer or type script in the workspace that owns the hardware
(`ghidra/processors/<name>/` and so on) with its `tests/run-ghidra.sh` and
`tests/check.py`. Move it here only when a second workspace needs it, and leave
a one-line note in the first workspace's README, as odsy does for `odsy-buzz`.
Scripts that read IRIX objects and are not specific to one hardware family
belong in [scripts/](scripts/).
