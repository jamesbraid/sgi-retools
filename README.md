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
| `tools/` | `Containerfile` and `Containerfile.ghidra`, `re-run`, `setup-clone.sh`, `check-shared`, `ghidra-export.py`, `README-analysis.md` |
| `tools/chips/` | the register-access census tools (scan, join, report, header generation) |
| `scripts/` | the code every workspace runs the same way: `inventory.py`, `facts.py`, `check_claims.py`, `mdebug.py`, `syscall_table.py`, `syssgi_selectors.py`, `capability_tree.py`, `mips_shim.py`, `toolchain.py`, `populate-root`, `pre-push`, `check-leaks.sh` and their tests |
| `scripts/<device>/` | extractors, disassemblers and analysis scripts for one device family (`kona`, `odsy`, `crime`, `chips`, `voyager`, `sysco`, `kudzu`, `gr4`); a script two families share sits in the first family's directory and the other links to it |
| `ghidra/scripts/` | the Ghidra scripts for IRIX MIPS objects and the export helpers (`Re*.java`) |
| `ghidra/processors/<name>/` | Ghidra processor extensions with their generators and tests (`kona-ge`, `kona-ged`, `odsy-buzz`, `ge11`) |
| `ghidra/import/<name>/`, `ghidra/types/<name>/` | firmware importers and data-type scripts (`kona-arm`, `kona-types`) |

Tools that name paths of their workspace (`docs/`, `root/`, `scripts/inventory-config.json`)
find the workspace through the link they were started by, not through this repository, so
they must be run by the workspace's path.

## What stays in a workspace

Content and configuration: documents, findings and generated tables, the inventory and its
config, root manifests, the list of IRIX files, `scripts/copy-check-allow.txt`, the per-chip
`tools/configs/`, and the forbidden-term list described next.

## The leak check

`scripts/check-leaks.sh` carries no term list. It reads `scripts/leak-terms.txt` of the
workspace (or `.re-leak-terms`, `~/.config/re-leak-terms`, or the file named by
`RE_LEAK_TERMS`) and fails when there is none. The file format is in the script's header.

## Licence

The code written for these workspaces is BSD 3-Clause, see [LICENSE](LICENSE). The scripts
descended from the gr4 project keep that project's notice, [scripts/LICENSE-gr4](scripts/LICENSE-gr4)
(BSD 3-Clause, copyright Dominik Behr): the adaptations carry a header naming it and the
original script they derive from. `scripts/gr4/` and `ghidra/processors/ge11/` come from the gr4
repository under that notice. Keep those headers and that file with any copy of them.
