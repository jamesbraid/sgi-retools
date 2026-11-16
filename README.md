# sgi-retools

The shared toolbox for our SGI reverse-engineering repositories. Graphics microcode, system ASICs and
their firmware, PROMs on MIPS and IA-64, L1 controllers, the IRIX kernel and userspace: the findings live
in each repository, the tools live here.

It is also the one home for our Ghidra work. Processors, loaders and scripts for any of those targets land
here, whichever repository needs them first.

## What's in it

- **A container runner.** `tools/re-run` runs any command in a pinned toolchain container with the
  repository mounted, so a fresh machine needs only Podman. `--ghidra` swaps in the Ghidra image.
- **Analysis tools** for reading binaries and grading what we learn from them. [tools/README-analysis.md](tools/README-analysis.md)
  covers them and sets the evidence order every repository follows.
- **Hardware definitions.** One TOML file per device becomes headers in C, Rust, Python, JSON and XML,
  plus the checks that keep them honest. See [tools/defs/README.md](tools/defs/README.md).
- **Ghidra support.** Processor modules, firmware loaders and scripts. Start at [ghidra/README.md](ghidra/README.md).
- **Per-family extractors** under `tools/<family>/`, for formats only one device family uses.
- **[hostfacts](tools/README-hostfacts.md)**, for reading a routine on a machine with no containers.

Every tool answers `--help`. That, not this page, is the reference for options.

## Getting started

A repository pulls this one in as its `retools/` submodule, pinned to a commit, and runs the tools by that
path from its own root:

```sh
git submodule update --init retools
tools/setup-clone.sh                  # the repository's own setup script
retools/tools/re-run --help
retools/tools/re-run retools/tools/defs/ci-check
```

The first `re-run` builds the container image, which takes a while. Later runs reuse it until the
Containerfile changes.

To move a repository to a newer toolbox: `git -C retools checkout COMMIT && git add retools`.

## Contributing

Pull requests are welcome on GitHub. Keep each change to one tool or one processor, with its test. A
change to shared behaviour should say which repositories it affects.

## Licence

BSD 3-Clause, see [LICENSE](LICENSE). The tools that came from the gr4 project keep that project's notice,
[tools/LICENSE-gr4](tools/LICENSE-gr4) (BSD 3-Clause, copyright Dominik Behr). That covers `tools/gr4/`,
`ghidra/processors/ge11/` and the adapted scripts whose headers name it. Keep those headers and that file
with any copy.
