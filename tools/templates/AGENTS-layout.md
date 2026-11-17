## Where new work goes

There is no `evidence/` directory. File each page by what it is about:

- `devices/<chip>/`, `platforms/<board>/`, `formats/<name>/`, `software/<area>/`: a note about one device, platform,
  format or software component.
- `<subject>/readings/<binary>.md`: per-routine readings of one binary, filed under the subject it explains (a driver
  object under its chip, a kernel object under `software/kernel/<platform>/`). `retools/tools/reading_round.py` files
  its entries there; `tools/config/readings-subjects.json` says which subject a binary belongs to.
- `references/`: what we hold and cite: binary, PROM and firmware lists with checksums, scope lists, source lists.
  Code submodules stay under `references/code/`.
- `generated/`: tool output that is regenerated and never hand-edited (`generated/inventory/`, diff tables, symbol
  tables, register output). Hand-kept audit tables sit in `generated/inventory/audits.tsv` by exception.
- `COVERAGE.md` at the root: progress tallies. The inventory block in it is rewritten by `retools/tools/inventory.py`.
- `questions/`: open questions.

`retools/tools/defs/ci-check` fails when an `evidence/` directory comes back.
