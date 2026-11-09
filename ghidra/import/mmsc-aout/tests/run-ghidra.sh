#!/bin/sh
# Import an MMSC image with MmscAoutImport.java, analyse it, and dump the result
# for tests/check.py.
#
#   retools/ghidra/import/mmsc-aout/tests/run-ghidra.sh IMAGE [OUTDIR]   (default .cache/mmsc-aout)
#
# Run from the workspace root inside the Ghidra container (tools/re-run --ghidra --)
# after making the map table in the toolchain container:
#   tools/re-run python3 retools/tools/sysco/mmsc_aout.py IMAGE --tsv OUTDIR/map.tsv
# Writes OUTDIR/ghidra.dump and ghidra.log.
set -eu
MOD=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=$1
OUT=${2:-.cache/mmsc-aout}
OUT=$(cd "$OUT" && pwd)
proj=$(mktemp -d /tmp/mmsc-aout-proj.XXXXXX)
trap 'rm -rf "$proj"' EXIT
analyzeHeadless "$proj" p -import "$IMAGE" -loader BinaryLoader \
    -processor x86:LE:32:default -scriptPath "$MOD/ghidra_scripts;$MOD/tests" \
    -preScript MmscAoutImport.java "$IMAGE" "$OUT/map.tsv" \
    -postScript DumpMmsc.java "$OUT/ghidra.dump" -deleteProject \
    >"$OUT/ghidra.log" 2>&1 || { tail -40 "$OUT/ghidra.log"; exit 1; }
grep -E 'MmscAoutImport.java>|ERROR' "$OUT/ghidra.log" || true
