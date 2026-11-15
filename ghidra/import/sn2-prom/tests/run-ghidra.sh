#!/bin/sh
# Import an SN2 PROM with SN2PromImport.java and dump what it laid out.
#
#   retools/ghidra/import/sn2-prom/tests/run-ghidra.sh IMAGE [OUTDIR]   (default .cache/sn2-prom)
#
# Run inside the Ghidra image (tools/re-run --ghidra --). Writes
# OUTDIR/symbols.tsv for tests/check.py. The image is loaded at 0 on purpose:
# the script must move it to end at 4 GiB.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
IMAGE=$1
OUT=${2:-.cache/sn2-prom}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PRESCRIPT=$HERE/../ghidra_scripts/SN2PromImport.java \
    sh "$HERE/../../../processors/ia64/tests/run-ghidra.sh" "$OUT" "$IMAGE" 0 DumpSymbols.java "$OUT/symbols.tsv"
grep 'SN2PromImport' "$OUT/headless.txt" | grep -v '^INFO  SCRIPT' || true
