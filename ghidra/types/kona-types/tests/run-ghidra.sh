#!/bin/sh
# Apply KonaTypes.java to the production ARM firmware and to every kernel
# object, and dump the result for tests/check.py.
#
#   ghidra/types/kona-types/tests/run-ghidra.sh [OUTDIR]     (default .cache/kona-types)
#
# Run from the repository root with analyzeHeadless on PATH and root/
# populated. Writes OUTDIR/arm1.u.dump and .log, and OUTDIR/kernel.log
# with OUTDIR/kernel.dump (all kernel objects in one).
set -eu
OUT=${1:-.cache/kona-types}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
proj=$(mktemp -d /tmp/kona-types-proj.XXXXXX)
trap 'rm -rf "$proj"' EXIT
SP="ghidra/import/kona-arm/ghidra_scripts;ghidra/types/kona-types/ghidra_scripts;ghidra/types/kona-types/tests"

rm -f "$OUT/arm1.u.dump"
analyzeHeadless "$proj" p -import ucode/KONA/arm1.u -loader BinaryLoader \
    -processor ARM:BE:32:v4 -scriptPath "$SP" \
    -preScript KonaArmImport.java "$(pwd)" -postScript KonaTypes.java "$(pwd)" \
    -postScript DumpTypes.java "$OUT/arm1.u.dump" -deleteProject \
    >"$OUT/arm1.u.log" 2>&1 || { tail -40 "$OUT/arm1.u.log"; exit 1; }
grep 'KonaTypes.java>' "$OUT/arm1.u.log" || true

rm -f "$OUT/kernel.dump"
analyzeHeadless "$proj" p -import kona_kernel/kona_*.o -scriptPath "$SP" \
    -postScript KonaTypes.java "$(pwd)" -postScript DumpTypes.java "$OUT/kernel.dump" \
    -deleteProject >"$OUT/kernel.log" 2>&1 || { tail -40 "$OUT/kernel.log"; exit 1; }
grep -c 'KonaTypes.java> hh' "$OUT/kernel.log" || true
