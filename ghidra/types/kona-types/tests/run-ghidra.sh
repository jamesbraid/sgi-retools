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
# A path written for the old layout, as this workspace has it (software/ucode/..., see tools/_layout.py).
sw() { python3 "$(dirname "$(readlink -f "$0")")/../../../../tools/_layout.py" sw "$1" 2>/dev/null || echo "$1"; }
OUT=${1:-.cache/kona-types}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
proj=$(mktemp -d /tmp/kona-types-proj.XXXXXX)
trap 'rm -rf "$proj"' EXIT
G=$(cd "$(dirname "$0")/../../.." && pwd)
SP="$G/import/kona-arm/ghidra_scripts;$G/types/kona-types/ghidra_scripts;$G/types/kona-types/tests"

rm -f "$OUT/arm1.u.dump"
analyzeHeadless "$proj" p -import $(sw ucode/KONA/arm1.u) -loader BinaryLoader \
    -processor ARM:BE:32:v4 -scriptPath "$SP" \
    -preScript KonaArmImport.java "$(pwd)" -postScript KonaTypes.java "$(pwd)" \
    -postScript DumpTypes.java "$OUT/arm1.u.dump" -deleteProject \
    >"$OUT/arm1.u.log" 2>&1 || { tail -40 "$OUT/arm1.u.log"; exit 1; }
grep 'KonaTypes.java>' "$OUT/arm1.u.log" || true

rm -f "$OUT/kernel.dump"
analyzeHeadless "$proj" p -import $(sw 'kona_kernel/kona_*.o') -scriptPath "$SP" \
    -postScript KonaTypes.java "$(pwd)" -postScript DumpTypes.java "$OUT/kernel.dump" \
    -deleteProject >"$OUT/kernel.log" 2>&1 || { tail -40 "$OUT/kernel.log"; exit 1; }
grep -c 'KonaTypes.java> hh' "$OUT/kernel.log" || true
