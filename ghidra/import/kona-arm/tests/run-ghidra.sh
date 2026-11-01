#!/bin/sh
# Import every KONA ARM image with KonaArmImport.java, analyse it, and dump
# what the import produced for tests/check.py.
#
#   ghidra/import/kona-arm/tests/run-ghidra.sh [OUTDIR]     (default .cache/kona-arm)
#
# Run from the repository root with analyzeHeadless on PATH and root/
# populated. Writes OUTDIR/<image>.dump and OUTDIR/<image>.log per image.
set -eu
MOD=ghidra/import/kona-arm
OUT=${1:-.cache/kona-arm}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
proj=$(mktemp -d /tmp/kona-arm-proj.XXXXXX)
trap 'rm -rf "$proj"' EXIT

for f in ucode/KONA/arm1.u ucode/KONA/arm1_kpm.u ucode/KONA/tport.bin \
         root/usr/diags/IR/ucode/arm1.u root/usr/diags/IR/ucode/arm1_nic.u \
         root/usr/diags/IR/ucode/diag_arm_init.u; do
    name=$(basename "$f")
    case $f in root/usr/diags/*) name=diag_$name ;; esac
    analyzeHeadless "$proj" p -import "$f" -loader BinaryLoader \
        -processor ARM:BE:32:v4 -scriptPath "$MOD/ghidra_scripts;$MOD/tests" \
        -preScript KonaArmImport.java "$(pwd)" \
        -postScript DumpArm.java "$OUT/$name.dump" -deleteProject \
        >"$OUT/$name.log" 2>&1 || { tail -40 "$OUT/$name.log"; exit 1; }
    grep -E 'KonaArmImport.java>|DumpArm.java>|ERROR' "$OUT/$name.log" || true
done
