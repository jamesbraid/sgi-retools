#!/bin/sh
# Check ReDbgImport.java on a synthetic x86 PE and its .dbg files (COFF symbols, CodeView NB09
# publics), and ReReturning.java on callers of a wrongly no-return routine: Python writes and checks,
# the Ghidra image imports.
#
#   ghidra/scripts/tests/dbg-check.sh [OUTDIR]
#
# Needs python3 and a container engine (ENGINE=podman or docker) with the Ghidra image named by
# IMAGE (default re-ghidra:ci, as built by ghidra/processors/ia64/tests/ci.sh). OUTDIR defaults to
# .cache/dbg-check. Files are copied in and out, not bind-mounted, so it works inside a CI container.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../.." && pwd)
cd "$top"
engine=${ENGINE:-podman}
tag=${IMAGE:-re-ghidra:ci}
out=${1:-.cache/dbg-check}
rm -rf "$out"
mkdir -p "$out"
python3 ghidra/scripts/tests/dbg_synthetic.py
python3 ghidra/scripts/tests/dbg_synthetic.py write "$out"
cid=$($engine create -w /work -e HOME=/tmp "$tag" sh -c '
    proj=$(mktemp -d); cd /work
    for case in coff nb09 coff-va coff-low; do
        dll=synthetic.dll
        case $case in
            coff) dbg=synthetic.dbg ;;
            nb09) dbg=synthetic-nb09.dbg ;;
            coff-va) dbg=synthetic-va.dbg ;;
            coff-low) dbg=synthetic-low.dbg; dll=synthetic-low.dll ;;
        esac
        analyzeHeadless "$proj" p$case -import in/$dll -loader PeLoader -noanalysis \
            -scriptPath "/opt/re-scripts;/work/tests" -preScript ReDbgImport.java in/$dbg \
            -postScript DumpDbgSymbols.java /work/symbols-$case.tsv -deleteProject > /work/headless-$case.txt 2>&1
    done
    analyzeHeadless "$proj" preturning -import in/synthetic-returning.dll -loader PeLoader -noanalysis \
        -scriptPath "/opt/re-scripts;/work/tests" -postScript ReReturningSetup.java 1000 1010 1020 1040 \
        -postScript DumpFunctionBodies.java /work/bodies-before.tsv -postScript ReReturning.java @0x10001000 \
        -postScript DumpFunctionBodies.java /work/bodies-after.tsv -deleteProject > /work/headless-returning.txt 2>&1')
trap '$engine rm -f "$cid" >/dev/null 2>&1' EXIT
$engine cp "$out" "$cid:/work/in"
$engine cp ghidra/scripts/tests "$cid:/work/tests"
$engine start -a "$cid" >/dev/null 2>&1 || true
status=0
for case in coff nb09 coff-va coff-low; do
    $engine cp "$cid:/work/symbols-$case.tsv" "$out/symbols-$case.tsv" || { echo "FAIL: Ghidra wrote no $case symbols"; exit 1; }
    $engine cp "$cid:/work/headless-$case.txt" "$out/headless-$case.txt"
    python3 ghidra/scripts/tests/dbg_synthetic.py check $case "$out/symbols-$case.tsv" "$out/headless-$case.txt" || status=1
done
for f in bodies-before.tsv bodies-after.tsv headless-returning.txt; do
    $engine cp "$cid:/work/$f" "$out/$f" || { echo "FAIL: Ghidra wrote no $f"; exit 1; }
done
python3 ghidra/scripts/tests/dbg_synthetic.py check-returning "$out/bodies-before.tsv" "$out/bodies-after.tsv" \
    "$out/headless-returning.txt" || status=1
exit $status
