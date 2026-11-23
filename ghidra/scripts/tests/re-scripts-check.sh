#!/bin/sh
# Check the shared Ghidra scripts on synthetic images: Python writes and checks, the Ghidra image runs.
#
#   ghidra/scripts/tests/re-scripts-check.sh [OUTDIR]
#
# Needs python3 and a container engine (ENGINE=podman or docker) with the Ghidra image named by IMAGE
# (default re-ghidra:ci, as built by ghidra/processors/ia64/tests/ci.sh). OUTDIR defaults to
# .cache/re-scripts-check. The scripts under test are copied into the container from this checkout, not
# read from the image, and files are copied in and out, so it works inside a CI container.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../.." && pwd)
cd "$top"
engine=${ENGINE:-podman}
tag=${IMAGE:-re-ghidra:ci}
out=${1:-.cache/re-scripts-check}
T=ghidra/scripts/tests
rm -rf "$out"
mkdir -p "$out/in" "$out/scripts"
python3 $T/mips_synthetic.py
python3 $T/mips_synthetic.py write "$out/in"
python3 ghidra/processors/ia64/tests/synthetic.py write-walk "$out/in"
# The scripts under test, with the check's own scripts beside them: the helper classes are only visible to
# scripts in their own directory, and the rest of tests/ needs classes that are not on the script path.
cp ghidra/scripts/*.java $T/FixtureSetup.java $T/WalkDump.java "$out/scripts"

# One headless run per fixture: the walks, then the scripts whose output is compared with a golden or a walk.
run='proj=$(mktemp -d); cd /work
    go() {  # go NAME HELPER-ADDRESS HELPER-NAME IMPORT-ARGS...
        name=$1; at=$2; helper=$3; shift 3
        analyzeHeadless "$proj" "$name" -import "$@" -noanalysis -scriptPath /work/scripts \
            -postScript FixtureSetup.java in/$name-functions.tsv $at \
            -postScript WalkDump.java /work/$name-calls.tsv /work/$name-accesses.tsv \
            -postScript DumpCallEdges.java /work/$name-edges.tsv \
            -postScript DumpCallEdges.java /work/$name-sites.tsv sites \
            -postScript FindWindowStores.java /work/$name-stores.tsv - \
            -postScript FindWindowStores.java /work/$name-helper.tsv "$helper" \
            -deleteProject > /work/headless-$name.txt 2>&1
    }
    go mips 0xbfc00500 FUN_bfc00500 in/mips.bin -loader BinaryLoader -loader-baseAddr 0xbfc00000 -processor MIPS:BE:64:64-32addr
    go ia64 0x80100 FUN_ram_00080100 in/ia64.bin -loader BinaryLoader -loader-baseAddr 0x80000 -processor IA64:LE:64:default'
cid=$($engine create -w /work -e HOME=/tmp "$tag" bash -c "$run")
trap '$engine rm -f "$cid" >/dev/null 2>&1' EXIT
$engine cp "$out/in" "$cid:/work/in"
$engine cp "$out/scripts" "$cid:/work/scripts"
$engine start -a "$cid" >/dev/null 2>&1 || true
for f in mips-calls.tsv mips-accesses.tsv mips-edges.tsv mips-sites.tsv mips-stores.tsv mips-helper.tsv headless-mips.txt \
         ia64-calls.tsv ia64-accesses.tsv ia64-edges.tsv ia64-sites.tsv ia64-stores.tsv ia64-helper.tsv headless-ia64.txt; do
    $engine cp "$cid:/work/$f" "$out/$f" || { echo "FAIL: Ghidra wrote no $f"; $engine cp "$cid:/work/headless-${f%%-*}.txt" "$out/" && tail -30 "$out/headless-${f%%-*}.txt"; exit 1; }
done
cp "$out"/in/*expected-*.tsv "$out/"
status=0
python3 $T/mips_synthetic.py check-walks "$out" mips- || status=1
python3 $T/mips_synthetic.py check-walks "$out" ia64- || status=1
for p in mips ia64; do
    python3 $T/mips_synthetic.py check-golden "$out" $T/golden $p || status=1
    python3 $T/mips_synthetic.py check-sites "$out" $p || status=1
done
exit $status
