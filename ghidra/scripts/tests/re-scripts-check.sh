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

cid=$($engine create -w /work -e HOME=/tmp "$tag" sh -c '
    proj=$(mktemp -d); cd /work
    analyzeHeadless "$proj" mips -import in/synthetic.bin -loader BinaryLoader -loader-baseAddr 0xbfc00000 \
        -processor MIPS:BE:64:64-32addr -noanalysis -scriptPath /work/scripts \
        -postScript FixtureSetup.java in/functions.tsv \
        -postScript WalkDump.java /work/calls.tsv /work/accesses.tsv \
        -deleteProject > /work/headless-mips.txt 2>&1
    analyzeHeadless "$proj" ia64 -import in/ia64.bin -loader BinaryLoader -loader-baseAddr 0x80000 \
        -processor IA64:LE:64:default -noanalysis -scriptPath /work/scripts \
        -postScript FixtureSetup.java in/ia64-functions.tsv \
        -postScript WalkDump.java /work/ia64-calls.tsv /work/ia64-accesses.tsv \
        -deleteProject > /work/headless-ia64.txt 2>&1')
trap '$engine rm -f "$cid" >/dev/null 2>&1' EXIT
$engine cp "$out/in" "$cid:/work/in"
$engine cp "$out/scripts" "$cid:/work/scripts"
$engine start -a "$cid" >/dev/null 2>&1 || true
for f in calls.tsv accesses.tsv ia64-calls.tsv ia64-accesses.tsv headless-mips.txt headless-ia64.txt; do
    $engine cp "$cid:/work/$f" "$out/$f" || { echo "FAIL: Ghidra wrote no $f"; $engine cp "$cid:/work/headless-mips.txt" "$out/headless-mips.txt" && tail -30 "$out/headless-mips.txt"; exit 1; }
done
cp "$out"/in/*expected-*.tsv "$out/"
status=0
python3 $T/mips_synthetic.py check-walks "$out" || status=1
python3 $T/mips_synthetic.py check-walks "$out" ia64- || status=1
exit $status
