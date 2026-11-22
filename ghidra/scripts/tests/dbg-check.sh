#!/bin/sh
# Check ReDbgImport.java on a synthetic x86 PE and its .dbg: Python writes and checks, the Ghidra image imports.
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
    analyzeHeadless "$proj" p -import in/synthetic.dll -loader PeLoader -noanalysis \
        -scriptPath "/opt/re-scripts;/work/tests" -preScript ReDbgImport.java in/synthetic.dbg \
        -postScript DumpDbgSymbols.java /work/symbols.tsv -deleteProject > /work/headless.txt 2>&1')
trap '$engine rm -f "$cid" >/dev/null 2>&1' EXIT
$engine cp "$out" "$cid:/work/in"
$engine cp ghidra/scripts/tests "$cid:/work/tests"
$engine start -a "$cid" >/dev/null 2>&1 || true
$engine cp "$cid:/work/symbols.tsv" "$out/symbols.tsv" || { echo "FAIL: Ghidra wrote no symbols"; exit 1; }
$engine cp "$cid:/work/headless.txt" "$out/headless.txt"
python3 ghidra/scripts/tests/dbg_synthetic.py check "$out/symbols.tsv" "$out/headless.txt"
