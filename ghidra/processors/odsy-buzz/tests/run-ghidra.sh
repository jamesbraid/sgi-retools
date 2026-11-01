#!/bin/sh
# Build the ODSY-BUZZ module and run the Ghidra half of its acceptance tests.
#
#   ghidra/processors/odsy-buzz/tests/run-ghidra.sh [OUTDIR]     (default .cache/odsy-buzz)
#
# Run from the repository root with Ghidra's support directory (sleigh,
# analyzeHeadless) on PATH and root/ populated. It writes, under OUTDIR:
#   xform.listing, xform.functions, decomp/*.c   ucode/ODSY/buzz_xform.bin
#   kernel.listing, kernel.functions             ucode/buzz_ucode_ip30.bin
#   diag.listing, diag.functions                 the field diagnostics' diagxform.bin
# and ghidra/processors/odsy-buzz/tests/check.py then compares them with
# scripts/buzz_ucode_disasm.py and the documents.
set -eu
MOD=ghidra/processors/odsy-buzz
OUT=${1:-.cache/odsy-buzz}
DIAG=root/builds/odydiags-6.5.15/usr/diags/ody/ucode/diagxform.bin
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
GHIDRA=$(dirname "$(dirname "$(readlink -f "$(command -v analyzeHeadless)")")")
props=$GHIDRA/Ghidra/application.properties
ver=$(sed -n 's/^application.version=//p' "$props")
rel=$(sed -n 's/^application.release.name=//p' "$props")

# A private settings directory with the module installed as an extension.
cfg=$(mktemp -d "${TMPDIR:-/tmp}/odsy-buzz-cfg.XXXXXX")
proj=$(mktemp -d "${TMPDIR:-/tmp}/odsy-buzz-proj.XXXXXX")
trap 'rm -rf "$cfg" "$proj"' EXIT
# Java takes its home from the password database, not $HOME, and Ghidra
# prefixes the user name to a settings directory outside that home.
export HOME="$cfg" XDG_CONFIG_HOME="$cfg/.config" XDG_CACHE_HOME="$cfg/.cache"
export JAVA_TOOL_OPTIONS="-Duser.home=$cfg"
ext="$cfg/.config/ghidra/ghidra_${ver}_$rel/Extensions"
mkdir -p "$ext"
ln -s "$(pwd)/$MOD" "$ext/odsy-buzz"

sleigh "$MOD/data/languages/odsy_buzz.slaspec" >/dev/null

headless() {
    analyzeHeadless "$proj" p -scriptPath "$MOD/ghidra_scripts;$MOD/tests" "$@" -deleteProject
}

# Three routines whose arithmetic the documents give: the clip-plane routine
# 0, the unlit transform program 214 and the normalize program 1520.
headless -import ucode/ODSY/buzz_xform.bin -loader BinaryLoader \
    -processor ODSY-BUZZ:BE:16:default -preScript BuzzImport.java \
    -postScript DumpFunctions.java "$OUT/xform.functions" \
    -postScript DecompileAt.java "$OUT/decomp" 0 214 1520 \
    -postScript DumpListing.java "$OUT/xform.listing"

headless -import ucode/buzz_ucode_ip30.bin -loader BinaryLoader \
    -processor ODSY-BUZZ:BE:16:default -preScript BuzzImport.java \
    -postScript DumpFunctions.java "$OUT/kernel.functions" \
    -postScript DumpListing.java "$OUT/kernel.listing"

if [ -e "$DIAG" ]; then
    headless -import "$DIAG" -loader BinaryLoader \
        -processor ODSY-BUZZ:BE:16:default -preScript BuzzImport.java \
        -postScript DumpFunctions.java "$OUT/diag.functions" \
        -postScript DumpListing.java "$OUT/diag.listing"
fi
