#!/bin/sh
# Build the GE11 module and run the Ghidra half of its tests.
#
#   ghidra/processors/ge11/tests/run-ghidra.sh [OUTDIR]   (default .cache/ge11)
#
# Run from the repository root with Ghidra's support directory (sleigh,
# analyzeHeadless) on PATH and root/ populated (IRIX_FILES.md, including the
# optional 6.5.7 diagnostic files). It writes, under OUTDIR:
#   prod.functions, prod.listing, decomp/*.c   ucode/mgras_ge.u (records)
#   hex.listing                                the same program from
#                                              mgras_ge.hex alone (table)
#   bin.listing                                ucode/ge11.bin alone (table)
#   diag.listing, diag.functions               the 6.5.7 diagnostic program
# and ghidra/processors/ge11/tests/check.py then compares them.
set -eu
MOD=ghidra/processors/ge11
OUT=${1:-.cache/ge11}
DIAG=root/irix-6.5.7-src/stand/arcs/ide/isddevices/graphics/MGRAS
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
# A failed import leaves no file behind, rather than last run's.
rm -rf "$OUT/decomp" "$OUT"/*.listing "$OUT"/*.functions
GHIDRA=$(dirname "$(dirname "$(readlink -f "$(command -v analyzeHeadless)")")")
props=$GHIDRA/Ghidra/application.properties
ver=$(sed -n 's/^application.version=//p' "$props")
rel=$(sed -n 's/^application.release.name=//p' "$props")

# A private settings directory with the module installed as an extension.
cfg=$(mktemp -d /tmp/ge11-cfg.XXXXXX)
proj=$(mktemp -d /tmp/ge11-proj.XXXXXX)
lone=$(mktemp -d /tmp/ge11-lone.XXXXXX)
trap 'rm -rf "$cfg" "$proj" "$lone"' EXIT
# Java takes its home from the password database, not $HOME, and Ghidra
# prefixes the user name to a settings directory outside that home.
export HOME="$cfg" XDG_CONFIG_HOME="$cfg/.config" XDG_CACHE_HOME="$cfg/.cache"
export JAVA_TOOL_OPTIONS="-Duser.home=$cfg"
ext="$cfg/.config/ghidra/ghidra_${ver}_$rel/Extensions"
mkdir -p "$ext"
ln -s "$(pwd)/$MOD" "$ext/ge11"

sleigh "$MOD/data/languages/ge11.slaspec" >/dev/null

headless() {
    analyzeHeadless "$proj" p -scriptPath "$MOD/ghidra_scripts;$MOD/tests" "$@" -deleteProject
}

# Production program with its records: functions, a few routines, every word.
headless -import ucode/mgras_ge.u -loader BinaryLoader -processor GE11:BE:32:default \
    -preScript GE11Import.java \
    -postScript DumpFunctions.java "$OUT/prod.functions" \
    -postScript DecompileAt.java "$OUT/decomp" 0x0e58 0x114e 0x298f \
    -postScript DumpListing.java "$OUT/prod.listing"

# The same program from its words alone, through the decode table: the hex
# away from its .u, and the raw image the kernel loads.
cp ucode/mgras_ge.hex "$lone/mgras_ge.hex"
headless -import "$lone/mgras_ge.hex" -loader BinaryLoader -processor GE11:BE:32:default \
    -preScript GE11Import.java -postScript DumpListing.java "$OUT/hex.listing"
headless -import ucode/ge11.bin -loader BinaryLoader -processor GE11:BE:32:default \
    -preScript GE11Import.java -postScript DumpListing.java "$OUT/bin.listing"

# The 6.5.7 diagnostic program, with its label table.
headless -import "$DIAG/mgras_ge.hex" -loader BinaryLoader -processor GE11:BE:32:default \
    -preScript GE11Import.java "$DIAG/ge11symtab.h" \
    -postScript DumpFunctions.java "$OUT/diag.functions" \
    -postScript DumpListing.java "$OUT/diag.listing"
