#!/bin/sh
# Build the KONA-GE module and run the Ghidra half of its acceptance tests.
#
#   ghidra/processors/kona-ge/tests/run-ghidra.sh [OUTDIR]     (default .cache/kona-ge)
#
# Run from the repository root with Ghidra's support directory (sleigh,
# analyzeHeadless) on PATH and root/ populated. It writes, under OUTDIR:
#   prod.functions, prod.listing, decomp/*.c   production ucode/KONA/ge.u
#   diag.listing                               usr/diags/IR/ucode/ge.u
# and ghidra/processors/kona-ge/tests/check.py then compares them with the Python
# disassembler and the documents.
set -eu
# A path written for the old layout, as this workspace has it (software/ucode/..., see tools/_layout.py).
sw() { python3 "$(dirname "$(readlink -f "$0")")/../../../../tools/_layout.py" sw "$1" 2>/dev/null || echo "$1"; }
MOD=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-.cache/kona-ge}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
GHIDRA=$(dirname "$(dirname "$(readlink -f "$(command -v analyzeHeadless)")")")
props=$GHIDRA/Ghidra/application.properties
ver=$(sed -n 's/^application.version=//p' "$props")
rel=$(sed -n 's/^application.release.name=//p' "$props")

# A private settings directory with the module installed as an extension.
cfg=$(mktemp -d /tmp/kona-ge-cfg.XXXXXX)
proj=$(mktemp -d /tmp/kona-ge-proj.XXXXXX)
trap 'rm -rf "$cfg" "$proj"' EXIT
# Java takes its home from the password database, not $HOME, and Ghidra
# prefixes the user name to a settings directory outside that home.
export HOME="$cfg" XDG_CONFIG_HOME="$cfg/.config" XDG_CACHE_HOME="$cfg/.cache"
export JAVA_TOOL_OPTIONS="-Duser.home=$cfg"
ext="$cfg/.config/ghidra/ghidra_${ver}_$rel/Extensions"
mkdir -p "$ext"
ln -s "$MOD" "$ext/kona-ge"

sleigh "$MOD/data/languages/kona_ge.slaspec" >/dev/null

headless() {
    analyzeHeadless "$proj" p -scriptPath "$MOD/ghidra_scripts;$MOD/tests" "$@" -deleteProject
}

# Production program: functions first, then the routines, then every word.
headless -import $(sw ucode/KONA/ge.u) -loader BinaryLoader \
    -processor KONA-GE:BE:32:default -preScript KonaGEImport.java \
    -postScript DumpFunctions.java "$OUT/prod.functions" \
    -postScript DecompileAt.java "$OUT/decomp" 0x1633 0x0e62 0x0eb0 0xf1dc \
    -postScript DumpListing.java "$OUT/prod.listing"

# The diagnostic program that irsaudit's instruction test runs.
headless -import $(sw diags/IR/ucode/ge.u) -loader BinaryLoader \
    -processor KONA-GE:BE:32:default -preScript KonaGEImport.java \
    -postScript DumpListing.java "$OUT/diag.listing"

# The same production program from its other two encodings, and the
# diagnostic set-up program: the import must give the same words.
for f in $(sw ucode/KONA/ge11.u) $(sw ucode/KONA/ge.hex) $(sw diags/IR/ucode/ge_diag_init.hex); do
    headless -import "$f" -loader BinaryLoader \
        -processor KONA-GE:BE:32:default -preScript KonaGEImport.java \
        -postScript DumpListing.java "$OUT/$(basename "$f").listing"
done
