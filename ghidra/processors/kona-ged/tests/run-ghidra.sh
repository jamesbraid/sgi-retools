#!/bin/sh
# Build the KONA-GED module and import ged1b.u for tests/check.py.
#
#   ghidra/processors/kona-ged/tests/run-ghidra.sh [OUTDIR]     (default .cache/kona-ged)
#
# Run from the repository root with Ghidra's support directory (sleigh,
# analyzeHeadless) on PATH and root/ populated. Writes OUTDIR/ged1b.listing.
set -eu
MOD=ghidra/processors/kona-ged
OUT=${1:-.cache/kona-ged}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
GHIDRA=$(dirname "$(dirname "$(readlink -f "$(command -v analyzeHeadless)")")")
props=$GHIDRA/Ghidra/application.properties
ver=$(sed -n 's/^application.version=//p' "$props")
rel=$(sed -n 's/^application.release.name=//p' "$props")

# A private settings directory with the module installed as an extension.
cfg=$(mktemp -d /tmp/kona-ged-cfg.XXXXXX)
proj=$(mktemp -d /tmp/kona-ged-proj.XXXXXX)
trap 'rm -rf "$cfg" "$proj"' EXIT
# Java takes its home from the password database, not $HOME, and Ghidra
# prefixes the user name to a settings directory outside that home.
export HOME="$cfg" XDG_CONFIG_HOME="$cfg/.config" XDG_CACHE_HOME="$cfg/.cache"
export JAVA_TOOL_OPTIONS="-Duser.home=$cfg"
ext="$cfg/.config/ghidra/ghidra_${ver}_$rel/Extensions"
mkdir -p "$ext"
ln -s "$(pwd)/$MOD" "$ext/kona-ged"

sleigh "$MOD/data/languages/kona_ged.slaspec" >/dev/null

analyzeHeadless "$proj" p -import ucode/KONA/ged1b.u -loader BinaryLoader \
    -processor KONA-GED:BE:32:default -scriptPath "$MOD/ghidra_scripts;$MOD/tests" \
    -preScript KonaGEDImport.java "$(pwd)" \
    -postScript DumpListing.java "$OUT/ged1b.listing" -deleteProject \
    >"$OUT/ged1b.log" 2>&1 || { tail -40 "$OUT/ged1b.log"; exit 1; }
grep -E 'KonaGEDImport.java>|ERROR' "$OUT/ged1b.log" || true
