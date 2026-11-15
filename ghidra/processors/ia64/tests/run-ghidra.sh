#!/bin/sh
# Build the IA-64 module and disassemble a flat image with it.
#
#   ghidra/processors/ia64/tests/run-ghidra.sh OUTDIR IMAGE BASE [SCRIPT ARGS...]
#
# Runs in the Ghidra image (tools/re-run --ghidra). Writes OUTDIR/slots.tsv,
# every bundle of IMAGE (loaded at BASE) disassembled, one instruction a line.
# With SCRIPT, runs that post-script from tests/ instead, with ARGS. With
# PRESCRIPT=FILE.java in the environment, runs that pre-script first, with
# PRESCRIPT_ARGS (words) after it. The scripts in ghidra/scripts are on the script path.
set -eu
MOD=$(cd "$(dirname "$0")/.." && pwd)
OUT=$1 IMAGE=$2 BASE=$3
shift 3
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
GHIDRA=$(dirname "$(dirname "$(readlink -f "$(command -v analyzeHeadless)")")")
props=$GHIDRA/Ghidra/application.properties
ver=$(sed -n 's/^application.version=//p' "$props")
rel=$(sed -n 's/^application.release.name=//p' "$props")

# The module tree may be read-only (retools mounted at /opt/retools), so install
# a copy as an extension. The slaspec is generated, not committed: take the one
# the image built (its tag covers the generator), or IA64_SLASPEC=FILE.
cfg=$(mktemp -d "${TMPDIR:-/tmp}/ia64-cfg.XXXXXX")
proj=$(mktemp -d "${TMPDIR:-/tmp}/ia64-proj.XXXXXX")
trap 'rm -rf "$cfg" "$proj"' EXIT
export HOME="$cfg" XDG_CONFIG_HOME="$cfg/.config" XDG_CACHE_HOME="$cfg/.cache"
export JAVA_TOOL_OPTIONS="-Duser.home=$cfg"
ext="$cfg/.config/ghidra/ghidra_${ver}_$rel/Extensions"
mkdir -p "$ext/ia64"
cp -r "$MOD/Module.manifest" "$MOD/extension.properties" "$MOD/data" "$ext/ia64/"
cp "${IA64_SLASPEC:-$GHIDRA/Ghidra/Processors/IA64/data/languages/ia64.slaspec}" "$ext/ia64/data/languages/ia64.slaspec"
sleigh "$ext/ia64/data/languages/ia64.slaspec" >/dev/null

if [ $# -gt 0 ]; then
    script=$1
    shift
else
    script=DumpSlots.java
    set -- "$OUT/slots.tsv"
fi
spath="$MOD/tests;$(cd "$MOD/../../scripts" && pwd)"
if [ -n "${PRESCRIPT:-}" ]; then
    spath="$spath;$(cd "$(dirname "$PRESCRIPT")" && pwd)"
    # shellcheck disable=SC2086
    set -- -preScript "$(basename "$PRESCRIPT")" ${PRESCRIPT_ARGS:-} -postScript "$script" "$@"
else
    set -- -postScript "$script" "$@"
fi
analyzeHeadless "$proj" p -import "$IMAGE" -loader BinaryLoader -loader-baseAddr "$BASE" \
    -processor IA64:LE:64:default -noanalysis -scriptPath "$spath" \
    "$@" -deleteProject > "$OUT/headless.txt" 2>&1 || {
    tail -40 "$OUT/headless.txt" >&2
    exit 1
}
