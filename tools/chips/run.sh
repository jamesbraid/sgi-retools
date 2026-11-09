#!/bin/sh
# Whole census for one ASIC.
#   retools/tools/chips/run.sh configs/ASIC.json DATASHEET_REPO MODEL_CHECKOUT [MODEL_REF]
# No-spec chips need no comparison: pass - for DATASHEET_REPO and MODEL_CHECKOUT.
# The comparison needs the emulator's datasheet checkout and model source; without them use stages 1-2 and retools/tools/chips/fields.py only.
# Needs python3 on the host; the only container step is retools/tools/chips/disasm.sh.
# SPEC_DIR=dir holds the register-map transcriptions named by a config's spec entries.
# SKIP_DISASM=1 reuses work/dis. NOTES=file appends hand-written findings to the report.
# Output lands in work/ASIC/ and is copied to chips/*/census/ASIC/.
set -eu
HERE=$(dirname "$(readlink -f "$0")")
CONFIG=${1:?config}; REPO=${2:?datasheet repo}; model=${3:?model checkout}; REF=${4:-HEAD}
ASIC=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['asic'])" "$CONFIG")
mkdir -p "work/$ASIC"
[ -n "${SKIP_DISASM:-}" ] || "$HERE/disasm.sh" "$CONFIG"
if [ "$model" != - ]; then "$HERE/export-model.sh" "$CONFIG" "$model" "$REF"; else mkdir -p work/model; fi
python3 "$HERE/scan.py" "$CONFIG" --base "$PWD" --out "work/$ASIC"
python3 "$HERE/ref.py" "$CONFIG" --repo "$REPO" --model work/model ${SPEC_DIR:+--spec-dir "$SPEC_DIR"} --out "work/$ASIC/ref.json"
python3 "$HERE/join.py" "$CONFIG" --sites "work/$ASIC/sites.tsv" --ref "work/$ASIC/ref.json" --out "work/$ASIC/$ASIC"
mkdir -p "chips/$ASIC/census"
python3 "$HERE/report.py" "$CONFIG" --dir "work/$ASIC" --repo "$REPO" --out "chips/$ASIC/census/census.md" ${NOTES:+--notes "$NOTES"}
python3 "$HERE/fields.py" "$CONFIG" --sites "work/$ASIC/sites.tsv" --calls "work/$ASIC/accessor-calls.tsv" --out "work/$ASIC/$ASIC"
for f in census census-sites census-windows; do cp "work/$ASIC/$ASIC-$f.tsv" "chips/$ASIC/census/$f.tsv"; done
cp "work/$ASIC/$ASIC-fields.tsv" "chips/$ASIC/census/fields.tsv"
cp "work/$ASIC/$ASIC-context.tsv" "chips/$ASIC/census/context.tsv"
