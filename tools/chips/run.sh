#!/bin/sh
# Whole census for one ASIC.
#   tools/run.sh configs/ASIC.json DATASHEET_REPO MODEL_CHECKOUT [MODEL_REF]
# No-spec chips need no comparison: pass - for DATASHEET_REPO and MODEL_CHECKOUT.
# The comparison needs the emulator's datasheet checkout and model source; without them use stages 1-2 and tools/fields.py only.
# Needs python3 on the host; the only container step is tools/disasm.sh.
# SPEC_DIR=dir holds the register-map transcriptions named by a config's spec entries.
# SKIP_DISASM=1 reuses work/dis. NOTES=file appends hand-written findings to the report.
# Output lands in work/ASIC/ and is copied to chips/*/census/ASIC/.
set -eu
cd "$(dirname "$0")/.."
CONFIG=${1:?config}; REPO=${2:?datasheet repo}; model=${3:?model checkout}; REF=${4:-HEAD}
ASIC=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['asic'])" "$CONFIG")
mkdir -p "work/$ASIC"
[ -n "${SKIP_DISASM:-}" ] || tools/disasm.sh "$CONFIG"
if [ "$model" != - ]; then tools/export-model.sh "$CONFIG" "$model" "$REF"; else mkdir -p work/model; fi
python3 tools/scan.py "$CONFIG" --base "$PWD" --out "work/$ASIC"
python3 tools/ref.py "$CONFIG" --repo "$REPO" --model work/model ${SPEC_DIR:+--spec-dir "$SPEC_DIR"} --out "work/$ASIC/ref.json"
python3 tools/join.py "$CONFIG" --sites "work/$ASIC/sites.tsv" --ref "work/$ASIC/ref.json" --out "work/$ASIC/$ASIC"
mkdir -p "chips/$ASIC/census"
python3 tools/report.py "$CONFIG" --dir "work/$ASIC" --repo "$REPO" --out "chips/$ASIC/census/census.md" ${NOTES:+--notes "$NOTES"}
python3 tools/fields.py "$CONFIG" --sites "work/$ASIC/sites.tsv" --calls "work/$ASIC/accessor-calls.tsv" --out "work/$ASIC/$ASIC"
for f in census census-sites census-windows; do cp "work/$ASIC/$ASIC-$f.tsv" "chips/$ASIC/census/$f.tsv"; done
cp "work/$ASIC/$ASIC-fields.tsv" "chips/$ASIC/census/fields.tsv"
cp "work/$ASIC/$ASIC-context.tsv" "chips/$ASIC/census/context.tsv"
