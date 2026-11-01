#!/bin/sh
# Copy the model files a census config names out of the emulator model repository, read only.
#   tools/export-model.sh CONFIG.json MODEL_CHECKOUT REF
# Writes work/model/<file> and work/model/MODEL_REV. Nothing in the checkout changes.
set -eu
cd "$(dirname "$0")/.."
CONFIG=${1:?config}; REPO=${2:?model checkout}; REF=${3:-HEAD}
mkdir -p work/model
git -C "$REPO" rev-parse "$REF" > work/model/MODEL_REV
python3 - "$CONFIG" <<'PY' | while read -r f; do
import json, sys
c = json.load(open(sys.argv[1]))
seen = set()
for v in c['reference'].values():
    for q in v.get('model', []):
        if q['file'] not in seen:
            seen.add(q['file']); print(q['file'])
PY
    # the config names the file by basename; find its path in the tree
    path=$(git -C "$REPO" ls-tree -r --name-only "$REF" | grep "/$f\$" | head -1)
    git -C "$REPO" show "$REF:$path" > "work/model/$f"
done
cat work/model/MODEL_REV
