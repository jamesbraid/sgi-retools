#!/bin/sh
# Regenerate the census units in defs/, then check the hardware definitions and build every output.
set -eu
HERE=$(dirname "$(readlink -f "$0")")
python3 "$HERE/gen_headers.py"
"$HERE/../defs/defs-gen"
"$HERE/../defs/defs-check" --build
