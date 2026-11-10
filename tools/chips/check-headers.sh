#!/bin/sh
# Regenerate include/*.h and compile them together in the build container.
set -eu
HERE=$(dirname "$(readlink -f "$0")")
python3 "$HERE/gen_headers.py"
# The headers are plain C99 macros, so any host C compiler checks them; the toolchain container has binutils
# but no compiler, which is why this step used to fail there.
CC=${CC:-$(command -v cc || command -v gcc)}
"$CC" -std=c99 -Wall -Werror -Iinclude -c include/chips_check.c -o /dev/null && echo headers compile
