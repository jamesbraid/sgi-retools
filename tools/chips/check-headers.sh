#!/bin/sh
# Regenerate include/*.h and compile them together in the build container.
set -eu
HERE=$(dirname "$(readlink -f "$0")")
python3 "$HERE/gen_headers.py"
"$HERE/../re-run" sh -c 'CCACHE_DISABLE=1 mips64-linux-gnuabi64-gcc -std=c99 -Wall -Werror -Iinclude -c include/chips_check.c -o /tmp/chips_check.o && echo headers compile'
