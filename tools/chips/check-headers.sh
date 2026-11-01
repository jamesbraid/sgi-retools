#!/bin/sh
# Regenerate include/*.h and compile them together in the build container.
set -eu
cd "$(dirname "$0")/.."
python3 tools/gen_headers.py
tools/re-run sh -c 'CCACHE_DISABLE=1 mips64-linux-gnuabi64-gcc -std=c99 -Wall -Werror -Iinclude -c include/chips_check.c -o /tmp/chips_check.o && echo headers compile'
