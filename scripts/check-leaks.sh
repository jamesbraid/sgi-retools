#!/bin/sh
# Leak check: no forbidden terms or private paths in what a push adds, no trailers in its
# commit messages. The work is done by check-leaks.py beside this file; run it with --help.
exec python3 "$(dirname "$(readlink -f "$0")")/check-leaks.py" "$@"
