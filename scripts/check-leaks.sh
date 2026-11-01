#!/bin/sh
# Pre-push check: no forbidden terms or private paths in tracked files, no trailers in commit messages.
# Exit 1 on any hit. Run from the repository root.
#
# The forbidden terms are not in this file. They come from the first of these that exists:
#   $RE_LEAK_TERMS                          a file named in the environment
#   scripts/leak-terms.txt                  the repository's own list (tracked, so clones have it)
#   .re-leak-terms                          in the repository root (git-ignored)
#   ${XDG_CONFIG_HOME:-$HOME/.config}/re-leak-terms
# With none of them the check fails: an unchecked push is never let through quietly.
#
# One entry per line; blank lines and lines starting with # are ignored.
#   term: ERE                       a hit in any tracked file (case-insensitive)
#   allow: LITERAL                  removed from a line before the terms are applied
#   exempt: PATH-ERE<TAB>LINE-ERE   a line of a matching file that is never reported
#   skip: PATH-ERE                  files that are not read at all
#   message: ERE                    a hit in a commit message
# Commit messages are always checked for Co-Authored-By and Signed-off-by trailers.
set -u
terms=${RE_LEAK_TERMS:-}
if [ -z "$terms" ]; then
    for c in scripts/leak-terms.txt .re-leak-terms "${XDG_CONFIG_HOME:-$HOME/.config}/re-leak-terms"; do
        [ -r "$c" ] && { terms=$c; break; }
    done
fi
if [ -z "$terms" ] || [ ! -r "$terms" ]; then
    echo "check-leaks: no term list: put one in scripts/leak-terms.txt, .re-leak-terms, ${XDG_CONFIG_HOME:-$HOME/.config}/re-leak-terms or RE_LEAK_TERMS" >&2
    exit 1
fi
join() { sed -n "s/^$1: *//p" "$terms" | paste -sd'|' -; }
pat=$(join term)
msgpat=$(join message)
skip=$(join skip)
allows=$(sed -n 's/^allow: *//p' "$terms")
[ -n "$pat" ] || { echo "check-leaks: $terms names no term" >&2; exit 1; }
# the shared tooling and the licence text name things the terms would flag
skip="scripts/check-leaks\.sh|scripts/leak-terms\.txt|scripts/LICENSE-gr4|LICENSE|retools(/|$)${skip:+|$skip}"
bad=0
git ls-files -z | xargs -0 grep -I -n -i -E "$pat" -- 2>/dev/null | grep -v -E "^($skip)" |
    while IFS= read -r l; do
        f=${l%%:*}
        # exempt lines: PATH-ERE <TAB> LINE-ERE
        ex=$(sed -n 's/^exempt: *//p' "$terms" | while IFS="$(printf '\t')" read -r pp lp; do
            printf '%s\n' "$f" | grep -q -E "$pp" && printf '%s\n' "$l" | grep -q -E "$lp" && echo y
        done)
        [ -n "$ex" ] && continue
        # a line with any other hit stays reported once the allowed literals are removed
        t=$l
        for a in $allows; do t=$(printf '%s\n' "$t" | sed "s/$a//Ig"); done
        printf '%s\n' "$t" | grep -q -i -E "$pat" && printf '%s\n' "$l"
    done | grep . && bad=1
if [ -n "$msgpat" ]; then
    git log --format=%B | grep -i -E "$msgpat" && bad=1
fi
git log --format=%B | grep -i -E '^(Co-Authored-By|Signed-off-by):' && bad=1
exit $bad
