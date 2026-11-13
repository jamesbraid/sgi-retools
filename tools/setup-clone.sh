#!/bin/sh
# Prepare a fresh clone of this repository to run its tools.
#
#   tools/setup-clone.sh [--root DIR] [--submodules "NAME ..."|all]
#
# Run it from inside the clone. It
#   - clones the sibling repositories named in tools/config/inventory-siblings.json
#     (scripts/inventory-siblings.json on the old layout) into .cache/siblings/, each
#     at the commit pinned there;
#   - initialises the retools submodule (the shared tooling) at the pinned commit;
#   - initialises the public-source submodules the tools read (m2c, spimdisasm
#     and ogl-sample, under references/code/ or at the top of an old layout, where
#     this repository has them; --submodules picks others by name, `all` takes
#     every one, which is several gigabytes);
#   - checks that root/ exists, linking it to DIR when --root is given.
#
# The IRIX files themselves are not in the repository and not downloadable
# from here. Copy the paths in the `files` block of evidence/irix-files.md
# (IRIX_FILES.md on the old layout) from your own
# IRIX 6.5.30 install or media into root/, keeping the directory layout.
#
# Siblings are cloned from the same place as this repository: the URL of the
# `origin` remote with its last component swapped for the sibling's name.
# Set SIBLING_BASE=URL to clone them from somewhere else.
set -eu
root_dir=
subs=
while [ $# -gt 0 ]; do
    case $1 in
        --root) root_dir=${2:?--root needs a directory}; shift 2 ;;
        --submodules) subs=${2:?--submodules needs a list}; shift 2 ;;
        -h|--help) sed -n '2,/^set -eu/{/^set -eu/!p;}' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'setup-clone: unknown argument %s\n' "$1" >&2; exit 2 ;;
    esac
done
# A workspace's tools/setup-clone.sh is a small stub that fetches the retools submodule and
# runs this file, so the workspace is the superproject of the submodule this file is in.
here=$(dirname "$0")
top=$(git -C "$here/.." rev-parse --show-superproject-working-tree 2>/dev/null || true)
cd "${top:-$here/..}"

# Keep the submodule at the pinned commit (the stub did the first checkout).
if [ -f .gitmodules ] && git ls-files --stage -- retools | grep -q '^160000'; then
    git submodule update -q --init retools
fi

pins=tools/config/inventory-siblings.json
[ -f "$pins" ] || pins=scripts/inventory-siblings.json
if [ -f "$pins" ]; then
    list=$(python3 -c '
import json, sys
for fam, sha in sorted(json.load(open(sys.argv[1])).items()):
    print(fam, sha)' "$pins")
else
    list=
fi
if [ -n "$list" ]; then
    base=${SIBLING_BASE:-}
    if [ -z "$base" ]; then
        origin=$(git remote get-url origin 2>/dev/null) || {
            printf 'setup-clone: no origin remote; set SIBLING_BASE=URL\n' >&2; exit 2; }
        base=${origin%/*}
    fi
    mkdir -p .cache/siblings
    printf '%s\n' "$list" | while read -r fam sha; do
        dir=.cache/siblings/$fam
        [ -d "$dir/.git" ] || git clone -q "$base/$fam.git" "$dir"
        git -C "$dir" cat-file -e "$sha^{commit}" 2>/dev/null || git -C "$dir" fetch -q origin
        git -C "$dir" checkout -q "$sha"
        printf 'sibling %s at %s\n' "$fam" "$(printf %.12s "$sha")"
    done
fi

if [ -f .gitmodules ]; then
    if [ "$subs" = all ]; then
        git submodule update -q --init --depth 1
        printf 'submodules initialised: all\n'
    else
        if [ -z "$subs" ]; then
            for n in m2c spimdisasm ogl-sample; do
                # only paths that are recorded as submodules in the tree
                if git ls-files --stage -- "references/code/$n" | grep -q '^160000'; then
                    subs="$subs references/code/$n"
                elif git ls-files --stage -- "$n" | grep -q '^160000'; then
                    subs="$subs $n"
                fi
            done
        fi
        # a name given on the command line means references/code/NAME once the repository has moved
        mapped=
        # shellcheck disable=SC2086
        for n in $subs; do
            case $n in references/code/*) mapped="$mapped $n"; continue ;; esac
            if git ls-files --stage -- "references/code/$n" | grep -q '^160000'; then
                mapped="$mapped references/code/$n"
            else
                mapped="$mapped $n"
            fi
        done
        subs=$mapped
        # shellcheck disable=SC2086
        if [ -n "$subs" ]; then
            git submodule update -q --init --depth 1 -- $subs
            printf 'submodules initialised:%s\n' "$subs"
        fi
    fi
fi

if [ -n "$root_dir" ] && [ ! -e root ]; then
    ln -s "$root_dir" root
fi
if [ -d root ]; then
    printf 'root/ present: %s\n' "$(cd root && pwd -P)"
else
    mkdir root
    printf 'root/ is empty. Fill it from your own IRIX 6.5.30 install as evidence/irix-files.md (IRIX_FILES.md on the old layout) describes.\n'
fi
printf 'Run a tool with: retools/tools/re-run python3 retools/tools/inventory.py\n'
