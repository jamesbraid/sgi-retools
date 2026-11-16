#!/bin/sh
# The checks that need no firmware: the Python tests, then the Ghidra ones on the synthetic images.
#
#   ghidra/processors/ia64/tests/ci.sh
#
# Needs python3 and a container engine (ENGINE=podman, or docker). Builds the Ghidra image from
# tools/Containerfile.ghidra as re-ghidra:ci (IMAGE=TAG to name it), writes under .cache/ia64-ci.
# Exits 1 if any check fails; the README lists what each one covers.
set -u
here=$(cd "$(dirname "$0")" && pwd)
top=$(cd "$here/../../../.." && pwd)
cd "$top"
T=ghidra/processors/ia64/tests
S="python3 $T/synthetic.py"
engine=${ENGINE:-podman}
tag=${IMAGE:-re-ghidra:ci}
out=.cache/ia64-ci
rc=0

# The checks run in a container whose files are copied in and out, not bind-mounted, because a CI job
# that is itself a container reaches the engine's host, where its own paths do not exist.
gh() {
    cid=$($engine create -w /work -e HOME=/tmp -e "PE=${PE:-}" -e "PRESCRIPT=${PRESCRIPT:-}" \
        -e "PRESCRIPT_ARGS=${PRESCRIPT_ARGS:-}" "$tag" sh /work/$T/run-ghidra.sh "$@") &&
        $engine cp ghidra "$cid:/work/ghidra" && $engine cp .cache "$cid:/work/.cache" &&
        $engine start -a "$cid" > "$out/last.txt" 2>&1 &&
        $engine cp "$cid:/work/$out/." "$out" > /dev/null || {
            echo "FAIL ghidra: $*"; tail -5 "$out/last.txt"; rc=1; }
    [ -z "${cid:-}" ] || $engine rm -f "$cid" > /dev/null 2>&1
}
ok() { "$@" || rc=1; }
dec() {  # dec ARGS... : DecompileAt.java over the synthetic image
    gh $out $out/synthetic.bin 0x80000 DecompileAt.java $out "$@"
}

rm -rf "$out"
mkdir -p "$out"
ok $S
ok python3 $T/test_generated.py
ok python3 $T/pe_synthetic.py
start=$(date +%s)
$engine build -q -t "$tag" -f tools/Containerfile.ghidra . > /dev/null || { echo "FAIL: the Ghidra image does not build"; exit 1; }
echo "ghidra image built in $(( $(date +%s) - start )) s"

$S write $out
gh $out $out/synthetic.bin 0x80000
ok $S check $out/slots.tsv
gh $out $out/synthetic.bin 0x80000 EmuSynthetic.java $out/emu.tsv $out/emu.out
ok $S check-emu $out/emu.out
a=$($S addr) c=$($S caller)
dec r1=1000 "$a" "$c"
ok $S check-dec $out/$a.c
ok $S check-call $out/$c.c
dec $($S frames)
ok $S check-frames $out
p=$($S pal)
dec pal=$p $p
ok $S check-pal $out/$p.c
mkdir -p $out/plain
gh $out/plain $out/synthetic.bin 0x80000 DecompileAt.java $out/plain $p
ok $S check-plain $out/plain/$p.c
dec $($S predloop)
ok $S check-predloop $out/$($S predloop).c
dec $($S breaks)
ok $S check-breaks $out
dec sigs $($S voids) $($S itc)
ok $S check-voids $out
ok $S check-itc $out/$($S itc).c
dec $($S rfi)
ok $S check-rfi $out/$($S rfi).c

# The PE32+ image at its preferred base and moved.
ok python3 $T/pe_synthetic.py write $out
PE=1 PRESCRIPT=/work/ghidra/scripts/IA64Pe.java gh $out $out/synthetic.efi 0 DumpSymbols.java $out/pe.tsv
ok python3 $T/pe_synthetic.py check $out/pe.tsv 0x10000000
PE=1 PRESCRIPT=/work/ghidra/scripts/IA64Pe.java PRESCRIPT_ARGS=base=0x20000000 \
    gh $out $out/synthetic.efi 0 DumpSymbols.java $out/pe-moved.tsv
ok python3 $T/pe_synthetic.py check $out/pe-moved.tsv 0x20000000
echo "ia64 checks: $([ $rc = 0 ] && echo pass || echo FAIL)"
exit $rc
