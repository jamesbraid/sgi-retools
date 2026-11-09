#!/bin/sh
# Run one verification driver against ddx/crm.so in the MIPS interpreter (mips.py).
#   tools/re-run scripts/crm_exec/run.sh t6.py
# Needs pyelftools, which the tools/re-run image has. The drivers chain with exec(), so run from this directory.
#
# driver  checks
#   t6      cfbLineSS, cfb16LineSS, cfb32LineSS against the thin-line reference (ref.py, ref2.py)
#   t8      cfbSegmentSS, cfb16SegmentSS, cfb32SegmentSS
#   t9      the six dashed drivers cfb{,16,32}{LineSD,SegmentSD}; t12 their background operations,
#           t13 odd dash lists and relative mode
#   cl1     the nine cfb*ClippedLine{Copy,General,Xor} routines; cl2 negative screen index
#   r6,r7   the nine cfb*LineSS1Rect{Copy,General,Xor} routines (r1 harness, r10 and/xor words)
#   s1      the nine cfb*SegmentSS1Rect{Copy,General,Xor} routines
#   mt3     mfbLineSS, mfbSegmentSS; mt4 mfbLineSD, mfbSegmentSD; mt5 the dashed end-point
#           truth table; mt7 when mfbLineSS calls mfbBresS
cd "$(dirname "$0")" || exit 1
exec python3 -c "import sys;sys.path.insert(0,'.');exec(open(sys.argv[1]).read())" "$@"
