#!/bin/sh
# Stage 1: disassemble every image a census config names, inside the build container.
#   retools/tools/chips/disasm.sh CONFIG.json            run from the census directory (the workspace)
# root/ in the workspace holds one symlink per IRIX tree (see HAIKU-BRIEF.md, setup).
# The container is tools/re-run; RR=/path/to/wrapper or RE_RUN=/path/to/re-run override it.
set -eu
HERE=$(dirname "$(readlink -f "$0")")
CONFIG=${1:?usage: disasm.sh CONFIG.json}
# RR is a wrapper that takes the command alone; RE_RUN takes --workspace DIR -- COMMAND.
RR=${RR:-}
RE_RUN=${RE_RUN:-$HERE/../re-run}
mkdir -p work/dis work/prom
python3 - "$CONFIG" > work/dis/.commands.sh <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
for i in c['images']:
    out = i['dis']
    if i['kind'] == 'elf':
        print("mips64-linux-gnuabi64-objdump -d %s -w -M no-aliases,gpr-names=numeric --no-show-raw-insn %s > %s" % ('-r' if i.get('reloc') else '', i['path'], out))
        print("mips64-linux-gnuabi64-nm -n -S %s > %s.nm" % (i['path'], out[:-2]))
        if i.get('literals'):
            print("mips64-linux-gnuabi64-readelf -x .MIPS.options %s > %s.opts.txt 2>/dev/null || true" % (i['path'], out[:-2]))
            secs = ' '.join('-j %s' % x for x in i.get('lit_sections', ['.lit8', '.srdata']))
            print("mips64-linux-gnuabi64-objdump -s %s %s > %s" % (secs, i['path'], i['literals']))
    elif i['kind'] == 'promgen64':
        print("python3 retools/tools/chips/promgen64.py %s work/prom %s" % (i['path'], i['label']))
        print("mips64-linux-gnuabi64-objdump -D -b binary -m %s -EB --adjust-vma=%s -w -M no-aliases,gpr-names=numeric --no-show-raw-insn work/prom/%s.%s.bin > %s"
              % (i.get('arch', 'mips:isa64'), i['vma'], i['label'], i['segment'], out))
    elif i['kind'] == 'raw':
        print("mips64-linux-gnuabi64-objdump -D -b binary -m %s -EB --adjust-vma=%s -w -M no-aliases,gpr-names=numeric --no-show-raw-insn %s > %s"
              % (i.get('arch', 'mips:isa64'), i['vma'], i['path'], out))
PY
if [ -n "$RR" ]; then "$RR" sh work/dis/.commands.sh; else "$RE_RUN" --workspace "$PWD" -- sh work/dis/.commands.sh; fi
wc -l work/dis/*.s
