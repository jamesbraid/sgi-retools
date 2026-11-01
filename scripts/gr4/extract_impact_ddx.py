#!/usr/bin/env python3
"""
scripts/extract_impact_ddx.py

Extracts functions, symbols, and disassembly from ddx/impactpc.so
(SGI IRIX X11 dynamic DDX driver for Impact / MGRAS graphics).

Organizes code into logical modules:
  - mgras_draw    (2D drawing acceleration: rects, spans, lines, polylines, arcs)
  - mgras_glyph   (Font glyph acceleration: TE6, TE8, TE9 blitting)
  - mgras_image   (Pixel transfers: 8-bit CI, 12-bit RGB, 24-bit TrueColor, DMA)
  - mgras_window  (Window private, clip, copy rect/window, buffer swap, WID/CID)
  - mgras_vc3     (VC3 video controller setup, SRAM load, timing tables, gamma)
  - mgras_cmap    (Colormaps: normal, overlay, 24-bit TrueColor, fake colormaps)
  - mgras_cursor  (Hardware cursor programming)
  - mgras_init    (Hardware probe, reset, kernel attach, screen init)
  - rrm           (Rendering Resource Manager & NFB bindings)
  - cfb_mi        (CFB framebuffer ops and Machine Independent X11 routines)

Generates:
  1. ddx/manifest.json (complete machine-readable database)
  2. ddx/asm/<module>/<func>.s (per-function and per-module assembly)
  3. ddx/include/impact_ddx.h (authoritative hardware DDX data structures)
  4. ddx/ctx_source.h & ddx/ctx.c (preprocessed context for m2c)
  5. ddx/decompile_ddx.sh (decompilation runner script)
"""

import os
import sys
import re
import json
import struct
import subprocess
from collections import defaultdict
from elftools.elf.elffile import ELFFile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.resolve_got import build_got_map

TARGET_SO = 'ddx/impactpc.so'
OUT_DIR = 'ddx'

def sanitize_ident(name):
    s = name.replace('*', '_').replace('..', '__').replace('.', '_').replace('$', '_')
    if s and s[0].isdigit():
        s = '_' + s
    return s

MODULE_GROUPS = {
    'mgras_draw': [
        'mgrasDrawSolidRects', 'mgrasTileRects', 'mgrasSolidSpans', 'mgrasSolidFillSpans',
        'mgrasStippledFS', 'mgrasStippledFillRect', 'mgrasPolyFillRectSolid', 'mgrasPolyFillRectStippled',
        'mgrasFillSolidPolygon', 'mgrasFillNarrowStippPolygon', 'mgrasLineSS', 'mgrasLineSD',
        'mgrasSegmentSS', 'mgrasSegmentSD', 'mgrasPolyPoint', 'mgrasDrawPoints', 'mgrasZeroPolyArc'
    ],
    'mgras_glyph': [
        'mgrasPolyGlyphBlt', 'mgrasPolyGlyphBltTE6', 'mgrasPolyGlyphBltTE8', 'mgrasPolyGlyphBltTE9',
        'mgrasImageGlyphBlt', 'mgrasImageGlyphBltTE6', 'mgrasImageGlyphBltTE8', 'mgrasImageGlyphBltTE9'
    ],
    'mgras_image': [
        'mgrasDrawImage', 'mgrasDrawImage12', 'mgrasDrawImage24',
        'mgrasReadImage', 'mgrasReadImage12', 'mgrasReadImage24',
        'mgrasDrawMonoImage', 'mgrasDrawOpaqueMonoImage', 'mgrasReadConvertPixels',
        'mgrasReadFBBlock', 'mgrasWriteFBSubBlock', 'mgrasFreeFBBlock', 'mgrasClearPlanes'
    ],
    'mgras_window': [
        'mgrasCopyRect8', 'mgrasCopyRect12', 'mgrasCopyRect24', 'mgrasCopyBigRect', 'mgrasCopyWindow',
        'mgrasInitWindowType', 'mgrasValidateClip', 'mgrasValidateSwapbuf', 'mgrasValidateMode',
        'mgrasValidateReservedMode', 'mgrasValidateReducedGC', 'mgrasValidateWindowGC',
        'mgrasValidateVisual', 'mgrasValidateWindowPriv', 'mgrasInitiateBufferSwap',
        'mgrasDrawCID', 'mgrasNeedCID', 'mgrasInitDIDState', 'mgrasReloadDummyDID'
    ],
    'mgras_vc3': [
        'vc3LoadSRAM', 'mgrasLoadTimingTable', 'mgrasLstVideoFmt', 'mgrasLstVideoFmtCombs',
        'mgrasLstFmtInComb', 'mgrasDefaultTTExists', 'mgrasLdComb', 'mgrasLoadAndInitICO',
        'mgrasLoadAndFree', 'mgrasBlankScreen', 'mgrasCheckCorona', 'mgrasQryMonitor',
        'mgrasQryPltParam', 'mgrasSetPltParam', 'mgrasDisableChannelProc', 'mgrasSetScrnGlock'
    ],
    'mgras_cmap': [
        'mgrasInstallNormalMap', 'mgrasInstallOverlayMap', 'mgrasInstall24Map', 'mgrasUninstall24Map',
        'mgrasInstallFakeMap', 'mgrasStoreColors', 'mgrasStore24Colors', 'mgrasStoreFakeColors',
        'mgrasChangeDIDCmap', 'mgrasInitializeColormap', 'mgrasBlackCmap', 'mgrasStrGamma8', 'mgrasStrGamma16'
    ],
    'mgras_cursor': [
        'mgrasCursorOn', 'mgrasDisplayCursor', 'mgrasInstallCursor', '_clone_1_mgrasCursorOn'
    ],
    'mgras_init': [
        'mgrasInit', 'mgrasPostInit', 'mgrasKernInit', 'mgrasProbe', 'mgrasResetProc',
        'mgrasAttachXvc', 'mgrasCloseScreen', 'mgrasInitRootWindow', 'mgrasPbufAllocConfirm', 'mgrasDebugf'
    ]
}

def classify_function(name):
    clean = sanitize_ident(name)
    for group, fnames in MODULE_GROUPS.items():
        if clean in fnames or name in fnames:
            return group
    if name.startswith(('rrm', 'nfb')):
        return 'rrm'
    if name.startswith(('cfb', 'mi')):
        return 'cfb_mi'
    return 'other'

def setup_dirs():
    os.makedirs(f'{OUT_DIR}/asm', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/decomp', exist_ok=True)
    os.makedirs(f'{OUT_DIR}/include', exist_ok=True)
    for group in list(MODULE_GROUPS.keys()) + ['rrm', 'cfb_mi', 'other']:
        os.makedirs(f'{OUT_DIR}/asm/{group}', exist_ok=True)
        os.makedirs(f'{OUT_DIR}/decomp/{group}', exist_ok=True)

def parse_dynsyms(so_path):
    with open(so_path, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        funcs = []
        objects = []
        for s in dynsym.iter_symbols():
            if s.name and s['st_value']:
                stype = s['st_info']['type']
                item = {
                    'name': s.name,
                    'clean_name': sanitize_ident(s.name),
                    'addr': s['st_value'],
                    'size': s['st_size'],
                    'type': stype
                }
                if stype == 'STT_FUNC':
                    funcs.append(item)
                elif stype == 'STT_OBJECT':
                    objects.append(item)

        funcs.sort(key=lambda x: x['addr'])
        objects.sort(key=lambda x: x['addr'])

        # Infer function sizes if size is 0
        for i in range(len(funcs) - 1):
            if funcs[i]['size'] == 0:
                funcs[i]['size'] = funcs[i+1]['addr'] - funcs[i]['addr']

        return funcs, objects

def get_disassembly(so_path):
    print(f"[*] Disassembling {so_path} using mips-unknown-linux-gnu-objdump...")
    cmd = ['mips-unknown-linux-gnu-objdump', '-d', '-z', '--no-show-raw-insn', so_path]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)

    disasm = {}
    pattern = re.compile(r'^\s*([0-9a-fA-F]+):\s*(.*)')
    for line in res.stdout.splitlines():
        m = pattern.match(line)
        if m:
            addr = int(m.group(1), 16)
            instr = m.group(2).strip()
            disasm[addr] = instr
    print(f"[+] Loaded {len(disasm)} disassembled instructions from DDX.")
    return disasm

def format_instruction(instr):
    regs = [
        'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
        'a4', 'a5', 'a6', 'a7', 't0', 't1', 't2', 't3',
        's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
        't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra',
        'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7',
        'f8', 'f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15',
        'f16', 'f17', 'f18', 'f19', 'f20', 'f21', 'f22', 'f23',
        'f24', 'f25', 'f26', 'f27', 'f28', 'f29', 'f30', 'f31'
    ]
    reg_pattern = r'(?<!\$)\b(' + '|'.join(regs) + r')\b'
    instr = re.sub(reg_pattern, r'$\1', instr)

    # Normalize MIPS IV condition codes $fcc0-$fcc7
    instr = re.sub(r'\b(c\.[a-z]+\.[sd])\s+\$fcc\d+\s*,\s*', r'\1 ', instr)
    instr = re.sub(r'\b(bc1[tf]l?)\s+\$fcc\d+\s*,\s*', r'\1 ', instr)

    return instr

def write_ddx_asm(funcs, disasm, got_map):
    print("[*] Generating DDX assembly files organized by module...")
    by_group = defaultdict(list)
    for f in funcs:
        group = classify_function(f['name'])
        by_group[group].append(f)

    for group, gfuncs in by_group.items():
        out_s = f"{OUT_DIR}/asm/{group}/{group}.s"
        with open(out_s, 'w') as out:
            out.write(f"# SGI Impact DDX Module: {group}\n")
            out.write(f"# Functions: {len(gfuncs)}\n\n")
            out.write(".text\n.set noat\n.set noreorder\n\n")

            for func in gfuncs:
                fname = func['name']
                cname = func['clean_name']
                low = func['addr']
                size = func['size']
                high = low + size if size > 0 else low + 64

                out.write(f"glabel {cname}\n")

                # Collect instructions and branch targets
                f_insns = []
                branch_targets = set()
                for addr in range(low, high, 4):
                    raw = disasm.get(addr, 'nop')
                    f_insns.append((addr, raw))
                    m = re.search(r'\b([0-9a-fA-F]{7,8})\b', raw)
                    if m:
                        t = int(m.group(1), 16)
                        if low <= t < high:
                            branch_targets.add(t)

                t9_sym = None
                for addr, raw in f_insns:
                    if addr in branch_targets:
                        out.write(f".L{addr:08x}:\n")

                    # Check for GOT loads
                    m_lw = re.search(r'lw\s+([$]?\w+),\s*(-?\d+)\([$]?(?:at|gp)\)', raw)
                    if m_lw:
                        dreg = m_lw.group(1)
                        off = int(m_lw.group(2))
                        if off in got_map:
                            sym = got_map[off]
                            if dreg in ('$t9', 't9'):
                                t9_sym = sym
                            else:
                                raw = f"la\t{dreg},{sanitize_ident(sym)}"

                    if 'jalr' in raw and '$t9' in raw and t9_sym:
                        raw = f"jal\t{sanitize_ident(t9_sym)}"
                        t9_sym = None

                    # Replace objdump targets with labels or symbols
                    m_tgt = re.search(r'\b([0-9a-fA-F]{7,8})\s*<([^>]+)>', raw)
                    if m_tgt:
                        target_addr = int(m_tgt.group(1), 16)
                        target_sym = m_tgt.group(2).split('+')[0]
                        if low <= target_addr < high:
                            raw = raw[:m_tgt.start()] + f".L{target_addr:08x}"
                        else:
                            raw = raw[:m_tgt.start()] + sanitize_ident(target_sym)
                    elif '<' in raw and '>' in raw:
                        raw = re.sub(r'<[^>]+>', '', raw).strip()

                    # Convert bgezall / bgezal with zero to bal
                    raw = re.sub(r'\bbgezall?\s+[$]?zero\s*,\s*', 'bal ', raw)

                    # Format registers
                    formatted = format_instruction(raw)
                    out.write(f"    {formatted}\n")

                out.write("\n")
        print(f"[+] [{group}] Emitted {len(gfuncs)} functions -> {out_s}")

def generate_ddx_headers():
    print("[*] Generating ddx/include/impact_ddx.h...")
    h_path = f"{OUT_DIR}/include/impact_ddx.h"
    with open(h_path, 'w') as f:
        f.write("""#ifndef __IMPACT_DDX_H__
#define __IMPACT_DDX_H__

/*
 * impact_ddx.h - SGI Impact / Mardi Gras X11 DDX Acceleration Structures
 * Reverse engineered from ddx/impactpc.so and IRIX 6.5 graphics subsystem.
 */

#include <stdint.h>
#include "../../MGRAS.h"
#include "../../HQ3.h"
#include "../../GE11.h"
#include "../../RE4.h"
#include "../../PP1.h"
#include "../../TE1.h"
#include "../../VC3.h"
#include "../../CMAP.h"

/* Primitive types */
typedef int32_t     Bool;
typedef uint32_t    Pixel;
typedef uint32_t    CARD32;
typedef uint16_t    CARD16;
typedef uint8_t     CARD8;
typedef int16_t     INT16;
typedef int32_t     INT32;

/* Forward declarations */
typedef struct _Screen      *ScreenPtr;
typedef struct _Window      *WindowPtr;
typedef struct _GCPrivate   *GCPtr;
typedef struct _Box         BoxRec, *BoxPtr;
typedef struct _Region      RegionRec, *RegionPtr;

struct _Box {
    INT16 x1, y1, x2, y2;
};

/* DDX Screen Private Structure (mgrasScreenRec) */
typedef struct mgrasScreenRec {
    /* 0x00: Hardware Register Base */
    mgras_hw                *hw;                /* 0x00: Memory-mapped hardware ASIC apertures */
    int32_t                 fd;                 /* 0x04: Kernel device file descriptor (/dev/gfx) */
    int32_t                 boardIndex;         /* 0x08: Graphics board index (0 for pipe 0) */
    int32_t                 boardRev;           /* 0x0C: Board revision */

    /* 0x10: Display Configuration */
    int32_t                 width;              /* 0x10: Screen width in pixels (e.g. 1280) */
    int32_t                 height;             /* 0x14: Screen height in pixels (e.g. 1024) */
    int32_t                 mmWidth;            /* 0x18: Width in millimeters */
    int32_t                 mmHeight;           /* 0x1C: Height in millimeters */
    int32_t                 depth;              /* 0x20: Screen depth (8, 12, or 24) */
    int32_t                 bitsPerPixel;       /* 0x24: Framebuffer bits per pixel */

    /* 0x28: Board Capabilities */
    uint32_t                numRE;              /* Number of RE4 chips: 1 or 2 */
    uint32_t                numTE;              /* Number of TE1 chips: 0, 1, or 2 */
    uint32_t                numPP;              /* Number of PP1 chips: 1 or 2 */
    uint32_t                tramSize;           /* TETRAM size in bytes (1MB or 4MB) */
    uint32_t                hasTbuf;            /* Texture buffer option installed */

    /* 0x3C: Shadowed ASIC State */
    uint32_t                re_mode1;           /* Current RE4 MODE1 */
    uint32_t                re_fillmode;        /* Current RE4 FILLMODE */
    uint32_t                re_viewport;        /* Current packed viewport */
    uint32_t                pp_fillmode;        /* Current PP1 FILLMODE (mgrasPP_Fillmode) */
    uint32_t                pp_rdfillmode;      /* Current PP1 RD_FILLMODE (mgrasPP_RdFillmode) */
    uint32_t                rd_dma_brkeven;     /* Read DMA break-even width */
    uint32_t                wr_dma_brkeven;     /* Write DMA break-even width */

    /* 0x58: Visual & Colormap Management */
    int32_t                 numVisuals;         /* Number of visual formats supported */
    void                    *allVisuals;        /* Pointer to mgrasAllVisuals array */
    void                    *allVisualPrivs;    /* Pointer to mgrasAllVisualPrivs */
    int32_t                 numHWCmaps;         /* Number of hardware colormaps (mgrasNumHWCmaps) */
    void                    *hwCmaps;           /* Hardware colormap structures */

    /* 0x6C: Cursor & DID Management */
    int32_t                 cursorOn;           /* Hardware cursor state (1=active) */
    int32_t                 cursorX;            /* Hardware cursor X position */
    int32_t                 cursorY;            /* Hardware cursor Y position */
    uint32_t                currentDID;         /* Active DID table index */
    uint32_t                didMode;            /* DID routing mode */

    /* 0x80: RRM Linkage */
    void                    *rrmPriv;           /* Rendering Resource Manager private */
    void                    *glxScreenPriv;     /* GLX screen private pointer */
} mgrasScreenRec, *mgrasScreenPtr;

/* DDX Window Private Structure (mgrasWinPriv) */
typedef struct mgrasWinPrivRec {
    int32_t                 wid;                /* Window ID (WID) assigned by RRM */
    int32_t                 cid;                /* Colormap ID (CID) assigned by RRM */
    uint32_t                did;                /* Display ID table index */
    uint32_t                planeMask;          /* Active planemask */
    int32_t                 doubleBuffer;       /* 1 if double buffered */
    int32_t                 readBuffer;         /* Read buffer selection */
    int32_t                 drawBuffer;         /* Draw buffer selection */
    BoxRec                  clipBox;            /* Current window bounds */
} mgrasWinPrivRec, *mgrasWinPrivPtr;

/* DDX GC Private Structure (mgrasGCPriv) */
typedef struct mgrasGCPrivRec {
    uint32_t                planemask;          /* Active planemask */
    uint32_t                fgColor;            /* Foreground color / pixel value */
    uint32_t                bgColor;            /* Background color / pixel value */
    uint32_t                alu;                /* ROP logic op (0..15) */
    uint32_t                fillStyle;          /* Fill style: Solid, Tiled, Stippled */
    void                    *ops;               /* Active acceleration ops pointer */
} mgrasGCPrivRec, *mgrasGCPrivPtr;

/* Function Prototypes */
Bool mgrasProbe(void);
Bool mgrasInit(int index, ScreenPtr pScreen, int argc, char **argv);
Bool mgrasCloseScreen(int index, ScreenPtr pScreen);
void mgrasResetProc(ScreenPtr pScreen);

/* 2D Drawing Acceleration */
void mgrasDrawSolidRects(void *pDrawable, void *pGC, int nBox, BoxPtr pBox);
void mgrasTileRects(void *pDrawable, void *pGC, int nBox, BoxPtr pBox);
void mgrasSolidSpans(void *pDrawable, void *pGC, int nPoints, void *pPoints, int *pWidths, int fSorted);
void mgrasPolyFillRectSolid(void *pDrawable, void *pGC, int nRects, void *pRects);
void mgrasLineSS(void *pDrawable, void *pGC, int mode, int npt, void *pptInit);
void mgrasLineSD(void *pDrawable, void *pGC, int mode, int npt, void *pptInit);

/* Pixel / Image Transfers */
void mgrasDrawImage(void *pDrawable, void *pGC, int depth, int x, int y, int w, int h, int leftPad, int format, char *pImage);
void mgrasReadImage(void *pDrawable, int x, int y, int w, int h, int format, unsigned long planeMask, char *pImage);
void mgrasCopyRect8(void *pSrc, void *pDst, void *pGC, BoxPtr pBox);
void mgrasCopyRect12(void *pSrc, void *pDst, void *pGC, BoxPtr pBox);
void mgrasCopyRect24(void *pSrc, void *pDst, void *pGC, BoxPtr pBox);
void mgrasCopyWindow(WindowPtr pWin, void *ptOldOrg, RegionPtr prgnSrc);

/* Colormaps & Video Controller */
void mgrasInstallNormalMap(void *pColormap);
void mgrasInstallOverlayMap(void *pColormap);
void mgrasInstall24Map(void *pColormap);
void mgrasStoreColors(void *pColormap, int nColors, void *pColors);
void mgrasChangeDIDCmap(void *pColormap);
void vc3LoadSRAM(mgras_hw *hw, uint32_t addr, uint32_t count, const uint32_t *data);
void mgrasBlankScreen(ScreenPtr pScreen, int on);

/* Hardware Cursor */
void mgrasCursorOn(ScreenPtr pScreen);
void mgrasDisplayCursor(ScreenPtr pScreen, void *pCursor);
void mgrasInstallCursor(ScreenPtr pScreen, void *pCursor);

#endif /* __IMPACT_DDX_H__ */
""")
    print(f"[+] Wrote {h_path}")

def generate_context_headers():
    ctx_src = f"{OUT_DIR}/ctx_source.h"
    with open(ctx_src, 'w') as f:
        f.write("""/*
 * ctx_source.h - Context header for DDX decompiler
 */
#define _LANGUAGE_C
#include "include/impact_ddx.h"
""")
    ctx_c = f"{OUT_DIR}/ctx.c"
    print(f"[*] Preprocessing {ctx_src} -> {ctx_c}...")
    cmd = ['gcc', '-std=c99', '-E', '-P', '-D_LANGUAGE_C', '-I.', f'-I{OUT_DIR}', ctx_src, '-o', ctx_c]
    subprocess.run(cmd, check=True)
    print(f"[+] Successfully generated {ctx_c}")

def generate_runner_script():
    script_path = f"{OUT_DIR}/decompile_ddx.sh"
    with open(script_path, 'w') as f:
        f.write(r"""#!/usr/bin/env bash
# decompile_ddx.sh - Automated decompiler runner for SGI Impact X11 DDX driver

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

M2C="python3 ${ROOT_DIR}/m2c/m2c.py -t mipsn32 --context ${SCRIPT_DIR}/ctx.c"

if [ $# -eq 0 ] || [ "$1" == "all" ]; then
    echo "[*] Decompiling all DDX modules..."
    for f in "${SCRIPT_DIR}"/asm/*/*.s; do
        mod="$(basename "$(dirname "$f")")"
        out="${SCRIPT_DIR}/decomp/${mod}/${mod}.c"
        echo "[*] Decompiling $f -> $out ..."
        $M2C "$f" > "$out" 2>&1 || true
        echo "[+] Done: $out ($(wc -l < "$out") lines)"
    done
    exit 0
fi

target="$1"
f="${SCRIPT_DIR}/asm/${target}/${target}.s"
if [ ! -f "$f" ]; then
    echo "[-] File not found: $f"
    exit 1
fi

out="${SCRIPT_DIR}/decomp/${target}/${target}.c"
echo "[*] Decompiling $f -> $out ..."
$M2C "$f" > "$out" 2>&1 || true
echo "[+] Done: $out ($(wc -l < "$out") lines)"
""")
    os.chmod(script_path, 0o755)
    print(f"[+] Created {script_path}")

def main():
    setup_dirs()
    got_map = build_got_map(TARGET_SO)
    print(f"[*] Loaded {len(got_map)} GOT entries.")
    funcs, objects = parse_dynsyms(TARGET_SO)
    print(f"[*] Parsed {len(funcs)} functions and {len(objects)} objects.")
    disasm = get_disassembly(TARGET_SO)
    write_ddx_asm(funcs, disasm, got_map)

    # Manifest
    manifest = {
        'target': TARGET_SO,
        'total_funcs': len(funcs),
        'total_objects': len(objects),
        'modules': {
            group: len([f for f in funcs if classify_function(f['name']) == group])
            for group in list(MODULE_GROUPS.keys()) + ['rrm', 'cfb_mi', 'other']
        }
    }
    with open(f'{OUT_DIR}/manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)

    generate_ddx_headers()
    generate_context_headers()
    generate_runner_script()
    print("\n[SUCCESS] DDX pipeline ready!")

if __name__ == '__main__':
    main()
