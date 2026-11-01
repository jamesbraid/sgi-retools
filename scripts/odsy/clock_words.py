#!/usr/bin/env python3
"""Check the clock-part formulas of docs/display-files.md against every VPro .vfo file.

Usage: clock_words.py [--root DIR]

For each usr/gfx/ucode/ODSY/vof/*.vfo it recomputes the first part's frequency,
12 MHz x (FdBkDiv0 + 8 + 256 x FdBkDiv1) / (Osc_Div - 126), and the second part's,
12 MHz x (0x4 x 256 + 0x3) / (0x1 x 256 + 0x0), and compares them with the file's
ICS_AchievedFrequency, AchievedFrequency and FormatInfo_PixelClock (hertz). It also
prints the loop-oscillator and phase-detector ranges. Exit status 1 on any mismatch.
"""
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from display_files import load  # noqa: E402

POST = (2, 4, 8, 16)


def main():
    root = os.path.join(os.path.dirname(HERE), 'root')
    if len(sys.argv) == 3 and sys.argv[1] == '--root':
        root = sys.argv[2]
    files = sorted(glob.glob(os.path.join(root, 'usr/gfx/ucode/ODSY/vof/*.vfo')))
    bad = 0
    loop, pfd, gap = [1e9, 0], [1e9, 0], 0.0
    for f in files:
        v = load(f)[4]
        fb = v['ODY_PLL_FdBkDiv0'] + 8 + 256 * v['ODY_PLL_FdBkDiv1']
        ref = v['ODY_PLL_Osc_Div'] - 126
        ics = 12.0 * fb / ref
        a = [v['ODY_AMI_PLL_0x%d' % i] for i in range(5)]
        ami = 12.0 * (a[4] * 256 + a[3]) / (a[1] * 256 + a[0])
        ok = (abs(ics - v['ICS_AchievedFrequency']) < 1e-6
              and abs(ami - v['AchievedFrequency']) < 1e-6
              and round(ami * 1e6) == v['FormatInfo_PixelClock'])
        if not ok:
            bad += 1
            print('MISMATCH', os.path.basename(f), ics, ami)
        lo = ics * POST[(v['ODY_PLL_LoopControl'] >> 4) & 3]
        loop = [min(loop[0], lo), max(loop[1], lo)]
        p = 12.0 / ref
        pfd = [min(pfd[0], p), max(pfd[1], p)]
        gap = max(gap, abs(ics - ami))
    print('%d files, %d mismatches' % (len(files), bad))
    print('loop oscillator %.1f to %.1f MHz, phase detector %.3f to %.3f MHz, '
          'largest gap between the two parts %.3f MHz' % tuple(loop + pfd + [gap]))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
