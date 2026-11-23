#!/usr/bin/env python3
"""Tests for the raw image kind in disasm.sh: a segment of a larger file (offset, length) is disassembled at its own base.

Run: python3 tools/chips/test_disasm_raw.py
"""
import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def commands(image):
    """The disassembly command disasm.sh writes for one raw image (a stub runner prints it instead of running it)."""
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, 'c.json')
        json.dump({'images': [dict(dict(label='t', dis='work/dis/t.s', path='t.bin', kind='raw', arch='mips:isa64'), **image)]},
                  open(cfg, 'w'))
        rr = os.path.join(d, 'rr')
        open(rr, 'w').write('#!/bin/sh\ncat work/dis/.commands.sh\n')
        os.chmod(rr, 0o755)
        env = dict(os.environ, RR=rr)
        r = subprocess.run(['sh', os.path.join(HERE, 'disasm.sh'), cfg], cwd=d, env=env, capture_output=True, text=True)
        return r.stdout


class RawKind(unittest.TestCase):
    def test_whole_file(self):
        out = commands(dict(vma='0xffffffffbfc00000'))
        self.assertIn('--adjust-vma=0xffffffffbfc00000 -w', out)
        self.assertNotIn('--start-address', out)

    def test_segment(self):
        out = commands(dict(vma='0x81000000', offset='0x9348', length=298608))
        self.assertIn('--adjust-vma=0x80ff6cb8 --start-address=0x81000000 --stop-address=0x81048e70 ', out)


class Promgen64Kind(unittest.TestCase):
    def test_segments_come_from_promkit_under_the_names_the_disassembly_reads(self):
        out = commands(dict(kind='promgen64', vma='0xc00000001fc00000', label='ip35', segment='ip35prom'))
        self.assertIn('prom/promkit unpack t.bin --out work/prom --label ip35\n', out)
        self.assertIn('work/prom/ip35.ip35prom.bin > work/dis/t.s', out)


if __name__ == '__main__':
    unittest.main()
