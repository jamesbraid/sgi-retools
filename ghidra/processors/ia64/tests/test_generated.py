#!/usr/bin/env python3
"""The generator runs and writes a slaspec with the expected parts."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, '..', 'tools', 'gen_slaspec.py')

LANDMARKS = ['define endian=little;', 'define context contextreg', 'define pcodeop unknown_insn;',
             'CallIn:', 'CallOut:', '"br.call.dpnt.few"', '"alloc"', '"extr.u"']


class Generated(unittest.TestCase):
    def test_generator_writes_slaspec(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'ia64.slaspec')
            subprocess.run([sys.executable, GEN, out], check=True)
            with open(out) as f:
                text = f.read()
        for mark in LANDMARKS:
            self.assertIn(mark, text)


if __name__ == '__main__':
    unittest.main()
