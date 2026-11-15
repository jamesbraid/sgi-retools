#!/usr/bin/env python3
"""The committed ia64.slaspec is what tools/gen_slaspec.py writes now."""
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MOD = os.path.join(HERE, '..')


class Generated(unittest.TestCase):
    def test_slaspec_current(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'ia64.slaspec')
            subprocess.run([sys.executable, os.path.join(MOD, 'tools', 'gen_slaspec.py'), out], check=True)
            with open(out) as f, open(os.path.join(MOD, 'data', 'languages', 'ia64.slaspec')) as g:
                self.assertTrue(f.read() == g.read(), 'ia64.slaspec is stale: run tools/gen_slaspec.py')


if __name__ == '__main__':
    unittest.main()
