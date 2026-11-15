#!/usr/bin/env python3
"""Tests of the language Ghidra's ELF import is given by ghidra-export.py, from stub ELF headers.

Run from the repository root: python3 tools/test_ghidra_export.py
"""
import importlib.util
import os
import struct
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('ghidra_export', os.path.join(HERE, 'ghidra-export.py'))
ge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ge)


def elf32(machine, order, flags=0, etype=1):
    """A bare ELF32 relocatable header: enough for the planner (no .mdebug read), not loadable."""
    ident = b'\x7fELF' + bytes([1, 1 if order == '<' else 2, 1]) + bytes(9)
    return ident + struct.pack(order + 'HHIIIIIHHHHHH', etype, machine, 1, 0, 0, 0, flags, 52, 0, 0, 40, 0, 0)


class PlanLanguage(unittest.TestCase):
    def plan(self, blob):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'obj')
            job = os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(blob)
            ge.prepare(['--job', job, '--decompile-all', obj])
            with open(os.path.join(job, 'ghidra.sh')) as f:
                return f.read()

    def test_arm_le_elf_gets_arm_language_and_no_mips_gp_script(self):
        script = self.plan(elf32(ge.EM_ARM, '<'))
        self.assertIn('-processor ARM:LE:32:v4', script)
        self.assertNotIn('ReMipsGp', script)

    def test_mips_elf_is_unchanged(self):
        script = self.plan(elf32(ge.EM_MIPS, '>'))
        self.assertNotIn('-processor', script)
        self.assertIn('ReMipsGp.java loader -', script)

    def test_wide_mips32_elf_keeps_its_variant(self):
        script = self.plan(elf32(ge.EM_MIPS, '>', flags=0x20000000 | ge.EF_MIPS_ABI2))
        self.assertIn('-processor MIPS:BE:64:64-32addr -cspec n32', script)

    def test_other_machines_and_byte_orders_are_refused(self):
        for blob in (elf32(3, '<'), elf32(ge.EM_ARM, '>'), elf32(ge.EM_MIPS, '<')):
            with self.assertRaises(SystemExit):
                self.plan(blob)


if __name__ == '__main__':
    unittest.main()
