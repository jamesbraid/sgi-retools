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


def pe(machine):
    """A DOS header pointing at a bare PE signature and COFF machine: enough for the planner."""
    return b'MZ' + bytes(0x3a) + struct.pack('<I', 0x40) + b'PE\0\0' + struct.pack('<H', machine)


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

    def test_ia64_elf_gets_ia64_language_and_its_gp_script(self):
        script = self.plan(elf32(ge.EM_IA_64, '<'))
        self.assertIn('-processor IA64:LE:64:default', script)
        self.assertIn('-preScript IA64Elf.java', script)
        self.assertNotIn('ReMipsGp', script)
        self.assertIn('-postScript IA64Signatures.java -postScript ReDecompileExport.java', script)

    def test_ia64_pe_gets_the_pe_loader_and_its_descriptor_script(self):
        script = self.plan(pe(ge.PE_MACHINE_IA64))
        self.assertIn('-processor IA64:LE:64:default', script)
        self.assertIn('-loader PeLoader -preScript IA64Pe.java', script)
        self.assertNotIn('IA64Elf', script)
        self.assertIn('-postScript IA64Signatures.java -postScript ReDecompileExport.java', script)

    def test_x86_pe_is_refused(self):
        with self.assertRaises(SystemExit):
            self.plan(pe(0x8664))

    def test_sal_runtime_is_an_sn2_prom_option(self):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'prom.bin')
            with open(obj, 'wb') as f:
                f.write(bytes(4096))
            for n, (flags, want) in enumerate((([], '-preScript SN2PromImport.java -postScript'),
                                (['--sal-runtime'], '-preScript SN2PromImport.java sal-runtime -postScript'),
                                (['--gzip-elfs'], '-preScript SN2PromImport.java gzip-elfs -postScript'),
                                (['--sal-runtime', '--gzip-elfs'],
                                 '-preScript SN2PromImport.java sal-runtime gzip-elfs -postScript'))):
                job = os.path.join(d, 'job%d' % n)
                os.mkdir(job)
                ge.prepare(['--job', job, '--sn2-prom', '--decompile-all'] + flags + [obj])
                with open(os.path.join(job, 'ghidra.sh')) as f:
                    self.assertIn(want, f.read())
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--sal-runtime', '--decompile-all', obj])
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--gzip-elfs', '--decompile-all', obj])

    def test_gzip_kernel_is_inflated_and_planned_by_its_machine(self):
        import gzip
        script = self.plan(gzip.compress(elf32(ge.EM_IA_64, '<')))
        self.assertIn('-processor IA64:LE:64:default', script)
        self.assertIn('/inflated/obj ', script)

    def test_flat_image_heap_follows_its_size_and_an_option_overrides_it(self):
        with tempfile.TemporaryDirectory() as d:
            obj = os.path.join(d, 'prom.bin')
            for mib, option, want in ((6, [], 'GHIDRA_HEADLESS_MAXMEM=8G'), (12, [], 'GHIDRA_HEADLESS_MAXMEM=14G'),
                                      (30, [], 'GHIDRA_HEADLESS_MAXMEM=14G'),
                                      (12, ['--heap', '20G'], 'GHIDRA_HEADLESS_MAXMEM=20G')):
                with open(obj, 'wb') as f:
                    f.truncate(mib << 20)
                job = os.path.join(d, 'job%d%d' % (mib, len(option)))
                os.mkdir(job)
                ge.prepare(['--job', job, '--sn2-prom', '--decompile-all'] + option + [obj])
                with open(os.path.join(job, 'ghidra.sh')) as f:
                    self.assertIn('export ' + want, f.read())
            with self.assertRaises(SystemExit):
                ge.prepare(['--job', d, '--heap', 'big', '--sn2-prom', '--decompile-all', obj])

    def test_elf_keeps_the_default_heap_and_no_analysis_is_passed_on(self):
        script = self.plan(elf32(ge.EM_IA_64, '<'))
        self.assertNotIn('MAXMEM', script)
        self.assertNotIn('-noanalysis', script)
        with tempfile.TemporaryDirectory() as d:
            obj, job = os.path.join(d, 'obj'), os.path.join(d, 'job')
            os.mkdir(job)
            with open(obj, 'wb') as f:
                f.write(elf32(ge.EM_IA_64, '<'))
            ge.prepare(['--job', job, '--decompile-all', '--no-analysis', obj])
            with open(os.path.join(job, 'ghidra.sh')) as f:
                self.assertIn(' -noanalysis ', f.read())

    def test_mips_elf_is_unchanged(self):
        script = self.plan(elf32(ge.EM_MIPS, '>'))
        self.assertNotIn('-processor', script)
        self.assertIn('ReMipsGp.java loader -', script)
        self.assertNotIn('IA64Signatures', script)

    def test_wide_mips32_elf_keeps_its_variant(self):
        script = self.plan(elf32(ge.EM_MIPS, '>', flags=0x20000000 | ge.EF_MIPS_ABI2))
        self.assertIn('-processor MIPS:BE:64:64-32addr -cspec n32', script)

    def test_other_machines_and_byte_orders_are_refused(self):
        for blob in (elf32(3, '<'), elf32(ge.EM_ARM, '>'), elf32(ge.EM_MIPS, '<'), elf32(ge.EM_IA_64, '>')):
            with self.assertRaises(SystemExit):
                self.plan(blob)


if __name__ == '__main__':
    unittest.main()
