#!/usr/bin/env python3
"""Tests of tools/m2c_flat.py on a synthetic MIPS segment, in the toolchain image (m2c and spimdisasm).

Run: tools/re-run python3 retools/tools/test_m2c_flat.py   (M2C_REQUIRED=1 turns a missing m2c into a failure)
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'ghidra', 'scripts', 'tests'))
import mips_synthetic as ms  # noqa: E402

TOOL = os.path.join(HERE, 'm2c_flat.py')
SWITCH = ms.BASE + 0x300
JT = ms.BASE + 0x900


def write(path, data, mode='w'):
    with open(path, mode) as f:
        f.write(data)


def have_m2c():
    return shutil.which('m2c') is not None


def fixture(dirname, with_tables=True):
    """A prom file, a code file and the segment bytes for the MIPS fixture, as they would sit beside a prom.json."""
    im = ms.build()
    data = ms.image_bytes(im)
    names = {ms.BASE: 'main_calls', ms.BASE + 0x100: 'dev_access', ms.BASE + 0x200: 'leaf_b', ms.BASE + 0x220: 'leaf_c',
             ms.BASE + 0x240: 'leaf_d', SWITCH: 'dispatch', ms.BASE + 0x400: 'pair_a', ms.BASE + 0x410: 'pair_b',
             ms.BASE + 0x500: 'store_helper', ms.BASE + 0x520: 'store_caller', ms.BASE + 0xa00: 'long_run'}
    entries = sorted(names)
    ends = {e: (entries[i + 1] if i + 1 < len(entries) else ms.BASE + 0xa00 + 4 * 601 + 4) for i, e in enumerate(entries)}
    ends[SWITCH] = SWITCH + 0x48
    ends[ms.BASE] = ms.BASE + 0x50
    ends[ms.BASE + 0x100] = ms.BASE + 0x148
    ends[ms.BASE + 0xa00] = ms.BASE + 0xa00 + 4 * 601 + 4
    for e in (ms.BASE + 0x200, ms.BASE + 0x220, ms.BASE + 0x240):
        ends[e] = e + 8
    ends[ms.BASE + 0x400] = ms.BASE + 0x410
    ends[ms.BASE + 0x410] = ms.BASE + 0x420
    ends[ms.BASE + 0x500] = ms.BASE + 0x510
    ends[ms.BASE + 0x520] = ms.BASE + 0x520 + 0x1c
    at = lambda a: {'segment': 'seg', 'address': ms.hexa(a)}
    code = {'functions': [{'segment': 'seg', 'entry': ms.hexa(e), 'end': ms.hexa(ends[e]), 'name': names[e]} for e in entries],
            'calls': [{'from': at(ms.BASE), 'to': at(ms.BASE + 0x100)}, {'from': at(ms.BASE + 0x520), 'to': at(ms.BASE + 0x500)}],
            'jump_tables': []}
    if with_tables:
        code['jump_tables'].append({'function': at(SWITCH), 'table': at(JT),
                                    'targets': [at(SWITCH + 0x30), at(SWITCH + 0x38), at(SWITCH + 0x40)]})
    write(os.path.join(dirname, 'seg.bin'), data, 'wb')
    prom = {'identity': {'sha256': hashlib.sha256(data).hexdigest()},
            'segments': [{'name': 'seg', 'file': 'seg.bin', 'length': ms.hexa(len(data)),
                          'regions': [{'name': 'text', 'address': ms.hexa(ms.BASE), 'offset': '0x0', 'length': '0x800', 'kind': 'code'},
                                      {'name': 'rodata', 'address': ms.hexa(ms.BASE + 0x800), 'offset': '0x800', 'length': '0x200',
                                       'kind': 'readonly'},
                                      {'name': 'more', 'address': ms.hexa(ms.BASE + 0xa00), 'offset': '0xa00', 'length': '0xd00',
                                       'kind': 'code'}]}]}
    write(os.path.join(dirname, 'x.prom.json'), json.dumps(prom))
    write(os.path.join(dirname, 'x.code.json'), json.dumps(code))
    return names


@unittest.skipUnless(have_m2c() or os.environ.get('M2C_REQUIRED'), 'no m2c here (run it in the toolchain image)')
class M2cFlat(unittest.TestCase):
    def run_tool(self, d, out, tables=True, extra=()):
        names = fixture(d, tables)
        cmd = [sys.executable, TOOL, '--prom', os.path.join(d, 'x.prom.json'), '--code', os.path.join(d, 'x.code.json'),
               '--segment', 'seg', '--out', out, '--cpu-seconds', '60'] + list(extra)
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p, names

    def status(self, d):
        return {r['entry']: r for r in json.loads(Path(d, 'x.m2c-status.json').read_text())['functions']}

    def test_one_file_per_function_and_the_switch_decompiles(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'out')
            p, names = self.run_tool(d, out)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(sorted(os.listdir(os.path.join(out, 'c'))), sorted('%08x.c' % e for e in names))
            self.assertEqual(sorted(os.listdir(os.path.join(out, 'asm'))), sorted('%08x.s' % e for e in names))
            self.assertIn('switch', Path(out, 'c', '%08x.c' % SWITCH).read_text())
            st = self.status(d)
            self.assertEqual(st[ms.hexa(SWITCH)]['status'], 'complete')
            # Nothing is written beside the output but the status file.
            self.assertEqual(set(os.listdir(d)), {'seg.bin', 'x.prom.json', 'x.code.json', 'out', 'x.m2c-status.json'})
            doc = json.loads(Path(d, 'x.m2c-status.json').read_text())
            self.assertEqual(doc['image']['sha256'], hashlib.sha256(Path(d, 'seg.bin').read_bytes()).hexdigest())
            self.assertIn('spimdisasm', doc)
            self.assertNotIn('c', st[ms.hexa(SWITCH)])

    def test_callee_names_survive_in_a_one_function_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'out')
            p, _ = self.run_tool(d, out)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('dev_access(', Path(out, 'c', '%08x.c' % ms.BASE).read_text())
            self.assertIn('store_helper(', Path(out, 'c', '%08x.c' % (ms.BASE + 0x520)).read_text())

    def test_a_rejected_function_fails_alone(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, 'out')
            p, names = self.run_tool(d, out, tables=False)
            self.assertEqual(p.returncode, 0, p.stderr)
            st = self.status(d)
            self.assertEqual(st[ms.hexa(SWITCH)]['status'], 'failed')
            self.assertTrue(st[ms.hexa(SWITCH)]['message'])
            others = {e: r['status'] for e, r in st.items() if e != ms.hexa(SWITCH)}
            self.assertEqual(len(others), len(names) - 1)
            self.assertNotIn('failed', others.values())

    def test_odd_names_and_ranges_cost_one_function_each(self):
        with tempfile.TemporaryDirectory() as d:
            names = fixture(d)
            code = json.loads(Path(d, 'x.code.json').read_text())
            for fn in code['functions']:
                if fn['name'] in ('leaf_c', 'leaf_d'):
                    fn['name'] = 'dup'
                if fn['name'] == 'leaf_b':
                    fn['name'] = '-evil;name'
            spill = ms.BASE + 0x7f8     # runs past the end of the text region
            code['functions'].append({'segment': 'seg', 'entry': ms.hexa(spill), 'end': ms.hexa(spill + 16), 'name': 'spill'})
            write(os.path.join(d, 'x.code.json'), json.dumps(code))
            out = os.path.join(d, 'out')
            p = subprocess.run([sys.executable, TOOL, '--prom', os.path.join(d, 'x.prom.json'), '--code',
                                os.path.join(d, 'x.code.json'), '--segment', 'seg', '--out', out], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            st = self.status(d)
            self.assertEqual(st[ms.hexa(spill)]['status'], 'failed')
            self.assertEqual(st[ms.hexa(spill)]['reason'], 'region')
            self.assertEqual(len(st), len(names) + 1)
            self.assertEqual(len([n for n in os.listdir(os.path.join(out, 'c')) if n.endswith('.c')]), len(names) + 1)
            for e in (ms.BASE + 0x200, ms.BASE + 0x220, ms.BASE + 0x240):
                self.assertEqual(st[ms.hexa(e)]['status'], 'complete')
            self.assertTrue(all(not n.startswith('-') for n in os.listdir(os.path.join(out, 'asm'))))

    def test_signals_are_told_apart(self):
        import m2c_flat
        for sig, want in ((24, 'limit'), (9, 'killed'), (11, 'signal 11')):
            fake = subprocess.CompletedProcess([], -sig, '', '')
            real = subprocess.run
            subprocess.run = lambda *a, **k: fake
            try:
                self.assertEqual(m2c_flat.run_m2c('m2c', 'mips', 'x.s', 'f', 1)[:2], ('failed', want))
            finally:
                subprocess.run = real

    def test_output_inside_an_unignored_work_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(['git', 'init', '-q', d], check=True)
            p, _ = self.run_tool(d, os.path.join(d, 'out'))
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('not ignored', p.stderr)
            self.assertFalse(os.path.exists(os.path.join(d, 'x.m2c-status.json')))
            write(os.path.join(d, '.gitignore'), 'out/\n')
            p, _ = self.run_tool(d, os.path.join(d, 'out'))
            self.assertEqual(p.returncode, 0, p.stderr)


if __name__ == '__main__':
    unittest.main()
