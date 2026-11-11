#!/usr/bin/env python3
"""Tests for the decode-header checker and Rust generator over a small fixture.

Run: python3 retools/tools/defs/test_defs.py
The fixture (testdata/mini) is copied into a throwaway git repository for each
test, so the generator's git-derived banner commit is exercised too.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, 'testdata', 'mini')
CHECK = os.path.join(HERE, 'check-publish-safe.py')
GEN = os.path.join(HERE, 'gen_decode_rust.py')


def run(*args):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True)


def git(root, *args):
    subprocess.run(['git', '-C', root, '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                    '-c', 'commit.gpgsign=false', *args], check=True, capture_output=True)


class DefsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.root = os.path.join(self.tmp, 'repo')
        shutil.copytree(FIXTURE, self.root, ignore=shutil.ignore_patterns('expected'))
        self.cfg = os.path.join(self.root, 'defs.toml')
        self.header = os.path.join(self.root, 'UART_DECODE.h')
        self.out = os.path.join(self.root, 'generated')
        git(self.root, 'init', '-q')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-q', '-m', 'fixture')

    def generate(self, *extra):
        return run(GEN, '--config', self.cfg, *extra)

    def edit(self, path, old, new):
        with open(path, encoding='utf-8') as f:
            text = f.read()
        self.assertIn(old, text)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text.replace(old, new))

    # -- generator ---------------------------------------------------------
    def test_generator_matches_golden(self):
        r = self.generate('--commit', 'abcdef012345')
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(FIXTURE, 'expected', 'uart.rs'), encoding='utf-8') as f:
            want = f.read()
        with open(os.path.join(self.out, 'uart.rs'), encoding='utf-8') as f:
            self.assertEqual(f.read(), want)

    def test_check_ignores_banner_commit(self):
        self.assertEqual(self.generate('--commit', 'abcdef012345').returncode, 0)
        r = self.generate('--check', '--commit', '1234567890ab')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_header_edit_is_stale(self):
        self.assertEqual(self.generate('--commit', 'abcdef012345').returncode, 0)
        self.edit(self.header, 'FRAME.payload 8:1', 'FRAME.payload 7:1')
        r = self.generate('--check', '--commit', 'abcdef012345')
        self.assertEqual(r.returncode, 1)
        self.assertIn('uart.rs is stale', r.stderr)

    def test_missing_and_extra_files_fail(self):
        self.assertEqual(self.generate('--commit', 'abcdef012345').returncode, 0)
        os.remove(os.path.join(self.out, 'uart.rs'))
        open(os.path.join(self.out, 'stray.rs'), 'w').close()
        r = self.generate('--check', '--commit', 'abcdef012345')
        self.assertEqual(r.returncode, 1)
        self.assertIn('uart.rs is missing', r.stderr)
        self.assertIn('stray.rs is not generated', r.stderr)

    def test_wrong_testvec_stops_the_generator(self):
        self.edit(self.header, 'divisor=4', 'divisor=5')
        r = self.generate('--commit', 'abcdef012345')
        self.assertEqual(r.returncode, 1)
        self.assertIn('divisor is 4', r.stderr)

    def test_uncommitted_header_gets_dirty_banner(self):
        self.edit(self.header, 'UART_FIFO_DEPTH 16', 'UART_FIFO_DEPTH 32')
        self.assertEqual(self.generate().returncode, 0)
        with open(os.path.join(self.out, 'uart.rs'), encoding='utf-8') as f:
            self.assertRegex(f.readline(), r'generated from mini [0-9a-f]{12}-dirty ')

    # -- checker -----------------------------------------------------------
    def committed_rust(self):
        self.assertEqual(self.generate().returncode, 0)
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-q', '-m', 'generated')

    def check(self, *extra):
        return run(CHECK, '--config', self.cfg, *extra)

    def test_fixture_is_clean(self):
        self.committed_rust()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_leak_in_header_fails(self):
        self.committed_rust()
        self.edit(self.header, '#define UART_FIFO_DEPTH 16', '#define UART_FIFO_DEPTH 16 /* see stand/src/uart.c */')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('vendor source path', r.stdout)
        self.assertIn('source/object file name', r.stdout)

    def test_configured_banned_rule_fires(self):
        self.edit(self.header, '#define UART_FIFO_DEPTH 16', '#define UART_FIFO_DEPTH 16 /* mini_reset */')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('driver routine prefix', r.stdout)

    def test_allowlist_exempts_a_name(self):
        self.edit(self.header, '#define UART_FIFO_DEPTH 16', '#define UART_FIFO_DEPTH 16 /* see uart.c */')
        self.assertEqual(self.check('--header', 'UART_DECODE.h').returncode, 1)
        with open(os.path.join(self.root, 'names.txt'), 'w') as f:
            f.write('# comment\nuart.c\tpublished driver\n')
        with open(self.cfg, 'a') as f:
            f.write('\n[allowlists]\nsource_names = "names.txt"\n')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_foreign_include_fails(self):
        self.edit(self.header, '#include <stdint.h>', '#include <stdint.h>\n#include "vendor.h"')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('header file name other than ours', r.stdout)

    def test_overlapping_fields_fail(self):
        self.edit(self.header, 'FRAME.payload 8:1', 'FRAME.payload 8:0')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('fields overlap in FRAME', r.stdout)

    def test_macro_must_match_field(self):
        self.edit(self.header, 'UART_CTL_PARITY_MASK  0x7u', 'UART_CTL_PARITY_MASK  0x3u')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('contradict FIELD', r.stdout)

    def test_enum_must_fit_and_match_macro(self):
        self.edit(self.header, 'UART_CTL_PARITY_ODD 1', 'UART_CTL_PARITY_ODD 3')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('ENUM UART.ctl.parity odd = 1 but macro', r.stdout)

    def test_testvec_must_decode(self):
        self.edit(self.header, 'payload=0x35', 'payload=0x36')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('payload is 53', r.stdout)

    def test_testvec_must_be_in_the_notes(self):
        self.edit(self.header, '0x0000006b as FRAME', '0x0000006c as FRAME')
        self.edit(self.header, 'start=1, payload=0x35', 'start=0, payload=0x36')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('not recorded in the RE notes', r.stdout)

    def test_register_offset_only_in_reg_lines(self):
        self.edit(self.header, '#define UART_FIFO_DEPTH 16 /* established */',
                  '#define UART_FIFO_DEPTH 16 /* at 0x120 */')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('outside a REG entry', r.stdout)

    def test_register_overlap_fails(self):
        self.edit(self.header, 'UART.status 0x11', 'UART.status 0x10')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('overlaps', r.stdout)

    # -- 64-bit words and address spaces -------------------------------------
    WIDE = (
        '/* WORD: WIDE 64 */\n'
        '/* FIELD: WIDE.hi 63:32 established */\n'
        '#define UART_WIDE_HI_SHIFT 32\n'
        '#define UART_WIDE_HI_MASK  0xffffffffull\n'
        '/* FIELD: WIDE.lo 31:0 established */\n'
        '#define UART_WIDE_LO_SHIFT 0\n'
        '#define UART_WIDE_LO_MASK  0xffffffffull\n'
        '/* REG: UART.wide 0x30 rw64 reset=0x0 inferred */\n'
        '/* FIELD: UART.wide.top 63:60 inferred */\n'
        '#define UART_WIDE_TOP_SHIFT 60\n'
        '#define UART_WIDE_TOP_MASK  0xfull\n'
        '/*\n * TESTVEC: 0x123456781abcdef0 as WIDE => hi=0x12345678, lo=0x1abcdef0\n */\n'
        '/*\n * TESTVEC: 0xa000000000000001 as UART.wide => top=10\n */\n')

    def add_wide(self):
        with open(self.header, 'a') as f:
            f.write(self.WIDE)
        with open(os.path.join(self.root, 'docs', 'uart.md'), 'a') as f:
            f.write('\nWide words 0x123456781abcdef0 and 0xa000000000000001.\n')

    def test_64_bit_fields_and_vectors(self):
        self.add_wide()
        git(self.root, 'commit', '-q', '-a', '-m', 'wide')
        self.committed_rust()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(os.path.join(self.out, 'uart.rs'), encoding='utf-8') as f:
            rs = f.read()
        self.assertIn('pub struct Wide(u64);', rs)
        self.assertIn('pub const fn hi(self) -> u64 {\n        self.0 >> 32', rs)
        self.assertIn('pub const fn top(self) -> u64', rs)
        self.assertIn('Wide::new(0x123456781abcdef0)', rs)

    def test_64_bit_testvec_must_decode(self):
        self.add_wide()
        self.edit(self.header, 'lo=0x1abcdef0', 'lo=0x1abcdef1')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('lo is', r.stdout)
        self.assertEqual(self.generate('--commit', 'abcdef012345').returncode, 1)

    def test_testvec_wider_than_word_fails(self):
        self.add_wide()
        self.edit(self.header, '0xa000000000000001 as UART.wide', '0x1a000000000000001 as UART.wide')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertIn('is wider than UART.wide (64 bits)', r.stdout)
        self.assertEqual(self.generate('--commit', 'abcdef012345').returncode, 1)

    def test_bit_63_needs_a_64_bit_word(self):
        self.edit(self.header, 'FRAME.payload 8:1', 'FRAME.payload 63:1')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('bad range 63:1 for FRAME.payload in a 32-bit word', r.stdout)

    def test_register_offsets_are_scoped_per_space(self):
        reg = '/* REG: UART.alias 0x10 rw32 %sreset=0x0 inferred */\n'
        self.edit(self.cfg, 'block = "UART"', 'block = "UART"\nspace = "cpu"')
        for tag, want in (('space=re ', 0), ('space=cpu ', 1)):
            with open(self.header, encoding='utf-8') as f:
                orig = f.read()
            with open(self.header, 'a') as f:
                f.write(reg % tag)
            r = self.check('--header', 'UART_DECODE.h')
            self.assertEqual(r.returncode, want, r.stdout)
            if want:
                self.assertIn('overlaps', r.stdout)
            with open(self.header, 'w') as f:
                f.write(orig)
        # Without any space, the same offset still collides.
        self.edit(self.cfg, 'space = "cpu"\n', '')
        with open(self.header, 'a') as f:
            f.write(reg % '')
        self.assertEqual(self.check('--header', 'UART_DECODE.h').returncode, 1)

    def test_prose_drift_fails_both_ways(self):
        doc = os.path.join(self.root, 'docs', 'uart.md')
        self.edit(doc, 'bits 31:16 of the control word', 'bits 30:16 of the control word')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('UART.ctl.divisor is 31:16 in the header but 30:16', r.stdout)
        self.edit(doc, 'The control register sits at', 'The control register is at')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertIn('prose for "control register fields" not found', r.stdout)

    def test_missing_doc_is_a_setup_error(self):
        os.remove(os.path.join(self.root, 'docs', 'uart.md'))
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 2)

    def test_unknown_header_is_a_setup_error(self):
        self.assertEqual(self.check('--header', 'NOPE_DECODE.h').returncode, 2)

    def test_stale_rust_fails(self):
        self.committed_rust()
        self.edit(self.header, 'FRAME.payload 8:1', 'FRAME.payload 9:1')
        r = self.check('--rust')
        self.assertEqual(r.returncode, 1)
        self.assertIn('stale', r.stdout)

    def test_rust_leak_scan(self):
        self.committed_rust()
        path = os.path.join(self.out, 'uart.rs')
        with open(path, 'a') as f:
            f.write('// the mini notes live in docs/uart.md\npub const BIG: u32 = 0x12345678;\n')
        r = self.check('--rust')
        self.assertEqual(r.returncode, 1)
        self.assertIn('note-file pointer', r.stdout)
        self.assertIn('mini named outside the banner', r.stdout)
        self.assertIn('hex literal 0x12345678', r.stdout)

    def test_rust_banner_commit_must_be_real(self):
        self.committed_rust()
        self.edit(self.header, 'UART_FIFO_DEPTH 16', 'UART_FIFO_DEPTH 32')
        self.assertEqual(self.generate().returncode, 0)  # dirty banner
        r = self.check('--rust')
        self.assertEqual(r.returncode, 1)
        self.assertIn('banner is not', r.stdout)

    def test_ci_check_runs_the_prose_checks(self):
        self.committed_rust()
        ci = os.path.join(HERE, 'ci-check')
        r = subprocess.run([sys.executable, ci], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.edit(os.path.join(self.root, 'docs', 'uart.md'),
                  'bits 31:16 of the control word', 'bits 30:16 of the control word')
        r = subprocess.run([sys.executable, ci], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn('publish-safe check', r.stderr)

    def test_docs_scan(self):
        self.committed_rust()
        with open(self.cfg, 'a') as f:
            f.write('\n[docs_scan]\npaths = ["docs/*.md"]\n')
        self.assertEqual(self.check().returncode, 0)
        with open(os.path.join(self.root, 'docs', 'uart.md'), 'a') as f:
            f.write('\nSee stand/src/uart.c for details.\n')
        r = self.check()
        self.assertEqual(r.returncode, 1)
        self.assertIn('docs/uart.md', r.stdout)

    def test_plugin_hooks(self):
        with open(os.path.join(self.root, 'plug.py'), 'w') as f:
            f.write('def check_header(ctx, h):\n'
                    '    ctx.rep.fail(h.file, "plugin saw %d fields" % len(h.fields))\n'
                    'def check_final(ctx):\n'
                    '    ctx.rep.fail("final", "plugin final")\n')
        self.edit(self.cfg, 'name = "mini"', 'name = "mini"\nplugin = "plug.py"')
        r = self.check('--header', 'UART_DECODE.h')
        self.assertEqual(r.returncode, 1)
        self.assertIn('plugin saw 6 fields', r.stdout)
        self.assertIn('plugin final', r.stdout)


if __name__ == '__main__':
    unittest.main()
