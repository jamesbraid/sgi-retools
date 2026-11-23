#!/usr/bin/env python3
"""promkit identify and unpack, against containers built here (never SGI bytes).

Run: python3 tools/prom/tests/test_prom.py
"""
import gzip
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)
import fixtures as fx  # noqa: E402
from prom import analyze, cli  # noqa: E402
from prom.model import ContainerError, document  # noqa: E402
from prom.payloads import lzw  # noqa: E402
from prom.schema import SchemaError, validate  # noqa: E402
from prom.transforms import swap16  # noqa: E402

PROMKIT = os.path.join(os.path.dirname(HERE), 'promkit')


def seg_at(image, name):
    """File offset of the SHDR segment called name (its name sits at +0x14)."""
    return image.index(name + b'\0') - 0x14


def checks(an):
    return {(s.name, c.rule): c.ok for s in an.segments for c in s.checks}


class Lzw(unittest.TestCase):
    def data(self):
        rng = random.Random(7)
        return rng.randbytes(9000) + b'a' * 500 + bytes(range(256)) * 4

    def test_round_trip_through_every_code_width_up_to_13_bits(self):
        data = self.data()
        self.assertEqual(lzw.decompress(fx.compress_z(data)), data)

    @unittest.skipUnless(shutil.which('gzip'), 'needs gzip')
    def test_the_encoder_agrees_with_the_host_decompressor(self):
        data = self.data()
        out = subprocess.run(['gzip', '-dc'], input=fx.compress_z(data), capture_output=True, check=True).stdout
        self.assertEqual(out, data)


    def test_a_clear_code_after_the_table_fills(self):
        data = random.Random(11).randbytes(150000)
        stream = fx.compress_z(data, clear_when_full=True)
        self.assertEqual(lzw.decompress(stream), data)
        if shutil.which('gzip'):
            out = subprocess.run(['gzip', '-dc'], input=stream, capture_output=True, check=True).stdout
            self.assertEqual(out, data)

    def test_a_code_past_the_table_is_an_error(self):
        stream = b'\x1f\x9d\x90' + (97 | 300 << 9).to_bytes(3, 'little')
        with self.assertRaises(ValueError):
            lzw.decompress(stream)


class Swap16(unittest.TestCase):
    def test_a_swapped_image_is_detected_and_restored(self):
        text = fx.mips_text()
        swapped = fx.mips_text(swapped=True)
        self.assertIsNone(swap16.probe(text))
        self.assertTrue(swap16.probe(swapped))
        self.assertEqual(swap16.apply(swapped), text)

    def test_an_odd_length_keeps_its_last_byte(self):
        self.assertEqual(swap16.apply(b'abcde'), b'badce')

    def test_analyze_reports_the_transform_and_byte_order(self):
        an = analyze(fx.mips_text(swapped=True))
        self.assertEqual(([t['name'] for t in an.transforms], an.byte_order, an.containers), (['swap16'], 'big', ['raw']))
        self.assertEqual(analyze(fx.mips_text()).transforms, [])


class Ip32Flash(unittest.TestCase):
    def test_five_segments_with_the_load_map(self):
        an = analyze(fx.installer(fx.o2_flash()))
        self.assertEqual(an.containers, ['installer', 'ip32-flash'])
        self.assertEqual([s.name for s in an.segments], ['sloader', 'env', 'post1', 'firmware', 'version'])
        self.assertTrue(an.ok)
        fw = an.segments[3]
        self.assertEqual((fw.load, fw.entry), (0x81000000, 0x81000000))
        self.assertEqual([(r['name'], r['address'], r['offset'], r['length']) for r in fw.regions],
                         [('text', 0x81000000, 0, 0x400), ('rodata', 0x81000400, 0x408, 0x200),
                          ('data', 0x81000600, 0x610, 0x100)])
        # each chunk follows its 8-byte record, so a region's bytes are found by offset, not by address
        for r, mark in zip(fw.regions[1:], (fx.MARK_RODATA, fx.MARK_DATA)):
            body = fw.data[r['offset']:r['offset'] + r['length']]
            self.assertEqual((len(body), struct.unpack('>I', body[:4])[0]), (r['length'], mark))
        self.assertEqual(an.segments[2].load, 0xbfc00000 + an.segments[2].offset - 0x100)

    def test_a_flash_without_the_installer_header(self):
        an = analyze(fx.o2_flash())
        self.assertEqual(an.containers, ['ip32-flash'])
        self.assertEqual(an.segments[0].offset, 0)

    def test_a_flipped_body_bit_fails_the_body_balance_only(self):
        flash = bytearray(fx.o2_flash())
        flash[seg_at(flash, b'env') + 0x60] ^= 1
        c = checks(analyze(bytes(flash)))
        self.assertFalse(c[('env', 'shdr-body-balance')])
        self.assertTrue(c[('env', 'shdr-header-zero-sum')])
        self.assertTrue(c[('post1', 'shdr-body-balance')])

    def test_a_flipped_header_bit_fails_the_header_sum(self):
        flash = bytearray(fx.o2_flash())
        flash[0x05] ^= 1                         # an unused header word of sloader
        self.assertFalse(checks(analyze(bytes(flash)))[('sloader', 'shdr-header-zero-sum')])

    def test_a_broken_load_map_fails_the_tiling_check(self):
        flash = bytearray(fx.o2_flash())
        off = seg_at(flash, b'firmware')
        flash[off + 0x40 + 7] ^= 1               # the first chunk length
        c = checks(analyze(bytes(flash)))
        self.assertFalse(c[('firmware', 'ip32-load-map-tiles')])
        self.assertTrue(c[('firmware', 'shdr-header-zero-sum')])

    def test_a_firmware_segment_too_short_for_a_load_map_fails_the_check(self):
        c = checks(analyze(fx.o2_flash(fx.shdr('firmware', '1.0', [], kind=3))))
        self.assertFalse(c[('firmware', 'ip32-load-map-tiles')])

    def test_installer_length_must_match_the_file(self):
        with self.assertRaises(ContainerError):
            analyze(fx.installer(fx.o2_flash()) + b'\0')


class Io4(unittest.TestCase):
    def test_flat(self):
        payload = fx.mips_text(40)
        an = analyze(fx.jfk4(payload))
        self.assertEqual(an.containers, ['io4-flat'])
        seg = an.segments[0]
        self.assertEqual((seg.data, seg.offset, seg.load, seg.entry), (payload, 24, 0x81800000, 0x81800000))
        self.assertTrue(an.ok)

    def test_flat_checksum_and_length(self):
        image = bytearray(fx.jfk4(fx.mips_text(40)))
        image[40] ^= 1
        self.assertFalse(analyze(bytes(image)).ok)
        with self.assertRaises(ContainerError):
            analyze(bytes(fx.jfk4(fx.mips_text(40))) + b'\0')

    def test_segmented_applies_the_bias_and_decodes_lzw(self):
        bodies = [(0x105, fx.mips_text(300)), (0x205, b'\x7fELF' + random.Random(3).randbytes(5000))]
        an = analyze(fx.jksw(bodies))
        self.assertEqual(an.containers, ['io4-segmented'])
        self.assertEqual([s.name for s in an.segments], ['loader', 'ip19', 'ip21'])
        self.assertEqual([s.data for s in an.segments[1:]], [b for _, b in bodies])
        self.assertEqual((an.segments[0].offset, an.segments[0].extra['table_offset']), (0x320, '0x1000'))
        self.assertEqual([s.format for s in an.segments[1:]], ['flat', 'elf'])
        self.assertTrue(an.ok)
        self.assertEqual(an.byte_order, 'big')

    def test_segmented_checksums_are_checked(self):
        image = bytearray(fx.jksw([(0x105, fx.mips_text(300))]))
        image[0x320 + 3] ^= 1                    # a loader byte: its record sum and the header sum both break
        c = checks(analyze(bytes(image)))
        self.assertFalse(c[('loader', 'record-halfword-sum')])
        self.assertFalse(c[('loader', 'header-halfword-sum')])
        self.assertTrue(c[('ip19', 'lzw-byte-sum')])

    def test_a_surplus_zero_byte_after_the_payload_is_trimmed_and_recorded(self):
        body = fx.mips_text(300)
        an = analyze(fx.jksw([(0x105, body)], pad=1))
        self.assertEqual((an.segments[1].data, an.segments[1].extra['lzw_trimmed']), (body, 1))
        self.assertTrue(an.ok)

    def test_a_surplus_nonzero_byte_stays_visible(self):
        an = analyze(fx.jksw([(0x105, fx.mips_text(300))], pad=1, pad_byte=b'x'))
        self.assertFalse(checks(an)[('ip19', 'lzw-length')])
        self.assertNotIn('lzw_trimmed', an.segments[1].extra)

    def test_a_jksw_header_without_a_segment_table_is_an_error(self):
        image = bytearray(fx.jksw([(0x105, fx.mips_text(300))]))
        image[0x18:0x1c] = b'XXXX'
        with self.assertRaises(ContainerError):
            analyze(bytes(image))

    def test_a_segment_outside_the_file_is_an_error(self):
        with self.assertRaises(ContainerError):
            analyze(fx.jksw([(0x105, fx.mips_text(300))])[:-100])


class Promgen64(unittest.TestCase):
    def test_raw_and_gzip_segments(self):
        a, b = fx.mips_text(50), fx.mips_text(70)
        an = analyze(fx.promgen64([('a', a, 0xc00000001fc00000, False), ('b', b, 0x80000000, True)]))
        self.assertEqual(an.containers, ['promgen64'])
        self.assertEqual([(s.name, s.data, s.compression, s.load) for s in an.segments],
                         [('a', a, 'none', 0xc00000001fc00000), ('b', b, 'gzip', 0x80000000)])
        self.assertTrue(an.ok)

    def test_a_byte_sum_mismatch_is_reported(self):
        image = bytearray(fx.promgen64([('a', fx.mips_text(50), 0, False)]))
        image[0x1000 + 1] ^= 1
        self.assertFalse(analyze(bytes(image)).ok)

    def test_a_corrupt_gzip_stream_is_an_error(self):
        image = bytearray(fx.promgen64([('a', fx.mips_text(50), 0, True)]))
        image[0x1000 + 12] ^= 0xff
        with self.assertRaises(ContainerError):
            analyze(bytes(image))

    def test_a_segment_past_the_end_is_an_error(self):
        with self.assertRaises(ContainerError):
            analyze(fx.promgen64([('a', fx.mips_text(50), 0, False)])[:-8])


class Truncated(unittest.TestCase):
    def test_a_cut_header_is_a_container_error_not_a_traceback(self):
        cases = {'io4-flat': fx.jfk4(fx.mips_text(4))[:10], 'io4-segmented': fx.jksw([(0x105, fx.mips_text(4))])[:0x1e],
                 'promgen64': fx.promgen64([('a', fx.mips_text(4), 0, False)])[:0x60],
                 'ip32-flash': fx.o2_flash()[:0x50]}
        for name, image in cases.items():
            with self.subTest(container=name), self.assertRaises(ContainerError):
                analyze(image)

    def test_the_command_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 't.bin')
            with open(path, 'wb') as f:
                f.write(fx.jfk4(fx.mips_text(4))[:10])
            r = subprocess.run([sys.executable, '-I', PROMKIT, 'unpack', path, '--out', d], capture_output=True, text=True)
            self.assertEqual((r.returncode, 'Traceback' in r.stderr), (2, False))


class Schema(unittest.TestCase):
    def doc(self):
        an = analyze(fx.installer(fx.o2_flash()))
        return document(an, 'o2.image', {i: 'segments/%d.bin' % i for i in range(len(an.segments))}, None, 'abc')

    def code(self):
        addr = {'segment': 'firmware', 'address': '0x81000000'}
        return {'schema': 'sgi-prom', 'version': 1, 'kind': 'code', 'tool': {'name': 'x', 'revision': 'y'},
                'image': {'sha256': '0' * 64}, 'functions': [{'address': addr, 'grade': 'inferred'}],
                'calls': [{'from': addr, 'to': addr, 'grade': 'inferred'}], 'device_accesses': [],
                'matches': [{'address': addr, 'image_sha256': '1' * 64, 'grade': 'unknown'}],
                'modules': [{'name': 'm', 'address': addr}]}

    def refused(self, doc, text):
        with self.assertRaises(SchemaError) as cm:
            validate(doc)
        self.assertIn(text, str(cm.exception))

    def test_what_promkit_writes_and_a_code_file_both_validate(self):
        validate(json.loads(json.dumps(self.doc())))
        validate(self.code())

    def test_an_unknown_version_is_refused_before_anything_else(self):
        for version in (2, 0, '1', True):
            doc = self.doc()
            doc['version'] = version
            doc['segments'] = 'not even checked'
            self.refused(doc, 'not supported')

    def test_another_schema_name_is_refused(self):
        self.refused(dict(self.doc(), schema='prom-manifest/1'), 'not an sgi-prom document')

    def test_a_missing_or_misplaced_field_names_its_path(self):
        doc = self.doc()
        del doc['identity']['sha256']
        doc['segments'][0]['load'] = '81000000'
        doc['segments'][0]['regions'] = [{'name': 'text'}]
        doc['stray'] = 1
        for text in ('$.identity: missing sha256', "$.segments[0].load: '81000000' does not match", '$.segments[0].regions[0]: missing offset',
                     '$: unknown field stray'):
            self.refused(doc, text)

    def test_segment_names_are_unique_and_a_parent_names_a_segment(self):
        doc = self.doc()
        doc['segments'][1]['name'] = doc['segments'][0]['name']
        self.refused(doc, 'duplicate name sloader')
        doc = self.doc()
        doc['segments'][0]['parent'] = 'flash'
        self.refused(doc, 'no segment named flash')
        doc['segments'][0]['parent'] = doc['segments'][1]['name']
        validate(doc)

    def test_a_grade_outside_the_six_ratings_is_refused(self):
        doc = self.code()
        doc['functions'][0]['grade'] = 'likely'
        self.refused(doc, "$.functions[0].grade: 'likely'")

    def test_the_kind_picks_the_shape(self):
        doc = self.code()
        del doc['calls']
        self.refused(doc, 'missing calls')
        self.refused(dict(self.code(), kind='facts'), 'kind must be one of')

    def test_validate_command(self):
        with tempfile.TemporaryDirectory() as d:
            good, bad = os.path.join(d, 'a.prom.json'), os.path.join(d, 'b.prom.json')
            with open(good, 'w') as f:
                json.dump(self.doc(), f)
            with open(bad, 'w') as f:
                json.dump(dict(self.doc(), version=2), f)
            run = lambda *a: subprocess.run([sys.executable, '-I', PROMKIT, 'validate', *a], capture_output=True, text=True)
            self.assertEqual(run(good).returncode, 0)
            r = run(good, bad)
            self.assertEqual(r.returncode, 1)
            self.assertIn('not supported', r.stderr)


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def path(self, name, data=None):
        p = os.path.join(self.dir, name)
        if data is not None:
            with open(p, 'wb') as f:
                f.write(data)
        return p

    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-I', PROMKIT, *args], capture_output=True, text=True, cwd=self.dir)

    def index(self, image):
        row = {'board': 'ip32', 'version': '9.9', 'rev': 'A', 'part': '', 'kind': 'shipped', 'name': 'prom/x.image',
               'size': len(image), 'sha256': hashlib.sha256(image).hexdigest()}
        return self.path('index.json', json.dumps({'format': 1, 'proms': [row]}).encode())

    def test_identify_reports_board_byte_order_and_container(self):
        image = fx.installer(fx.o2_flash())
        r = self.run_cli('identify', '--catalog', self.index(image), self.path('o2.image', image))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ip32 9.9 rev A  unknown  installer>ip32-flash', r.stdout)

    def test_identify_json_and_an_uncatalogued_swapped_image(self):
        text = fx.mips_text()
        r = self.run_cli('identify', '--json', '--catalog', self.index(text), self.path('t.bin', fx.mips_text(swapped=True)))
        doc = json.loads(r.stdout)
        self.assertEqual((doc['catalog']['board'], doc['transforms'], doc['container']), ('ip32', ['swap16'], 'raw'))

    def test_identify_offline_uses_the_cached_index(self):
        image = fx.jfk4(fx.mips_text(40))
        os.makedirs(os.path.join(self.dir, '.cache', 'prom'))
        shutil.copy(self.index(image), os.path.join(self.dir, '.cache', 'prom', 'index.json'))
        r = self.run_cli('identify', self.path('f.bin', image))
        self.assertIn('ip32 9.9', r.stdout)
        self.assertEqual(r.stderr, '')

    def test_unpack_writes_segments_and_the_prom_file(self):
        image = fx.installer(fx.o2_flash())
        r = self.run_cli('unpack', self.path('o2.image', image), '--out', os.path.join(self.dir, 'out'))
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.dir, 'out', 'o2.image.prom.json')) as f:
            m = json.load(f)
        validate(m)
        self.assertEqual((m['schema'], m['version'], m['kind'], m['identity']['container'], m['identity']['sha256']),
                         ('sgi-prom', 1, 'prom', 'installer>ip32-flash', hashlib.sha256(image).hexdigest()))
        self.assertEqual((m['tables'], m['strings'], m['assets']), ([], [], []))
        fw = [s for s in m['segments'] if s['name'] == 'firmware'][0]
        self.assertEqual((fw['load'], fw['offset'], fw['file']), ('0x81000000', hex(seg_at(image, b'firmware')), 'segments/firmware.bin'))
        with open(os.path.join(self.dir, 'out', fw['file']), 'rb') as f:
            self.assertEqual(f.read(), image[int(fw['offset'], 16):][:int(fw['length'], 16)])

    def test_duplicate_segment_names_write_nothing(self):
        image = fx.promgen64([('a', fx.mips_text(4), 0, False), ('a', fx.mips_text(8), 0, False)])
        out = os.path.join(self.dir, 'out')
        r = self.run_cli('unpack', self.path('d.img', image), '--out', out)
        self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.exists(out))

    def test_a_segment_name_cannot_leave_the_output_directory(self):
        out = os.path.join(self.dir, 'a', 'b')
        for name in ('../../escape', 'x/y', 'x\\y', '..'):
            with self.subTest(name=name):
                r = self.run_cli('unpack', self.path('e.img', fx.promgen64([(name, fx.mips_text(4), 0, False)])), '--out', out)
                self.assertEqual(r.returncode, 2)
                self.assertIn('cannot be a file name', r.stderr)
        self.assertEqual(os.listdir(os.path.join(self.dir, 'a')) if os.path.isdir(os.path.join(self.dir, 'a')) else [], [])

    def test_unpack_exits_1_after_writing_when_a_check_fails(self):
        flash = bytearray(fx.o2_flash())
        flash[seg_at(flash, b'env') + 0x60] ^= 1
        r = self.run_cli('unpack', self.path('bad.bin', bytes(flash)), '--out', os.path.join(self.dir, 'out'))
        self.assertEqual(r.returncode, 1)
        self.assertIn('shdr-body-balance', r.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.dir, 'out', 'segments', 'env.bin')))

    def test_unpack_label_names_files_the_way_the_old_promgen64_script_did(self):
        image = fx.promgen64([('ip27prom', fx.mips_text(50), 0xc00000001fc00000, False)])
        r = self.run_cli('unpack', self.path('p.img', image), '--out', os.path.join(self.dir, 'prom'), '--label', 'ip27')
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(self.dir, 'prom', 'ip27.ip27prom.bin'), 'rb') as f:
            self.assertEqual(f.read(), fx.mips_text(50))

    def test_a_structural_error_exits_2(self):
        r = self.run_cli('unpack', self.path('bad.image', fx.installer(fx.o2_flash()) + b'\0'), '--out', self.dir)
        self.assertEqual(r.returncode, 2)

    def test_an_unreadable_catalog_is_a_setup_error(self):
        r = self.run_cli('identify', '--catalog', self.path('none.json'), self.path('t.bin', fx.mips_text()))
        self.assertEqual(r.returncode, 2)


if __name__ == '__main__':
    unittest.main()
