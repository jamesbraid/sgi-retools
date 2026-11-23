#!/usr/bin/env python3
"""promkit against catalogued PROM images, found by sha256 in the directory RETOOLS_PROM_IMAGES names.

An image that is not there skips its test and prints the sha256 to fetch. The expected results are the golden
sgi-prom documents in golden/ (derived numbers only, no image bytes) and the values the chips pages establish.
`PROM_WRITE_GOLDEN=1` rewrites the goldens from the tool's own output; review the diff before committing.

Run: RETOOLS_PROM_IMAGES=DIR python3 tools/prom/tests/test_real_images.py
"""
import atexit
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from prom import analyze, cli  # noqa: E402
from prom.assets import extract  # noqa: E402
from prom.model import JR_RA, document  # noqa: E402
from prom.schema import validate  # noqa: E402

GOLDEN = os.path.join(HERE, 'golden')
GOLDEN_ASSETS = os.path.join(GOLDEN, 'assets')
_found = {}


def find(sha):
    """Path of the file under RETOOLS_PROM_IMAGES whose sha256 is sha, else None."""
    root = os.environ.get('RETOOLS_PROM_IMAGES')
    if root and not _found and os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                with open(path, 'rb') as f:
                    _found[hashlib.sha256(f.read()).hexdigest()] = path
    return _found.get(sha)


def load(sha):
    path = find(sha)
    if path is None:
        raise unittest.SkipTest('image %s not found under RETOOLS_PROM_IMAGES' % sha)
    with open(path, 'rb') as f:
        return f.read()


def normalized(an):
    doc = document(an, '', {i: 'segments/%s.bin' % s.name for i, s in enumerate(an.segments)}, None, '')
    validate(doc)
    del doc['tool']
    for key in ('file', 'catalog', 'family'):
        del doc['identity'][key]
    return doc


# What the chips pages establish, keyed by the image's sha256 (prefix) and the segment: the payload sha256 table of
# the IO4 payload page (decompressed bytes), and the loader lengths and the header checksum it gives.
IO4_PAYLOADS = {
    '10d24938': {'ip19': '3df8837b4097f934244900ae0f18215fd47b14ec8c17a80d7adedb65531e39a2', 'ip21': '53410dad9068abee035cb35a22ce72730b7d26a04ae3c3b34c40bf10a7941d0e', 'graphics': 'f94b68cfec6731444ce900794e1a732931c062d05c789f3b0a3c09170abea164'},
    'cf617388': {'ip19': 'cd4d6ad92e7259501f5b1fab16c61c8370484133421d021685373558c190edce', 'ip21': 'c84efcbd401ba56f348d13b280156fef5d8de87398b1b1ab471d2e8e5df746a8', 'graphics': 'f94b68cfec6731444ce900794e1a732931c062d05c789f3b0a3c09170abea164'},
    'a639d23e': {'ip19': '373d5a2104d994a8b4ea6832ea22df6a6556714c8e4dc450ebfd5421bbaa14b6', 'ip21': '817bc14835f6d8c8a1b400fce1935186f3e7604ef1533275cb6d797ff5f80a0f', 'graphics': 'f94b68cfec6731444ce900794e1a732931c062d05c789f3b0a3c09170abea164'},
    '31c657b4': {'ip19': 'ecc1c75eed440b0cc68d539f30f0a2d0398ac3d39fc67b26de8ac0709754f001', 'ip21': '43e4181126ed46939dfc486cdea3f191e71372e9ee86579c8adda7731ca3ef61', 'graphics': 'f94b68cfec6731444ce900794e1a732931c062d05c789f3b0a3c09170abea164'},
    '935cda24': {'ip19': 'a83d4c4c1b62cdf8b67c2a2801a4dc952575aedfd112a15718b37ce968b33dfd', 'ip21': 'cc9ebf7b725b1195d01999a58d9613d7922cbf5b8b823cdf197f4fb3ce35315c', 'ip25': '143a0ccaa2a95dc6396830f34dbf1bc00a05fc4393ee2ac5ceec0d8873d93b6f'},
    '7019deae': {'ip19': '50b71b3dc7bdc4d09e3ed26d86ef040fec6b2d9dfbc1885313ffb8c3b1162535', 'ip21': '9d1f00d7ffba23c8f63be603a169e28c9df54e27d8e00257c5f29ac49bf0e2e6', 'ip25': '4ff8984a3bd50804354bae2a7c06e343e36cfbbafa8dacf83c5f9729ed8f5a39'},
    'bc9e654a': {'ip19': 'bbbc0be25b7e698960ee33adf7284187cf81f797d4c093a26c28c4b3535da679', 'ip21': 'bc9e9412aa1aca49ff6da21dd00b27a6ba11de8fa9baf779c30a9bff1c200daf', 'ip25': 'd41322da06fa9804f780862b3cf3a95c4ac5fe6aa51924498eba6f357d1af76a'},
}
IO4_FLAT = {   # image -> start of the flat IP19 payload's sha256
    '248cfc68': 'f1ca1b8d', '53f19c35': '5abe1fea', 'e07b482e': 'bf849c7c',
    '4b068858': '004cbbc6', '037b1174': '0ebc962f', '1d598680': 'ba6478c1'}
IO4_LOADER_LENGTH = {'10d24938': 0x3570, 'cf617388': 0x3570, 'a639d23e': 0x3570, '31c657b4': 0x3570,
                     '935cda24': 0x4870, '7019deae': 0x4870, 'bc9e654a': 0x4600}
# O2 flash segments as (name, flash offset, length); the file holds the 0x100-byte header before the flash.
O2_SEGMENTS = {
    '11230c35': [('sloader', 0, 0x4000), ('env', 0x4000, 0x400), ('post1', 0x4400, 0x4d44),
                 ('firmware', 0x9200, 0x5fffc), ('version', 0x69200, 0x388)],
    '820585be': [('sloader', 0, 0x4000), ('env', 0x4000, 0x400), ('post1', 0x4400, 0x4c34),
                 ('firmware', 0x9200, 0x5f27c), ('version', 0x68600, 0x388)],
}
O2_418_LOAD_MAP = [('text', 0x81000000, 0x48e70), ('rodata', 0x81048e70, 0xb290), ('data', 0x81054100, 0xbee0)]


class RealImages(unittest.TestCase):
    def full(self, prefix):
        for name in os.listdir(GOLDEN):
            if name.startswith(prefix[:8]):
                with open(os.path.join(GOLDEN, name)) as f:
                    return json.load(f)['identity']['sha256']
        raise AssertionError('no golden for %s' % prefix)

    def an(self, prefix):
        return analyze(load(self.full(prefix)))

    def test_io4_payloads_match_the_chips_table(self):
        for prefix, table in IO4_PAYLOADS.items():
            with self.subTest(image=prefix):
                an = self.an(prefix)
                self.assertTrue(an.ok)
                self.assertEqual({s.name: hashlib.sha256(s.data).hexdigest() for s in an.segments[1:]}, table)
                self.assertEqual(an.segments[0].stored_length, IO4_LOADER_LENGTH[prefix])
                self.assertEqual(len(an.segments), 4)

    def test_io4_flat_payloads_match_the_chips_table(self):
        for prefix, start in IO4_FLAT.items():
            with self.subTest(image=prefix):
                an = self.an(prefix)
                self.assertTrue(an.ok)
                self.assertTrue(hashlib.sha256(an.segments[0].data).hexdigest().startswith(start))

    def test_the_1996_header_checksum_is_the_one_chips_gives(self):
        data = load(self.full('7019deae'))
        self.assertEqual(data[4:8].hex(), '06a8fd00')

    def test_o2_segment_tables_match_the_chips_page(self):
        for prefix, table in O2_SEGMENTS.items():
            with self.subTest(image=prefix):
                an = self.an(prefix)
                self.assertTrue(an.ok)
                self.assertEqual([(s.name, s.offset - 0x100, s.stored_length) for s in an.segments], table)

    def test_o2_418_load_map_matches_the_chips_page(self):
        fw = self.an('11230c35').segments[3]
        self.assertEqual([(r['name'], r['address'], r['length']) for r in fw.regions], O2_418_LOAD_MAP)
        # each chunk after the first starts 8 bytes after its record; the closing record follows the last chunk
        self.assertEqual([r['offset'] for r in fw.regions], [0, 0x48e78, 0x54110])
        data = fw.regions[2]
        self.assertEqual(data['offset'] + data['length'], 0x5fff0)
        self.assertEqual(fw.data[0x48e70:0x48e78], bytes.fromhex('81048e70') + (0xb290).to_bytes(4, 'big'))

    def test_the_swapped_indigo_dump_swaps_back_to_big_endian_code(self):
        data = load('5c758f4b89dbe5607915c869363af9a231f1a2f4d99baeee7f7fd32739d1d3d0')
        an = analyze(data)
        self.assertEqual([t['name'] for t in an.transforms], ['swap16'])
        self.assertEqual(sum(1 for i in range(0, len(an.data) - 3, 4) if an.data[i:i + 4] == JR_RA), 753)


# What chips platforms/ip32/prom-assets.md gives for the two O2 builds, 4.18 first: the routines the assets are found
# through, where the logo and tune arrays sit, and the icon objects (menu items in order, then the install dialog's).
O2_ASSETS = {
    '11230c35': {'palette': 0x81030270, 'gradient': 0x810461a0, 'menu': 0x810423ec, 'background': 0x81048a10,
                 'lookup': 0x8104629c, 'tagline': 0x810488d8, 'logo': 0x8105ed04, 'tunes': 0x81054394, 'jump_table': 0x81049414,
                 'fonts': (0x8105b970, 0x8105cffc, 0x8105d08c, 0x8105e2e4),
                 'icons': (0x81057498, 0x810578a0, 0x81057bd4, 0x81057f70, 0x81058320, 0x81058630,
                           0x81057234, 0x81056520, 0x81055e54, 0x81056a54)},
    '820585be': {'palette': 0x8102f7d0, 'gradient': 0x81045680, 'menu': 0x810418cc, 'background': 0x81047ef0,
                 'lookup': 0x8104577c, 'tagline': 0x81047db8, 'logo': 0x8105df84, 'tunes': 0x81053704, 'jump_table': 0x810488f4,
                 'fonts': (0x8105abf0, 0x8105c27c, 0x8105c30c, 0x8105d564),
                 'icons': (0x81056728, 0x81056b30, 0x81056e64, 0x81057200, 0x810575b0, 0x810578c0,
                           0x810564c4, 0x810557b0, 0x810550e4, 0x81055ce4)},
}
ICON_LAYERS = (10, 10, 6, 6, 5, 10, 9, 7, 8, 8)
TUNE_VOICES = (7, 5, 6, 6, 5, 5, 4, 5, 7, 7, 7)
TUNE_TOTALS = (0x1e576, 0x1ec2f, 0x22740, 0x21f4b, 0x1eb23, 0x1ec2f, 0x1ef43, 0x21119, 0x1e576, 0x1e576, 0x1e576)
_assets = {}


def assets_of(image):
    """(manifest assets, output directory) of the image, extracted once per run."""
    if image not in _assets:
        out = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, out, True)
        _assets[image] = (extract(analyze(image), out), out)
    return _assets[image]


class RealAssets(unittest.TestCase):
    def setUp(self):
        self.full = RealImages().full

    def load(self, prefix):
        files, out = assets_of(load(self.full(prefix)))
        self.by = {f['name']: f for f in files}
        self.out = out
        self.want = O2_ASSETS[prefix]

    def doc(self, name):
        with open(os.path.join(self.out, self.by[name]['file'])) as f:
            return json.load(f)

    def each(self):
        for prefix in O2_ASSETS:
            with self.subTest(image=prefix):
                self.load(prefix)
                yield prefix

    def test_every_output_is_listed_with_its_hash_and_source_address(self):
        for _ in self.each():
            files, out = assets_of(load(self.full(_)))
            self.assertEqual(len(files), 106)
            for f in files:
                with open(os.path.join(out, f['file']), 'rb') as g:
                    self.assertEqual(hashlib.sha256(g.read()).hexdigest(), f['sha256'])
                self.assertEqual(f['address']['segment'], 'firmware')

    def test_the_routines_are_the_ones_the_chips_page_names(self):
        for _ in self.each():
            at = lambda name: int(self.by[name]['address']['address'], 16)
            self.assertEqual(at('palette'), self.want['palette'])
            self.assertEqual(at('background gradient'), self.want['gradient'])
            self.assertEqual(self.doc('menu and logo layout')['menu']['routine'], '0x%x' % self.want['menu'])
            self.assertEqual(self.doc('menu and logo layout')['background']['routine'], '0x%x' % self.want['background'])
            self.assertEqual(self.doc('tagline glyphs')['routine'], '0x%x' % self.want['tagline'])
            self.assertEqual(self.doc('font 0')['lookup']['routine'], '0x%x' % self.want['lookup'])

    def test_palette_has_the_ramp_and_the_page_colour_entries(self):
        for _ in self.each():
            d = self.doc('palette')
            self.assertEqual((len(d['entries']), len(d['unwritten'])), (201, 55))
            self.assertEqual((d['ramp']['first_index'], d['ramp']['count']), (0x60, 160))
            self.assertEqual([c['step'] for c in d['ramp']['channels']], ['0x8199', '0xb800', '0xb333'])
            self.assertEqual([e['index'] for e in d['entries'] if 'source' in e], [9, 10])
            self.assertEqual(self.doc('background gradient')['numerator'], '0xa00000')

    def test_fonts_have_the_chips_entry_counts_heights_and_descents(self):
        for _ in self.each():
            fonts = [self.doc('font %d' % k) for k in range(4)]
            self.assertEqual([f['entry_count'] for f in fonts], [190, 7, 95, 95])
            self.assertEqual([(f['height'], f['descent']) for f in fonts], [(17, 4), (20, 4), (23, 5), (14, 3)])
            self.assertEqual([f['bitmap_address'] for f in fonts], ['0x%x' % a for a in self.want['fonts']])
            self.assertEqual(fonts[0]['fixed_advance'], 9)
            self.assertEqual([e['index'] for e in fonts[1]['entries'] if 'drawable' in e], [4])
            self.assertEqual([e['index'] for f in (fonts[0], fonts[2], fonts[3]) for e in f['entries'] if 'drawable' in e], [])

    def test_the_tagline_has_nineteen_glyphs_and_a_33_character_index(self):
        for _ in self.each():
            d = self.doc('tagline glyphs')
            self.assertEqual((d['entry_count'], len(d['index']), d['pool_size']), (19, 33, 660))

    def test_the_logo_is_1095_bytes_of_494_by_237(self):
        for _ in self.each():
            f = self.by['logo']
            self.assertEqual((f['details']['width'], f['details']['height'], f['details']['encoded_length']), (494, 237, 1095))
            self.assertEqual(f['address']['address'], '0x%x' % self.want['logo'])

    def test_ten_icons_with_the_chips_layer_counts_in_use_order(self):
        for _ in self.each():
            d = self.doc('icon list')['icons']
            self.assertEqual([len(i['layers']) for i in d], list(ICON_LAYERS))
            self.assertEqual([i['object_address'] for i in d], ['0x%x' % a for a in self.want['icons']])
            self.assertEqual((min(i['width'] for i in d), max(i['width'] for i in d), max(i['height'] for i in d)), (15, 67, 64))
            self.assertEqual([i['yoffset'] for i in d if i['yoffset']], [-2])

    def test_sixty_four_voices_in_eleven_tunes_laid_out_as_chips_gives(self):
        for _ in self.each():
            d = self.doc('tune and voice descriptors')
            self.assertEqual(d['jump_table'], '0x%x' % self.want['jump_table'])
            self.assertEqual([t['voice_count'] for t in d['tunes']], list(TUNE_VOICES))
            self.assertEqual([t['total_length'] for t in d['tunes']], list(TUNE_TOTALS))
            self.assertEqual(sum(len(t['voices']) for t in d['tunes']), 64)
            self.assertEqual({v['sample_count'] for t in d['tunes'] for v in t['voices']}, {88200})
            self.assertEqual(min(int(t['array_address'], 16) for t in d['tunes']), self.want['tunes'])

    def test_both_builds_carry_the_same_payloads(self):
        outs = []
        for prefix in O2_ASSETS:
            self.load(prefix)
            outs.append({n: f['sha256'] for n, f in self.by.items()})
        shared = ('logo', 'palette swatch', 'tagline glyph bitmap', 'font 0 bitmap', 'font 1 bitmap', 'font 2 bitmap',
                  'font 3 bitmap') + tuple('menu-%d' % k for k in range(6)) + tuple('install-%d' % k for k in range(4))
        for name in shared:
            self.assertEqual(outs[0][name], outs[1][name], name)

    def test_the_assets_command_writes_a_valid_document_that_lists_them(self):
        for prefix in O2_ASSETS:
            with self.subTest(image=prefix):
                load(self.full(prefix))            # skips when the image is absent
                path = find(self.full(prefix))
                out = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, out, True)
                index = os.path.join(out, 'index.json')
                with open(index, 'w') as f:
                    f.write('{"proms": []}')
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(['assets', path, '--out', out, '--catalog', index]), 0)
                with open(os.path.join(out, os.path.basename(path) + '.prom.json')) as f:
                    doc = json.load(f)
                validate(doc)
                self.assertEqual(len(doc['assets']), 106)
                self.assertEqual(doc['assets'], assets_of(load(self.full(prefix)))[0])


def assets_golden_test(name):
    def test(self):
        path = os.path.join(GOLDEN_ASSETS, name)
        with open(path) as f:
            want = json.load(f)
        got = {'image': want['image'], 'assets': assets_of(load(want['image']))[0]}
        if os.environ.get('PROM_WRITE_GOLDEN'):
            with open(path, 'w') as f:
                json.dump(got, f, indent=1)
                f.write('\n')
        self.assertEqual(got, want)
    return test


if os.path.isdir(GOLDEN_ASSETS):
    for _name in sorted(os.listdir(GOLDEN_ASSETS)):
        setattr(RealAssets, 'test_golden_' + _name[:16], assets_golden_test(_name))


def golden_test(name):
    def test(self):
        path = os.path.join(GOLDEN, name)
        with open(path) as f:
            want = json.load(f)
        got = normalized(analyze(load(want['identity']['sha256'])))
        if os.environ.get('PROM_WRITE_GOLDEN'):
            with open(path, 'w') as f:
                json.dump(got, f, indent=1)
                f.write('\n')
        self.assertEqual(got, want)
    return test


for _name in sorted(os.listdir(GOLDEN)):
    if _name.endswith('.json'):
        setattr(RealImages, 'test_golden_' + _name[:16], golden_test(_name))

if __name__ == '__main__':
    unittest.main()
