#!/usr/bin/env python3
"""Tests of tools/hdsp/sonic_dsp.py on a small synthetic resource fork.

Run: python3 tools/hdsp/test_sonic_dsp.py   (no vendor files, no third-party packages)

The fork is assembled from the layout the module documents: a 16-byte header (data offset and
length, map offset and length), data records with a 4-byte length prefix, a map with a type list,
reference entries and a name list.
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sonic_dsp as sd  # noqa: E402


def build_fork(resources):
    """resources: list of (type, id, name, body). Returns the fork bytes."""
    data = b''
    offs = []
    for _t, _i, _n, body in resources:
        offs.append(len(data))
        data += struct.pack('>I', len(body)) + body
    types = []
    for t, *_ in resources:
        if t not in types:
            types.append(t)
    names = b''
    name_off = {}
    for _t, i, n, _b in resources:
        if n:
            name_off[i, _t] = len(names)
            names += bytes([len(n)]) + n.encode('latin-1')
    tl = 28
    nt = len(types)
    refs_base = 2 + 8 * nt
    type_list = struct.pack('>H', nt - 1)
    refs = b''
    for t in types:
        group = [(k, r) for k, r in enumerate(resources) if r[0] == t]
        type_list += t.encode('latin-1') + struct.pack('>HH', len(group) - 1, refs_base + len(refs))
        for k, (_t, i, n, _b) in group:
            no = name_off.get((i, t), 0xffff)
            refs += struct.pack('>hH', i, no) + b'\0' + struct.pack('>I', offs[k])[1:] + b'\0\0\0\0'
    type_list += refs
    nl_off = tl + len(type_list)
    m = b'\0' * 24 + struct.pack('>HH', tl, nl_off) + type_list + names
    return struct.pack('>IIII', 256, 256 + len(data), len(data), len(m)).ljust(256, b'\0') + data + m


def upgm(space, start, words):
    return struct.pack('>HHI', space, len(words), start) + b''.join(struct.pack('>I', w) for w in words)


def usym(space, syms):
    b = struct.pack('>HH', space, len(syms))
    for n, v in syms:
        b += n.encode().ljust(32, b'\0') + struct.pack('>I', v)
    return b


def ucde(parts):
    b = struct.pack('>HH', 1, len(parts))
    for t, i in parts:
        b += t.encode() + b'\0' * 66 + struct.pack('>h', i)
    return b


def fixture():
    return build_fork([
        ('UPGM', 10, '', upgm(3, 0x100, [0x0af080, 0x000123, 0x000000])),
        ('UPGM', 11, '', upgm(1, 0, [0x7f0001, 0x000002])),
        ('USYM', 20, '', usym(1, [('sym_a', 2), ('sym_b', 3)])),
        ('UCDE', 1, 'img_p0.lnk', ucde([('USYM', 20), ('UPGM', 10), ('UPGM', 11)])),
        ('UCDE', 2, 'empty.lnk', ucde([])),
    ])


class Fork(unittest.TestCase):
    def test_resources_listed_with_names_and_lengths(self):
        r = sd.Resources(fixture())
        kinds = sorted((t, i) for t, i, *_ in r.list)
        self.assertEqual(kinds, [('UCDE', 1), ('UCDE', 2), ('UPGM', 10), ('UPGM', 11), ('USYM', 20)])
        self.assertEqual(r.images(), {'img_p0.lnk': 1, 'empty.lnk': 2})

    def test_image_segments_and_symbols(self):
        segs, syms = sd.Resources(fixture()).image('img_p0.lnk')
        self.assertEqual(segs, [(3, 0x100, [0x0af080, 0x123, 0]), (1, 0, [0x7f0001, 2])])
        self.assertEqual(syms, {1: [('sym_a', 2), ('sym_b', 3)]})

    def test_words_are_masked_to_24_bits(self):
        r = sd.Resources(build_fork([('UPGM', 1, '', upgm(3, 0, [0xff123456]))]))
        self.assertEqual(r.segment(1)[2], [0x123456])

    def test_bad_segment_length_is_an_error(self):
        bad = upgm(3, 0, [1, 2])[:-2]
        with self.assertRaises(ValueError):
            sd.Resources(build_fork([('UPGM', 1, '', bad)])).segment(1)

    def test_empty_image(self):
        self.assertEqual(sd.Resources(fixture()).image('empty.lnk'), ([], {}))

    def test_cli_listing_and_image(self):
        import io
        import tempfile
        from contextlib import redirect_stderr, redirect_stdout
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(fixture())
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                sd.main([f.name, 'list', 'UCDE'])
            self.assertIn("'img_p0.lnk'", out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                sd.main([f.name, 'image', 'img_p0.lnk'])
            self.assertIn('P start 0x000100 words 3', out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                sd.main([f.name, 'syms', 'img_p0.lnk'])
            self.assertIn('X:000002 sym_a', out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                sd.main([f.name, 'dis', 'img_p0.lnk'])
            self.assertIn('000100: 0af080 000123', out.getvalue())
            self.assertIn('jmp $0123', out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                sd.main([f.name, 'dis', 'img_p0.lnk', '--check'])
            self.assertIn('undecoded words: 0', out.getvalue())
            for args in (['image'], ['dis'], ['syms'], ['image', 'no_such_image.lnk']):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
                    sd.main([f.name] + args)
                self.assertEqual(cm.exception.code, 2)
        finally:
            os.unlink(f.name)


if __name__ == '__main__':
    unittest.main()
