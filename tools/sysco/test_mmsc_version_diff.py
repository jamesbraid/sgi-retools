#!/usr/bin/env python3
"""Tests of the MMSC version diff: the help-table pattern and the object-level statuses.

Run in the toolchain container, since the module imports capstone:
    retools/tools/re-run python3 retools/tools/sysco/test_mmsc_version_diff.py
"""
import collections
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mmsc_version_diff as mvd  # noqa: E402


class FakeBuild:
    def __init__(self, routines, owners):
        self.routines = routines
        self._owners = owners

    def owner(self, addr):
        return self._owners[addr]


class HelpLineTest(unittest.TestCase):
    def match(self, line):
        hit = mvd.HELP_LINE.match(line)
        return hit.group(1).decode() if hit else None

    def test_commands_with_arguments_and_one_or_two_spaces(self):
        self.assertEqual(self.match(b'COM <p> HWFLOW ON|OFF - Enable/disable HW flow'),
                         'COM <p> HWFLOW ON|OFF')
        self.assertEqual(self.match(b'COM <p>  - Show parameters for MMSC port <p>'),
                         'COM <p>')
        self.assertEqual(self.match(b'VER                  - Show current MMSC firmware'),
                         'VER')
        self.assertEqual(self.match(b'PARTGET <id>        - Show a partition'),
                         'PARTGET <id>')

    def test_response_text_is_not_a_command(self):
        self.assertIsNone(self.match(b'R%ld:OK COM %d speed %ld func %s'))
        self.assertIsNone(self.match(b'Changed baud rate of COM%d to %d'))
        self.assertIsNone(self.match(b'Valid baud rates include: 300, 1200'))


class ModuleRowsTest(unittest.TestCase):
    def test_statuses_follow_the_routine_rows(self):
        a = FakeBuild({'x': (0x100, 4, True), 'gone': (0x200, 4, True)},
                      {0x100: 'a.o', 0x200: 'a.o'})
        b = FakeBuild({'x': (0x100, 4, True), 'y': (0x300, 4, True)},
                      {0x100: 'a.o', 0x300: 'new.o'})
        rows = [
            ('changed', 'x', 0x100, 4, 0x100, 4, '0.900', 'mov', 'mov'),
            ('same-code-moved', 'x', 0x100, 4, 0x100, 4, '1.000', '', ''),
            ('removed', 'gone', 0x200, 4, None, None, '', '', ''),
            ('added', 'y', None, None, 0x300, 4, '', '', ''),
        ]
        got = mvd.module_rows('a -> b', a, b, rows, {'a.o'}, {'a.o', 'new.o'})
        self.assertEqual(got, [
            ('a -> b', 'a.o', 'changed', 1, 0, 1),
            ('a -> b', 'new.o', 'added', 0, 1, 0),
        ])

    def test_object_with_only_moved_code_is_not_listed(self):
        a = FakeBuild({'x': (0x100, 4, True)}, {0x100: 'a.o'})
        b = FakeBuild({'x': (0x100, 4, True)}, {0x100: 'a.o'})
        rows = [('same-code-moved', 'x', 0x100, 4, 0x100, 4, '1.000', '', '')]
        self.assertEqual(mvd.module_rows('s', a, b, rows, {'a.o'}, {'a.o'}), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
