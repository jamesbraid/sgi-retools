#!/usr/bin/env python3
"""Tests of the public-list parsers and name normalisation in syscall_table.py. They need no kernel image.

Run from the repository root: python3 scripts/test_syscall_table.py
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import syscall_table  # noqa: E402


class PublicLists(unittest.TestCase):
    def test_public_list_parsers(self):
        with tempfile.TemporaryDirectory() as d:
            lin = os.path.join(d, 'l.S')
            with open(lin, 'w') as f:
                f.write('\tsys\tsys_exit\t1\t/* 1001  exit()\t       V*/\n')
            nb = os.path.join(d, 'n.master')
            with open(nb, 'w') as f:
                f.write('4\tNOARGS\t\t{ int sys_write(int fd, char *buf, u_int nbyte); }\n'
                        '5\tSTD\t\t{ int irix_sys_open(const char *path, int flags, \\\n\t\t    int mode); }\n')
            qi = os.path.join(d, 'q.h')
            with open(qi, 'w') as f:
                f.write('#define TARGET_NR_read\t\t(3+TARGET_NR_Linux)\n')
            self.assertEqual(syscall_table.linux_table(lin), {1001: ('exit', 1)})
            self.assertEqual(syscall_table.netbsd_table(nb), {4: ('sys_write', 3), 5: ('irix_sys_open', 3)})
            self.assertEqual(syscall_table.qirix_table(qi), {3: 'read'})
            self.assertEqual(syscall_table.norm('sys_exit'), syscall_table.norm('rexit'))

    def test_number_base_is_read_from_the_subtraction_before_the_bound_check(self):
        class I:
            def __init__(self, m, o):
                self.mnemonic, self.op_str = m, o
        order = [I('addiu', '$s7, $s7, -0x3e8'), I('sltu', '$v1, $s7, $v0')]
        self.assertEqual(syscall_table.number_base(order), 1000)
        self.assertIsNone(syscall_table.number_base([I('addiu', '$s7, $s7, -8'), I('sltu', '$v1, $s7, $v0')]))


if __name__ == '__main__':
    unittest.main()
