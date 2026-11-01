#!/usr/bin/env python3
"""Tests of mips_shim.py against plain float32 and float64 arithmetic: needs unicorn and numpy.

Run from the repository root: python3 scripts/test_mips_shim.py

Each test assembles a few instructions the Unicorn MIPS core lacks (the COP1X multiply-add
family, movz and movn, a compare on condition code 1), lets `install` rewrite them, runs the
result and compares the registers with the same arithmetic done in numpy. The registers used
include odd-numbered ones, doubles in odd-numbered ones (the Unicorn core keeps 32 independent
64-bit registers without any Status.FR change, which the odd-register double test shows) and a
destination equal to the addend, as the N32 library's evaluators do.
"""
import os
import struct
import sys
import unittest

import numpy as np
from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_BIG_ENDIAN, UC_MODE_MIPS64
import unicorn.mips_const as mc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mips_shim  # noqa: E402

BASE = 0x1000


def cop1x(fn, fd, fr, fs, ft):
    return (0x13 << 26) | (fr << 21) | (ft << 16) | (fs << 11) | (fd << 6) | fn


def special(fn, rd, rs, rt):
    return (rs << 21) | (rt << 16) | (rd << 11) | fn


def machine(words):
    mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS64 | UC_MODE_BIG_ENDIAN)
    mu.mem_map(BASE, 0x1000)
    mu.mem_write(BASE, b''.join(struct.pack('>I', w) for w in words + [0, 0]))
    mips_shim.install(mu, BASE, BASE + 4 * len(words))
    return mu


def run(mu, n):
    mu.emu_start(BASE, BASE + 4 * n)


def setf(mu, n, value, double):
    mu.reg_write(mips_shim.F(n), mips_shim.b64(value) if double else mips_shim.b32(value))


def getf(mu, n, double):
    bits = mu.reg_read(mips_shim.F(n))
    return mips_shim.f64(bits) if double else mips_shim.f32(bits)


class MultiplyAdd(unittest.TestCase):
    # function code, single or double, expected result from fs * ft and fr
    CASES = [
        (0x20, False, lambda p, z: p + z), (0x28, False, lambda p, z: p - z),
        (0x30, False, lambda p, z: -(p + z)), (0x38, False, lambda p, z: -(p - z)),
        (0x21, True, lambda p, z: p + z), (0x29, True, lambda p, z: p - z),
        (0x31, True, lambda p, z: -(p + z)), (0x39, True, lambda p, z: -(p - z)),
    ]

    def check(self, fn, double, expect, fd, fr, fs, ft):
        T = np.float64 if double else np.float32
        mu = machine([cop1x(fn, fd, fr, fs, ft)])
        vals = {}
        for r, v in ((fr, 0.625), (fs, 3.5), (ft, -1.75)):
            vals[r] = T(v)
            setf(mu, r, vals[r], double)
        run(mu, 1)
        want = expect(T(vals[fs] * vals[ft]), vals[fr])
        self.assertEqual(getf(mu, fd, double), want, (hex(fn), fd, fr, fs, ft))

    def test_even_registers(self):
        for fn, double, expect in self.CASES:
            self.check(fn, double, expect, 4, 6, 8, 10)

    def test_odd_registers_and_destination_equal_to_addend(self):
        for fn, double, expect in self.CASES:
            self.check(fn, double, expect, 29, 29, 31, 27)
            self.check(fn, double, expect, 3, 5, 7, 9)

    def test_double_in_odd_register_keeps_all_64_bits(self):
        mu = machine([cop1x(0x21, 31, 29, 27, 25)])
        setf(mu, 29, 1.0, True)
        setf(mu, 27, 1.0 + 2.0 ** -40, True)
        setf(mu, 25, 1.0, True)
        run(mu, 1)
        self.assertEqual(getf(mu, 31, True), np.float64(1.0 + 2.0 ** -40) + np.float64(1.0))


class Moves(unittest.TestCase):
    def test_movz_movn(self):
        for fn, rt_value, moves in ((0x0a, 0, True), (0x0a, 5, False), (0x0b, 0, False), (0x0b, 5, True)):
            mu = machine([special(fn, 8, 9, 10)])
            mu.reg_write(mc.UC_MIPS_REG_8, 111)
            mu.reg_write(mc.UC_MIPS_REG_9, 222)
            mu.reg_write(mc.UC_MIPS_REG_10, rt_value)
            run(mu, 1)
            self.assertEqual(mu.reg_read(mc.UC_MIPS_REG_8), 222 if moves else 111, (hex(fn), rt_value))


class ConditionCodes(unittest.TestCase):
    def test_compare_on_code_one_then_branch(self):
        # c.lt.s $fcc1, $f2, $f4 ; bc1t $fcc1 over the next addiu ; nop ; addiu $8, $0, 1 ; addiu $8, $8, 2
        c_lt = (0x11 << 26) | (0x10 << 21) | (4 << 16) | (2 << 11) | (1 << 8) | 0x3c
        bc1t = (0x11 << 26) | (8 << 21) | (1 << 18) | (1 << 16) | 2
        for a, b, taken in ((1.0, 2.0, True), (2.0, 1.0, False)):
            mu = machine([c_lt, bc1t, 0, 0x24080001, 0x25080002])
            setf(mu, 2, np.float32(a), False)
            setf(mu, 4, np.float32(b), False)
            mu.reg_write(mc.UC_MIPS_REG_8, 0)
            run(mu, 5)
            self.assertEqual(mu.reg_read(mc.UC_MIPS_REG_8), 2 if taken else 3, (a, b))

    def test_movf_and_movt_on_a_nonzero_code(self):
        # c.lt.s $fcc7, $f2, $f4 ; addiu $2, $0, 1 ; movf/movt $2, $0, $fcc7
        c_lt = (0x11 << 26) | (0x10 << 21) | (4 << 16) | (2 << 11) | (7 << 8) | 0x3c
        li = 0x24020001
        for tf in (0, 1):
            movc = (0 << 21) | (7 << 18) | (tf << 16) | (2 << 11) | 1
            for a, b in ((1.0, 2.0), (2.0, 1.0)):
                mu = machine([c_lt, li, movc])
                setf(mu, 2, np.float32(a), False)
                setf(mu, 4, np.float32(b), False)
                run(mu, 3)
                less = a < b
                cleared = (not less) if tf == 0 else less   # movf clears when the code is false, movt when true
                self.assertEqual(mu.reg_read(mc.UC_MIPS_REG_2), 0 if cleared else 1, (tf, a, b))


if __name__ == '__main__':
    unittest.main()
