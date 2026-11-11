#!/usr/bin/env python3
"""firmware_layout cuts a container into segments and finds one again from the key the inventory wrote."""
import gzip
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import firmware_layout as fl  # noqa: E402


def have_capstone():
    try:
        import capstone  # noqa: F401
        import elftools  # noqa: F401
    except ImportError:
        return False
    return True


# coldfire: link.w a6,#0; movea.l #0x10000000,a0; move.l 0x14(a0),d0; unlk a6; rts
CF_CODE = bytes.fromhex("4e560000" "207c10000000" "20280014" "4e5e" "4e75")
# ppc32: stwu r1,-16(r1); lis r11,0x1000; lwz r0,0x14(r11); addi r1,r1,16; blr
PPC_CODE = bytes.fromhex("9421fff0" "3d601000" "800b0014" "38210010" "4e800020")
L1_LOAD, L2_LOAD, KERNEL_LOAD = 0xffe00000, 0xfe000000, 0xc0000000


def l1_container(code):
    """A pre-container L1 image: ESTFBINR, the load and last addresses, then the vector table (the initial
    stack pointer 0x301017fc and a reset vector in the flash) at 0x20 and the code after it."""
    head = b"ESTFBINR" + struct.pack(">II", L1_LOAD, L1_LOAD + 0x100) + bytes(0x10)
    return head + struct.pack(">II", 0x301017fc, L1_LOAD + 8) + code


def l2_container(flash, kernel):
    """An L2 image: ESTFBINR and the flash load address, the flash from 0x2c, then the kernel as gzip."""
    head = b"ESTFBINR" + struct.pack(">I", L2_LOAD) + bytes(0x2c - 12)
    return head + flash + gzip.compress(kernel)


CONFIG = {"binaries": [
    {"group": "host-tools", "paths": ["usr/sbin/*"]},
    {"group": "l1", "arch": "coldfire", "layout": "sysco-l1", "paths": ["fw/l1.bin"]},
    {"group": "l2", "arch": "ppc32", "layout": "sysco-l2", "kernel_load": "0xc0000000", "paths": ["fw/l2.bin"]},
    {"group": "flat", "arch": "coldfire", "layout": "flat", "load": "0x2000", "offset": "4",
     "paths": ["fw/flat.bin"]}]}


def write_root(root, files):
    for rel, data in files.items():
        os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
        with open(os.path.join(root, rel), "wb") as handle:
            handle.write(data)


def workspace(root):
    write_root(root, {"fw/l1.bin": l1_container(CF_CODE), "fw/l2.bin": l2_container(PPC_CODE, PPC_CODE),
                      "fw/flat.bin": b"abcd" + CF_CODE, "usr/sbin/tool": b"\x7fELF"})


class Layout(unittest.TestCase):
    def test_a_flat_layout_maps_the_file_from_its_offset(self):
        seg = fl.firmware_segments({"layout": "flat", "load": "0x2000", "offset": "4"}, "x.bin", b"abcdefgh")
        self.assertEqual(seg, [("", b"efgh", 0x2000)])

    def test_the_l2_container_gives_its_flash_and_its_inflated_kernel(self):
        seg = fl.firmware_segments(CONFIG["binaries"][2], "fw/l2.bin", l2_container(PPC_CODE, b"kernel"))
        self.assertEqual(seg, [("flash", PPC_CODE, L2_LOAD), ("kernel", b"kernel", KERNEL_LOAD)])

    def test_keys_split_into_path_and_member(self):
        self.assertEqual(fl.split_segment_key("a/l1.bin(l1#2)"), ("a/l1.bin", "l1#2"))
        self.assertEqual(fl.split_segment_key("a/l1.bin:l1#2"), ("a/l1.bin", "l1#2"))
        self.assertEqual(fl.split_segment_key("a/flat.bin()"), ("a/flat.bin", ""))
        self.assertEqual(fl.split_segment_key("a/flat.bin"), ("a/flat.bin", ""))


class Resolve(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.dir.name, "root")
        workspace(self.root)

    def tearDown(self):
        self.dir.cleanup()

    def test_a_key_gives_the_segment_bytes_and_load_address(self):
        arch, body, load, _g = fl.segment_at(CONFIG, self.root, "fw/l2.bin(flash)")
        self.assertEqual((arch, body, load), ("ppc32", PPC_CODE, L2_LOAD))
        arch, body, load, _g = fl.segment_at(CONFIG, self.root, "fw/l2.bin(kernel)")
        self.assertEqual((arch, body, load), ("ppc32", PPC_CODE, KERNEL_LOAD))
        arch, body, load, _g = fl.segment_at(CONFIG, self.root, "fw/l1.bin(l1#0)")
        self.assertEqual((arch, body[8:], load), ("coldfire", CF_CODE, L1_LOAD))
        arch, body, load, _g = fl.segment_at(CONFIG, self.root, "fw/flat.bin()")
        self.assertEqual((arch, body, load), ("coldfire", CF_CODE, 0x2000))

    def test_a_file_in_no_layout_group_is_not_a_segment(self):
        self.assertIsNone(fl.segment_at(CONFIG, self.root, "usr/sbin/tool"))
        self.assertIsNone(fl.segment_at(CONFIG, self.root, "usr/lib/lib.a(m.o)"))
        self.assertIsNone(fl.segment_at({}, self.root, "fw/l2.bin(flash)"))

    def test_a_member_the_container_lacks_is_an_error(self):
        with self.assertRaises(LookupError):
            fl.segment_at(CONFIG, self.root, "fw/l2.bin(rom)")
        with self.assertRaises(LookupError):
            fl.segment_at(CONFIG, self.root, "fw/l1.bin(l1#7)")

    def test_a_missing_file_is_an_error(self):
        cfg = {"binaries": [dict(CONFIG["binaries"][1], paths=["fw/gone.bin"])]}
        with self.assertRaises(LookupError):
            fl.segment_at(cfg, self.root, "fw/gone.bin(l1#0)")

    @unittest.skipUnless(have_capstone(), "needs capstone and pyelftools")
    def test_the_routine_is_decoded_from_the_segment_at_its_load_address(self):
        routine = fl.segment_routine(CONFIG, self.root, "fw/l2.bin(kernel)", hex(KERNEL_LOAD), len(PPC_CODE))
        self.assertEqual([i["mn"] for i in routine.insns], ["stwu", "lis", "lwz", "addi", "blr"])
        self.assertEqual(routine.img.load, KERNEL_LOAD)
        routine = fl.segment_routine(CONFIG, self.root, "fw/l1.bin(l1#0)", hex(L1_LOAD + 8), len(CF_CODE))
        self.assertEqual(routine.insns[0]["mn"], "link.w")


if __name__ == "__main__":
    unittest.main()
