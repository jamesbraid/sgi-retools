"""Register slot size per address range, for chips whose registers are not all 8-byte slots.

A config's "slot_rules" is a list of {"lo", "hi", "bytes"}: an offset in [lo, hi) is folded to a multiple
of "bytes" (a power of two). Offsets in no rule use 8, the slot of the XIO and node-controller chips.
MACE has 32-bit registers on 4-byte steps in the PCI block and byte registers 256 bytes apart in the
calendar-clock block.
"""


def make(cfg):
    rules = [(int(str(r['lo']), 0), int(str(r['hi']), 0), int(r['bytes'])) for r in cfg.get('slot_rules', [])]

    def slot_of(off):
        for lo, hi, n in rules:
            if lo <= off < hi:
                return off & ~(n - 1)
        return off & ~7

    def part_of(off):
        for lo, hi, n in rules:
            if lo <= off < hi:
                return off & (n - 1)
        return off & 7
    return slot_of, part_of
