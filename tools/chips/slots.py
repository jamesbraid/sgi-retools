"""Register slot size per address range, for chips whose registers are not all 8-byte slots.

A config's "slot_rules" is a list of {"lo", "hi", "bytes"}: an offset in [lo, hi) is folded to a multiple
of "bytes" (a power of two). Offsets in no rule use 8, the slot of the XIO and node-controller chips.
MACE has 32-bit registers on 4-byte steps in the PCI block and byte registers 256 bytes apart in the
calendar-clock block.

A config's "address_spaces" maps a scan window name to another address space that the same offsets can
land in: {"window-18": {"space": "boot-space", "slot_bytes": 4}}. An access through such a window is not
a register of the ASIC, so it keeps its own rows (keyed by space as well as offset) and folds to
"slot_bytes" (default 4) instead of the register slot. Windows not listed are the register space, named "".
"""


def make(cfg):
    rules = [(int(str(r['lo']), 0), int(str(r['hi']), 0), int(r['bytes'])) for r in cfg.get('slot_rules', [])]

    spaces = {w: (d['space'], int(d.get('slot_bytes', 4))) for w, d in cfg.get('address_spaces', {}).items()}

    def slot_of(off, space=''):
        if space:
            return off & ~(space_bytes(space) - 1)
        for lo, hi, n in rules:
            if lo <= off < hi:
                return off & ~(n - 1)
        return off & ~7

    def part_of(off, space=''):
        if space:
            return off & (space_bytes(space) - 1)
        for lo, hi, n in rules:
            if lo <= off < hi:
                return off & (n - 1)
        return off & 7

    def space_bytes(space):
        return next(n for sp, n in spaces.values() if sp == space)
    return slot_of, part_of


def space_of(cfg):
    """Function from a scan window name to its address space: "" for the register space."""
    spaces = {w: d['space'] for w, d in cfg.get('address_spaces', {}).items()}
    return lambda window: spaces.get(window, '')
