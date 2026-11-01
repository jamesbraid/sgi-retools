"""Locate the MIPS cross binutils. Set MIPS_OBJDUMP / MIPS_READELF to override."""
import os
import shutil

PREFIXES = ('mips-unknown-linux-gnu-', 'mips64-linux-gnuabi64-',
            'mips-linux-gnu-', 'mips64-unknown-linux-gnu-')


def find(tool, env):
    if os.environ.get(env):
        return os.environ[env]
    for p in PREFIXES:
        if shutil.which(p + tool):
            return p + tool
    raise SystemExit(f"no MIPS {tool} found on PATH (tried {', '.join(p + tool for p in PREFIXES)}); set {env}")


def objdump():
    return find('objdump', 'MIPS_OBJDUMP')


def readelf():
    return find('readelf', 'MIPS_READELF')


def nm():
    return find('nm', 'MIPS_NM')
