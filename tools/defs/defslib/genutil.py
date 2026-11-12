"""Small helpers shared by the generators."""
import re

from .model import block_of


class GenError(Exception):
    """A unit cannot be rendered (a name collision, say)."""


def banner(src, comment="/*", end=" */"):
    return "%s generated from %s by defs-gen - do not edit, change the source%s" % (comment, src, end)


def one_line(s):
    return re.sub(r"\s+", " ", s).replace("*/", "* /").replace("/*", "/ *").strip()


def cblock(text, indent=""):
    if not text:
        return ""
    body = text.replace("*/", "* /").replace("/*", "/ *").strip().splitlines()
    return "%s/*\n%s\n%s */\n" % (indent, "\n".join("%s * %s" % (indent, l) if l else "%s *" % indent for l in body), indent)


def lit(v, wide=False):
    return "0x%x%s" % (v, "ull" if wide or v > 0xffffffff else "u")


def field_macro(u, kind, parent, fn):
    """Registers use the block name, plain words the prefix."""
    head = block_of(u) if kind == "register" else u["prefix"]
    return "%s_%s_%s" % (head, parent.upper(), fn.upper())
