"""Small helpers shared by the generators."""
import re
import textwrap

from .model import block_of


# Bump when the form of any generated file changes; every output carries it (see stamp.py).
GENERATOR_VERSION = "3"


class GenError(Exception):
    """A unit cannot be rendered (a name collision, say)."""


def banner(src, comment="/*", end=" */"):
    return "%s generated from %s by defs-gen - do not edit, change the source%s" % (comment, src, end)


def one_line(s):
    return re.sub(r"\s+", " ", s).replace("*/", "* /").replace("/*", "/ *").strip()


COMMENT_WIDTH = 80      # comments wrap here, 10 under the 90 columns QEMU's checkpatch allows, so a few extra words never trip it


def wrap_comment(text, indent="", width=COMMENT_WIDTH):
    """`text` as a C comment: one line when it fits, else a block of lines wrapped at `width`."""
    text = one_line(text)
    one = "%s/* %s */" % (indent, text)
    if len(one) <= width:
        return [one]
    lines = textwrap.wrap(text, max(width - len(indent) - 3, 20), break_long_words=False, break_on_hyphens=False)
    out = ["%s/* %s" % (indent, lines[0])] + ["%s * %s" % (indent, ln) for ln in lines[1:]]
    if len(out[-1]) + 3 <= width:
        out[-1] += " */"
    else:
        out.append("%s */" % indent)
    return out


def cblock(text, indent="", width=COMMENT_WIDTH):
    """A multi-line C comment: each line of `text` wrapped at `width`, blank lines and indentation kept."""
    if not text:
        return ""
    body = []
    for l in text.replace("*/", "* /").replace("/*", "/ *").strip().splitlines():
        lead = l[:len(l) - len(l.lstrip())]
        body += textwrap.wrap(l, max(width - len(indent) - 3, 20), subsequent_indent=lead, break_long_words=False,
                              break_on_hyphens=False) or [""]
    return "%s/*\n%s\n%s */\n" % (indent, "\n".join("%s * %s" % (indent, l) if l else "%s *" % indent for l in body), indent)


def lit(v, wide=False):
    return "0x%x%s" % (v, "ull" if wide or v > 0xffffffff else "u")


def field_macro(u, kind, parent, fn):
    """Registers use the block name, plain words the prefix."""
    head = block_of(u) if kind == "register" else u["prefix"]
    return "%s_%s_%s" % (head, parent.upper(), fn.upper())
