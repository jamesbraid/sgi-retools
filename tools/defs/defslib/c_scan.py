"""Read #define lines out of a C header without a preprocessor.

Good enough for the decode and census headers: line continuations, trailing
comments (also across lines) and the include guard. Anything cleverer is the
C compiler's job, and the compare check uses it.
"""
import re

DEFINE_RE = re.compile(r"^\s*#\s*define\s+(\w+)(\([^)]*\))?\s*(.*)$")


class Define:
    def __init__(self, name, params, body, comment, line, indent, raw):
        self.name, self.params, self.body = name, params, body
        self.comment, self.line, self.indent, self.raw = comment, line, indent, raw


def scan_defines(text):
    """Return the #define lines in order, each with its body and trailing comment."""
    lines = text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        m = DEFINE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        start = i
        rest = m.group(3)
        raw = [lines[i]]
        while rest.rstrip().endswith("\\") and i + 1 < len(lines):
            rest = rest.rstrip()[:-1] + " " + lines[i + 1].strip()
            i += 1
            raw.append(lines[i])
        comment = ""
        if "/*" in rest:
            body, com = rest.split("/*", 1)
            while "*/" not in com and i + 1 < len(lines):
                i += 1
                raw.append(lines[i])
                com += " " + lines[i].strip().lstrip("*").strip()
            comment = re.sub(r"\s+", " ", com.split("*/")[0]).strip()
            rest = body
        elif "//" in rest:
            rest, comment = rest.split("//", 1)
            comment = comment.strip()
        indent = len(re.match(r"^\s*#\s*define(\s+)", lines[start]).group(1))
        out.append(Define(m.group(1), m.group(2), re.sub(r"\s+", " ", rest).strip(), comment, start + 1, indent, raw))
        i += 1
    return out


def include_guard(text):
    m = re.search(r"^\s*#\s*ifndef\s+(\w+)\s*\n\s*#\s*define\s+\1\b", text, re.M)
    return m.group(1) if m else None


def num_literal(body):
    """Integer value of a plain literal like 0x1fu, 16 or (0x20), else None."""
    m = re.fullmatch(r"\(?\s*(0[xX][0-9a-fA-F]+|\d+)\s*[uUlL]*\s*\)?", body)
    return int(m.group(1), 0) if m else None


def block_comment_before(lines, i):
    """Text of the block comment that ends on the line before lines[i], if any."""
    j = i - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j < 0 or not lines[j].rstrip().endswith("*/") or lines[j].strip().startswith("/* "):
        return ""
    k = j
    while k >= 0 and not lines[k].lstrip().startswith("/*"):
        k -= 1
    txt = []
    for ln in lines[k:j + 1]:
        ln = ln.strip()
        ln = re.sub(r"^/\*+", "", ln)
        ln = re.sub(r"\*+/$", "", ln)
        ln = re.sub(r"^\*\s?", "", ln).rstrip()
        txt.append(ln)
    t = "\n".join(txt).strip()
    if "=====" in t or "TESTVEC" in t or "FIELD:" in t or "REG:" in t:
        return ""
    return re.sub(r"[ \t]+\n", "\n", t)


def strip_comments(text):
    """The text with every comment replaced by spaces (newlines kept), string literals left alone."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def extract_code(text, guard=None):
    """The C that is not a #define, not the include guard and not <stdint.h>.

    A line is code when it has something left after comments are removed. Code
    comes out as the original lines, so trailing comments (a table row's name,
    say) stay, together with comment lines inside a run of code and a comment
    directly above it. Comments that only describe #defines are not carried.
    """
    orig = text.splitlines()
    bare = strip_comments(text).splitlines()
    last_endif = max((i for i, l in enumerate(bare) if re.match(r"\s*#\s*endif\b", l)), default=-1)
    code, in_define = [], False
    for i, ln in enumerate(bare):
        s = ln.strip()
        if in_define:
            in_define = s.endswith("\\")
            continue
        if not s:
            continue
        if s.startswith("#"):
            if re.match(r"#\s*define\b", s):
                in_define = s.endswith("\\")
                continue
            if guard and re.match(r"#\s*ifndef\s+%s\b" % re.escape(guard), s):
                continue
            if i == last_endif and guard:
                continue
            if re.match(r"#\s*include\s*<stdint\.h>", s):
                continue
        code.append(i)
    if not code:
        return ""
    # which original lines belong to a #define (its continuation lines and its trailing comment)
    define_lines, i = set(), 0
    while i < len(bare):
        if re.match(r"\s*#\s*define\b", bare[i]):
            j = i
            while bare[j].rstrip().endswith("\\") and j + 1 < len(bare):
                j += 1
            define_lines.update(range(i, j + 1))
            # a trailing comment can run on past the #define's last line
            k = j
            while k + 1 < len(orig) and not bare[k + 1].strip() and orig[k + 1].strip() and k + 1 not in code \
                    and not orig[k].rstrip().endswith("*/") and "/*" in orig[j] and "*/" not in orig[j].split("/*", 1)[1]:
                k += 1
                define_lines.add(k)
            i = j + 1
        else:
            i += 1
    keep = set(code)
    cset = sorted(code)
    for a_, b_ in zip(cset, cset[1:]):
        between = range(a_ + 1, b_)
        if all(x not in define_lines and not bare[x].strip() for x in between):
            keep.update(x for x in between if orig[x].strip())      # comment-only lines inside a run
    for c in cset:                                                   # a comment directly above a run of code
        x = c - 1
        while x >= 0 and x not in define_lines and not bare[x].strip() and orig[x].strip() and x not in keep:
            keep.add(x)
            x -= 1
    out, prev = [], None
    for x in sorted(keep):
        if prev is not None and x - prev > 1:
            out.append("")
        out.append(orig[x].rstrip())
        prev = x
    return "\n".join(out).strip("\n")


KNOWN_ANNOTATIONS = {"REG", "WORD", "FIELD", "ENUM", "TESTVEC", "EXAMPLE"}
ANNOTATION_RE = re.compile(r"^\s*(?:/\*|\*)?\s*([A-Z][A-Z_]{2,})(?: \(unverified\))?:\s")


def unknown_annotation_lines(text):
    """The comment lines like ` * CALC: ...` that the importer does not read, verbatim."""
    found = []
    in_comment = False
    for ln in text.splitlines():
        s = ln.strip()
        starts = s.startswith("/*")
        if starts or in_comment:
            m = ANNOTATION_RE.match(ln)
            if m and m.group(1) not in KNOWN_ANNOTATIONS and "<" not in ln:
                line = ln.split("*/")[0].rstrip()
                if line.lstrip().startswith("/*"):
                    line = " * " + line.lstrip()[2:].strip()      # it will sit inside one comment block
                found.append((m.group(1), line))
            in_comment = "*/" not in s
    return found


def unknown_annotations(text):
    """Keyword -> count of those lines."""
    found = {}
    for kw, _ in unknown_annotation_lines(text):
        found[kw] = found.get(kw, 0) + 1
    return found
