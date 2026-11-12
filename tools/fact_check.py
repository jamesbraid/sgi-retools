"""Mechanical fact check of a routine-role entry against the facts rendered for its routine.

A role entry is prose written from the same rendered facts that render_reading.py prints
(`reading_round` renders them, a model writes the prose, `grade_readings.py` grades the rendered
sentences). Prose is where the mistakes are: a branch direction reversed, an argument register
numbered one off, a store called a read, a call called unconditional. This module pulls the
checkable claims out of the prose with fixed patterns and tests each against the facts. It reports
only a contradiction, never a missing detail, and it skips a claim it cannot place on one call,
branch or access.

    sheet = sheet_for(binary_path, member, address, size)     # cached per binary and address
    problems = check_entry(prose_sentences, sheet)           # [(rule, reason, sentence)]

A fact sheet holds what the renderer prints (calls with their argument slots, branch conditions,
returns, accesses) plus the block graph the renderer's branch sentences come from, so a claim about
"when" or "then" can be tested on paths. It round-trips through plain JSON so tests need no binary.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

HEX = r"0x[0-9a-fA-F]+"
ORDINALS = {"first": 0, "second": 1, "third": 2, "fourth": 3, "fifth": 4, "sixth": 5, "seventh": 6, "eighth": 7,
            "1st": 0, "2nd": 1, "3rd": 2, "4th": 3, "5th": 4, "6th": 5, "7th": 6, "8th": 7}
ORDINAL_NAMES = ["first", "second", "third", "fourth", "fifth", "sixth", "seventh", "eighth"]
ORD = "|".join(ORDINALS)
NUMBER = r"(?:-?" + HEX + r"|\d+)"

# The slot a number lands in is the same under n32 and n64, so the convention only matters past the
# fourth: o32 passes four arguments in a0-a3 and the rest on the stack.
CONVENTION_NOTE = {
    "n32": "n32 passes the first eight arguments in a0-a7, so the fifth is a4",
    "n64": "n64 passes the first eight arguments in a0-a7, so the fifth is a4",
    "o32": "o32 passes only the first four arguments in a0-a3; the fifth is on the stack",
}


def _int(text):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


class FactSheet:
    """The facts of one routine. Plain data: see to_dict/from_dict."""

    def __init__(self, name="", abi="", text="", accesses=(), calls=None, branches=None, returns=None, blocks=()):
        self.name, self.abi, self.text = name, abi, text
        self.accesses = list(accesses)    # {"address", "kind", "mn", "offset" (or None)}
        self.calls = calls or {}          # site -> {"callee", "target", "args": {slot: text}, "tail"}
        self.branches = branches or {}    # address -> {"mn", "target", "taken", "fall"}
        self.returns = returns or {}      # address -> v0 text
        self.blocks = list(blocks)        # {"first", "last", "succ": [indexes], "reached"}
        self._reach = {}

    def to_dict(self):
        return {"name": self.name, "abi": self.abi, "text": self.text, "accesses": self.accesses,
                "calls": self.calls, "branches": self.branches, "returns": self.returns, "blocks": self.blocks}

    @classmethod
    def from_dict(cls, data):
        calls = {site: dict(call, args={int(k): v for k, v in call["args"].items()})
                 for site, call in data["calls"].items()}
        return cls(data["name"], data["abi"], data["text"], data["accesses"], calls, data["branches"],
                   data["returns"], data["blocks"])

    # ---- block graph

    def block_of(self, address):
        value = _int(address)
        for index, block in enumerate(self.blocks):
            if block["first"] <= value <= block["last"]:
                return index
        return None

    def _walk(self, start, avoid=None):
        seen, pending = set(), [start]
        while pending:
            node = pending.pop()
            if node in seen or node == avoid or node is None or not self.blocks[node].get("reached", True):
                continue
            seen.add(node)
            pending.extend(self.blocks[node]["succ"])
        return seen

    def guarded(self, address):
        """Whether some path from entry to an exit misses the instruction at address."""
        target = self.block_of(address)
        if target is None or not self.blocks:
            return None
        if target == 0:
            return False
        reachable = self._walk(0, avoid=target)
        return any(not self.blocks[node]["succ"] for node in reachable)

    def reaches(self, first, second):
        """Whether execution can go from the instruction at first to the one at second."""
        a, b = self.block_of(first), self.block_of(second)
        if a is None or b is None:
            return None
        if a == b:
            if _int(first) < _int(second):
                return True
            # the same block again only through a loop that returns to it
            return any(a in self._walk(s) for s in self.blocks[a]["succ"])
        return any(b in self._walk(s) for s in self.blocks[a]["succ"])

    def deciding(self, site):
        """Branches that decide whether the instruction at site runs, as (address, side that runs it)."""
        target = self.block_of(site)
        found = []
        if target is None:
            return found
        for index, block in enumerate(self.blocks):
            address = block.get("branch")
            if address is None or len(block["succ"]) != 2 or not block.get("reached", True):
                continue
            taken, fall = block["succ"]
            runs_taken = target in self._walk(taken)
            runs_fall = target in self._walk(fall)
            if runs_taken != runs_fall and index != target:
                found.append((address, "taken" if runs_taken else "fall"))
        return found

    def optional(self, site):
        """Whether a branch can skip the instruction at site and still run on to where it leads: a guarded
        call that every path goes on to share, as opposed to a call made on one of several exits."""
        target = self.block_of(site)
        if target is None:
            return None
        after = set()
        for s in self.blocks[target]["succ"]:
            after |= self._walk(s)
        for index, block in enumerate(self.blocks):
            if block.get("branch") is None or len(block["succ"]) != 2 or index == target:
                continue
            taken, fall = block["succ"]
            runs = [target in self._walk(x) for x in (taken, fall)]
            if runs[0] != runs[1]:
                skipped = fall if runs[0] else taken
                if self._walk(skipped) & after and target not in self._walk(skipped):
                    return True
        return False

    def sites_of(self, name_or_target):
        return [site for site, call in self.calls.items()
                if name_or_target in (call.get("callee"), call.get("target"))]


# ---------------------------------------------------------------- building a sheet from a binary

_CALL = re.compile(r"The `(?P<mn>\w[\w.]*)` at (?P<site>" + HEX + r") calls (?P<callee>.*?) with (?P<args>.*)\.$")
_TAIL = re.compile(r"Calls (?P<callee>.*?) via \S+ with (?P<args>.*) \(`(?P<mn>\w[\w.]*)` at (?P<site>" + HEX + r")\)\.$")
_BRANCH = re.compile(r"The `(?P<mn>\w+)` branch at (?P<at>" + HEX + r") targets (?P<target>" + HEX + r"), is taken when "
                     r"(?P<taken>.*), and falls through when (?P<fall>.*?)(?:; its branch-likely.*)?\.$")
_RETURN = re.compile(r"The return at (?P<at>" + HEX + r") has v0 = (?P<value>.*)\.$")
_CALLEE = re.compile(r"(?P<name>.*?) \[(?P<target>" + HEX + r")\]$")


def split_args(text):
    """{slot: value text} of "a0=..., a1=..." as the renderer writes call arguments."""
    import hostfacts
    slots = {}
    for part in hostfacts.split_top_level(text.split("; fp ")[0]):
        m = re.match(r"a(\d)=(.*)$", part.strip())
        if m:
            slots[int(m.group(1))] = m.group(2).strip()
    return slots


def sheet_from_text(rendered, routine=None, facts=None):
    """Build a sheet from the renderer's entry text and, when given, the routine's facts and flow."""
    lines = [line.strip() for line in rendered.splitlines()]
    calls, branches, returns = {}, {}, {}
    for line in lines:
        m = _CALL.match(line) or _TAIL.match(line)
        if m:
            callee = m.group("callee")
            c = _CALLEE.match(callee)
            calls[m.group("site")] = {"callee": c.group("name") if c else callee,
                                      "target": c.group("target") if c else None,
                                      "args": split_args(m.group("args")), "tail": line.startswith("Calls ")}
            continue
        m = _BRANCH.match(line)
        if m:
            branches[m.group("at")] = {"mn": m.group("mn"), "target": m.group("target"),
                                       "taken": m.group("taken"), "fall": m.group("fall")}
            continue
        m = _RETURN.match(line)
        if m:
            returns[m.group("at")] = m.group("value")
    header = re.search(r"at (" + HEX + r") \((\w+)\)", lines[0]) if lines else None
    sheet = FactSheet(abi=header.group(2) if header else "", text=rendered, calls=calls, branches=branches,
                      returns=returns)
    if routine is not None:
        sheet.name = facts["routine"].get("name") or ""
        sheet.abi = facts["routine"].get("abi") or sheet.abi
        for a in facts.get("accesses", []):
            if a.get("stack") or a.get("base") in ("sp", "gp"):
                continue
            sheet.accesses.append({"address": a["address"], "kind": a["kind"], "mn": a["mnemonic"],
                                   "offset": a.get("origin_offset") if "origin" in a else None})
        sheet.blocks = _blocks_of(routine)
    return sheet


def _blocks_of(routine):
    import hostfacts
    blocks, by_first = hostfacts.build_blocks(routine)
    hostfacts.wire(routine, blocks, by_first)
    ids = {id(block): index for index, block in enumerate(blocks)}
    out = []
    for block in blocks:
        reached = block.first in routine.in_states
        succ = [ids[id(s)] for _kind, s in block.succ if s is not None] if reached else []
        entry = {"first": routine.insns[block.first]["addr"], "last": routine.insns[block.last]["addr"],
                 "succ": succ, "reached": reached}
        if block.exit["kind"] == "cond" and reached:
            entry["branch"] = "0x%x" % routine.insns[block.exit["index"]]["addr"]
        out.append(entry)
    return out


_SHEETS = {}


def sheet_for(binary, member, address, size=None):
    """The fact sheet of the routine at address in a binary, rendered once per binary and address."""
    key = (os.path.abspath(binary), member, address, size)
    if key not in _SHEETS:
        import hostfacts
        import render_reading
        routine = hostfacts.routine_for(binary, address, member=member, size=size)
        facts = routine.facts(False)
        rendered = render_reading.render_entry(routine, facts, os.path.basename(binary), "Inferred")
        _SHEETS[key] = sheet_from_text(rendered, routine, facts)
    return _SHEETS[key]


# ---------------------------------------------------------------- reading the prose

def sentences_of(lines):
    """Split the prose lines of an entry into sentences, without the markup around the evidence grade."""
    text = " ".join(lines).replace("`", "")
    text = re.sub(r"\*\*\w+\.\*\*", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return [s for s in re.split(r"(?<=\.)\s+(?=[A-Z])", text) if s]


def _token(value):
    return re.escape(value) + r"(?![0-9A-Za-z_])"


def mentions(sentence, sheet):
    """Calls the sentence names, in text order: {"pos", "end", "sites"}. A call is named by the callee,
    by its target address or by the address of the call instruction; a site address names that one call."""
    found = []
    by_callee = {}
    for site, call in sheet.calls.items():
        by_callee.setdefault((call["callee"], call["target"]), []).append(site)
    for (name, target), sites in by_callee.items():
        if name and not name.startswith(("(", ".")):
            # not "ret(name)" or "a1 = name": those name a returned value, not the call
            for m in re.finditer(r"(?<![0-9A-Za-z_(])" + re.escape(name) + r"(?![0-9A-Za-z_])", sentence):
                found.append({"pos": m.start(), "end": m.end(), "sites": sites, "callee": (name, target)})
        if target:
            for m in re.finditer(_token(target), sentence):
                found.append({"pos": m.start(), "end": m.end(), "sites": sites, "callee": (name, target)})
    for site, call in sheet.calls.items():
        for m in re.finditer(_token(site), sentence):
            found.append({"pos": m.start(), "end": m.end(), "sites": [site], "callee": (call["callee"], call["target"])})
    found.sort(key=lambda f: (f["pos"], -f["end"]))
    merged = []
    for item in found:
        if merged and item["pos"] < merged[-1]["end"]:
            continue
        if merged and item["callee"] == merged[-1]["callee"] and item["pos"] - merged[-1]["end"] <= 5 \
                and len(item["sites"]) == len(merged[-1]["sites"]):
            merged[-1]["end"] = item["end"]
            continue
        merged.append(item)
    return merged


def _nearest(items, pos):
    before = [i for i in items if i["pos"] <= pos]
    return before[-1] if before else (items[0] if items else None)


def _label(sheet, site):
    return "%s at %s" % (sheet.calls[site]["callee"], site)


# ---------------------------------------------------------------- argument slots

def _arg_claims(sentence):
    """(position, slot, value, text) of every "value goes in this argument" claim."""
    claims = []
    for m in re.finditer(r"(?P<v>" + NUMBER + r")(?![\w.])\s+(?:as|in)\s+(?:its |the |their )?(?P<o>" + ORD + r")\s+argument",
                         sentence):
        claims.append((m.start(), ORDINALS[m.group("o")], _int(m.group("v")), m.group(0)))
    for m in re.finditer(r"(?P<v>" + NUMBER + r")(?![\w.])\s+(?:as|in)\s+a(?P<r>[0-7])\b", sentence):
        claims.append((m.start(), int(m.group("r")), _int(m.group("v")), m.group(0)))
    for m in re.finditer(r"\ba(?P<r>[0-7])\s*(?:=|of)\s*(?P<v>" + NUMBER + r")(?![\w.])", sentence):
        claims.append((m.start(), int(m.group("r")), _int(m.group("v")), m.group(0)))
    for m in re.finditer(r"\b(?P<o>" + ORD + r") argument\s+(?:fixed at|is|=)\s+(?P<v>" + NUMBER + r")(?![\w.])", sentence):
        claims.append((m.start(), ORDINALS[m.group("o")], _int(m.group("v")), m.group(0)))
    return claims


def check_arguments(sentence, sheet):
    problems = []
    note = CONVENTION_NOTE.get(sheet.abi, "")
    for m in re.finditer(r"\b(?P<o>" + ORD + r") argument\s*\(a(?P<r>[0-7])\)", sentence):
        slot = ORDINALS[m.group("o")]
        if slot != int(m.group("r")):
            problems.append(("arg-register", "%r names a%s as the %s argument; the %s argument is a%d%s" % (
                m.group(0), m.group("r"), m.group("o"), m.group("o"), slot,
                " (%s)" % note if note else ""), sentence))
    items = mentions(sentence, sheet)
    for pos, slot, value, text in _arg_claims(sentence):
        near = _nearest(items, pos)
        if near is None or value is None:
            continue
        # "A, B and C pass x, y and z as their fourth argument" pairs calls with values one by one
        if re.search(r"(?:" + NUMBER + r",?|and)\s+$", sentence[max(0, pos - 12):pos]) or re.match(
                r"[^.]{0,40}?(?:,|\band)\s+-?" + NUMBER, sentence[pos + len(text):pos + len(text) + 24]):
            continue
        # a site written right after the claim ("a1 of 1 at 0xec43bc4") narrows it to that call
        after = re.match(r"\s*\(?(?:\w+ )?(?:at|from) (" + HEX + r")", sentence[pos + len(text):])
        sites = [after.group(1)] if after and after.group(1) in sheet.calls else near["sites"]
        results = []
        for site in sites:
            args = sheet.calls[site]["args"]
            got = args.get(slot)
            # a small number in another slot proves nothing: 0, 1 and 2 are everywhere
            elsewhere = sorted(k for k, v in args.items() if k != slot and _int(v) == value and value > 0xf)
            results.append((site, got, elsewhere))
        satisfied = [site for site, got, _e in results if got is not None and _int(got) == value]
        if satisfied:
            continue
        bad = [(site, got, elsewhere) for site, got, elsewhere in results if site not in satisfied]
        site, got, elsewhere = bad[0]
        if elsewhere:
            reason = "%r puts the value in a%d, but %s passes it in a%d, the %s argument%s" % (
                text, slot, _label(sheet, site), elsewhere[0], ORDINAL_NAMES[elsewhere[0]],
                " (%s)" % note if note else "")
        elif got is not None and _int(got) is not None:
            reason = "%r, but %s passes %s in a%d" % (text, _label(sheet, site), got, slot)
        else:
            continue
        problems.append(("arg-slot", reason, sentence))
    return problems


# ---------------------------------------------------------------- branch direction

_POLARITY = {"clear": 0, "cleared": 0, "unset": 0, "zero": 0, "null": 0, "false": 0, "not set": 0,
             "set": 1, "nonzero": 1, "non-zero": 1, "non-null": 1, "nonnull": 1, "true": 1}
_WORD = {0: "zero (clear)", 1: "nonzero (set)"}


def _runs_when(sheet, site, claim_address):
    """1 or 0 when the branch deciding site compares a word with zero and runs site on a nonzero or zero
    word. None when the facts leave that open."""
    options = []
    for address, side in sheet.deciding(site):
        branch = sheet.branches.get(address)
        if not branch:
            continue
        text = branch["taken" if side == "taken" else "fall"]
        m = re.fullmatch(r"(?P<l>.+?) (?P<op>==|!=) 0", text)
        if not m:
            continue
        if claim_address and claim_address not in text:
            continue
        options.append((_int(address), 0 if m.group("op") == "==" else 1, text))
    if not options:
        return None
    options.sort()
    return options[-1][1], options[-1][2]


def _compares(token, condition):
    """Whether the compared value is the register or number the prose names. A register inside a
    bracket is a field of what it points to, not the register itself."""
    token = token.lstrip("+")
    if re.fullmatch(r"[av]\d", token):
        return re.search(r"(?<![\w\[+])" + token + r"(?![\w+])", condition) is not None
    return token in condition


def check_branch_direction(sentence, sheet):
    """"when the flag is clear, calls X" and "calls X when the flag is set" against the branch that decides X."""
    problems = []
    items = mentions(sentence, sheet)
    if not items:
        return problems
    pattern = (r"\b(?P<w>when|if|unless)\b(?P<subj>[^,;.]{0,70}?)\b(?:is|are|was|equals)\s+"
               r"(?P<v>not set|non-zero|nonzero|non-null|nonnull|cleared|clear|unset|zero|null|set|true|false)\b")
    for m in re.finditer(pattern, sentence):
        value = _POLARITY[m.group("v")]
        if m.group("w") == "unless":
            value = 1 - value
        lead = sentence[:m.start()]
        if re.search(r"\b(skips?|bypass\w*|avoids?|omits?|suppress\w*|ignores?)\b[^,;.]*$", lead):
            value = 1 - value
        if re.search(r"\b(result|return value|returned|returns)\b", m.group("subj")):
            continue                      # a condition on a call's result, not on a flag
        tail = sentence[m.end():]
        if re.match(r"[^,;.]{0,60}?\b(and|or|but)\b", tail) and not re.match(r"\s*\([^)]*\)\s*,", tail):
            continue                      # a compound condition
        starts_clause = re.search(r"(?:^|[,;.]\s*|\band\s*,?\s*)$", lead) is not None
        if starts_clause:
            after = [i for i in items if i["pos"] >= m.end() and not re.search(r"[;.]", sentence[m.end():i["pos"]])
                     and i["pos"] - m.end() <= 90]
            target = after[0] if after else None
        else:
            before = [i for i in items if i["end"] <= m.start() and not re.search(r"[,;.]", sentence[i["end"]:m.start()])
                      and m.start() - i["end"] <= 90]
            target = before[-1] if before else None
        if target is None:
            continue
        addresses = [a for a in re.findall(HEX, sentence[:m.end()]) if a not in sheet.calls]
        flag = addresses[-1] if addresses else None
        if starts_clause and re.search(r"\b(skips?|bypass\w*|avoids?)\b", sentence[m.end():target["pos"]]):
            value = 1 - value
        subject = set(re.findall(r"\ba[0-7]\b|\bv[01]\b|\+?\b\d{2,}\b", m.group("subj")))
        wrong = []
        for site in target["sites"]:
            found = _runs_when(sheet, site, flag)
            if found is not None and not flag and not any(_compares(t, found[1]) for t in subject):
                found = None              # nothing ties the words to the compared value
            if found is None or found[0] == value:
                wrong = []
                break
            wrong.append((site, found))
        if wrong:
            site, (actual, text) = wrong[0]
            problems.append(("branch-direction", "%r puts %s under a %s word, but the branch that decides it runs it "
                             "when %s, a %s word" % (m.group(0) + "...", _label(sheet, site), "zero" if value == 0 else "nonzero",
                                                     text, "zero" if actual == 0 else "nonzero"), sentence))
    return problems


# ---------------------------------------------------------------- call order

_LINKING = {"calls", "call", "invokes", "runs", "falls", "into", "the", "a", "to", "through", "makes", "passes",
            "jumps", "it", "and", "again", "also", "with", "via", "by", "at", "its", "then", "also"}
_NORETURN = re.compile(r"^(assfail|panic|cmn_err\w*|abort|exit|_exit)$")


def check_order(sentences, sheet):
    """Claims written as "A, then B", "A after B" and "A before B" between two named calls."""
    problems = []
    text = " ".join(sentences)
    items = mentions(text, sheet)
    for first, second in zip(items, items[1:]):
        if first["callee"] == second["callee"] and first["sites"] == second["sites"]:
            continue
        between = text[first["end"]:second["pos"]]
        if len(between) > 160 or re.search(r"\b(when|if|unless|otherwise|else)\b", between):
            continue
        # one sentence, or a next sentence that opens with "then": "A at x. It then calls B"
        if re.search(r"\.", between) and not re.fullmatch(r"[^.]*\.\s+(?:It |The routine )?then\b[^.]*", between):
            continue
        if _NORETURN.search(first["callee"][0] or "") or _NORETURN.search(second["callee"][0] or ""):
            continue                      # a panic path is not a step in the order
        # the connector leads straight into the second call: "A with x, then B", "A, then falls into B"
        link = re.search(r"\b(?:then|followed by|after that|next)\b(?P<rest>[^.]*)$", between)
        near = re.search(r"\b(?P<w>before|after)\b(?P<rest>[^.]*)$", between)
        if link and set(re.findall(r"[a-z]+", link.group("rest").lower())) <= _LINKING:
            early, late, word = first, second, "then"
        elif near and len(near.group("rest")) < 12 and not re.search(r"\bthen\b", between):
            early, late, word = (first, second, "before") if near.group("w") == "before" else (second, first, "after")
        else:
            continue
        pairs = [(a, b) for a in early["sites"] for b in late["sites"]]
        if any(sheet.reaches(a, b) for a, b in pairs):
            continue
        if any(sheet.reaches(b, a) for a, b in pairs):
            a, b = next((a, b) for a, b in pairs if sheet.reaches(b, a))
            problems.append(("call-order", "the entry puts %s before %s (%r), but the facts reach %s first and never "
                             "reach %s from it" % (_label(sheet, a), _label(sheet, b), word, _label(sheet, b),
                                                   _label(sheet, a)), text[max(0, first["pos"] - 20):second["end"] + 20]))
    return problems


# ---------------------------------------------------------------- conditional wording

_COND = (r"\b(when|whenever|if|unless|otherwise|else|only|any|path|paths|branch|branches|test|tests|tested|gated|guard|"
         r"guards|guarded|depending|depends|either|loop|loops|until|while|each|every|retry|retries|falls|skips|skipped|"
         r"taken|check|checks|checked|compare|compares|nonzero|zero|null|case|error|fails|fail|success|whether|"
         r"alternate|alternatively)\b")
_ACKNOWLEDGED = r"\b(variants?|selects?|switches|depending|depends|either|other path|alternative|covers)\b"


def _actions(sentence, sheet):
    """Calls and stores the sentence cites by instruction address."""
    store = {a["address"] for a in sheet.accesses if a["kind"] == "store"}
    return [(m.start(), m.group(0)) for m in re.finditer(HEX + r"(?![0-9A-Fa-f])", sentence)
            if m.group(0) in sheet.calls or m.group(0) in store]


# A release or teardown stated flatly is the claim a guard most often falsifies: free(NULL) is skipped, a
# lock is dropped only when it was taken. Other calls are described with a condition often enough that a
# bare statement of one proves nothing.
_RELEASE = re.compile(r"free|release|destroy|dealloc|unmap", re.I)


def check_conditional_wording(sentence, entry_text, sheet):
    problems = []
    explicit = re.search(r"\b(unconditionally|on every path|every path|on all paths|regardless of)\b", sentence)
    if explicit:
        for _pos, address in _actions(sentence, sheet):
            if sheet.guarded(address):
                problems.append(("conditional-wording", "the entry says %r about %s, but a branch can skip it" % (
                    explicit.group(1), address), sentence))
    for m in re.finditer(r"\b(?:otherwise|else)\b(?P<rest>[^.]*)", sentence):
        for _pos, address in _actions(m.group("rest"), sheet):
            if sheet.guarded(address) is False:
                problems.append(("conditional-wording", "the entry puts %s on the 'otherwise' side of a branch, but it "
                                 "runs on every path" % address, sentence))
    if not explicit and not re.search(_COND, sentence, re.I) and not re.search(_ACKNOWLEDGED, entry_text, re.I):
        # An unqualified call that a branch can skip, with no word about a branch in the sentence.
        for _pos, address in _actions(sentence, sheet):
            if address not in sheet.calls or not _RELEASE.search(sheet.calls[address]["callee"] or ""):
                continue
            same = [m for m in re.finditer(HEX, sentence) if m.group(0) in sheet.calls
                    and sheet.calls[m.group(0)]["callee"] == sheet.calls[address]["callee"]]
            deciders = [a for a, _side in sheet.deciding(address)]
            # one or two tests around a release is the shape of "free it unless it is null"; a dozen is an
            # error-handling ladder the entry may be describing as a whole
            if len(same) > 1 or len(deciders) > 2 or not sheet.guarded(address) or not sheet.optional(address):
                continue
            if any(d in entry_text for d in deciders):
                continue
            problems.append(("conditional-wording", "the entry states the call at %s with no condition, but a branch at %s "
                             "can skip it" % (address, ", ".join(deciders) or "?"), sentence))
    return problems


# ---------------------------------------------------------------- the entry

def check_entry(sentences, sheet):
    """[(rule, reason, sentence)] for every claim of the prose that the facts contradict."""
    entry_text = " ".join(sentences)
    problems = []
    for sentence in sentences:
        problems.extend(check_arguments(sentence, sheet))
        problems.extend(check_branch_direction(sentence, sheet))
        problems.extend(check_conditional_wording(sentence, entry_text, sheet))
    problems.extend(check_order(sentences, sheet))
    seen, unique = set(), []
    for item in problems:
        if item[:2] not in seen:
            seen.add(item[:2])
            unique.append(item)
    return unique
