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


# Where a routine's arguments arrive, by architecture: (register prefix, number of the first argument
# register, regex of the register numbers). An architecture that passes arguments on the stack (ColdFire, m68k)
# has no entry: a claim about an argument register has nothing to be tested against there, so those rules skip.
ARG_REGS = {"mips": ("a", 0, "[0-7]"), "ppc32": ("r", 3, "(?:[3-9]|10)")}
# The architectures of the non-MIPS firmware images whose facts are rendered (see sheet_from_firmware).
FIRMWARE_ARCHES = ("ppc32", "coldfire", "m68k")
# A register of the architecture as a condition or a sentence writes it.
_COND_REG = {"mips": r"[av]\d", "ppc32": r"r\d+", "coldfire": r"[da][0-7]", "m68k": r"[da][0-7]"}
_SUBJECT_REG = {"mips": r"a[0-7]|v[01]", "ppc32": r"r\d+", "coldfire": r"[da][0-7]", "m68k": r"[da][0-7]"}
CONVENTION_NOTE["ppc-sysv"] = "PowerPC passes the first eight arguments in r3-r10, so the fifth is r7"


def _int(text):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


class FactSheet:
    """The facts of one routine. Plain data: see to_dict/from_dict."""

    def __init__(self, name="", abi="", text="", accesses=(), calls=None, branches=None, returns=None, blocks=(),
                 arch="mips", retreg="v0"):
        self.name, self.abi, self.text = name, abi, text
        self.arch, self.retreg = arch, retreg
        self.accesses = list(accesses)    # {"address", "kind", "mn", "offset" (or None)}
        self.calls = calls or {}          # site -> {"callee", "target", "args": {slot: text}, "tail"}
        self.branches = branches or {}    # address -> {"mn", "target", "taken", "fall"}
        self.returns = returns or {}      # address -> v0 text
        self.blocks = list(blocks)        # {"first", "last", "succ": [indexes], "reached"}
        self._reach = {}
        self._end = {}

    def to_dict(self):
        return {"name": self.name, "abi": self.abi, "text": self.text, "accesses": self.accesses,
                "calls": self.calls, "branches": self.branches, "returns": self.returns, "blocks": self.blocks,
                "arch": self.arch, "retreg": self.retreg}

    @classmethod
    def from_dict(cls, data):
        calls = {site: dict(call, args={int(k): v for k, v in call["args"].items()})
                 for site, call in data["calls"].items()}
        return cls(data["name"], data["abi"], data["text"], data["accesses"], calls, data["branches"],
                   data["returns"], data["blocks"], data.get("arch", "mips"), data.get("retreg", "v0"))

    # ---- argument registers

    def arg_regs(self):
        """(prefix, first register number, digit regex) of the argument registers, or None when the
        architecture passes arguments on the stack."""
        return ARG_REGS.get(self.arch)

    def reg_name(self, slot):
        """The register that carries argument slot, or "arg<slot>" where arguments are on the stack."""
        spec = self.arg_regs()
        return "%s%d" % (spec[0], spec[1] + slot) if spec else "arg%d" % slot

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
        return any(self._ends(node) for node in reachable)

    def _ends(self, node):
        """Whether execution can end at a block: it has no successor, or it is in a loop it can never leave
        (a routine that spins on itself after a fatal call has no return to reach)."""
        if node not in self._end:
            ahead = self._walk(node)
            if not self.blocks[node]["succ"]:
                self._end[node] = True
            elif any(not self.blocks[n]["succ"] for n in ahead):
                self._end[node] = False         # a return can still be reached from here
            else:
                self._end[node] = all(node in self._walk(n) for n in ahead)
        return self._end[node]

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


def sheet_from_firmware(routine, facts, rendered=None):
    """A sheet for a routine of a non-MIPS firmware image (PowerPC, ColdFire, m68k), built from the facts the
    firmware renderer prints. It holds the same things as a MIPS sheet: calls with their argument slots,
    conditional branches with both conditions, returns, loads and stores outside the frame, and the block graph.
    Arguments are in r3-r10 on PowerPC; on ColdFire and m68k they are on the stack and no slots are listed, so
    the argument rules skip. An argument register the routine leaves as it came in reads "rN at entry"."""
    arch = routine.arch
    if arch not in FIRMWARE_ARCHES:
        raise ValueError("no facts are rendered for %s firmware" % arch)
    if rendered is None:
        import render_reading
        rendered = "\n".join(render_reading.firmware_sentences(routine, facts))
    mnemonic = {hex(ins["addr"]): ins["mn"] for ins in routine.insns}
    spec = ARG_REGS.get(arch)
    sheet = FactSheet(name=facts["routine"].get("name") or "", abi=facts["routine"].get("abi") or "", text=rendered,
                      arch=arch, retreg=facts["exits"][0]["register"] if facts.get("exits") else routine.retreg)
    for call in facts.get("calls", []):
        callee = call.get("callee") or ("(unnamed)" if call.get("target") else "(unknown callee)")
        args = {}
        for arg in call.get("args", []) if spec else ():
            m = re.fullmatch(re.escape(spec[0]) + r"(\d+)", arg["location"])
            if m and 0 <= int(m.group(1)) - spec[1] < 8:
                args[int(m.group(1)) - spec[1]] = "%s at entry" % arg["location"] if arg["value"] == arg["location"] \
                    else arg["value"]
        sheet.calls[call["address"]] = {"callee": callee, "target": call.get("target"), "args": args,
                                        "tail": bool(call.get("tail"))}
    for exit_fact in facts.get("exits", []):
        sheet.returns[exit_fact["address"]] = exit_fact["value"]
    for a in facts.get("accesses", []):
        if a.get("origin") == "sp" or a.get("stack") or a.get("base") in ("sp", "gp", "r1", "a7"):
            continue
        sheet.accesses.append({"address": a["address"], "kind": a["kind"], "mn": a["mnemonic"],
                               "offset": a.get("origin_offset") if "origin" in a else None})
    unreached = set(facts.get("unreached", []))
    index = {block["id"]: n for n, block in enumerate(facts.get("blocks", []))}
    for block in facts.get("blocks", []):
        reached = block["first"] not in unreached
        # a conditional block lists its taken side first, as the MIPS blocks do
        order = sorted(block["successors"], key=lambda s: s["kind"] != "taken")
        entry = {"first": _int(block["first"]), "last": _int(block["last"]),
                 "succ": [index[s["block"]] for s in order] if reached else [], "reached": reached}
        if block["kind"] == "conditional" and reached and block.get("target") is not None:
            entry["branch"] = block["last"]
            sheet.branches[block["last"]] = {"mn": mnemonic.get(block["last"], "?"), "target": block["target"],
                                             "taken": block["taken_when"], "fall": block["falls_through_when"]}
        sheet.blocks.append(entry)
    return sheet


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
    # a sentence can start with a lowercase routine name, as in "... later. gl_compile is then called"
    return [s for s in re.split(r"(?<=\.)\s+(?=[A-Z]|[a-z]+_\w+)", text) if s]


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

def _arg_claims(sentence, spec=ARG_REGS["mips"]):
    """(position, slot, value, text) of every "value goes in this argument" claim. spec names the argument
    registers (ARG_REGS); a register outside them is not a claim about an argument."""
    prefix, base, digits = spec
    claims = []
    for m in re.finditer(r"(?P<v>" + NUMBER + r")(?![\w.])\s+(?:as|in)\s+(?:its |the |their )?(?P<o>" + ORD + r")\s+argument",
                         sentence):
        claims.append((m.start(), ORDINALS[m.group("o")], _int(m.group("v")), m.group(0)))
    for m in re.finditer(r"(?P<v>" + NUMBER + r")(?![\w.])\s+(?:as|in)\s+" + prefix + r"(?P<r>" + digits + r")\b", sentence):
        claims.append((m.start(), int(m.group("r")) - base, _int(m.group("v")), m.group(0)))
    for m in re.finditer(r"\b" + prefix + r"(?P<r>" + digits + r")\s*(?:=|of)\s*(?P<v>" + NUMBER + r")(?![\w.])", sentence):
        claims.append((m.start(), int(m.group("r")) - base, _int(m.group("v")), m.group(0)))
    for m in re.finditer(r"\b(?P<o>" + ORD + r") argument\s+(?:fixed at|is|=)\s+(?P<v>" + NUMBER + r")(?![\w.])", sentence):
        claims.append((m.start(), ORDINALS[m.group("o")], _int(m.group("v")), m.group(0)))
    return claims


def check_arguments(sentence, sheet):
    problems = []
    spec = sheet.arg_regs()
    if spec is None:
        return problems                   # arguments on the stack: no register to name
    prefix, base, digits = spec
    note = CONVENTION_NOTE.get(sheet.abi, "")
    for m in re.finditer(r"\b(?P<o>" + ORD + r") argument\s*\(" + prefix + r"(?P<r>" + digits + r")\)", sentence):
        slot = ORDINALS[m.group("o")]
        if slot != int(m.group("r")) - base:
            problems.append(("arg-register", "%r names %s%s as the %s argument; the %s argument is %s%s" % (
                m.group(0), prefix, m.group("r"), m.group("o"), m.group("o"), sheet.reg_name(slot),
                " (%s)" % note if note else ""), sentence))
    items = mentions(sentence, sheet)
    for pos, slot, value, text in _arg_claims(sentence, spec):
        near = _nearest(items, pos)
        if near is None or value is None:
            continue
        # "the helper f at 0xADDR as r4": the address is where the call is, not a value passed
        if re.search(r"\bat\s+$", sentence[max(0, pos - 4):pos]) and "0x%x" % value in sheet.calls:
            continue
        # "A, B and C pass x, y and z as their fourth argument" pairs calls with values one by one
        # ("A and B with r3=0x20 and r3=0x80" pairs them too: the same register named again is the next call's)
        named = re.match(re.escape(spec[0]) + r"\d+", text)
        again = r"(?:" + re.escape(named.group(0)) + r"\s*=\s*)?" if named else ""
        if re.search(r"(?:" + NUMBER + r",?|and)\s+$", sentence[max(0, pos - 12):pos]) or re.match(
                r"[^.]{0,40}?(?:,|\band)\s+" + again + r"-?" + NUMBER, sentence[pos + len(text):pos + len(text) + 24]):
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
            reason = "%r puts the value in %s, but %s passes it in %s, the %s argument%s" % (
                text, sheet.reg_name(slot), _label(sheet, site), sheet.reg_name(elsewhere[0]), ORDINAL_NAMES[elsewhere[0]],
                " (%s)" % note if note else "")
        elif got is not None and _int(got) is not None:
            reason = "%r, but %s passes %s in %s" % (text, _label(sheet, site), got, sheet.reg_name(slot))
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
        m = re.fullmatch(r"(?P<l>.+?) (?P<op>==|!=) 0(?:x0)?", text)
        if not m:
            continue
        if claim_address and claim_address not in text:
            continue
        options.append((_int(address), 0 if m.group("op") == "==" else 1, text))
    if not options:
        return None
    options.sort()
    return options[-1][1], options[-1][2]


def _compares(token, condition, register=_COND_REG["mips"]):
    """Whether the compared value is the register or number the prose names. A register inside a
    bracket is a field of what it points to, not the register itself."""
    token = token.lstrip("+")
    if re.fullmatch(register, token):
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
        subject = set(re.findall(r"\b(?:" + _SUBJECT_REG.get(sheet.arch, _SUBJECT_REG["mips"]) + r")\b|\+?\b\d{2,}\b",
                                 m.group("subj")))
        wrong = []
        for site in target["sites"]:
            found = _runs_when(sheet, site, flag)
            if found is not None and not flag and not any(_compares(t, found[1], _COND_REG.get(sheet.arch, _COND_REG["mips"])) for t in subject):
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


# ---------------------------------------------------------------- loads and stores

_READ = r"(?:reads?|loads?|loaded|reading|fetch(?:es)?)"
_WRITE = r"(?:writes?|written|stores?|stored|storing|resets?|clears?|zeroe?s|advances?)"
_BREAK = r"\b(?:calls?|passes|forwards|returns?|copies|tests|compares|branches|mallocs|frees|through|via|from|using|of the)\b"


def _verb_kind(word):
    return "load" if re.fullmatch(_READ, word.lower()) else "store"


def check_access_kind(sentence, sheet):
    problems = []
    if re.search(r"\b(reads and writes|loads and stores|read-modify-write|reads or writes)\b", sentence):
        return problems
    verbs = [(m.start(), m.end(), _verb_kind(m.group(0))) for m in
             re.finditer(r"\b(?:" + _READ + "|" + _WRITE + r")\b", sentence)]
    kinds_at = {}
    for a in sheet.accesses:
        if a["offset"] is not None:
            kinds_at.setdefault(a["offset"], set()).add(a["kind"])
    # offsets named right after a read or write verb: "reads the state at p +0xba8 and +0xbb0 and stores a word to +0xd8"
    for m in re.finditer(r"\+(0x[0-9a-fA-F]+)\b", sentence):
        offset = int(m.group(1), 16)
        prior = [v for v in verbs if v[1] <= m.start()]
        if not prior or offset not in kinds_at:
            continue
        verb = prior[-1]
        between = sentence[verb[1]:m.start()]
        lead = sentence[max(0, verb[0] - 24):verb[0]]
        if (re.search(_BREAK + r"|[(),:;.]", re.sub(r"(?:,|, and| and) \+0x[0-9a-f]+", "", between)) or len(between) > 60
                or re.search(r"[\w\])]$", sentence[:m.start()])
                or re.search(r"\b(no|not|never|without|nor)\b", lead + between)
                or re.search(r"\bof the\b|\bthrough\b|\bat \+0x[0-9a-f]+ of\b", sentence[m.end():m.end() + 12])):
            continue
        if verb[2] not in kinds_at[offset]:
            claimed = "reads" if verb[2] == "load" else "writes"
            actual = "loaded" if "load" in kinds_at[offset] else "stored"
            problems.append(("access-kind", "the entry says it %s +0x%x, but the facts only show it %s" % (
                claimed, offset, actual), sentence))
    # "reads comm_stdsize (0xADDR) and comm_buffer (0xADDR, 0xADDR)": the cited instruction's kind
    kind_of = {a["address"]: a["kind"] for a in sheet.accesses}
    for m in re.finditer(r"\b(?P<v>" + _READ + "|" + _WRITE + r")\b(?P<rest>(?: [\w+\-./\[\]]+){1,6}? \((?P<a>" + HEX +
                         r"(?:, " + HEX + r")*)\)(?: and [\w+\-./]+ \(" + HEX + r"(?:, " + HEX + r")*\))*)", sentence):
        if re.search(r"\b(?:" + _READ + "|" + _WRITE + r")\b", m.group("rest")):
            continue                      # "reads and writes the word at x (a, b)": two verbs share the addresses
        kind = _verb_kind(m.group("v"))
        listed = [a for a in re.findall(HEX, m.group("rest")) if a in kind_of]
        if listed and all(kind_of[a] != kind for a in listed):
            problems.append(("access-kind", "the entry says it %s at %s, but the instruction there is a %s" % (
                "reads" if kind == "load" else "writes", listed[0], kind_of[listed[0]]), sentence))
    return problems


# ---------------------------------------------------------------- returns

def check_return(sentence, sheet):
    if not re.search(r"\b[Rr]eturns\b", sentence) or re.search(
            r"\b(or|either|one of|depending|depends|whichever|otherwise|when|if|path|paths|each|both|on|upon|fail\w*|"
            r"error|zero|nonzero|null|miss\w*)\b", sentence, re.I):
        return []
    cited = [a for a in re.findall(HEX, sentence) if a in sheet.returns]
    values = [sheet.returns[a] for a in cited]
    if not cited and len(sheet.returns) == 1 and re.match(r"(It|The routine|Returns?)\b", sentence):
        cited = list(sheet.returns)
        values = list(sheet.returns.values())
    for address, value in zip(cited, values):
        # Two call results are a routine's ordinary tail; a value beside a call result is an error path left out.
        import hostfacts
        parts = hostfacts.split_top_level(value[7:]) if value.startswith("one of ") else []
        mixed = any(p.startswith("ret(") for p in parts) and any(not re.match(r"\[?ret\(", p) for p in parts)
        if value.startswith("one of ") and "?" not in value and mixed and not re.search(r"result|ret\(|callee", sentence):
            return [("return-value", "the entry gives one return value, but the return at %s is %s" % (address, value),
                     sentence)]
    return []


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
        for pos, address in _actions(sentence, sheet):
            # an address after the phrase belongs to it only while the clause runs on: a closing bracket or a
            # stop before it, or a condition before it or after it in its own clause ("... on every path, and
            # at B only when ..."), starts another claim
            cond = r"\b(?:when|whenever|if|unless|otherwise|else|only)\b"
            if pos > explicit.end() and (
                    re.search(r"[;.)]|" + cond, sentence[explicit.end():pos])
                    or re.search(cond, re.split(r"[;.)]", sentence[pos:], maxsplit=1)[0])):
                continue
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


# ---------------------------------------------------------------- enable and disable

def check_enable(sentence, entry_text, sheet):
    problems = []
    if sheet.arg_regs() is None or re.search(r"disabl|\bclears?\b|\boff\b|%s of 0\b" % sheet.reg_name(1), entry_text):
        return problems
    for m in re.finditer(r"\benables (?P<v>" + NUMBER + r")(?![\w.])", sentence):
        value = _int(m.group("v"))
        for item in mentions(sentence, sheet):
            for site in item["sites"]:
                call = sheet.calls[site]
                if "nable" not in (call["callee"] or ""):
                    continue
                for other, c in sheet.calls.items():
                    if c["callee"] == call["callee"] and _int(c["args"].get(0, "")) == value \
                            and _int(c["args"].get(1, "")) == 0:
                        problems.append(("enable-only", "the entry says it enables %s, but %s passes %s=0x0 at %s" % (
                            m.group("v"), call["callee"], sheet.reg_name(1), other), sentence))
                        return problems
    return problems


# ---------------------------------------------------------------- role words

_ROLE_OK = {"zero", "null", "nil", "empty", "negative", "positive", "blocking", "trivial", "standard", "default",
            "local", "volatile", "matching", "leaf", "inline", "existent", "overlapping", "aligned", "present",
            "maskable", "power", "interactive", "reentrant", "recursive", "atomic", "cacheable", "cached", "speculative"}


def check_role_words(sentence, sheet):
    problems = []
    facts_text = sheet.text.lower()
    for m in re.finditer(r"\bnon-([a-z]+)\b", sentence, re.I):
        word = m.group(1).lower()
        if word not in _ROLE_OK and word not in facts_text:
            problems.append(("role-word", "%r denies a property the facts never mention; a negated role qualifier is "
                             "carried over from a name, not shown by the facts" % m.group(0), sentence))
    # "The float fields suggest a colour-and-position move": a role pinned on the facts. A guess that says it
    # rests on names, or that the facts do not show it, is the honest form.
    for m in re.finditer(r"\b(?P<subj>(?:[\w-]+ ){1,3}(?:stores|fields|loads|values|constants|offsets|operands|"
                         r"halfwords|words))\s+(?:suggest|imply|indicate|point to)s?\s+(?P<role>[^.,;]*)", sentence):
        if not re.search(r"\b(not|no|cannot|names?|alone)\b", sentence):
            problems.append(("role-word", "%r names a role the facts do not give; attribute the guess to the routine's "
                             "name or say the facts do not show it" % (m.group(0)[:70]), sentence))
    return problems


# ---------------------------------------------------------------- the entry

def check_entry(sentences, sheet):
    """[(rule, reason, sentence)] for every claim of the prose that the facts contradict."""
    entry_text = " ".join(sentences)
    problems = []
    for sentence in sentences:
        problems.extend(check_arguments(sentence, sheet))
        problems.extend(check_branch_direction(sentence, sheet))
        problems.extend(check_access_kind(sentence, sheet))
        problems.extend(check_return(sentence, sheet))
        problems.extend(check_conditional_wording(sentence, entry_text, sheet))
        problems.extend(check_enable(sentence, entry_text, sheet))
        problems.extend(check_role_words(sentence, sheet))
    problems.extend(check_order(sentences, sheet))
    seen, unique = set(), []
    for item in problems:
        if item[:2] not in seen:
            seen.add(item[:2])
            unique.append(item)
    return unique


# ---------------------------------------------------------------- cited claims

# A cited entry (README-analysis.md, "Cited entries") puts a citation after every claim: [@0x10a4] names the
# instruction at an address, [call 3] the third call of the facts in address order, and a citation can take a
# side, [@0x10a0 fall]. Several citations in one bracket belong together: [call 4, @0x10a0 fall] says the
# call runs on the fall-through side of the branch. check_cited tests each citation against the fact it names
# and flags every sentence that states a fact and cites none, so a wrong claim has no place to hide.

_CITE = re.compile(r"\[(?P<body>(?:@|call\s)[^\]]*)\]")
_PART = re.compile(r"^(?:@(?P<addr>" + HEX + r")(?:\s+(?P<side>taken|fall)(?:\s+(?P<pol>zero|nonzero))?)?"
                   r"|call\s+(?P<call>\d+))$")

# Rules that describe how the entry is labelled, not a claim the facts contradict.
NOTE_RULES = {"role-from-name"}

_FROM_FACTS = re.compile(r"^Role \(from facts\):", re.I)
_FROM_NAME = re.compile(r"^Role \(from name\):", re.I)
_HEDGE = re.compile(r"\b(?:facts|render|rendered facts|listing|disassembly)\b[^.]*\b(?:do(?:es)? not|don't|cannot|never|"
                    r"leave|leaves|no)\b|\b(?:not (?:shown|established|derived|resolved|identified|settled)|"
                    r"unknown|unresolved|open)\b", re.I)
_FACT_VERB = re.compile(r"\b(?:calls?|stores?|writes?|loads?|reads?|returns?|tests?|compares?|branch(?:es)?|passes|"
                        r"saves|sets|clears|copies|allocates|frees|jumps?|loops?|skips?|zeroe?s|advances|masks|"
                        r"checks)\b", re.I)
_NAMED_ROLE = re.compile(r"\b(?:the name (?:suggests|implies|says|fits|reads)|by its name|from the name|"
                         r"name suggests|looks like|reads as|fits a|is probably)\b", re.I)
_CALL_VERB = re.compile(r"\b(?:calls?|invokes?|jumps? to|tail-calls?)\b", re.I)
_STORE_VERB = re.compile(r"\b(?:stores?|stored|writes?|writing|written)\b", re.I)
_LOAD_VERB = re.compile(r"\b(?:loads?|loaded|reads?|reading)\b", re.I)
_BRANCH_VERB = re.compile(r"\b(?:tests?|compares?|branch(?:es)?|skips?)\b", re.I)
_CONDITION = re.compile(r"\b(?:when|whenever|if|unless|only|otherwise|else|skips?|skipped|depending)\b", re.I)
_UNCOND = re.compile(r"\b(?:unconditionally|always|on every path|every path|on all paths|both paths|either way|both ways|in either case|"
                     r"regardless of)\b", re.I)
_LOOP = re.compile(r"\b(?:loops?|repeats?|until|while)\b", re.I)
_VALUE_CLAIM = re.compile(r"\b(?:stores?|writes?|clears?|zeroe?s|zeros)\s+(?:the\s+)?(?:value\s+)?"
                          r"(?:(?:zero|0x[0-9a-fA-F]+|\d+|a[0-7])\b(?!-byte|-bit|\s+bytes?)|its arguments?|"
                          r"the arguments?|arguments)|\bclears?\b", re.I)
_PASS_THROUGH = re.compile(r"\b(?:passes|forwards|passing|forwarding)\s+(?:its|the|all|every)\s+(?:own\s+)?"
                           r"(?:argument|arguments|argument registers)\b|\bunchanged\b|\bstraight into\b", re.I)
_COUNT = re.compile(r"\b(?P<approx>about|around|roughly|up to|at most|some)?\s*(?P<n>\d+|one|two|three|four|five|six|"
                    r"seven|eight|nine|ten|eleven|twelve)\s+(?P<kind>indirect |direct )?(?:calls|call sites)\b", re.I)
_WORD_NUMBER = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
                "ten": 10, "eleven": 11, "twelve": 12}


def _hex(text):
    value = _int(text)
    return None if value is None else "0x%x" % value


def _call_sites(sheet):
    """The sites of the facts' calls in address order: [call N] is the Nth of them, counting from 1."""
    return sorted(sheet.calls, key=lambda site: _int(site))


def _known_addresses(sheet):
    known = {}
    for site in sheet.calls:
        known[_hex(site)] = "call"
    for address in sheet.branches:
        known[_hex(address)] = "branch"
    for address in sheet.returns:
        known[_hex(address)] = "return"
    for access in sheet.accesses:
        known[_hex(access["address"])] = access["kind"]
    return known


def citations_of(sentence, sheet):
    """[(start, end, group)] for each bracket of the sentence, where a group is a list of parts
    {"addr", "side", "pol", "call" (the site a [call N] names), "n"}. A part that does not parse, or a
    [call N] past the last call, has "bad" set."""
    sites = _call_sites(sheet)
    found = []
    for m in _CITE.finditer(sentence):
        group = []
        for text in re.split(r"\s*,\s*", m.group("body").strip()):
            part = _PART.match(text)
            if not part:
                group.append({"bad": text})
            elif part.group("call"):
                n = int(part.group("call"))
                group.append({"n": n, "addr": sites[n - 1] if 1 <= n <= len(sites) else None, "call": True,
                              "bad": None if 1 <= n <= len(sites) else "call %d" % n})
            else:
                group.append({"addr": _hex(part.group("addr")), "side": part.group("side"),
                              "pol": part.group("pol"), "call": False, "bad": None})
        found.append((m.start(), m.end(), group))
    return found


def _numbers(text):
    return re.findall(NUMBER, text)


def _check_call_args(segment, site, sheet):
    """Argument claims written before a call's citation, tested on that call."""
    problems = []
    spec = sheet.arg_regs()
    if spec is None:
        return problems                   # arguments on the stack: no register to name
    prefix, base, digits = spec
    args = sheet.calls[site]["args"]
    note = CONVENTION_NOTE.get(sheet.abi, "")
    for m in re.finditer(r"\b(?P<o>" + ORD + r") argument\s*\(" + prefix + r"(?P<r>" + digits + r")\)", segment):
        if ORDINALS[m.group("o")] != int(m.group("r")) - base:
            problems.append(("cite-arg", "%r names %s%s as the %s argument; the %s argument is %s%s" % (
                m.group(0), prefix, m.group("r"), m.group("o"), m.group("o"), sheet.reg_name(ORDINALS[m.group("o")]),
                " (%s)" % note if note else "")))
    for _pos, slot, value, text in _arg_claims(segment, spec):
        if value is None:
            continue
        got = args.get(slot)
        if got is not None and _int(got) == value:
            continue
        elsewhere = sorted(k for k, v in args.items() if k != slot and _int(v) == value and value > 0xf)
        if elsewhere:
            problems.append(("cite-arg", "%r puts the value in %s, but %s passes it in %s, the %s argument%s" % (
                text, sheet.reg_name(slot), _label(sheet, site), sheet.reg_name(elsewhere[0]),
                ORDINAL_NAMES[elsewhere[0]], " (%s)" % note if note else "")))
        elif got is None or _int(got) is None:
            problems.append(("cite-arg", "%r, but the facts give %s=%s at %s, so no value can be stated there" % (
                text, sheet.reg_name(slot), got if got is not None else "(not set)", _label(sheet, site))))
        else:
            problems.append(("cite-arg", "%r, but %s passes %s in %s" % (text, _label(sheet, site), got,
                                                                         sheet.reg_name(slot))))
    # "a1 = a2 at entry": slot a1 holds the caller's a2, and "a2 at entry as its fourth argument" says the same
    # of the slot the ordinal names
    reg = prefix + digits
    for m in re.finditer(r"\b" + prefix + r"(?P<slot>" + digits + r")\s*=\s*(?P<reg>" + prefix + r"\d+) at entry", segment):
        _check_entry_register(problems, m.group(0), int(m.group("slot")) - base, m.group("reg"), site, sheet)
    for m in re.finditer(r"\b(?P<reg>" + prefix + r"\d+) at entry (?:as|in) (?:its |the )?(?P<o>" + ORD + r") argument", segment):
        _check_entry_register(problems, m.group(0), ORDINALS[m.group("o")], m.group("reg"), site, sheet)
    rest = re.sub(r"\b" + prefix + r"\d+\s*=\s*" + prefix + r"\d+ at entry|\b" + prefix + r"\d+ at entry (?:as|in) (?:its |the )?(?:"
                  + ORD + r") argument", " ", segment)
    for m in re.finditer(r"\b(?P<reg>" + reg + r")\s+(?:unchanged|as received|at entry|passed through)", rest):
        _check_entry_register(problems, m.group(0), int(m.group("reg")[len(prefix):]) - base, m.group("reg"), site, sheet)
    return problems


def _check_entry_register(problems, text, slot, reg, site, sheet):
    got = sheet.calls[site]["args"].get(slot, "")
    if not str(got).startswith("%s at entry" % reg):
        problems.append(("cite-arg", "%r, but %s passes %s in %s" % (
            text, _label(sheet, site), got or "(not set)", sheet.reg_name(slot))))


def _check_return_claim(segment, address, sheet):
    value = sheet.returns.get(address, "")
    m = re.search(r"\breturns?\s+(?:the\s+)?(?:result|value) of (?P<n>[\w.$@]+)", segment, re.I)
    if m:
        if "ret(%s" % m.group("n") not in value:
            return [("cite-return", "the entry says the return at %s is the result of %s, but v0 there is %s" % (
                address, m.group("n"), value or "(not shown)"))]
        return []
    m = re.search(r"\breturns?\s+(?P<v>-?0x[0-9a-fA-F]+|-?\d+)\b", segment, re.I)
    if m and not re.search(r"(?<![\w-])" + re.escape(m.group("v")) + r"(?![\w])", value):
        return [("cite-return", "the entry says the return at %s gives %s, but v0 there is %s" % (
            address, m.group("v"), value or "(not shown)"))]
    return []


def check_cited(sentences, sheet):
    """[(rule, reason, sentence)] for an entry written in the cited format: every citation tested against
    the fact it names (the address exists, the call target and arguments, the branch side, a load or a
    store, the return value), every sentence that states a fact and cites none, and the Role sentence.
    The rules of check_entry also run, on the prose with its citations."""
    sentences = [s for s in sentences if not re.match(r"Reviewed:", s)]
    problems = []
    known = _known_addresses(sheet)
    roles = {"facts": 0, "name": 0}
    previous_site = None
    for sentence in sentences:
        cites = citations_of(sentence, sheet)
        plain = _CITE.sub(" ", sentence)
        found = []
        if _FROM_NAME.match(sentence):
            roles["name"] += 1
            found.append(("role-from-name", "the role comes from the name, so the entry earns at most located", None))
        elif _FROM_FACTS.match(sentence):
            roles["facts"] += 1
            if not cites:
                found.append(("role-uncited", "a Role (from facts) sentence must cite the facts it rests on", None))
        elif _NAMED_ROLE.search(plain):
            found.append(("role-unmarked", "a role taken from the name belongs in a sentence that starts "
                          "'Role (from name):'", None))
        names_fact = (bool(re.search(HEX, plain)) or bool(_FACT_VERB.search(plain)) or bool(mentions(plain, sheet)))
        if (not cites and names_fact and not _FROM_NAME.match(sentence) and not _HEDGE.search(plain)
                and not _FROM_FACTS.match(sentence)):
            found.append(("uncited", "the sentence states a fact and cites none; add [@0xADDR] or [call N]", None))
        previous_end, sites_here = 0, []
        for start, end, group in cites:
            segment = _CITE.sub(" ", sentence[previous_end:start])
            for part in group:
                if part.get("bad"):
                    found.append(("cite-address", "%r is not a citation of this routine's facts (a call number "
                                  "counts from 1 over %d calls, an address must be one the facts list)" % (
                                      part["bad"], len(sheet.calls)), None))
                    continue
                address = part["addr"]
                kind = known.get(address)
                if kind is None:
                    found.append(("cite-address", "%s is not an instruction the facts list for this routine" % address,
                                  None))
                    continue
                if part["call"] or (not part["side"] and kind == "call"):
                    site = address
                    sites_here.append(site)
                    names = mentions(segment, sheet)
                    last = names[-1] if names else None
                    if last and not any(sheet.calls[site][k] and sheet.calls[site][k] in last["callee"]
                                        for k in ("callee", "target")):
                        found.append(("cite-callee", "the sentence names %s, but %s is a call to %s" % (
                            last["callee"][0] or last["callee"][1], "[call %d]" % (_call_sites(sheet).index(site) + 1)
                            if part["call"] else site, sheet.calls[site]["callee"] or sheet.calls[site]["target"]), None))
                    found.extend((r, why, None) for r, why in _check_call_args(segment, site, sheet))
                    if _STORE_VERB.search(segment[-40:]) and not _CALL_VERB.search(segment[-40:]):
                        found.append(("cite-kind", "the sentence says it stores at %s, which the facts show as a call" % site,
                                      None))
                elif part["side"]:
                    if kind != "branch":
                        found.append(("cite-kind", "%s takes a side, but the facts show a %s there, not a branch" % (
                            address, kind), None))
                elif kind in ("load", "store"):
                    # the verb that governs a run of citations is the last one before them: "reads A, B and C [@a][@b][@c]"
                    before = _CITE.sub(" ", sentence[:start])[-100:]
                    verbs = sorted([(m.start(), "store") for m in _STORE_VERB.finditer(before)] +
                                   [(m.start(), "load") for m in _LOAD_VERB.finditer(before)])
                    said = verbs[-1][1] if verbs else None
                    if said == "store" and kind == "load":
                        found.append(("access-kind", "the sentence says it stores at %s, but the instruction there is "
                                      "a load" % address, None))
                    elif said == "load" and kind == "store":
                        found.append(("access-kind", "the sentence says it reads at %s, but the instruction there is "
                                      "a store" % address, None))
                    if kind == "store" and _VALUE_CLAIM.search(before[-80:]):
                        found.append(("cite-value", "the facts list the store at %s but not what it stores; say a word "
                                      "or a doubleword was stored, not its value" % address, None))
                elif kind == "return":
                    found.extend((r, why, None) for r, why in _check_return_claim(segment, address, sheet))
                elif kind == "branch" and re.search(r"\bcalls\b", segment[-40:]):
                    found.append(("cite-kind", "the sentence says it calls at %s, but the facts show a branch there" %
                                  address, None))
            if _PASS_THROUGH.search(segment) and any(p["call"] or known.get(p["addr"]) == "call"
                                                    for p in group if p.get("addr")):
                found.append(("cite-arg", "'passes its arguments' is not checkable; name each register, for example "
                              "'a1 at entry'", None))
            found.extend((r, why, None) for r, why in _check_group(group, sheet, sentence))
            previous_end = end
        found.extend((r, why, None) for r, why in _check_sentence(sentence, plain, cites, sheet, known))
        if cites:
            call_sites = [p["addr"] for _s, _e, g in cites for p in g
                          if p.get("addr") and not p.get("bad") and known.get(p["addr"]) == "call"]
            if call_sites and previous_site and re.match(r"(?:It |The routine )?(?:then|next)\b", plain.strip(), re.I) \
                    and sheet.reaches(previous_site, call_sites[0]) is False and sheet.reaches(call_sites[0], previous_site):
                found.append(("cite-order", "the sentence puts %s after %s, but the facts reach them in the other order" % (
                    _label(sheet, call_sites[0]), _label(sheet, previous_site)), None))
            if call_sites:
                previous_site = call_sites[-1]
        problems.extend((rule, why, sentence) for rule, why, _s in found)
    looped = any(_LOOP.search(_CITE.sub(" ", x)) and not _HEDGE.search(x) and _CITE.search(x) for x in sentences)
    if looped:
        info = {_hex(a): b for a, b in sheet.branches.items()}
        back = [p for x in sentences for _s, _e, g in citations_of(x, sheet) for p in g
                if p.get("side") == "taken" and p.get("addr") in info
                and _int(info[p["addr"]]["target"]) <= _int(p["addr"])]
        if not back:
            problems.append(("cite-loop", "the entry describes a loop and cites no branch whose taken side goes back "
                             "to an earlier address", ""))
    if not roles["facts"] and not roles["name"]:
        problems.append(("role-missing", "the entry has no sentence that starts 'Role (from facts):' or "
                         "'Role (from name):'", ""))
    # the prose rules that do not duplicate a citation check: branch words, order, returns, role words
    skip = ("arg-slot", "arg-register") + (("access-kind",) if any(p[0] == "access-kind" for p in problems) else ())
    problems.extend(item for item in check_entry([_CITE.sub(" ", s) for s in sentences], sheet)
                    if item[0] not in skip)
    seen, unique = set(), []
    for item in problems:
        if item[:2] not in seen:
            seen.add(item[:2])
            unique.append(item)
    return unique


def _check_group(group, sheet, sentence):
    """The branch sides of one bracket against the calls and stores cited beside them."""
    problems = []
    infos = {_hex(a): b for a, b in sheet.branches.items()}
    branches = [p for p in group if p.get("side") and not p.get("bad") and p["addr"] in infos]
    actions = [p["addr"] for p in group if not p.get("side") and not p.get("bad") and p.get("addr")]
    for branch in branches:
        info = infos[branch["addr"]]
        if branch.get("pol"):
            text = info["taken" if branch["side"] == "taken" else "fall"]
            m = re.fullmatch(r"(?P<l>.+?) (?P<op>==|!=) 0(?:x0)?", text)
            want = "==" if branch["pol"] == "zero" else "!="
            if not m:
                problems.append(("cite-branch", "the branch at %s does not compare a word with zero (it is %s on the "
                                 "%s side), so %s cannot be checked" % (branch["addr"], text, branch["side"], branch["pol"])))
            elif m.group("op") != want:
                problems.append(("cite-branch", "the branch at %s is %s on its %s side, not a %s word" % (
                    branch["addr"], text, branch["side"], branch["pol"])))
        for action in actions:
            deciders = dict(sheet.deciding(action))
            mine = next((a for a in deciders if _hex(a) == branch["addr"]), None)
            if mine is None:
                # a call that runs on both sides is not wrong to cite under one of them, unless the sentence says
                # the side is the only one that runs it
                if not sheet.guarded(action) and not re.search(r"\b(only|alone|unless|skips?|solely|no such call|without)\b", sentence):
                    continue
                problems.append(("cite-branch", "the branch at %s does not decide whether %s runs" % (
                    branch["addr"], action)))
            elif deciders[mine] != branch["side"]:
                problems.append(("cite-branch", "%s runs on the %s side of the branch at %s, not the %s side" % (
                    action, deciders[mine], branch["addr"], branch["side"])))
    return problems


def _check_sentence(sentence, plain, cites, sheet, known):
    """Rules that read a whole sentence: conditions, unconditional wording, counts, order."""
    problems = []
    flat = [p for _s, _e, g in cites for p in g if p.get("addr") and not p.get("bad") and p["addr"] in known]
    call_parts = [p for p in flat if known[p["addr"]] == "call"]
    branch_parts = [p for p in flat if known[p["addr"]] == "branch"]
    hedged = bool(_HEDGE.search(plain))
    is_role = bool(_FROM_FACTS.match(sentence) or _FROM_NAME.match(sentence))
    # a call or store cited after "otherwise" that no branch skips cannot be on the other side of one
    for m in re.finditer(r"\b(?:otherwise|else)\b", plain):
        for start, end, group in cites:
            if start >= m.start():
                for p in group:
                    if p.get("addr") and p["addr"] in known and known[p["addr"]] in ("call", "store") \
                            and not p.get("side") and sheet.guarded(p["addr"]) is False:
                        problems.append(("cite-conditional", "the sentence puts %s on the 'otherwise' side of a branch, "
                                         "but it runs on every path" % p["addr"]))
    # "always calls f [call 1]": the word belongs to the citation after it in its clause, or else the one before it
    for m in _UNCOND.finditer(sentence):
        after = next(((s, e, g) for s, e, g in cites if s >= m.end()), None)
        if after and re.search(r"[;.]", sentence[m.end():after[0]]):
            after = None
        before = next(((s, e, g) for s, e, g in reversed(cites) if e <= m.start()), None)
        for _s, _e, group in [after or before] if (after or before) else []:
            for p in group:
                if p.get("addr") and known.get(p["addr"]) == "call" and not p.get("side") and sheet.guarded(p["addr"]):
                    problems.append(("cite-conditional", "the sentence says the call at %s is unconditional, but a "
                                     "branch can skip it" % p["addr"]))
    # a call behind one or two tests is the shape of a flag-gated call; one behind a ladder of tests is left to the
    # reviewer, since a sentence cannot cite them all
    if call_parts and not hedged and not branch_parts and not is_role:
        for p in call_parts:
            deciders = [a for a, _side in sheet.deciding(p["addr"])]
            if sheet.guarded(p["addr"]) and 0 < len(deciders) <= 2 and not _UNCOND.search(plain):
                problems.append(("condition-missing", "the call at %s runs only on one side of the branch at %s; cite "
                                 "the branch, for example [call N, @%s taken]" % (p["addr"], deciders[-1], deciders[-1])))
    if _CONDITION.search(plain) and cites and not hedged and not branch_parts and not _FROM_NAME.match(sentence):
        problems.append(("condition-uncited", "the sentence states a condition and cites no branch; add the branch "
                         "with its side, for example [@0xADDR taken]"))
    for m in _COUNT.finditer(plain):
        n = _WORD_NUMBER.get(m.group("n").lower()) or _int(m.group("n"))
        kind = (m.group("kind") or "").strip()
        total = sum(1 for c in sheet.calls.values()
                    if kind != "indirect" or not c.get("target")) if kind != "direct" else sum(
                        1 for c in sheet.calls.values() if c.get("target"))
        if m.group("approx"):
            problems.append(("cite-count", "%r is not a count the facts can confirm; give the exact number" % m.group(0).strip()))
        elif n != total:
            problems.append(("cite-count", "the sentence says %d%s calls, but the facts list %d" % (
                n, " " + kind if kind else "", total)))
    for (s1, e1, g1), (s2, e2, g2) in zip(cites, cites[1:]):
        a = next((p["addr"] for p in g1 if p.get("addr") and known.get(p["addr"]) == "call"), None)
        b = next((p["addr"] for p in g2 if p.get("addr") and known.get(p["addr"]) == "call"), None)
        if not a or not b or a == b:
            continue
        between = sentence[e1:s2]
        word = re.search(r"\b(then|before|after)\b", between)
        if not word or re.search(r"\b(when|if|unless|otherwise)\b", between):
            continue
        early, late = (b, a) if word.group(1) == "after" else (a, b)
        if sheet.reaches(early, late) is False and sheet.reaches(late, early):
            problems.append(("cite-order", "the sentence puts %s %s %s, but the facts reach %s first" % (
                _label(sheet, a), word.group(1), _label(sheet, b), _label(sheet, late))))
    return problems



# ---------------------------------------------------------------- the facts, numbered for a reader

def fact_index(sheet):
    """The citable facts of a routine, one per line in address order: calls with their number, branches with
    both conditions, returns, and the loads and stores. This is what a writer cites and a reviewer reads."""
    rows = []
    for number, site in enumerate(_call_sites(sheet), 1):
        c = sheet.calls[site]
        args = " ".join("%s=%s" % (sheet.reg_name(slot), value) for slot, value in sorted(c["args"].items()))
        rows.append((_int(site), "call %-3d @%s  %s%s%s  %s" % (
            number, site, "tail " if c.get("tail") else "", c["callee"] or "?",
            " [%s]" % c["target"] if c.get("target") else "", args)))
    for address, b in sheet.branches.items():
        rows.append((_int(address), "branch   @%s  %s -> %s  taken: %s | fall: %s" % (
            address, b["mn"], b["target"], b["taken"], b["fall"])))
    for address, value in sheet.returns.items():
        rows.append((_int(address), "return   @%s  %s = %s" % (address, sheet.retreg, value)))
    for a in sheet.accesses:
        rows.append((_int(a["address"]), "%-8s @%s  %s%s" % (
            a["kind"], a["address"], a["mn"], " +0x%x" % a["offset"] if a["offset"] is not None else "")))
    return [text for _addr, text in sorted(rows, key=lambda r: r[0])]
