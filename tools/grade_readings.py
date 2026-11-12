#!/usr/bin/env python3
"""Compare facts-only instruction readings with hostfacts output, or lint a routine-role document.

    grade_readings.py DOC --root ROOT [--count N | --routine NAME...]    grade instruction readings
    grade_readings.py DOC --check-doc [--inventory functions.tsv]         lint docs/routines/*.md
    grade_readings.py DOC --check-doc --check-facts [--root ROOT]         also test each entry's claims against its facts
    grade_readings.py DOC --check-doc --check-facts --strict-citations    require and test a citation for every claim
    grade_readings.py DOC --review-pack OUT [--root ROOT]                 entries beside their facts, for a reviewer
    grade_readings.py DOC --apply-verdicts VERDICTS.json                   rewrite entries from a review, add Reviewed lines

--check-doc reads DOC the way tools/inventory.py does and reports every routine entry that will not
reach located or understood, with the reason, plus every heading that looks like a routine header and
is not one. It exits 1 when it reports anything. It needs no root/. With the workspace's functions
table (default docs/inventory/functions.tsv when it exists) it also checks that the header's binary
and address are a row of the table and that a bare file name several builds share can say which build.
The canonical entry is in README-analysis.md, "Routine role entries".

--check-facts adds the mechanical fact check of fact_check.py: for each entry it renders the routine's
facts, pulls the checkable claims out of the prose (argument slots, branch direction, call order, loads
against stores, conditional wording, return values) and reports each one the facts contradict, with the
reason. It needs root/, reads the entry's size from the functions table when the header has none, and
skips entries it cannot render (non-MIPS images, binaries that are not in root/) with a count.

--strict-citations reads each entry as a cited entry instead (README-analysis.md, "Cited entries"): each
claim carries a [@0xADDR] or [call N] citation that is tested against the fact it names, a sentence that
states a fact and cites nothing is reported, and the entry must have a Role (from facts) or Role (from
name) sentence.

--review-pack OUT writes, for each entry, its text beside the facts rendered for its routine (calls
numbered as the citations count them) and the checker's findings: what a reviewer reads. --routine,
--unreviewed and --batch K/M choose the entries.

--apply-verdicts JSON reads a reviewer's verdicts, {entry key: {"verdict": "ok" | "fixed" | "reject",
"text": corrected role lines, "reviewer": optional name}}, and rewrites DOC: ok keeps the entry, fixed
replaces the lines under its header with text, and both add "Reviewed: DATE"; reject changes nothing. A key or
verdict that does not fit stops the run before anything is written. --review-pack, --apply-verdicts and
--check-facts take the entries the inventory reads: bullets, header-only bullets with indented paragraphs
after blank lines, and headings that give the binary and address with their paragraphs. An entry written
as a heading stays a heading: fixed text replaces its paragraphs and the Reviewed line follows as a
paragraph of its own.
"""
import argparse
import collections
import csv
import itertools
import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hostfacts  # noqa: E402
import render_reading  # noqa: E402


HEX = r"0x[0-9a-fA-F]+"
ARCH_LINE = re.compile(r"^\s*Architecture: ([\w-]+), load (" + HEX + r"), offset (" + HEX + r")(, elf)?\.\s*$", re.M)
HEADER = re.compile(r"^- `(?P<name>[^`]+)`(?: in `(?P<binary>[^`]+)` at (?P<address>" + HEX + r")| \(`(?P<legacy>[^`]+)`, (?P<legacy_address>" + HEX + r"), (?P<legacy_size>\d+) bytes\))")


def parse_entries(doc):
    """Read bullet entries and their sentences in the formats used by landed rounds."""
    with open(doc, encoding="utf-8") as source:
        return parse_lines(source.read().splitlines())


def _heading_site(line):
    """(binary, address) written in a routine reading's heading, or (None, None). The binary is the path or
    file name in it (a code span or a bare token) or the name before `:0xADDR`; the address is the first
    exact one."""
    import inventory as inv
    text = re.sub(r"^#+\s*", "", line.strip()).replace("`", " ")
    address = next((m.group(2) for m in inv.HEXLIT.finditer(text) if not m.group(1)), None)
    if address is None:
        return None, None
    colon = re.search(r"([A-Za-z_][\w.+-]*):0[xX][0-9a-fA-F]", text)
    if colon:
        return colon.group(1), "0x" + address
    for m in inv.PATHTOK.finditer(inv.HEXLIT.sub(" ", text)):
        token = m.group(0).strip(".,;:")
        if "/" in token or (inv.FILELIKE.fullmatch(token) and not token.rsplit(".", 1)[-1].isdigit()):
            return token, "0x" + address
    return None, None


def parse_lines(lines):
    """parse_entries over text already split into lines. The entries are the ones the inventory reads
    (inventory.md_entries): a bullet whose header is `name` in `binary` at 0xADDR, with its indented lines
    (and, for a header-only bullet, its indented paragraphs after blank lines), and a heading that gives the
    binary and address, with its paragraphs. Entries also carry `end` (the exclusive index of their last
    line), `shape` ('bullet', 'list' for a header-only bullet or 'head' for a heading), `install` (the
    binary path as written, member in parentheses included) and `grade` (the evidence grade line, if any)."""
    import inventory as inv
    groups, _entry_of, folded = inv.md_entries(lines)
    entries = []
    for index, group in enumerate(groups):
        start = group[0]
        shape = folded.get(index)
        if shape == "head":
            binary, address = _heading_site(lines[start])
            end = group[-1] + 1
            body = [lines[i] for i in group[1:]]
            name = inv.heading_subject(lines[start]) or inv.leading_unit(" ".join(line.strip() for line in body))
            if not (binary and address and name):
                continue
            header = None
        elif lines[start].startswith("- "):
            header = HEADER.match(lines[start])
            if not header:
                continue
            if shape == "list":
                end = group[-1] + 1
            else:
                end = start + 1
                while end < len(lines) and lines[end][:1].isspace():
                    end += 1
            name, binary, address = header.group("name"), header.group("binary") or header.group("legacy"), \
                header.group("address") or header.group("legacy_address")
            shape = shape or "bullet"
        else:
            continue
        block = lines[start:end]
        meta = "\n".join(block)
        exact = re.search(r"^\s*Exact binary: `([^`]+)`\s*$", meta, re.M)
        binary = exact.group(1) if exact else binary
        install = binary
        grade_line = re.search(r"^\s*Evidence grade: (\w+)\.", meta, re.M)
        span = re.search(r"^\s*Range: (" + HEX + r")-(" + HEX + r") \((\d+) bytes\)", meta, re.M)
        size_line = re.search(r"^\s*It occupies (\d+) bytes\.", meta, re.M)
        legacy_size = header.group("legacy_size") if header else None
        size = int(legacy_size or (span.group(3) if span else 0) or (size_line.group(1) if size_line else 0)) or None
        # Old entries put the binary and address in the title. Exact binary overrides it.
        if binary and "(" in binary and binary.endswith(")"):
            binary = re.sub(r"\(([^()]*)\)$", r":\1", binary)
        arch = ARCH_LINE.search(meta)
        firmware = ({"arch": arch.group(1), "load": int(arch.group(2), 16), "offset": int(arch.group(3), 16),
                     "elf": bool(arch.group(4))} if arch else None)
        sentences = [line.strip() for line in block[1:] if line.strip() and not re.match(
            r"(?:Evidence grade:|Exact binary:|Exact build:|Architecture:|Range:|Role:|Reviewed:)", line.strip())]
        entries.append({"name": name, "binary": binary, "address": address, "size": size,
                        "sentences": sentences, "line": start + 1, "end": end, "shape": shape,
                        "install": install, "grade": grade_line.group(1) if grade_line else None,
                        "firmware": firmware})
    return entries


def _value(value):
    value = re.sub(r"(?<![A-Za-z0-9_])\(unknown\)", "?", value)
    value = re.sub(r" \((?:arg[0-7] at entry|at entry|base unknown)\)", "", value)
    value = value.replace("unknown", "?")
    return re.sub(r"\s+", " ", value).strip()


def _value_variants(value):
    value = re.sub(r"(?<![A-Za-z0-9_])\(unknown\)", "?", value)
    value = re.sub(r" \((?:arg[0-7] at entry|at entry|base unknown)\)", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    unknowns = list(re.finditer(r"\bunknown\b", value))
    variants = set()
    for replacements in itertools.product(("?", "ret(?)"), repeat=len(unknowns)):
        parts = []
        start = 0
        for match, replacement in zip(unknowns, replacements):
            parts.extend((value[start:match.start()], replacement))
            start = match.end()
        parts.append(value[start:])
        variants.add(_value("".join(parts)))
    return variants


def _values_match(left, right):
    left = re.sub(r" \(c\.\w+ at " + HEX + r"\)", "", left)
    right = re.sub(r" \(c\.\w+ at " + HEX + r"\)", "", right)
    return bool(_value_variants(left) & _value_variants(right))


def _targets_match(left, right):
    left = _value(left)
    right = _value(right)
    return _values_match(left, right) or left == right + " +0x0"


def _access_target_matches(access, target):
    actual = _access_target(access)
    return _targets_match(actual, target)


def _callee_matches(callee, expected):
    if callee in expected:
        return True
    cited = set(re.findall(HEX, callee))
    resolved = set(re.findall(HEX, expected))
    return bool(cited & resolved) or (callee == "(unknown callee)" and "(unnamed)" in expected)


def _canonical_calls(value, calls):
    for call in calls.values():
        m = re.search(r"([^\s]+) \[(" + HEX + r")\]", call["callee"])
        if m:
            value = value.replace("ret(%s)" % m.group(1), "ret(%s)" % m.group(2))
        for alias in call.get("aliases", ()):
            value = value.replace("ret(%s)" % alias, "ret(%s)" % m.group(2))
    return value


def _access_target(a):
    if "absolute" in a:
        return "abs " + a["absolute"] + (" (%s)" % a["symbol"] if a.get("symbol") else "")
    if "reloc" in a:
        return "reloc " + a["reloc"]
    if "origin" in a:
        origin = a["origin"]
        if re.fullmatch(r"a[0-7]", origin):
            origin += " (arg%d at entry)" % int(origin[1])
        return "%s %s" % (origin, ("+" if a["origin_offset"] >= 0 else "-") + "0x%x" % abs(a["origin_offset"]))
    return "?"


def _return_choices(value):
    if value.startswith("one of "):
        choices = []
        for part in hostfacts.split_top_level(value[7:]):
            choices.extend(_return_choices(part))
        return choices
    return [part.strip() for part in re.split(r"\s+or\s+", value)]


def resolve_binary(root, entry):
    """Return (path, member) of the binary an entry cites."""
    binary_path, separator, member = entry["binary"].partition(":")
    binary = os.path.join(root, binary_path)
    if not os.path.isfile(binary):
        # Some older documents name paths relative to the checkout, rather than root/.
        checkout_candidate = os.path.join(os.path.dirname(os.path.abspath(root)), binary_path)
        if os.path.isfile(checkout_candidate):
            binary = checkout_candidate
        else:
            raise FileNotFoundError(binary)
    return binary, (member if separator else None)


def firmware_facts(root, entry):
    """(routine, facts) of an entry written for a non-MIPS image."""
    binary, _member = resolve_binary(root, entry)
    fw = entry["firmware"]
    # a segment of a firmware container is cut out by the workspace's layout, as the inventory did
    import firmware_layout
    config = firmware_layout.read_config(os.path.dirname(os.path.abspath(root)))
    routine = firmware_layout.segment_routine(config, root, entry["binary"], entry["address"], entry["size"])
    if routine:
        if (routine.arch, routine.img.load) != (fw["arch"], fw["load"]):
            raise ValueError("the header says %s at load 0x%x, the config's layout gives %s at 0x%x" % (
                fw["arch"], fw["load"], routine.arch, routine.img.load))
        return routine, routine.facts(False)
    routine = hostfacts.routine_for(binary, entry["address"], size=entry["size"], arch=fw["arch"],
                                    load=fw["load"], offset=fw["offset"], elf=fw["elf"])
    return routine, routine.facts(False)


def facts_for(root, entry):
    binary, member = resolve_binary(root, entry)
    routine = hostfacts.routine_for(binary, entry["address"], member=member, size=entry["size"])
    facts = routine.facts(False)
    facts["instructions"] = {"0x%x" % insn["addr"]: insn["mn"] for insn in routine.insns}
    rendered = hostfacts.render(routine, facts).splitlines()
    return facts, rendered


def _render_maps(facts, rendered):
    accesses = collections.defaultdict(list)
    for a in facts["accesses"]:
        accesses[a["address"]].append({"mn": a["mnemonic"], "kind": a["kind"], "width": a["width"],
                                        "register": a["text"].split(" ", 1)[1].split(",")[0],
                                        "base": a["base"], "target": _access_target(a), "value": a.get("value")})
    calls, branches, returns = {}, {}, {}
    last_call = None
    branch_at = None
    return_at = None
    for line in rendered:
        m = re.match(r"\s+(0x[0-9a-f]+) (tail )?(\w+) (.*?) via (\S+)$", line)
        if m and "args:" not in line:
            calls[m.group(1)] = {"tail": bool(m.group(2)), "mn": m.group(3), "callee": m.group(4),
                                 "via": m.group(5), "args": ""}
            last_call = m.group(1)
            continue
        m = re.match(r"\s+args: (.*)$", line)
        if m and last_call:
            calls[last_call]["args"] = m.group(1)
            continue
        m = re.match(r"\s+(0x[0-9a-f]+) `(\w+) .*?,([0-9a-f]+)` never taken \(its condition can never hold for these operands\); falls through", line)
        if m:
            branches[m.group(1)] = {"mn": m.group(2), "target": "0x" + m.group(3), "taken": None,
                                   "fall": None, "always": False, "never": True,
                                   "likely": False, "delay": None}
            branch_at = m.group(1)
            continue
        m = re.match(r"\s+(0x[0-9a-f]+) `(\w+) (.*?)` always taken ->", line)
        if m:
            target = m.group(3).rsplit(",", 1)[-1]
            if re.fullmatch(r"[0-9a-f]+", target):
                branches[m.group(1)] = {"mn": m.group(2), "target": "0x" + target, "taken": None,
                                       "fall": None, "always": True, "never": False,
                                       "likely": False, "delay": None}
                branch_at = m.group(1)
                continue
        m = re.match(r"\s+(0x[0-9a-f]+) `(\w+) (.*?)` -> (0x[0-9a-f]+)", line)
        if m:
            branch_at = m.group(1)
            branches[branch_at] = {"mn": m.group(2), "target": m.group(4), "taken": None, "fall": None,
                                   "always": "always taken" in line, "never": "never taken" in line,
                                   "likely": False, "delay": None}
            continue
        m = re.match(r"\s+(0x[0-9a-f]+) `.*?` returns; delay slot (0x[0-9a-f]+) `(.*?)` runs", line)
        if m:
            returns[m.group(1)] = {"value": None, "paths": {}, "delay": (m.group(2), m.group(3))}
            return_at = m.group(1)
            continue
        m = re.match(r"\s+taken when (.*?) ->", line)
        if m and branch_at:
            branches[branch_at]["taken"] = m.group(1)
            continue
        m = re.match(r"\s+falls through when (.*?) ->", line)
        if m and branch_at:
            branches[branch_at]["fall"] = m.group(1)
            continue
        m = re.match(r"\s+delay slot (0x[0-9a-f]+) `(.*?)`", line)
        if m and branch_at:
            branches[branch_at]["delay"] = (m.group(1), m.group(2))
            branches[branch_at]["likely"] = "branch-likely" in line
            continue
        m = re.match(r"\s+(0x[0-9a-f]+) in \S+: v0 = (.*?)(?:; reached.*)?$", line)
        if m:
            returns.setdefault(m.group(1), {"paths": {}})["value"] = m.group(2)
            return_at = m.group(1)
            continue
        m = re.match(r"\s+from (0x[0-9a-f]+): v0 = (.*)$", line)
        if m and return_at in returns:
            returns[return_at]["paths"][m.group(1)] = m.group(2)
    return accesses, calls, branches, returns


def check_sentence(sentence, facts, rendered, maps):
    accesses, calls, branches, returns = maps
    group_accesses = [a for a in facts["accesses"]
                      if not hostfacts.is_stack_or_global_access(a)]
    text = sentence.rstrip(".")
    text = re.sub(r" \(value (.*?)\)$", r" with value \1", text)
    m = re.match(r"It occupies (\d+) bytes", text)
    if m:
        return ("OK", None) if int(m.group(1)) == facts["routine"]["size"] else ("MISMATCH", "size %d bytes" % facts["routine"]["size"])
    routine_size = re.match(r"The routine occupies (\d+) bytes at address (" + HEX + r")", text)
    if routine_size:
        size, address = routine_size.groups()
        if int(size) != facts["routine"]["size"] or address != facts["routine"]["address"]:
            return "MISMATCH", "routine size/address"
        return "OK", None
    instruction = re.match(r"The instruction at (" + HEX + r") is `(\w+(?:\.\w+)?)`, a (.+)$", text)
    if instruction:
        address, mnemonic, _description = instruction.groups()
        return ("OK", None) if facts.get("instructions", {}).get(address) == mnemonic else ("MISMATCH", "instruction at %s" % address)
    nonbranch_instructions = re.match(r"The `(\w+(?:\.\w+)?)` at (.+) is not a branch", text)
    if nonbranch_instructions:
        mnemonic, listed = nonbranch_instructions.groups()
        addresses = re.findall(HEX, listed)
        branches = {branch["address"] for branch in facts.get("branches", []) + facts.get("branch_likely", [])}
        if not addresses or any(facts.get("instructions", {}).get(address) != mnemonic or address in branches
                                for address in addresses):
            return "MISMATCH", "non-branch instruction"
        return "OK", None
    # Accesses, including old forms with several cited instruction addresses.
    acc = re.match(r"The `(\w+)` at (" + HEX + r") (loads|stores) (\d+) bytes? (?:from|to) (.*?)(?: via base (\w+) \((.*?)\))?(?: with value (.*))?$", text)
    old_acc = re.match(r"(Loads|Stores) (\d+) bytes? (?:into `?(\$?\w+)`? from|from `?(\$?\w+)`? (?:to|at)) (.*) \(`(\w+)` at (.*?)\)(?: with value (.*))?$", text)
    loc_acc = re.match(r"(Loads|Stores) (\d+) bytes? at (.*?) \(`(\w+)` at (" + HEX + r")\)(?: with value (.*))?$", text)
    if acc:
        mn, address, direction, width, target, base, _base_note, value = acc.groups()
        addrs = [address]
        reg = None
    elif loc_acc:
        direction, width, target, mn, address, value = loc_acc.groups()
        addrs = [address]
        reg = None
    elif old_acc:
        direction, width, dest, src, target, mn, addr_list, value = old_acc.groups()
        addrs = re.findall(HEX, addr_list)
        reg = src or dest
    else:
        acc_group_simple_value = re.match(r"(\d+) such `(\w+)` accesses (load|store) (\d+) bytes? (?:from|to) (.*?) with value (.*?), including (.*)$", text)
        acc_group_simple_parenthesized_value = re.match(r"(\d+) such `(\w+)` accesses (load|store) (\d+) bytes? (?:from|to) (.*?) \(value (.*?)\), including (.*)$", text)
        acc_group_simple = re.match(r"(\d+) such `(\w+)` accesses (load|store) (\d+) bytes? (?:from|to) (.*?), including (.*)$", text)
        acc_group_legacy = re.match(r"(\d+) such accesses, including (.*), (loads|stores) (\d+) bytes? (?:from|to) (.*)$", text)
        acc_group = re.match(r"(\d+) such accesses (load|store) (\d+) bytes? (?:from|to) (.*?) via base (\w+) \((.*?)\)(?: with value (.*?))?, including (.*)$", text)
        acc_group_mn = re.match(r"(\d+) such `(\w+)` accesses (load|store) (\d+) bytes? (?:from|to) (.*?) via base (\w+) \((.*?)\)(?: with value (.*?))?, including (.*)$", text)
        acc_group2 = re.match(r"Performs (\d+) (\d+)-byte (loads|stores) (?:from|to) (.*), including (.*)$", text)
        acc_group4 = re.match(r"(\d+) (\d+)-byte `?(\w+)`? (loads|stores) at (.*?), including (.*)$", text)
        acc_group5 = re.match(r"(\d+) such accesses: Stores (\d+) bytes? from (\w+) to (.*?) \(base unknown\) \(including (.*)\)$", text)
        acc_group3 = re.match(r"(Loads|Stores) (\d+) bytes? (.*?) into `?(\w+)`?: (\d+) such accesses, including (.*)$", text)
        if not acc_group3:
            acc_group3 = re.match(r"(Loads|Stores) (\d+) bytes? from `?(\w+)`? to (.*?): (\d+) such accesses, including (.*)$", text)
        if acc_group5:
            count, width, register, target, items = acc_group5.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            mn = refs[0][0] if refs else ""
            addrs = [address for _op, address in refs]
            reg = register
            value = None
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == "store"
                       and a["width"] == int(width)
                       and a["text"].split(" ", 1)[1].split(",")[0].lstrip("$") == register
                       and _targets_match(_access_target(a), target)]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group4:
            count, width, mn, direction, target, items = acc_group4.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [address for _op, address in refs]
            reg = None
            value = None
            kind = "load" if direction == "loads" else "store"
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == kind
                       and a["width"] == int(width) and _access_target_matches(a, target)]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group_legacy:
            count, items, direction, width, target = acc_group_legacy.groups()
            first_ref = re.search(r"`(\w+)` at (" + HEX + r")", items)
            mn = first_ref.group(1) if first_ref else ""
            addrs = re.findall(HEX, items)
            reg = None
            value = None
            kind = "load" if direction == "loads" else "store"
            ref_bases = {a["base"] for a in group_accesses if a["address"] in addrs}
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == kind
                       and a["width"] == int(width) and _values_match(_access_target(a), target)
                       and (not ref_bases or a["base"] in ref_bases)]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group_simple_value:
            count, mn, direction, width, target, group_value, items = acc_group_simple_value.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [address for _op, address in refs]
            reg = None
            value = None
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == direction
                       and a["width"] == int(width) and _values_match(_access_target(a), target)
                       and _values_match(a.get("value") or "", group_value)]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group_simple_parenthesized_value:
            count, mn, direction, width, target, group_value, items = acc_group_simple_parenthesized_value.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [address for _op, address in refs]
            reg = None
            value = None
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == direction
                       and a["width"] == int(width) and _values_match(_access_target(a), target)
                       and _values_match(a.get("value") or "", group_value)]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group_simple:
            count, mn, direction, width, target, items = acc_group_simple.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [address for _op, address in refs]
            reg = None
            value = None
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == direction
                       and a["width"] == int(width) and _values_match(_access_target(a), target)]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group_mn:
            count, mn, direction, width, target, base, _note, group_value, items = acc_group_mn.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [address for _op, address in refs]
            reg = None
            value = None
            matches = [a for a in group_accesses if a["mnemonic"] == mn and a["kind"] == direction
                       and a["width"] == int(width) and a["base"] == base
                       and _values_match(_access_target(a), target)
                       and (not group_value or _values_match(a.get("value") or "", group_value))]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group:
            count, direction, width, target, base, _note, group_value, items = acc_group.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [a for _op, a in refs]
            mn = refs[0][0] if refs else ""
            reg = None
            value = None
            matches = [a for a in group_accesses if a["kind"] == direction and a["width"] == int(width)
                       and a["base"] == base and _values_match(_access_target(a), target)
                       and (not group_value or _values_match(a.get("value") or "", group_value))]
            if len(matches) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matches))
        elif acc_group2:
            count, width, direction, target, items = acc_group2.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [a for _op, a in refs]
            mn = refs[0][0] if refs else ""
            reg = None
            value = None
            matching = [a for a in group_accesses if a["kind"] == direction[:-1] and a["width"] == int(width)
                        and _values_match(_access_target(a), target)]
            if len(matching) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matching))
        elif acc_group3:
            direction, width, target, register, count, items = acc_group3.groups()
            refs = re.findall(r"`(\w+)` at (" + HEX + r")", items)
            addrs = [a for _op, a in refs]
            mn = refs[0][0] if refs else ""
            reg = None
            value = None
            kind = "load" if direction == "Loads" else "store"
            if direction == "Loads":
                target = re.sub(r"^from ", "", target)
            matching = [a for a in group_accesses if a["kind"] == kind and a["width"] == int(width)
                        and _values_match(_access_target(a), target)]
            if len(matching) != int(count):
                return "MISMATCH", "group count %s (hostfacts: %d)" % (count, len(matching))
        else:
            # Fall through to other sentence classes.
            addrs = None
    if addrs is not None:
        for address in addrs:
            candidates = accesses.get(address, [])
            if not any(a["mn"] == mn and (reg is None or a["register"].lstrip("$") == reg.lstrip("$")) for a in candidates):
                return "MISMATCH", "access at %s" % address
            fact = next(a for a in candidates if a["mn"] == mn and (reg is None or a["register"].lstrip("$") == reg.lstrip("$")))
            if acc and (fact["kind"] != ("load" if direction == "loads" else "store") or fact["width"] != int(width) or not _values_match(fact["target"], target) or (value is not None and not _values_match(fact.get("value") or "", value))):
                return "MISMATCH", "%s %d-byte %s from %s" % (fact["kind"], fact["width"], mn, fact["target"])
            if loc_acc and (fact["kind"] != ("load" if direction == "Loads" else "store") or fact["width"] != int(width) or not _targets_match(fact["target"], target) or (value is not None and not _values_match(fact.get("value") or "", value))):
                return "MISMATCH", "%s %d-byte %s from %s" % (fact["kind"], fact["width"], mn, fact["target"])
            if old_acc and (not _targets_match(fact["target"], target) or fact["width"] != int(width) or fact["kind"] != ("load" if direction == "Loads" else "store") or (value is not None and not _values_match(fact.get("value") or "", value))):
                return "MISMATCH", "%s %d-byte %s from %s" % (fact["kind"], fact["width"], mn, fact["target"])
        return "OK", None

    # Calls with all argument slots; captures are greedy so nested [] and () stay intact.
    m = re.match(r"The `(\w+)` at (" + HEX + r") calls (.*?) with (.*)$", text)
    old_call = re.match(r"Calls `(.*?)` via (\S+) with (.*) \(`(\w+)` at (" + HEX + r")\)$", text)
    tail_call = re.match(r"Calls (.*?) via (\S+) with (.*) \(`(\w+)` at (" + HEX + r")\)$", text)
    if m or old_call or tail_call:
        if m:
            op, address, callee, args = m.groups()
            callee = callee.strip("`")
            expected = calls.get(address)
            is_tail = op == "tail"
            callee_matches = _callee_matches(callee, expected["callee"]) if expected else False
            if not expected or (is_tail and not expected["tail"]) or (not is_tail and expected["mn"] != op) or not callee_matches:
                return "MISMATCH", "call at %s" % address
        elif old_call:
            callee, via, args, op, address = old_call.groups()
            expected = calls.get(address)
            if not expected or expected["mn"] != op or expected["via"] != via or not _callee_matches(callee, expected["callee"]):
                return "MISMATCH", "call at %s" % address
        else:
            callee, via, args, op, address = tail_call.groups()
            expected = calls.get(address)
            callee_matches = _callee_matches(callee.strip("`"), expected["callee"]) if expected else False
            if not expected or not expected["tail"] or expected["mn"] != op or expected["via"] != via or not callee_matches:
                return "MISMATCH", "call at %s" % address
        if not _values_match(_canonical_calls(args, calls), _canonical_calls(expected["args"], calls)):
            return "MISMATCH", expected["args"]
        return "OK", None

    # Branch sentences in current and previous round layouts.
    always_branch = re.match(r"The `(\w+)` branch at (" + HEX + r") targets (" + HEX + r") and is always taken", text)
    always_branch2 = re.match(r"At `(\w+)` at (" + HEX + r") \(target (" + HEX + r")\), the branch is always taken", text)
    if always_branch or always_branch2:
        op, address, target = always_branch.groups() if always_branch else always_branch2.groups()
        expected = branches.get(address)
        if not expected or expected["mn"] != op or expected["target"] != target or not expected["always"]:
            return "MISMATCH", "branch at %s" % address
        return "OK", None

    never_branch = re.match(r"The `(\w+)` branch at (" + HEX + r") targets (" + HEX + r") and is never taken: its condition can never hold for these operands, so execution always falls through", text)
    if never_branch:
        op, address, target = never_branch.groups()
        expected = branches.get(address)
        if not expected or expected["mn"] != op or expected["target"] != target or not expected["never"]:
            return "MISMATCH", "branch at %s" % address
        return "OK", None

    unanalyzed_branch = re.match(r"The `(\w+)` branch at (" + HEX + r") targets (" + HEX + r"); its condition is not analyzed(?:; its branch-likely delay slot `(.*?)` at (" + HEX + r") runs only when taken and is annulled on fall-through)?", text)
    if unanalyzed_branch:
        op, address, target, delay_op, delay_address = unanalyzed_branch.groups()
        expected = branches.get(address)
        if not expected or expected["mn"] != op or expected["target"] != target:
            return "MISMATCH", "branch at %s" % address
        if expected["taken"] != "condition not analyzed" or expected["fall"] != "condition not analyzed":
            return "MISMATCH", "branch condition"
        if delay_op and (not expected["likely"] or expected["delay"] != (delay_address, delay_op)):
            return "MISMATCH", "branch-likely delay slot"
        return "OK", None

    branch = re.match(r"The `(\w+)` branch at (" + HEX + r") goes to (" + HEX + r") when (.*) and falls through when (.*)$", text)
    branch4 = re.match(r"The `(\w+)` branch at (" + HEX + r") targets (" + HEX + r"), is taken when (.*), and falls through when (.*)$", text)
    branch2 = re.match(r"At `(\w+)` at (" + HEX + r") \(target (" + HEX + r")\), taken when (.*?)(?:;| and) falls through when (.*)$", text)
    branch3 = re.match(r"The `(\w+)`(?: branch)? at (" + HEX + r") is taken when (.*) and falls through when (.*)$", text)
    if branch or branch2 or branch3 or branch4:
        if branch:
            op, address, target, taken, fall = branch.groups()
        elif branch4:
            op, address, target, taken, fall = branch4.groups()
        elif branch2:
            op, address, target, taken, fall = branch2.groups()
        else:
            op, address, taken, fall = branch3.groups()
            target = None
        expected = branches.get(address)
        if not expected or expected["mn"] != op or (target and expected["target"] != target):
            return "MISMATCH", "branch at %s" % address
        delay_claim = re.search(r"; its `(\w+)` delay slot at (" + HEX + r") runs only when taken and is annulled on fall-through$", fall)
        if not delay_claim:
            delay_claim = re.search(r"; its branch-likely delay slot `(.*?)` at (" + HEX + r") runs only when taken and is annulled on fall-through$", fall)
        if delay_claim:
            fall = fall[:delay_claim.start()]
            delay_op, delay_address = delay_claim.groups()
            if not expected["likely"] or expected["delay"] != (delay_address, delay_op):
                return "MISMATCH", "branch-likely delay slot"
        taken = re.sub(r" -> (?:B\d+|outside|end of routine)$", "", taken)
        fall = re.sub(r" -> (?:B\d+|outside|end of routine)$", "", fall)
        if taken != "condition not analyzed" and (
                not _values_match(_canonical_calls(taken, calls), _canonical_calls(expected["taken"], calls)) or
                not _values_match(_canonical_calls(fall, calls), _canonical_calls(expected["fall"], calls))):
            return "MISMATCH", "taken when %s; falls through when %s" % (expected["taken"], expected["fall"])
        # A branch-likely sentence may explicitly describe annulment/delay behavior.
        if "branch-likely" in text and not expected["likely"]:
            return "MISMATCH", "branch is not branch-likely"
        return "OK", None

    # Returns may describe the merged value, one of several values, or each path.
    ret = re.match(r"The return at (" + HEX + r") has v0 = (.*)$", text)
    old_ret = re.match(r"Returns v0 = (.*) \(`jr` at (" + HEX + r")\)$", text)
    ret3 = re.match(r"The `jr` at (" + HEX + r") returns with v0 = (.*?)(?:; its delay slot executes `(\w+)` at (" + HEX + r"))?$", text)
    path_ret = re.match(r"The return at (" + HEX + r") has v0 = (.*?) on the path from (" + HEX + r")$", text)
    if ret or old_ret or ret3 or path_ret:
        delay_claim = None
        if path_ret:
            address, value, source = path_ret.groups()
            expected = returns.get(address, {}).get("paths", {}).get(source)
            if expected:
                expected = expected.split("; f0 =", 1)[0].split(", f0 =", 1)[0]
        else:
            address, value = ret.groups() if ret else (old_ret.group(2), old_ret.group(1)) if old_ret else ret3.group(1, 2)
            value = value.split("; f0 =", 1)[0].split(", f0 =", 1)[0]
            if ret3 and ret3.group(3):
                delay_claim = (ret3.group(4), ret3.group(3))
            expected = returns.get(address, {}).get("value")
            if expected:
                expected = expected.split("; f0 =", 1)[0].split(", f0 =", 1)[0]
        if expected is None:
            return "MISMATCH", "return at %s" % address
        if value.startswith("one of "):
            choices = set(_return_choices(value))
            if expected == "?" and address in returns:
                actual = set(choice for path_value in returns[address]["paths"].values()
                             for choice in _return_choices(path_value))
            else:
                actual = set(_return_choices(expected))
            if not actual or len(choices) != len(actual) or any(
                    not any(_values_match(_canonical_calls(choice, calls), _canonical_calls(fact, calls))
                            for fact in actual) for choice in choices):
                return "MISMATCH", "one of %s" % ", ".join(sorted(actual or {expected}))
        elif not _values_match(_canonical_calls(expected, calls), _canonical_calls(value, calls)):
            # The merged v0 can be "?" while every path agrees on one value (a call's result,
            # ret(?)); the renderer reports that value, which is true of the return.
            path_values = set(choice for path_value in returns.get(address, {}).get("paths", {}).values()
                              for choice in _return_choices(path_value)) if expected == "?" else set()
            if len(path_values) != 1 or not _values_match(_canonical_calls(next(iter(path_values)), calls),
                                                          _canonical_calls(value, calls)):
                return "MISMATCH", "v0 = %s" % expected
        if delay_claim and returns.get(address, {}).get("delay") != delay_claim:
            return "MISMATCH", "delay slot %s at %s" % (returns.get(address, {}).get("delay"), address)
        return "OK", None

    # Unreached ranges: only assert an empty reachable-fact set when the sentence says so.
    unreached = re.search(r"instructions from (" + HEX + r") to (" + HEX + r") are not reached by any path", text)
    if unreached:
        start, end = (int(v, 16) for v in unreached.groups())
        missing = ["0x%x" % address for address in range(start, end + 1, 4)
                   if "0x%x" % address not in facts["unreached"]]
        if missing:
            return "MISMATCH", "reachable address in claimed range: %s" % missing[0]
        return "OK", None
    jump_table = re.match(r"The indirect jump at (" + HEX + r") uses the jump table at (" + HEX + r") with targets (.*)$", text)
    if jump_table:
        jump, table, targets = jump_table.groups()
        expected = next((item for item in facts.get("jump_tables", []) if item["jump"] == jump), None)
        actual_targets = [target.strip() for target in targets.split(",")]
        if not expected or expected.get("table") != table or expected.get("targets", []) != actual_targets:
            return "MISMATCH", "jump table at %s" % jump
        return "OK", None
    unresolved_table = re.match(r"The indirect jump at (" + HEX + r") uses a jump table whose successors are unresolved", text)
    if unresolved_table:
        address = unresolved_table.group(1)
        if not any(re.match(r"\s+%s `.*?` \(jump table; successors unresolved\)" % re.escape(address), line)
                   for line in rendered):
            return "MISMATCH", "unresolved jump table at %s" % address
        return "OK", None
    return "UNPARSED", sentence


def grade_entry(root, entry):
    if entry.get("firmware"):
        # Non-MIPS sentences are plain renderings of the fact sheet: each must be one the
        # renderer produces now from the same image bytes.
        routine, facts = firmware_facts(root, entry)
        expected = set(render_reading.firmware_sentences(routine, facts))
        expected.add("It occupies %d bytes." % routine.size)
        return [("OK", "") if sentence in expected else ("MISMATCH", "not in the facts: " + sentence[:100])
                for sentence in entry["sentences"]]
    facts, rendered = facts_for(root, entry)
    maps = _render_maps(facts, rendered)
    calls = maps[1]
    for sentence in entry["sentences"]:
        call = re.match(r"The `\w+` at (" + HEX + r") calls (.*?) with ", sentence.rstrip("."))
        old_call = re.match(r"Calls `(.*?)` via \S+ with .*? \(`\w+` at (" + HEX + r")\)", sentence.rstrip("."))
        tail_call = re.match(r"Calls (.*?) via \S+ with .*? \(`\w+` at (" + HEX + r")\)", sentence.rstrip("."))
        if call:
            address, callee = call.groups()
        elif old_call:
            callee, address = old_call.groups()
        elif tail_call:
            callee, address = tail_call.groups()
        else:
            continue
        expected = calls.get(address)
        target = re.search(r"([^\s]+) \[" + HEX + r"\]", callee)
        if expected and target and _callee_matches(callee, expected["callee"]):
            expected.setdefault("aliases", set()).add(target.group(1))
    results = [check_sentence(sentence, facts, rendered, maps) for sentence in entry["sentences"]]
    return results


def _function_rows(path):
    """{name: [(binary, address, code_sha)]} of a functions table, and the builds it lists."""
    rows, builds = collections.defaultdict(list), set()
    with open(path, encoding="utf-8", newline="") as table:
        for row in csv.DictReader(table, delimiter="\t"):
            builds.add(row["binary"])
            try:
                address = int(row["address"], 16)
            except ValueError:
                continue
            rows[row["name"]].append((row["binary"], address, row.get("code_sha", "")))
    return rows, builds


def needs_review(doc, workspace):
    """Whether the workspace's inventory config lists DOC in review_required."""
    import inventory as inv
    path = os.path.join(workspace, "scripts", "inventory-config.json")
    if not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8") as config:
        cfg = json.load(config)
    return inv.review_required(cfg, os.path.relpath(os.path.abspath(doc), workspace))


def is_routines_file(doc, workspace):
    """Whether DOC is a routines file of the workspace: one the inventory config lists in review_required,
    or one under docs/routines/."""
    rel = os.path.relpath(os.path.abspath(doc), workspace)
    return needs_review(doc, workspace) or rel.startswith("docs" + os.sep + "routines" + os.sep)


ENTRY_LIKE = re.compile(r"(?:[-*+]|\d+\.|#{1,6})\s")


def entry_like_lines(lines):
    """[(line number, text)] of the lines outside code fences that look like an entry header: a bullet or
    heading at the left margin that gives a code address 0x... and says "in" or "at". Indented lines are
    the text of an entry and are not counted."""
    found, fence = [], False
    for i, text in enumerate(lines):
        if text.strip().startswith("```"):
            fence = not fence
        elif (not fence and ENTRY_LIKE.match(text) and re.search(HEX, text)
              and re.search(r"\b(?:in|at)\b", text)):
            found.append((i + 1, text.strip()))
    return found


def unread_entries(lines):
    """[(line number, reason)] for a routines file: each entry-like line the parser did not take as an entry
    header, or line 1 when the file is empty or yields no entry at all. Without this a file whose headers are
    all in a shape the parser does not read passes every other check on an empty set."""
    if not "".join(lines).strip():
        return [(1, "the file is empty")]
    taken = {e["line"] for e in parse_lines(lines)}
    found = [(n, "%r gives an address but is not an entry the parser reads; write `routine` in "
                 "`path/of/binary` at 0xADDR with the role lines under it" % text[:70])
             for n, text in entry_like_lines(lines) if n not in taken]
    return found or ([] if taken else [(1, "the file has no entry the parser reads")])


def check_doc(doc, inventory=None, out=None, review=False, routines=False):
    """Lint a routine-role document. Prints each problem as DOC:LINE: subject, then the reason, and
    returns how many entries were reported. review says the workspace requires a Reviewed line in
    each entry of DOC. routines says DOC is a routines file, so an empty file or an entry-like line the
    parser did not take as an entry is a problem. See the module docstring."""
    import inventory as inv
    out = out or sys.stdout
    saved = inv.REPO
    inv.REPO = os.path.dirname(os.path.abspath(doc))
    try:
        index = inv.DocIndex({"docs": {}, "review_required": ["*"] if review else []})
        index.read_md(os.path.abspath(doc), False)
    finally:
        inv.REPO = saved
    index.cap_entries()
    rows, owners = {}, None
    if inventory and os.path.isfile(inventory):
        rows, builds = _function_rows(inventory)
        owners = inv.path_owners([{"label": b, "copies": []} for b in sorted(builds)])
    with open(doc, encoding="utf-8", errors="replace") as source:
        lines = source.read().split("\n")
    logged = {line: (kind, unit, ent) for _file, line, kind, unit, ent in index.entry_log}
    problems, counts = [], collections.Counter()

    def report(line, subject, reason, problem=True):
        problems.append((line, subject, reason, problem))

    fence = False
    for i, text in enumerate(lines):
        n = i + 1
        stripped = text.strip()
        if stripped.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        heading = re.match(r"#{2,6}\s+(.*)", stripped)
        candidate = heading or re.match(r"[-*+]\s+`", stripped)
        if not candidate and re.match(r"[-*+]\s+[\w.+@$/-]+\s+at\s+0x[0-9a-fA-F]+\s*:\s*\S", stripped):
            # `- libGLcore.so at 0x1234: routine` is not a header the inventory reads
            report(n, stripped[:70], "a list item that gives `file at 0xADDR: routine` is not an entry the inventory "
                   "reads; write `routine` in `path/of/binary` at 0xADDR with the role lines under it")
            continue
        if not candidate:
            continue
        if heading and not inv.reading_head(stripped):
            title = heading.group(1)
            if not (re.search(HEX, title) or "`" in title):
                continue                     # a section title, not a header
            if not re.search(HEX, title):
                reason = "the heading gives no exact address (0xADDR)"
            else:
                reason = ("the heading gives an address but no binary; write `routine` in `path/of/binary` "
                          "at 0xADDR")
            report(n, "heading %r" % title, reason + ", so the paragraphs under it are not one entry")
            continue
        kind, unit, ent = logged.get(n, (None, None, None))
        if ent is None:
            continue                         # a list item inside another entry
        subject = unit or "(no routine named)"
        if kind == "head" and not unit:
            report(n, subject, "the heading names no routine and the paragraph does not start with one in "
                   "backticks")
            continue
        body = ent.text
        status = ent.level
        why = ""
        if status != "understood":
            if inv.UNVERIFIED.search(inv.bare_text(body)):
                why = "it closes with Unverified (at most located)"
            else:
                why = inv.read_why(body, ent.subj)[2]
            if (not why and review and not inv.REVIEWED.search(body)
                    and inv.classify(body, ent.subj)[0] == "understood"):
                why = ("it has no Reviewed line (Reviewed: YYYY-MM-DD) and the workspace requires one in this "
                       "file, so it is held at located")
        elif ent.capped:
            status, why = "located", ("it shares sentences with more than %d other entries, so the "
                                      "template cap holds it at located" % inv.TEMPLATE_CAP)
        counts[status] += 1
        if status == "named-only":
            report(n, subject, "named-only: %s" % (why or "no role the classifier can read is stated"))
        elif why:
            report(n, subject, "%s, not understood: %s" % (status, why), problem=False)
        if owners is not None and unit:
            site = inv.header_site(ent, unit, owners)
            if site is None:
                report(n, subject, "the header gives no binary the functions table lists, or no exact address; "
                       "write `routine` in `path/of/binary` at 0xADDR")
                continue
            addresses, named, shared = site
            where = [(b, a, c) for (b, a, c) in rows.get(unit, ()) if a in addresses and b in (named or shared)]
            if not where:
                report(n, subject, "no row of the functions table has %s at %s in the binary the header names"
                       % (unit, ", ".join("0x%x" % a for a in sorted(addresses))))
            elif not named and len({c for _b, _a, c in where}) > 1:
                report(n, subject, "the header writes only a file name that %d builds share and their code "
                       "differs there, so no build is credited; write the build's full path" % len(where))
            elif not named and status == "understood" and len({c for _b, _a, c in rows[unit]}) > 1:
                report(n, subject, "the header writes only a file name that %d builds share, and %s has different "
                       "code in some of them, so the entry is held at located; write the build's full path"
                       % (len({b for b, _a, _c in rows[unit]}), unit))
                counts["understood"] -= 1
                counts["located"] += 1
    for line, subject, reason, problem in problems:
        print("%s:%d: %s%s\n  %s" % (doc, line, subject, "" if problem else " (note)", reason), file=out)
    count = sum(1 for p in problems if p[3])
    if routines:
        reported = {p[0] for p in problems}      # a line the checks above reported is not reported twice
        for line, reason in unread_entries(lines):
            if line not in reported:
                count += 1
                print("%s:%d: %s" % (doc, line, reason), file=out)
    print("entries=%d understood=%d located=%d named-only=%d problems=%d" % (
        sum(counts.values()), counts["understood"], counts["located"], counts["named-only"], count), file=out)
    return count


def _function_sites(path):
    """{(binary, address): (abi, size)} of a functions table."""
    sites = {}
    with open(path, encoding="utf-8", newline="") as table:
        for row in csv.DictReader(table, delimiter="\t"):
            try:
                sites[(row["binary"], int(row["address"], 16))] = (row.get("abi", ""), int(row.get("size") or 0) or None)
            except ValueError:
                continue
    return sites


def check_facts(doc, root, inventory=None, out=None, strict=False):
    """Test the claims of each entry of a routine-role document against the facts of its routine.
    Prints each contradiction as DOC:LINE: routine [rule], then the reason, and returns the count of
    entries reported. Entries the fact sheet cannot be built for are counted and skipped. With strict,
    each entry is read as a cited entry (fact_check.check_cited): every citation is tested, a sentence that
    states a fact and cites none is reported, and so is an entry with no marked Role sentence. A finding
    that only labels the entry (Role (from name)) is printed as a note and does not count."""
    import fact_check
    out = out or sys.stdout
    sites = _function_sites(inventory) if inventory and os.path.isfile(inventory) else {}
    skipped, checked, reported = collections.Counter(), 0, 0
    for entry in parse_entries(doc):
        abi, size = sites.get((entry["install"], int(entry["address"], 16)), ("", None))
        if entry["firmware"] or abi not in ("", "o32", "n32", "n64"):
            skipped["not MIPS"] += 1
            continue
        try:
            binary, member = resolve_binary(root, entry)
            sheet = fact_check.sheet_for(binary, member, entry["address"], entry["size"] or size)
        except (Exception, SystemExit):
            # facts refuses an address it cannot place with SystemExit; the rest of the document is still checked
            skipped["no facts"] += 1
            continue
        checked += 1
        sentences = fact_check.sentences_of(entry["sentences"])
        found = (fact_check.check_cited if strict else fact_check.check_entry)(sentences, sheet)
        for rule, reason, sentence in found:
            note = rule in fact_check.NOTE_RULES
            print("%s:%d: %s [%s]%s\n  %s\n  in: %s" % (doc, entry["line"], entry["name"], rule, " (note)" if note else "",
                                                       reason, sentence[:160]), file=out)
        reported += any(rule not in fact_check.NOTE_RULES for rule, _r, _s in found)
    print("facts: checked=%d not-mips=%d no-facts=%d reported=%d" % (
        checked, skipped["not MIPS"], skipped["no facts"], reported), file=out)
    return reported


REVIEWED = re.compile(r"\bReviewed:\s*\d{4}-\d{2}-\d{2}")
VERDICTS = ("ok", "fixed", "reject")


def entry_key(entry):
    """The key a review verdict file uses for an entry: routine, address and the binary as written."""
    return "%s@%s@%s" % (entry["name"], entry["address"], entry["install"])


def _columns(left, right, width=78):
    """Two blocks of text side by side, each line wrapped to width."""
    import textwrap
    lines_l = [w for text in left for w in (textwrap.wrap(text, width) or [""])]
    lines_r = [w for text in right for w in (textwrap.wrap(text, width, subsequent_indent="    ") or [""])]
    rows = max(len(lines_l), len(lines_r))
    lines_l += [""] * (rows - len(lines_l))
    lines_r += [""] * (rows - len(lines_r))
    return ["%-*s | %s" % (width, a, b) for a, b in zip(lines_l, lines_r)]


def review_pack(doc, root, inventory=None, out_path=None, routines=None, unreviewed=False, batch=None):
    """Write, for each entry of a routine-role document, the entry beside the facts it was written from and what
    the checker finds, in the form a reviewer reads. Entries with citations are checked as cited entries.
    Returns the number of entries written."""
    import fact_check
    sites = _function_sites(inventory) if inventory and os.path.isfile(inventory) else {}
    entries = parse_entries(doc)
    if routines:
        entries = [e for e in entries if e["name"] in routines]
    with open(doc, encoding="utf-8") as source:
        lines = source.read().splitlines()
    if unreviewed:
        entries = [e for e in entries if not REVIEWED.search("\n".join(lines[e["line"] - 1:e["end"]]))]
    if batch:
        index, total = batch
        size = -(-len(entries) // total)
        entries = entries[(index - 1) * size:index * size]
    out = ["# Review pack for %s" % os.path.basename(doc), "",
           "Each entry is shown beside the facts rendered for its routine (call N counts the calls in address order) "
           "and the findings of the checker. A finding is a reason to look, not a verdict.", ""]
    for entry in entries:
        abi, size = sites.get((entry["install"], int(entry["address"], 16)), ("", None))
        sentences = fact_check.sentences_of(entry["sentences"])
        facts, findings, why = [], [], ""
        if entry["firmware"] or abi not in ("", "o32", "n32", "n64"):
            why = "not MIPS: the facts are not rendered"
        else:
            try:
                binary, member = resolve_binary(root, entry)
                sheet = fact_check.sheet_for(binary, member, entry["address"], entry["size"] or size)
                facts = fact_check.fact_index(sheet)
                cited = any("[@" in s or "[call " in s for s in entry["sentences"])
                findings = (fact_check.check_cited if cited else fact_check.check_entry)(sentences, sheet)
            except (Exception, SystemExit) as error:
                why = "no facts: %s" % error
        out += ["## %s" % entry_key(entry), "",
                "%s:%d, %d finding%s" % (os.path.basename(doc), entry["line"], len(findings),
                                         "" if len(findings) == 1 else "s"), "", "```"]
        out += _columns(["ENTRY"] + [""] + entry["sentences"], ["FACTS"] + [""] + (facts or [why or "(none)"]))
        out += ["```", ""]
        for rule, reason, sentence in findings:
            out += ["- [%s] %s" % (rule, reason)] + (["  in: %s" % sentence[:200]] if sentence else [])
        out.append("")
    text = "\n".join(out) + "\n"
    if out_path:
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    return len(entries)


def apply_verdicts(doc, verdicts_path, date, out=None):
    """Rewrite the entries of a routine-role document from a reviewer's verdicts and add the review marker.
    The verdicts file is JSON, {entry key: {"verdict": "ok" | "fixed" | "reject", "text": "...",
    "reviewer": "..."}}. ok keeps the entry and marks it reviewed, fixed replaces the lines under the header with
    text and marks it, reject changes nothing and leaves the entry unreviewed. Nothing is written when a key or a
    verdict is wrong. Returns {verdict: count}."""
    import json
    out = out or sys.stdout
    with open(verdicts_path, encoding="utf-8") as handle:
        verdicts = json.load(handle)
    with open(doc, encoding="utf-8") as source:
        lines = source.read().split("\n")
    entries = {entry_key(e): e for e in parse_lines(lines)}
    errors = []
    for key, item in verdicts.items():
        if key not in entries:
            errors.append("%s: no such entry in %s" % (key, doc))
        elif item.get("verdict") not in VERDICTS:
            errors.append("%s: verdict must be one of %s" % (key, ", ".join(VERDICTS)))
        elif item["verdict"] == "fixed" and not str(item.get("text", "")).strip():
            errors.append("%s: a fixed verdict needs the corrected text" % key)
    if errors:
        for error in errors:
            print(error, file=out)
        raise SystemExit(1)
    counts = collections.Counter()
    for key, item in sorted(verdicts.items(), key=lambda kv: -entries[kv[0]]["line"]):
        counts[item["verdict"]] += 1
        if item["verdict"] == "reject":
            continue
        entry = entries[key]
        first, end = entry["line"] - 1, entry["end"]
        head = entry["shape"] == "head"
        if item["verdict"] == "fixed":
            text = str(item["text"]).strip("\n").split("\n")
            # a heading keeps its shape: the text is its paragraphs, so it is not indented
            body = text if head else [l if not l or l[:1].isspace() else "  " + l for l in text]
            body = [""] + body if head and body[0] else body
        else:
            body = lines[first + 1:end]
        body = [l for l in body if not REVIEWED.match(l.strip())]
        while body and not body[-1].strip():
            body.pop()
        note = "Reviewed: %s%s" % (date, " (%s)" % item["reviewer"] if item.get("reviewer") else "")
        # under a heading the marker is a paragraph of its own, so it stays in the entry
        marker = ["", note] if head else ["  " + note]
        lines[first:end] = [lines[first]] + body + marker
    with open(doc, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print("verdicts: ok=%d fixed=%d reject=%d" % (counts["ok"], counts["fixed"], counts["reject"]), file=out)
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("doc")
    parser.add_argument("--check-doc", action="store_true",
                        help="lint DOC as a routine-role document instead of grading instruction readings")
    parser.add_argument("--check-facts", action="store_true",
                        help="with --check-doc, also test each entry's claims against the facts rendered for its routine")
    parser.add_argument("--strict-citations", action="store_true",
                        help="with --check-doc --check-facts, read each entry as a cited entry: every claim carries a "
                             "[@0xADDR] or [call N] citation that is tested against its fact, and the role is marked")
    parser.add_argument("--review-pack", metavar="OUT",
                        help="write, for each entry of DOC, the entry beside its rendered facts and the checker's findings "
                             "to OUT; --routine, --unreviewed and --batch K/M choose the entries")
    parser.add_argument("--apply-verdicts", metavar="JSON",
                        help="rewrite the entries of DOC from a reviewer's verdicts (JSON of entry key -> verdict, corrected "
                             "text) and add each reviewed entry's Reviewed line")
    parser.add_argument("--review-date", metavar="YYYY-MM-DD", help="the date of the Reviewed lines (default: today)")
    parser.add_argument("--unreviewed", action="store_true", help="with --review-pack, only entries with no Reviewed line")
    parser.add_argument("--batch", metavar="K/M",
                        help="with --review-pack, the Kth of M equal slices of the chosen entries (K from 1)")
    parser.add_argument("--inventory", metavar="FUNCTIONS_TSV",
                        help="functions table for --check-doc (default: docs/inventory/functions.tsv of the workspace)")
    parser.add_argument("--root", help="directory containing the cited binaries")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--seed", type=int, default=0)
    group.add_argument("--routine", nargs="+", help="grade named routine entries")
    parser.add_argument("--count", type=int, default=12, help="sample size; 0 grades every entry")
    args = parser.parse_args(argv)
    if args.check_facts and not args.check_doc:
        parser.error("--check-facts goes with --check-doc")
    if args.strict_citations and not args.check_facts:
        parser.error("--strict-citations goes with --check-doc --check-facts")
    if args.apply_verdicts:
        import datetime
        apply_verdicts(args.doc, args.apply_verdicts, args.review_date or datetime.date.today().isoformat())
        return 0
    if args.review_pack:
        from _workspace import find_workspace
        workspace = find_workspace()
        batch = tuple(int(n) for n in args.batch.split("/")) if args.batch else None
        if batch and not 1 <= batch[0] <= batch[1]:
            parser.error("--batch K/M needs 1 <= K <= M")
        table = args.inventory or os.path.join(workspace, "docs", "inventory", "functions.tsv")
        count = review_pack(args.doc, args.root or os.path.join(workspace, "root"), table, args.review_pack,
                            args.routine, args.unreviewed, batch)
        print("review pack: %d entries written to %s" % (count, args.review_pack))
        return 0
    if args.check_doc:
        from _workspace import find_workspace
        workspace = find_workspace()
        table = args.inventory
        if table is None:
            table = os.path.join(workspace, "docs", "inventory", "functions.tsv")
        problems = check_doc(args.doc, table, review=needs_review(args.doc, workspace),
                             routines=is_routines_file(args.doc, workspace))
        if args.check_facts:
            problems += check_facts(args.doc, args.root or os.path.join(workspace, "root"), table,
                                    strict=args.strict_citations)
        return 1 if problems else 0
    if not args.root:
        parser.error("--root is required to grade readings")
    entries = parse_entries(args.doc)
    if args.routine:
        selected = [e for e in entries if e["name"] in args.routine]
        missing = set(args.routine) - {e["name"] for e in selected}
        if missing:
            parser.error("routines not found: " + ", ".join(sorted(missing)))
    elif args.count == 0:
        selected = entries
    else:
        selected = random.Random(args.seed).sample(entries, min(args.count, len(entries)))
    totals = collections.Counter()
    input_errors = 0
    for entry in selected:
        try:
            results = grade_entry(args.root, entry)
        except (Exception, SystemExit) as error:
            # facts refuses an unresolvable address with SystemExit; catching it keeps the rest of the document graded
            print("%s:%d %s MISMATCH (%s)" % (args.doc, entry["line"], entry["name"], error))
            input_errors += 1
            continue
        bad = [(state, detail) for state, detail in results if state != "OK"]
        totals.update(state for state, _detail in results)
        status = "MISMATCH" if any(state == "MISMATCH" for state, _ in bad) else "UNPARSED" if bad else "OK"
        print("%s:%d %s %s" % (args.doc, entry["line"], entry["name"], status))
        for state, detail in bad:
            print("  %s: %s" % (state, detail))
    print("entries=%d sentences=%d OK=%d MISMATCH=%d UNPARSED=%d" % (
        len(selected), sum(totals.values()), totals["OK"], totals["MISMATCH"] + input_errors,
        totals["UNPARSED"]))
    return 1 if totals["MISMATCH"] or input_errors else 0


if __name__ == "__main__":
    sys.exit(main())
