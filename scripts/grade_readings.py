#!/usr/bin/env python3
"""Compare facts-only instruction readings with hostfacts output."""
import argparse
import collections
import itertools
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import hostfacts  # noqa: E402


HEX = r"0x[0-9a-fA-F]+"
HEADER = re.compile(r"^- `(?P<name>[^`]+)`(?: in `(?P<binary>[^`]+)` at (?P<address>" + HEX + r")| \(`(?P<legacy>[^`]+)`, (?P<legacy_address>" + HEX + r"), (?P<legacy_size>\d+) bytes\))")


def parse_entries(doc):
    """Read bullet entries and their sentences in the formats used by landed rounds."""
    with open(doc, encoding="utf-8") as source:
        lines = source.read().splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("- ")]
    entries = []
    for start in starts:
        end = start + 1
        while end < len(lines) and lines[end][:1].isspace():
            end += 1
        block = lines[start:end]
        header = HEADER.match(block[0])
        if not header:
            continue
        meta = "\n".join(block)
        name = header.group("name")
        binary = header.group("binary") or header.group("legacy")
        address = header.group("address") or header.group("legacy_address")
        exact = re.search(r"^\s*Exact binary: `([^`]+)`\s*$", meta, re.M)
        binary = exact.group(1) if exact else binary
        span = re.search(r"^\s*Range: (" + HEX + r")-(" + HEX + r") \((\d+) bytes\)", meta, re.M)
        size_line = re.search(r"^\s*It occupies (\d+) bytes\.", meta, re.M)
        size = int(header.group("legacy_size") or (span.group(3) if span else 0) or (size_line.group(1) if size_line else 0)) or None
        # Old entries put the binary and address in the title. Exact binary overrides it.
        if binary and "(" in binary and binary.endswith(")"):
            binary = re.sub(r"\(([^()]*)\)$", r":\1", binary)
        sentences = [line.strip() for line in block[1:] if line.strip() and not re.match(
            r"(?:Evidence grade:|Exact binary:|Exact build:|Range:|Role:)", line.strip())]
        entries.append({"name": name, "binary": binary, "address": address, "size": size,
                        "sentences": sentences, "line": start + 1})
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


def facts_for(root, entry):
    binary_path, separator, member = entry["binary"].partition(":")
    binary = os.path.join(root, binary_path)
    if not os.path.isfile(binary):
        # Some older documents name paths relative to the checkout, rather than root/.
        checkout_candidate = os.path.join(os.path.dirname(os.path.abspath(root)), binary_path)
        if os.path.isfile(checkout_candidate):
            binary = checkout_candidate
        else:
            raise FileNotFoundError(binary)
    member = member if separator else None
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("doc")
    parser.add_argument("--root", required=True, help="directory containing the cited binaries")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--seed", type=int, default=0)
    group.add_argument("--routine", nargs="+", help="grade named routine entries")
    parser.add_argument("--count", type=int, default=12, help="sample size; 0 grades every entry")
    args = parser.parse_args(argv)
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
        except Exception as error:
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
