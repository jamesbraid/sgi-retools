#!/usr/bin/env python3
"""Render hostfacts as a complete facts-only instruction reading entry."""
import argparse
import collections
import json
import os
import re
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import hostfacts  # noqa: E402


GRADES = ("established", "inferred", "approximated", "unknown")


def _address(value):
    return "0x%x" % value if isinstance(value, int) else str(value)


def access_target(access, nargs):
    if "absolute" in access:
        return "abs %s%s" % (access["absolute"],
                             " (%s)" % access["symbol"] if access.get("symbol") else "")
    if "reloc" in access:
        return "reloc %s" % access["reloc"]
    if "origin" in access:
        origin = access["origin"]
        if re.fullmatch(r"a[0-7]", origin) and int(origin[1]) < nargs:
            origin += " (arg%d at entry)" % int(origin[1])
        offset = access.get("origin_offset", 0)
        return "%s %s0x%x" % (origin, "+" if offset >= 0 else "-", abs(offset))
    return "?"


def access_sentences(accesses, nargs):
    """Describe pointer accesses, excluding frame and global-pointer traffic."""
    groups = collections.OrderedDict()
    for access in accesses:
        if hostfacts.is_stack_or_global_access(access):
            continue
        target = access_target(access, nargs)
        key = (access["mnemonic"], access["kind"], access["width"], target)
        groups.setdefault(key, []).append(access)

    lines = []
    for (mnemonic, kind, width, target), group in groups.items():
        refs = ", ".join("`%s` at %s" % (mnemonic, item["address"])
                         for item in group[:3])
        size_text = "%d byte%s" % (width, "" if width == 1 else "s")
        if len(group) == 1:
            verb = "loads" if kind == "load" else "stores"
            lines.append("The `%s` at %s %s %s %s %s." % (
                mnemonic, group[0]["address"], verb, size_text,
                "from" if kind == "load" else "to", target))
        else:
            lines.append("%d such `%s` accesses %s %s %s %s, including %s." % (
                len(group), mnemonic, kind, size_text, "from" if kind == "load" else "to", target, refs))
    return lines


def return_value(exit_fact):
    value = exit_fact.get("v0", "?")
    source_values = [value] if value != "?" else [
        path.get("v0", "?") for path in exit_fact.get("paths", [])]
    had_choices = any(item.startswith("one of ") for item in source_values)
    values = []
    pending = list(source_values)
    while pending:
        item = pending.pop(0)
        if item.startswith("one of "):
            had_choices = True
            pending[0:0] = hostfacts.split_top_level(item[7:])
        elif item not in values:
            values.append(item)
    if len(values) > 1 or had_choices:
        return "one of " + ", ".join(values)
    return values[0] if values else value


def _call_sentences(routine, facts):
    calls_by_address = {call["address"]: call for call in facts.get("calls", [])}
    output = []
    for index, ins in enumerate(routine.insns):
        if index not in routine.in_states:
            continue
        if ins["mn"] not in hostfacts.facts.CALLS and ins["mn"] not in ("j", "jr", "jr.hb"):
            continue
        call = calls_by_address.get(_address(ins["addr"]))
        if not call:
            continue
        name = call.get("callee") or ("(unnamed)" if call.get("target") else "(unknown callee)")
        if call.get("target"):
            name += " [%s]" % call["target"]
        args, _fp = hostfacts.arg_text(routine, routine.in_states[index], index)
        rendered_args = ", ".join(args) or "none set"
        if _fp:
            rendered_args += "; fp " + ", ".join(_fp)
        if call.get("tail"):
            output.append("Calls %s via %s with %s (`%s` at %s)." % (
                name, call.get("kind", "?"), rendered_args, ins["mn"], _address(ins["addr"])))
        else:
            output.append("The `%s` at %s calls %s with %s." % (
                ins["mn"], _address(ins["addr"]), name, rendered_args))
    return output


def _branch_sentences(routine, facts):
    blocks, by_first = hostfacts.build_blocks(routine)
    hostfacts.wire(routine, blocks, by_first)
    asm = hostfacts.facts.Recorder(routine).text
    output = []
    for block in blocks:
        exit_fact = block.exit
        kind = exit_fact["kind"]
        if kind not in ("cond", "always", "never"):
            continue
        index = exit_fact["index"]
        if index not in routine.in_states:
            continue
        ins = routine.insns[index]
        address = _address(ins["addr"])
        target = _address(exit_fact["target"])
        if kind == "always":
            output.append("The `%s` branch at %s targets %s and is always taken." % (
                ins["mn"], address, target))
            continue
        if kind == "never":
            output.append("The `%s` branch at %s targets %s and is never taken: its condition can never hold for these operands, so execution always falls through." % (
                ins["mn"], address, target))
            continue
        taken, fall = hostfacts.cond_words(routine, block, index)
        if not taken or not fall:
            sentence = "The `%s` branch at %s targets %s; its condition is not analyzed" % (
                ins["mn"], address, target)
            if ins["mn"] in hostfacts.facts.LIKELY and index + 1 < len(routine.insns):
                delay = routine.insns[index + 1]
                delay_text = "nop" if delay["mn"] == "sll" and delay["ops"] == ["$0", "$0", "0x0"] else asm(delay)
                sentence += "; its branch-likely delay slot `%s` at %s runs only when taken and is annulled on fall-through" % (
                    delay_text, _address(delay["addr"]))
            output.append(sentence + ".")
            continue
        sentence = "The `%s` branch at %s targets %s, is taken when %s, and falls through when %s" % (
            ins["mn"], address, target, taken, fall)
        if ins["mn"] in hostfacts.facts.LIKELY and index + 1 < len(routine.insns):
            delay = routine.insns[index + 1]
            delay_text = "nop" if delay["mn"] == "sll" and delay["ops"] == ["$0", "$0", "0x0"] else asm(delay)
            sentence += "; its branch-likely delay slot `%s` at %s runs only when taken and is annulled on fall-through" % (
                delay_text, _address(delay["addr"]))
        output.append(sentence + ".")
    return output


def _jump_table_sentences(routine, facts):
    lines = []
    for table in facts.get("jump_tables", []):
        lines.append("The indirect jump at %s uses the jump table at %s with targets %s." % (
            table["jump"], table["table"], ", ".join(table.get("targets", []))))
    known = {table["jump"] for table in facts.get("jump_tables", [])}
    for index, ins in enumerate(routine.insns):
        address = _address(ins["addr"])
        if address in known or index not in routine.in_states or ins["mn"] not in ("jr", "jr.hb"):
            continue
        if hostfacts.unresolved_table_jump(routine, index):
            lines.append("The indirect jump at %s uses a jump table whose successors are unresolved." % address)
    return lines


def _unreached_sentences(facts):
    addresses = sorted(int(address, 16) for address in facts.get("unreached", []))
    if not addresses:
        return []
    ranges = []
    start = previous = addresses[0]
    for address in addresses[1:]:
        if address != previous + 4:
            ranges.append((start, previous))
            start = address
        previous = address
    ranges.append((start, previous))
    return ["The instructions from %s to %s are not reached by any path from the entry, and their branches are not listed." %
            (_address(start), _address(end)) for start, end in ranges]


def _firmware_args(call):
    shown = [a for a in call.get("args", []) if a["value"] not in ("?", a["location"])]
    return ", ".join("%s=%s" % (a["location"], a["value"]) for a in shown) or "none set"


def firmware_sentences(routine, facts):
    """Sentences for a routine from the non-MIPS adapters (m68k, ColdFire, ARM, PowerPC).

    The adapters have no delay slots, so each sentence reads straight off the fact sheet.
    """
    mnemonic = {hex(ins["addr"]): ins["mn"] for ins in routine.insns}
    lines = access_sentences(facts.get("accesses", []), 0)
    for call in facts.get("calls", []):
        name = call.get("callee") or ("(unnamed)" if call.get("target") else "(unknown callee)")
        if call.get("target"):
            name += " [%s]" % call["target"]
        line = "The `%s` at %s calls %s with %s" % (call["mnemonic"], call["address"], name, _firmware_args(call))
        if call.get("taken_when"):
            line += ", when %s" % call["taken_when"]
        lines.append(line + ".")
    for block in facts.get("blocks", []):
        if block["kind"] != "conditional":
            continue
        mn = mnemonic.get(block["last"], "?")
        if block["target"] is None:
            lines.append("The `%s` branch at %s has an unresolved target." % (mn, block["last"]))
        else:
            lines.append("The `%s` branch at %s targets %s, is taken when %s, and falls through when %s." % (
                mn, block["last"], block["target"], block["taken_when"], block["falls_through_when"]))
    for exit_fact in facts.get("exits", []):
        line = "The return at %s has %s = %s" % (exit_fact["address"], exit_fact["register"], exit_fact["value"])
        if exit_fact.get("condition"):
            line += "; it is taken when %s" % exit_fact["condition"]
        lines.append(line + ".")
    unreached = set(facts.get("unreached", []))
    run = []
    for ins in routine.insns + [None]:
        address = hex(ins["addr"]) if ins else None
        if ins and address in unreached:
            run.append(address)
        elif run:
            lines.append("The instructions from %s to %s are not reached by any path from the entry, "
                         "and their branches are not listed." % (run[0], run[-1]))
            run = []
    lines.extend("Analysis note: %s." % warning.rstrip(".") for warning in facts.get("warnings", []))
    return lines


def render_entry(routine, facts, install_path, grade, requested_name=None):
    rt = facts["routine"]
    name = requested_name or rt.get("name") or "(unnamed)"
    address = rt["address"]
    end = rt.get("end") or hex(int(address, 16) + int(rt["size"]))
    lines = ["- `%s` in `%s` at %s (%s)." % (name, install_path, address, rt.get("abi", "unknown")),
             "  Evidence grade: %s." % grade.lower(),
             "  Exact binary: `%s`." % install_path,
             "  Range: %s-%s (%d bytes)." % (address, end, int(rt["size"])),
             "  It occupies %d bytes." % int(rt["size"])]
    if isinstance(routine, hostfacts.FirmwareRoutine):
        # Names the image layout so the grader can reload the same bytes.
        lines.insert(3, "  Architecture: %s, load %s, offset %s%s." % (
            routine.arch, hex(routine.img.load), hex(routine.img.offset), ", elf" if routine.img.elf else ""))
        sentences = firmware_sentences(routine, facts)
        lines.extend("  " + sentence for sentence in sentences)
        return "\n".join(lines) + "\n"
    sentences = access_sentences(facts.get("accesses", []), routine.nargs)
    sentences.extend(_call_sentences(routine, facts))
    sentences.extend(_branch_sentences(routine, facts))
    for exit_fact in facts.get("exits", []):
        sentences.append("The return at %s has v0 = %s." % (
            exit_fact["address"], return_value(exit_fact)))
    sentences.extend(_unreached_sentences(facts))
    sentences.extend(_jump_table_sentences(routine, facts))
    lines.extend("  " + sentence for sentence in sentences)
    return "\n".join(lines) + "\n"


def load_json(path):
    with open(path, encoding="utf-8") as source:
        facts = json.load(source)
    routine_facts = facts.get("routine", {})
    binary, member = hostfacts.split_binary(routine_facts.get("file", ""))
    if not binary or not os.path.isfile(binary):
        raise ValueError("hostfacts JSON routine.file does not name a readable binary")
    routine = hostfacts.routine_for(binary, routine_facts["address"], member=member,
                                    size=int(routine_facts["size"]))
    routine.facts(False)
    return routine, facts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", help="binary path, optionally followed by :member")
    parser.add_argument("routine", nargs="?", help="routine name or 0xADDRESS")
    parser.add_argument("--size", type=lambda value: int(value, 0))
    parser.add_argument("--path", required=True, help="binary install path for the entry header")
    parser.add_argument("--grade", choices=[grade.title() for grade in GRADES], default="Inferred")
    parser.add_argument("--json-in", metavar="FILE", help="read saved hostfacts --json output")
    args = parser.parse_args(argv)

    if args.json_in:
        if args.binary or args.routine or args.size:
            parser.error("BINARY, ROUTINE, and --size cannot be used with --json-in")
        routine, facts = load_json(args.json_in)
    else:
        if not args.binary or not args.routine:
            parser.error("BINARY and ROUTINE are required unless --json-in is used")
        binary, member = hostfacts.split_binary(args.binary)
        routine = hostfacts.routine_for(binary, args.routine, member=member, size=args.size)
        facts = routine.facts(False)
        facts["routine"]["file"] = args.binary
    requested_name = (args.routine if args.routine and
                      not re.fullmatch(r"0x[0-9a-fA-F]+", args.routine) else None)
    sys.stdout.write(render_entry(routine, facts, args.path, args.grade,
                                  requested_name=requested_name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
