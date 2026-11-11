#!/usr/bin/env python3
"""Run one instruction-reading round in a workspace, with no LLM involved.

Selects the uncovered routines of docs/inventory/functions.tsv, renders each with
render_reading.py, grades each entry alone with grade_readings.py, and writes
docs/instruction-readings-REPO-gN.md, committing every 25 entries. Never pushes.

Run from the workspace root (it needs `root/`, the binary root, and the retools submodule):

    uv run --with capstone --with pyelftools --with numpy --with unicorn \\
        python -I retools/tools/reading_round.py --repo-name kona --round g43 --out-dir DIR

The call check is built in: every call sentence of the finished document must name a real call
site of the routine it cites, with the mnemonic and (when cited) the target the facts give.
`--call-check PATH` runs an external checker instead.

Repos whose routines are mostly `located` (kona, voyager, crime, chips) need
`--from-grade located`, usually with `--hardware-only`. A firmware image of another
architecture takes `--arch coldfire|m68k|arm|thumb|ppc32 --load ADDR` (plus `--offset N` for a
payload that starts inside its file, `--elf` for a mapped ARM ELF, `--binary PATH` to keep one
image's rows). Those entries carry an `Architecture:` line so grade_readings can reload them.
A row keyed by a segment of a firmware container (`l1.bin(l1#2)`, `l2.bin(kernel)`, which the inventory
writes for a binaries group with a `layout`) needs none of those options: the arch, the bytes and the load
address come from the workspace's scripts/inventory-config.json, the same layout code the inventory used.

The entry it writes is the canonical routine role entry of README-analysis.md, which
`grade_readings.py DOC --check-doc` lints.

Target selection, in order:
  1. Rows of docs/inventory/functions.tsv on HEAD with a status at or below --from-grade
     (default named-only: named-only or undocumented; located adds located rows) and scope
     `in` (out:N rows are excluded from coverage on purpose). --hardware-only then keeps only
     the rows rule 5 ranks 1, routines a hardware table names, whatever their role.
  2. Drop rows that already have an entry header in docs/*.md, matched on binary + routine
     (an archive member is part of the binary: lib.a(member.o)) or on binary + address.
  3. Drop rows at address 0x0 with an empty size: the renderer cannot resolve them.
  4. Keep the first row per binary + address (glFoo and glFooEXT share one).
  5. Rank hardware-facing first, stable within a rank (inventory order):
       0  kernel objects and boot paths: role ending in `-kernel`, or a binary path with a
          `boot` component (IP27boot, IP35boot);
       1  routines the hardware tables name: a function listed in the `functions` column of
          mmio.tsv, a handler or sender in ioctls.tsv, or the `binary:routine` example of a row
          of mmio.tsv, ioctls.tsv or tokens.tsv (an example written `routine@0xADDR` links by
          address);
       2  everything else.
"""
import argparse
import csv
import io
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

BATCH = 25
# Lowest grade first; --from-grade names the highest one a round may pick up.
GRADES = ("undocumented", "named-only", "located")
FIRMWARE_ARCHES = ("m68k", "coldfire", "arm", "thumb", "ppc32")
HEX = r"0x[0-9a-fA-F]+"
NEW_HEADER = re.compile(r"^\s*- `([^`]+)` in `([^`]+)`(?: at (" + HEX + r"))?")
OLD_HEADER = re.compile(r"^\s*- `([^`]+)` \(`([^`]+)`, (" + HEX + r"), \d+ bytes\)")


def norm_binary(path):
    """lib.a:member.o and lib.a(member.o) name one thing; use the parenthesised form."""
    m = re.fullmatch(r"(.+\.a):(.+)", path)
    return "%s(%s)" % m.groups() if m else path


def to_int(text):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def read_tsv(text):
    return list(csv.DictReader(io.StringIO(text), delimiter="\t", quoting=csv.QUOTE_NONE))


def header_keys(lines):
    """(names, addrs): sets of (binary, routine) and (binary, address) from entry headers."""
    names, addrs = set(), set()
    for line in lines:
        m = NEW_HEADER.match(line) or OLD_HEADER.match(line)
        if not m:
            continue
        routine, binary, address = m.groups()
        binary = norm_binary(binary)
        names.add((binary, routine))
        if to_int(address) is not None:
            addrs.add((binary, to_int(address)))
    return names, addrs


def hardware_links(mmio, ioctls, tokens):
    """(names, addrs) the hardware tables point at: routine names and (binary, address)."""
    names, addrs = set(), set()

    def example(value):
        if ":" not in value:
            return
        binary, routine = value.rsplit(":", 1)
        binary = norm_binary(binary)
        if "@" in routine:
            addr = to_int(routine.split("@", 1)[1])
            if addr is not None:
                addrs.add((binary, addr))
        elif routine:
            names.add(routine)

    def listed(value):
        for item in value.split(";"):
            item = item.strip()
            if item and not re.fullmatch(r"\+\d+ more", item):
                names.add(item)

    for row in mmio:
        listed(row.get("functions") or "")
        example(row.get("example") or "")
    for row in ioctls:
        listed(row.get("senders") or "")
        if row.get("handler"):
            names.add(row["handler"])
        example(row.get("example") or "")
    for row in tokens:
        example(row.get("example") or "")
    return names, addrs


def rank(row, link_names, link_addrs):
    binary = norm_binary(row["binary"])
    parts = binary.replace("(", "/").split("/")
    if (row.get("role") or "").endswith("-kernel") or any(p.endswith("boot") for p in parts):
        return 0
    addr = to_int(row["address"])
    if row["name"] in link_names or (binary, addr) in link_addrs:
        return 1
    return 2


def hardware_linked(row, link_names, link_addrs):
    """Whether a hardware table (mmio, ioctls, tokens) names this routine."""
    return row["name"] in link_names or (norm_binary(row["binary"]), to_int(row["address"])) in link_addrs


def select_targets(rows, doc_names, doc_addrs, link_names=(), link_addrs=(),
                   from_grade="named-only", hardware_only=False, binaries=()):
    """Apply the selection rules in the module docstring; returns rows in target order."""
    statuses = GRADES[:GRADES.index(from_grade) + 1]
    seen, picked = set(), []
    for row in rows:
        if row.get("status") not in statuses or row.get("scope") != "in":
            continue
        if binaries and norm_binary(row["binary"]) not in binaries:
            continue
        if hardware_only and not hardware_linked(row, link_names, link_addrs):
            continue
        if "address-unknown" in (row.get("rejected") or ""):
            continue
        binary = norm_binary(row["binary"])
        addr = to_int(row["address"])
        if addr is None:
            continue
        if addr == 0 and not (row.get("size") or "").strip():
            continue
        if (binary, row["name"]) in doc_names or (binary, addr) in doc_addrs:
            continue
        if (binary, addr) in seen:
            continue
        seen.add((binary, addr))
        picked.append(row)
    keyed = [(rank(r, link_names, link_addrs), i, r) for i, r in enumerate(picked)]
    keyed.sort(key=lambda k: (k[0], k[1]))
    return [r for _rank, _i, r in keyed]


def git(*args, cwd=".", check=True):
    return subprocess.run(("git",) + args, cwd=cwd, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def head_file(path):
    try:
        return git("show", "HEAD:" + path)
    except subprocess.CalledProcessError:
        return open(path, encoding="utf-8").read() if os.path.exists(path) else ""


def intro_text(docs_dir, own):
    """Header of the newest existing instruction-readings doc, up to its first entry."""
    def key(name):
        m = re.search(r"-g(\d+)\.md$", name)
        return int(m.group(1)) if m else -1
    names = sorted((n for n in os.listdir(docs_dir)
                    if n.startswith("instruction-readings") and n.endswith(".md") and n != own),
                   key=key)
    if names:
        out = []
        for line in open(os.path.join(docs_dir, names[-1]), encoding="utf-8").read().splitlines():
            if line.startswith("- `"):
                break
            out.append(line)
        text = "\n".join(out).rstrip()
        if text:
            return text + "\n"
    return ("# Instruction readings from hostfacts\n\nThese entries record instruction facts "
            "rendered from the routines below. They describe software behavior, not hardware "
            "behavior, and each locator names an address in the identified binary.\n")


def render_one(row, root, firmware=None, config=None):
    """Render one routine; returns entry text. firmware is the non-MIPS image layout, if any. config is
    the workspace's inventory config: a binary that names a segment of a firmware container
    (`l1.bin(l1#2)`) is cut out of its file by the config's layout, the way the inventory cut it."""
    import firmware_layout
    import hostfacts
    import render_reading
    binary = norm_binary(row["binary"])
    size = to_int(row.get("size") or "")
    segment = firmware_layout.segment_routine(config, root, binary, row["address"], size or None) if config else None
    if segment:
        facts = segment.facts(False)
        return render_reading.render_entry(segment, facts, binary, "Inferred", requested_name=row["name"])
    m = re.fullmatch(r"(.+\.a)\((.+)\)", binary)
    arg = os.path.join(root, m.group(1) if m else binary)
    member = m.group(2) if m else None
    if firmware:
        routine = hostfacts.routine_for(arg, row["address"], size=size or None, **firmware)
    else:
        routine = hostfacts.routine_for(arg, row["address"], member=member, size=size or None)
    facts = routine.facts(False)
    # Firmware images carry no symbols, so the inventory's name is the only one there is.
    return render_reading.render_entry(routine, facts, binary, "Inferred",
                                       requested_name=row["name"] if firmware else None)


def grade_one(entry_text, root, scratch):
    """Grade one rendered entry alone; returns (ok, message)."""
    import grade_readings
    with open(scratch, "w", encoding="utf-8") as handle:
        handle.write(entry_text)
    entries = grade_readings.parse_entries(scratch)
    if len(entries) != 1:
        return False, "UNPARSED: header did not parse as one entry"
    results = grade_readings.grade_entry(root, entries[0])
    bad = [(s, d) for s, d in results if s != "OK"]
    if bad:
        return False, "; ".join("%s: %s" % b for b in bad[:3])
    return True, ""


CALL_SENTENCES = (
    # (pattern, group order of mnemonic, address, callee)
    (re.compile(r"The `(\w[\w.]*)` at (" + HEX + r") calls (.*?) with "), (1, 2, 3)),
    (re.compile(r"Calls (.*?) via \S+ with .*? \(`(\w[\w.]*)` at (" + HEX + r")\)"), (2, 3, 1)),
)


def check_call_addrs(doc, root):
    """Check the call sentences of a readings document against the routines they cite.

    Each call address must be a call site of its routine, carry the cited mnemonic, and, when
    the sentence cites a `[0xTARGET]`, reach that target. Returns (calls checked, problems).
    """
    import grade_readings
    checked, problems = 0, []
    for entry in grade_readings.parse_entries(doc):
        sites = None
        for sentence in entry["sentences"]:
            for pattern, (mn_at, addr_at, callee_at) in CALL_SENTENCES:
                m = pattern.match(sentence.rstrip("."))
                if not m:
                    continue
                if sites is None:
                    try:
                        if entry.get("firmware"):
                            routine, facts = grade_readings.firmware_facts(root, entry)
                        else:
                            routine = hostfacts_routine(root, entry)
                            facts = routine.facts(False)
                    except (Exception, SystemExit) as error:
                        problems.append("%s: cannot load routine: %s" % (entry["name"], one_line(error)))
                        sites = {}
                        break
                    sites = {call["address"]: (call["mnemonic"], call.get("target"))
                             for call in facts.get("calls", [])}
                mn, address, callee = m.group(mn_at), m.group(addr_at), m.group(callee_at)
                checked += 1
                address = hex(int(address, 16))
                if address not in sites:
                    problems.append("%s: %s is not a call site" % (entry["name"], address))
                    break
                site_mn, target = sites[address]
                if site_mn != mn:
                    problems.append("%s: %s is `%s`, not `%s`" % (entry["name"], address, site_mn, mn))
                cited = re.search(r"\[(" + HEX + r")\]", callee)
                if cited and target and int(cited.group(1), 16) != int(target, 16):
                    problems.append("%s: call at %s reaches %s, not %s" % (
                        entry["name"], address, target, cited.group(1)))
                break
    return checked, problems


def hostfacts_routine(root, entry):
    import grade_readings
    import hostfacts
    binary, member = grade_readings.resolve_binary(root, entry)
    return hostfacts.routine_for(binary, entry["address"], member=member, size=entry["size"])


def one_line(text):
    return re.sub(r"\s+", " ", str(text)).strip()


def commit(doc, subject, repo_dir, amend=False):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    env = dict(os.environ, GIT_AUTHOR_NAME="James Braid", GIT_COMMITTER_NAME="James Braid",
               GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
    email = git("config", "user.email", cwd=repo_dir, check=False).strip() or "jamesb@loreland.org"
    env.update(GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_EMAIL=email)
    subprocess.run(["git", "add", "--", doc], cwd=repo_dir, check=True, env=env)
    cmd = ["git", "commit", "-q", "--amend", "--no-edit", "--date", stamp] if amend else \
        ["git", "commit", "-q", "-m", subject]
    subprocess.run(cmd + ["--", doc], cwd=repo_dir, check=True, env=env, stdout=subprocess.PIPE)


def closing_sentence(skips):
    total = sum(skips.values())
    if not total:
        return "Skipped no routines."
    parts = []
    if skips["renderer"]:
        parts.append("%d because the renderer could not read them" % skips["renderer"])
    if skips["grader"]:
        parts.append("%d because the grader flagged a rendered sentence" % skips["grader"])
    return "Skipped %d routines: %s." % (total, " and ".join(parts))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo-name", required=True)
    ap.add_argument("--round", required=True, help="round label such as g43")
    ap.add_argument("--count", type=int, default=500, help="targets to render (default 500)")
    ap.add_argument("--out-dir", required=True, help="where the targets, conflicts and logs go")
    ap.add_argument("--call-check", help="external call checker run as `python3 -I PATH DOC`; "
                    "default is the built-in check")
    ap.add_argument("--from-grade", choices=GRADES, default="named-only",
                    help="highest inventory status to pick up (default named-only, which also "
                    "takes undocumented rows); located adds located rows")
    ap.add_argument("--hardware-only", action="store_true",
                    help="keep only routines the mmio, ioctls or tokens tables name")
    ap.add_argument("--arch", default="mips", choices=("mips",) + FIRMWARE_ARCHES,
                    help="architecture of the binaries (default mips)")
    ap.add_argument("--load", type=lambda s: int(s, 0), help="firmware load address (non-MIPS)")
    ap.add_argument("--offset", type=lambda s: int(s, 0), default=0, help="firmware payload offset in its file")
    ap.add_argument("--elf", action="store_true", help="the firmware is a mapped ARM ELF")
    ap.add_argument("--binary", action="append", default=[], metavar="PATH",
                    help="keep only rows of this binary (repeatable)")
    args = ap.parse_args(argv)
    firmware = None
    if args.arch != "mips":
        if args.load is None:
            ap.error("--arch %s needs --load ADDR" % args.arch)
        firmware = dict(arch=args.arch, load=args.load, offset=args.offset, elf=args.elf)
    elif args.load is not None or args.offset or args.elf:
        ap.error("--load, --offset and --elf need a non-MIPS --arch")

    repo = os.getcwd()
    root = "root"
    if not os.path.isdir(root):
        ap.error("run from a workspace root with a root/ link")
    os.makedirs(args.out_dir, exist_ok=True)
    import firmware_layout
    config = firmware_layout.read_config(repo)
    tag = "%s-%s" % (args.repo_name, args.round)
    doc_rel = "docs/instruction-readings-%s.md" % tag
    started = time.time()

    rows = read_tsv(head_file("docs/inventory/functions.tsv"))
    link_names, link_addrs = hardware_links(
        *(read_tsv(head_file("docs/inventory/%s.tsv" % n)) for n in ("mmio", "ioctls", "tokens")))
    lines = []
    for name in sorted(os.listdir("docs")):
        if name.endswith(".md") and name != os.path.basename(doc_rel):
            with open(os.path.join("docs", name), encoding="utf-8") as handle:
                lines.extend(handle.read().splitlines())
    doc_names, doc_addrs = header_keys(lines)
    targets = select_targets(rows, doc_names, doc_addrs, link_names, link_addrs, args.from_grade,
                             args.hardware_only, {norm_binary(b) for b in args.binary})

    targets_path = os.path.join(args.out_dir, "targets-%s.tsv" % tag)
    with open(targets_path, "w", encoding="utf-8") as out:
        out.write("# total %d\n" % len(targets))
        out.write("binary\taddress\tsize\tname\trole\tstatus\n")
        for r in targets:
            out.write("\t".join((norm_binary(r["binary"]), r["address"], r.get("size") or "",
                                 r["name"], r.get("role") or "", r["status"])) + "\n")
    print("targets: %d (%s)" % (len(targets), targets_path))

    conflicts_path = os.path.join(args.out_dir, "renderer-conflicts-%s.tsv" % tag)
    conflicts = open(conflicts_path, "w", encoding="utf-8")
    conflicts.write("binary\taddress\troutine\treason\tmessage\n")
    scratch = os.path.join(args.out_dir, "entry-%s.tmp.md" % tag)

    with open(doc_rel, "w", encoding="utf-8") as handle:
        handle.write(intro_text("docs", os.path.basename(doc_rel)) + "\n")

    skips = {"renderer": 0, "grader": 0}
    done = pending = last_committed = 0
    buffer = []

    def flush(final):
        nonlocal pending, last_committed
        if final:
            with open(doc_rel, "a", encoding="utf-8") as handle:
                handle.write("\n" + closing_sentence(skips) + "\n")
        if pending or final:
            first, last = last_committed + 1, done
            if last >= first:
                commit(doc_rel, "docs: add %s %s readings %d to %d" % (
                    args.repo_name, args.round, first, last), repo)
            elif final and done:
                # the last batch was already committed; fold the closing sentence into it
                commit(doc_rel, "", repo, amend=True)
            last_committed, pending = done, 0

    for i, row in enumerate(targets[:args.count], 1):
        binary = norm_binary(row["binary"])
        try:
            text = render_one(row, root, firmware, config)
        except BaseException as error:   # the renderer exits through SystemExit on some inputs
            if isinstance(error, KeyboardInterrupt):
                raise
            skips["renderer"] += 1
            conflicts.write("\t".join((binary, row["address"], row["name"], "renderer",
                                       one_line(error))) + "\n")
            continue
        try:
            ok, message = grade_one(text, root, scratch)
        except Exception as error:
            ok, message = False, "grader raised: %s" % error
        if not ok:
            skips["grader"] += 1
            conflicts.write("\t".join((binary, row["address"], row["name"], "grader",
                                       one_line(message))) + "\n")
            continue
        with open(doc_rel, "a", encoding="utf-8") as handle:
            handle.write(text)
        done += 1
        pending += 1
        if i % 50 == 0:
            print("  %d targets attempted, %d entries" % (i, done), flush=True)
        # keep the last batch for the closing sentence
        if pending == BATCH and i < min(args.count, len(targets)):
            flush(False)
    conflicts.close()
    if os.path.exists(scratch):
        os.remove(scratch)
    flush(True)

    # full-document grade and call-address check
    import grade_readings
    grade_log = os.path.join(args.out_dir, "grade-%s.txt" % tag)
    with open(grade_log, "w", encoding="utf-8") as log:
        saved = sys.stdout
        sys.stdout = log
        try:
            grade_status = grade_readings.main([doc_rel, "--root", root, "--count", "0"])
        finally:
            sys.stdout = saved
    grade_tail = open(grade_log, encoding="utf-8").read().strip().splitlines()[-1:]
    call_log = os.path.join(args.out_dir, "calls-%s.txt" % tag)
    if args.call_check:
        with open(call_log, "w", encoding="utf-8") as log:
            call = subprocess.run(["python3", "-I", args.call_check, doc_rel], stdout=log,
                                  stderr=subprocess.STDOUT, text=True, cwd=repo)
        call_status = call.returncode
    else:
        calls, problems = check_call_addrs(doc_rel, root)
        with open(call_log, "w", encoding="utf-8") as log:
            log.write("%d calls checked, %d problems\n" % (calls, len(problems)))
            log.writelines(p + "\n" for p in problems)
        call_status = 1 if problems else 0
    call_tail = open(call_log, encoding="utf-8").read().strip().splitlines()[:1]

    print("repo %s round %s: %d targets, %d entries written, %d skipped (renderer %d, grader %d)" % (
        args.repo_name, args.round, len(targets), done, sum(skips.values()),
        skips["renderer"], skips["grader"]))
    print("full-doc grade (exit %d): %s" % (grade_status, " ".join(grade_tail)))
    print("call check (exit %d): %s" % (call_status, " ".join(call_tail)))
    print("logs: %s, %s, %s" % (grade_log, call_log, conflicts_path))
    print("elapsed %.1f s" % (time.time() - started))
    return 1 if grade_status or call_status else 0


if __name__ == "__main__":
    sys.exit(main())
