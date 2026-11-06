#!/usr/bin/env python3
"""Re-render facts-only reading entries that no longer match hostfacts.

Run from an RE workspace (the directory holding `root/` and `docs/`). Every
docs/instruction-readings-*.md is graded with grade_readings in process, every
entry. An entry that grades MISMATCH or UNPARSED is rendered again with
render_reading from the binary, member, address and install path in its header
(and the stated size, only when it differs from the symbol's size) and the whole
entry is replaced. The new entry is graded again; if it still fails, or cannot
be rendered, the old entry stays and is listed in the conflicts file.

Only rendered-format documents are rewritten. Prose documents are never opened
for writing; check them with check_claims.py.
"""
import argparse
import collections
import multiprocessing
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import grade_readings  # noqa: E402
import render_reading  # noqa: E402

DOC_PREFIX = "instruction-readings-"


def rewritable(doc):
    name = os.path.basename(doc)
    return name.startswith(DOC_PREFIX) and name.endswith(".md")


def grade_status(root, entry):
    """Return (OK|MISMATCH|UNPARSED, detail), summarised as grade_readings.main does."""
    try:
        results = grade_readings.grade_entry(root, entry)
    except (Exception, SystemExit) as error:
        # facts refuses an unresolvable address with SystemExit
        return "MISMATCH", str(error)
    bad = [(state, detail) for state, detail in results if state != "OK"]
    if any(state == "MISMATCH" for state, _ in bad):
        return "MISMATCH", "; ".join(str(d) for s, d in bad if s == "MISMATCH")
    if bad:
        return "UNPARSED", "; ".join(str(d) for _, d in bad)
    return "OK", ""


def render_text(root, entry):
    """Render the entry again from its header. Raises when it cannot be rendered."""
    binary, member = grade_readings.resolve_binary(root, entry)
    hostfacts = render_reading.hostfacts
    routine = hostfacts.routine_for(binary, entry["address"], member=member)
    facts = routine.facts(False)
    stated = entry["size"]
    if stated and stated != int(facts["routine"]["size"]):
        routine = hostfacts.routine_for(binary, entry["address"], member=member, size=stated)
        facts = routine.facts(False)
    grade = (entry["grade"] or "inferred").title()
    if grade.lower() not in render_reading.GRADES:
        grade = "Inferred"
    return render_reading.render_entry(routine, facts, entry["install"], grade,
                                       requested_name=entry["name"])


def process(root, entry, grade=grade_status, render=render_text):
    """Return (state, new_text, detail). state is ok, replaced or conflict."""
    state, detail = grade(root, entry)
    if state == "OK":
        return "ok", None, ""
    before = "%s: %s" % (state, detail)
    try:
        text = render(root, entry)
    except (Exception, SystemExit) as error:
        return "conflict", None, "%s; cannot render: %s" % (before, error)
    fresh = grade_readings.parse_lines(text.splitlines())
    if len(fresh) != 1:
        return "conflict", None, "%s; rendered text does not parse as one entry" % before
    state, detail = grade(root, fresh[0])
    if state != "OK":
        return "conflict", None, "%s; still %s after rendering: %s" % (before, state, detail)
    return "replaced", text, before


_WORKER = {}


def _init(root):
    _WORKER["root"] = root


def _work(entry):
    return process(_WORKER["root"], entry)


def rerender_doc(doc, root, pool=None, grade=None, render=None):
    """Rewrite one document. Returns (counts, conflicts). conflicts hold (entry, detail)."""
    if not rewritable(doc):
        raise ValueError("refusing to rewrite %s: not a rendered-format reading document" % doc)
    with open(doc, encoding="utf-8") as source:
        text = source.read()
    lines = text.splitlines()
    entries = grade_readings.parse_lines(lines)
    if pool:
        outcomes = pool.imap(_work, entries, chunksize=4)
    else:
        kwargs = {}
        if grade:
            kwargs["grade"] = grade
        if render:
            kwargs["render"] = render
        outcomes = (process(root, entry, **kwargs) for entry in entries)
    counts = collections.Counter(entries=len(entries))
    conflicts = []
    edits = []
    for entry, (state, new_text, detail) in zip(entries, outcomes):
        if state == "ok":
            counts["ok"] += 1
            continue
        counts["failing"] += 1
        if state == "conflict":
            counts["conflict"] += 1
            conflicts.append((entry, detail))
        else:
            counts["rerendered"] += 1
            edits.append((entry, new_text))
    for entry, new_text in reversed(edits):
        start = entry["line"] - 1
        lines[start:entry["end"]] = new_text.splitlines()
    if edits:
        out = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        handle, temp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(doc)), prefix=".rerender-")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as sink:
                sink.write(out)
            os.chmod(temp, os.stat(doc).st_mode & 0o7777)
            os.replace(temp, doc)
        except BaseException:
            if os.path.exists(temp):
                os.unlink(temp)
            raise
    return counts, conflicts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default="root", help="directory containing the cited binaries")
    parser.add_argument("--docs", default="docs", help="directory holding the reading documents")
    parser.add_argument("--only", nargs="+", metavar="DOC", help="process just these documents")
    parser.add_argument("--jobs", type=int, default=4, help="grading processes")
    parser.add_argument("--conflicts", default="rerender-conflicts.tsv", help="conflicts tsv to write")
    args = parser.parse_args(argv)

    if args.only:
        docs = [os.path.join(args.docs, d) if os.sep not in d else d for d in args.only]
    else:
        docs = sorted(os.path.join(args.docs, n) for n in os.listdir(args.docs)
                      if n.startswith(DOC_PREFIX) and n.endswith(".md"))
    for doc in docs:
        if not rewritable(doc):
            parser.error("%s is not an %s*.md document" % (doc, DOC_PREFIX))

    pool = multiprocessing.Pool(args.jobs, _init, (args.root,)) if args.jobs > 1 else None
    if pool is None:
        _init(args.root)
    total = collections.Counter()
    with open(args.conflicts, "w", encoding="utf-8") as tsv:
        tsv.write("doc\tline\tname\tbinary\taddress\tdetail\n")
        print("doc\tentries\tfailing\trerendered\tconflicts")
        for doc in docs:
            counts, conflicts = rerender_doc(doc, args.root, pool)
            total.update(counts)
            for entry, detail in conflicts:
                tsv.write("%s\t%d\t%s\t%s\t%s\t%s\n" % (
                    os.path.basename(doc), entry["line"], entry["name"], entry["install"],
                    entry["address"], " ".join(detail.split())))
            tsv.flush()
            print("%s\t%d\t%d\t%d\t%d" % (os.path.basename(doc), counts["entries"], counts["failing"],
                                           counts["rerendered"], counts["conflict"]), flush=True)
    print("total\t%d\t%d\t%d\t%d" % (total["entries"], total["failing"], total["rerendered"],
                                      total["conflict"]))
    if pool:
        pool.close()
        pool.join()
    return 0


if __name__ == "__main__":
    sys.exit(main())
