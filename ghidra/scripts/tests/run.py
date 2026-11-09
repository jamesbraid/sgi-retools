#!/usr/bin/env python3
"""Run the IRIX GOT/PLT filter and import regressions in an existing Ghidra image."""
import argparse
import contextlib
import hashlib
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

SCRIPTS = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("GHIDRA_IMAGE", "localhost/re-ghidra:a851eccc301f")


def run(command, **kwargs):
    print("+ " + " ".join(shlex.quote(str(part)) for part in command), flush=True)
    return subprocess.run([str(part) for part in command], text=True, **kwargs)


def container(work, command, evidence=None, timeout=900):
    mounts = ["-v", f"{SCRIPTS}:/opt/re-scripts:ro", "-v", f"{work}:/work-test"]
    if evidence:
        mounts += ["-v", f"{evidence.parent}:/evidence:ro"]
    return run(["podman", "run", "--rm", "--userns=keep-id", "--security-opt", "label=disable",
                *mounts, "-w", "/work-test", "-e", "HOME=/tmp", IMAGE, "sh", "-c", command],
               timeout=timeout)


EXPECTED_REAL_REPAIR = (12955, 49, 2442, 12958)


def expected_filter_spans(data):
    """Return the two pre-DT_NULL MIPS tag spans, using the ELF program headers."""
    elf64 = data[4] == 2
    endian = "big" if data[5] == 2 else "little"
    word = 8 if elf64 else 4
    def uint(offset, size):
        return int.from_bytes(data[offset:offset + size], endian)
    phoff = uint(32 if elf64 else 28, word)
    phentsize = uint(54 if elf64 else 42, 2)
    phnum = uint(56 if elf64 else 44, 2)
    spans = []
    for index in range(phnum):
        ph = phoff + index * phentsize
        if uint(ph, 4) != 2:  # PT_DYNAMIC
            continue
        offset = uint(ph + (8 if elf64 else 4), word)
        size = uint(ph + (32 if elf64 else 16), word)
        for entry in range(offset, offset + size, 2 * word):
            tag = uint(entry, word)
            if tag == 0:
                break
            if tag in (0x7000000a, 0x70000013):
                spans.append((entry, entry + word))
    return spans


def assert_real_regression(original, work, before):
    original_bytes = original.read_bytes()
    filtered_bytes = (work / "real.filtered.elf").read_bytes()
    expected = bytearray(original_bytes)
    spans = expected_filter_spans(original_bytes)
    if len(spans) != 2:
        raise AssertionError(f"expected two real dynamic tag spans, got {spans}")
    for start, end in spans:
        expected[start:end] = bytes(end - start)
    if filtered_bytes != expected:
        raise AssertionError("real filtered file differs outside the two pre-DT_NULL dynamic tags")
    differences = [i for i, (a, b) in enumerate(zip(original_bytes, filtered_bytes)) if a != b]
    print("PASS real filtered bytes only: " + ", ".join(hex(i) for i in differences))
    log = (work / "real-import-repair.log").read_text()
    match = re.search(r"IrixGotPltRepair: pointers=(\d+), externalLinkages=(\d+), skipped=(\d+), totalGotEntries=(\d+)", log)
    if not match:
        raise AssertionError("missing real repair totals")
    totals = tuple(map(int, match.groups()))
    if totals != EXPECTED_REAL_REPAIR:
        raise AssertionError(f"repair totals: expected {EXPECTED_REAL_REPAIR}, got {totals}")
    print(f"PASS real repair totals: pointers={totals[0]}, externalLinkages={totals[1]}, skipped={totals[2]}, totalGotEntries={totals[3]}")
    classifications = {
        "ordinary function collision": 882,
        "unrelocated/unresolved or otherwise invalid": 1557,
        "pointer is outside one initialized memory block": 3,
        "rollback failed": 0,
    }
    for text, expected_count in classifications.items():
        actual_count = log.count(text)
        if actual_count != expected_count:
            raise AssertionError(f"{text!r}: expected {expected_count}, got {actual_count}")
    print("PASS real skip classifications: 882 ordinary collisions, 1557 invalid/unresolved targets, 3 out-of-block pointers, 0 rollback failures")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-elf", type=Path, help="optional real IRIX ELF regression input")
    parser.add_argument("--keep", type=Path, help="keep test output in this non-repository directory")
    args = parser.parse_args()
    if args.keep:
        args.keep.mkdir(parents=True, exist_ok=True)
        context = contextlib.nullcontext(tempfile.mkdtemp(prefix="run-", dir=args.keep))
    else:
        context = tempfile.TemporaryDirectory(prefix="irix-got-plt-", dir="/tmp/opencode")
    with context as temporary:
        work = Path(temporary)
        compile_and_unit = r'''set -eu
CP=$(find /opt/ghidra/Ghidra -name '*.jar' -printf '%p:')
javac -cp "$CP" -d /work-test/classes \
  /opt/re-scripts/IrixGotPltFilter.java \
  /opt/re-scripts/IrixGotPltRepair.java \
  /opt/re-scripts/tests/IrixGotPltScriptTest.java
java -cp "/work-test/classes:$CP" IrixGotPltScriptTest /work-test
mkdir -p /work-test/project
analyzeHeadless /work-test/project synthetic -import /work-test/fixture-ELF64-MSB.filtered.elf \
  -noanalysis -deleteProject > /work-test/synthetic-import.log 2>&1
! grep -q 'NullPointerException' /work-test/synthetic-import.log
grep -E 'IMPORTING|Import succeeded|REPORT:' /work-test/synthetic-import.log
'''
        result = container(work, compile_and_unit)
        if result.returncode:
            (work / "synthetic-import.log").read_text() if (work / "synthetic-import.log").exists() else None
            return result.returncode
        if args.real_elf:
            original = args.real_elf.resolve(strict=True)
            before = hashlib.sha256(original.read_bytes()).hexdigest()
            filtered = work / (original.name + ".filtered")
            real = r'''set -eu
CP=$(find /opt/ghidra/Ghidra -name '*.jar' -printf '%p:')
java -cp "/work-test/classes:$CP" IrixGotPltFilter /evidence/INPUT /work-test/real.filtered.elf
mkdir -p /work-test/real-project
analyzeHeadless /work-test/real-project real -import /work-test/real.filtered.elf \
  -noanalysis -loader-applyRelocations false -loader-applyUndefinedData false \
  -scriptPath /opt/re-scripts -postScript IrixGotPltRepair.java /evidence/INPUT \
  -deleteProject > /work-test/real-import-repair.log 2>&1
! grep -q 'NullPointerException' /work-test/real-import-repair.log
grep -E 'IrixGotPltFilter:|IrixGotPltRepair: pointers=|Import succeeded|REPORT:' /work-test/real-import-repair.log
'''.replace("INPUT", original.name)
            result = container(work, real, evidence=original, timeout=1800)
            after = hashlib.sha256(original.read_bytes()).hexdigest()
            if before != after:
                print(f"FAIL original hash changed: {before} -> {after}", file=sys.stderr)
                return 1
            print(f"PASS real original SHA-256 unchanged: {after}")
            assert_real_regression(original, work, before)
            if result.returncode:
                log = work / "real-import-repair.log"
                if log.exists():
                    print(log.read_text()[-20000:], file=sys.stderr)
                return result.returncode
        print("PASS all requested IRIX GOT/PLT tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
