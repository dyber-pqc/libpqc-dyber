#!/usr/bin/env python3
# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run test_ct under Valgrind memcheck for every algorithm and report.

    run_ctgrind.py build/tests/test_ct [--only SUBSTR] [--jobs N]
                   [--gate tests/ct/ct_gate.txt [--gate-only]]
                   [--report out.md] [--logs DIR]

Each algorithm runs in its own Valgrind process so that every finding is
attributed to one algorithm and one operation. A finding is a memcheck
report that a branch ("Conditional jump") or a memory address ("Use of
uninitialised value") depends on secret data. Findings are de-duplicated
by the source location of the innermost library frame.

Exit status: 1 if any algorithm listed in the gate file has a finding or
fails to run correctly, 0 otherwise. Algorithms not in the gate file are
reported but do not fail the run.
"""

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys

KINDS = {
    "Conditional jump or move depends on uninitialised value(s)": "branch",
    "Use of uninitialised value of size": "index",
    "Syscall param": "syscall",
}

FRAME = re.compile(r"==\d+==\s+(?:at|by) 0x[0-9A-Fa-f]+: (\S+) \(([^)]*)\)")
HDR = re.compile(r"==\d+== (\S.*)$")


def parse(stderr):
    """Return (findings, functional_errors). findings: list of dicts."""
    findings, functional = [], []
    step = "setup"
    lines = stderr.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("==ct== "):
            msg = line[7:]
            if msg.startswith("FUNCTIONAL") or msg.startswith("not available"):
                functional.append(msg)
            else:
                step = msg
            i += 1
            continue
        m = HDR.match(line)
        kind = None
        if m:
            for prefix, k in KINDS.items():
                if m.group(1).startswith(prefix):
                    kind = k
                    break
        if not kind:
            i += 1
            continue
        frames = []
        i += 1
        while i < len(lines):
            f = FRAME.match(lines[i])
            if not f:
                break
            frames.append((f.group(1), f.group(2)))
            i += 1
        # Innermost frame that is library code rather than libc/harness.
        site = next((fr for fr in frames
                     if re.search(r"\.(c|h|S):\d+$", fr[1])
                     and not fr[1].startswith("test_ct.c")),
                    frames[0] if frames else ("?", "?"))
        findings.append({
            "kind": kind, "step": step,
            "func": site[0], "loc": site[1],
            "stack": " < ".join(f"{fn}" for fn, _ in frames[:6]),
        })
    return findings, functional


def run_one(valgrind, tool, kind, name, timeout):
    cmd = [valgrind, "--tool=memcheck", "--error-exitcode=99",
           "--track-origins=yes", "--num-callers=30", "--error-limit=no",
           "--leak-check=no", tool, kind, name]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return name, kind, None, ["timed out"], None
    findings, functional = parse(p.stderr)
    if p.returncode not in (0, 99) and not functional:
        functional.append(f"exit status {p.returncode}")
    return name, kind, findings, functional, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tool")
    ap.add_argument("--valgrind", default=shutil.which("valgrind") or "valgrind")
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--skip", action="append", default=[],
                    help="exact algorithm name to leave out (repeatable)")
    ap.add_argument("--gate")
    ap.add_argument("--gate-only", action="store_true",
                    help="run only the algorithms listed in the gate file")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--report")
    ap.add_argument("--logs", help="directory for full Valgrind output")
    a = ap.parse_args()

    tool = os.path.abspath(a.tool)
    out = subprocess.run([tool, "--list"], capture_output=True, text=True,
                         check=True).stdout
    algs = [tuple(l.split("\t", 1)) for l in out.splitlines() if "\t" in l]
    if a.only:
        algs = [x for x in algs if any(s in x[1] for s in a.only)]
    if a.skip:
        algs = [x for x in algs if x[1] not in a.skip]

    gate = set()
    if a.gate:
        with open(a.gate, encoding="utf-8") as f:
            gate = {l.strip() for l in f
                    if l.strip() and not l.lstrip().startswith("#")}
        unknown = gate - {n for _, n in algs}
        if unknown and not a.only:
            print(f"gate lists unknown algorithms: {sorted(unknown)}")
            return 2
        if a.gate_only:
            algs = [x for x in algs if x[1] in gate]
    elif a.gate_only:
        ap.error("--gate-only needs --gate")

    if a.logs:
        os.makedirs(a.logs, exist_ok=True)

    results = {}
    with concurrent.futures.ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(run_one, a.valgrind, tool, k, n, a.timeout)
                for k, n in algs]
        for fut in concurrent.futures.as_completed(futs):
            name, kind, findings, functional, log = fut.result()
            results[name] = (kind, findings, functional)
            if a.logs and log is not None:
                safe = re.sub(r"[^A-Za-z0-9_.+-]", "_", name)
                with open(os.path.join(a.logs, safe + ".log"), "w",
                          encoding="utf-8") as f:
                    f.write(log)
            sites = len({(x["func"], x["loc"]) for x in findings or []})
            state = ("ERROR" if functional else
                     "clean" if not findings else f"{sites} site(s)")
            print(f"  {name:32s} {state}", flush=True)

    rep = ["| Algorithm | Gated | Result | Findings (op: function @ location) |",
           "|---|---|---|---|"]
    bad = 0
    for kind, name in algs:
        k, findings, functional = results[name]
        uniq = {}
        for x in findings or []:
            uniq.setdefault((x["kind"], x["func"], x["loc"]), x["step"])
        g = name in gate
        if functional:
            res = "error: " + "; ".join(functional)
        elif uniq:
            res = f"{len(uniq)} site(s)"
        else:
            res = "clean"
        if g and (functional or uniq):
            bad += 1
        detail = "<br>".join(f"{st}: {kd} in `{fn}` @ {loc}"
                             for (kd, fn, loc), st in sorted(uniq.items()))
        rep.append(f"| {name} | {'yes' if g else ''} | {res} | {detail} |")

    text = "\n".join(rep) + "\n"
    print()
    print(text)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            f.write(text)
    if bad:
        print(f"{bad} gated algorithm(s) not constant-time clean")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
