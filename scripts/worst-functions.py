#!/usr/bin/env python3
"""Per-function coverage drill-down for the SecretSpec Bitwarden provider.

Prints the N functions with the worst line coverage in the PR's source files
(by default just bw.rs — the provider code; add more files with --sources),
using a merged llvm-cov profile (e.g. from scripts/coverage-bitwarden.sh),
and reports how many more lines are needed to hit given coverage targets.

Usage:
  python3 scripts/worst-functions.py <merged.profdata> \\
      --objects <bin> <lib-test-bin> \\
      [--sources secretspec/src/provider/bw.rs] [--n 20] [--targets 80,90]

  --sources    files to drill into (repeatable; default: bw.rs only, since the
               unit profile runs only bw tests and other provider test files
               would flood the list with unrelated uncovered functions)
  --n          how many worst functions to print (default 20)
  --targets    comma-separated line-coverage goals, printed as a hint
  --short      shorten the demangled name prefix to bw::

Requires: llvm-cov + llvm-nm on PATH (or /opt/homebrew/opt/llvm/bin), python3.
"""

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
from collections import defaultdict


def find_tool(name, env):
    p = os.environ.get(env)
    if p:
        return p
    p = shutil.which(name)
    if p:
        return p
    p = f"/opt/homebrew/opt/llvm/bin/{name}"
    return p if os.path.exists(p) else name


LLVM_COV = find_tool("llvm-cov", "LLVM_COV")
LLVM_CXXFILT = find_tool("llvm-cxxfilt", "LLVM_CXXFILT")


def demangle_map(names):
    """mangled -> demangled, via llvm-cxxfilt (handles Rust v0 incl. backrefs)."""
    if not names:
        return {}
    uniq = list(dict.fromkeys(names))
    res = subprocess.run([LLVM_CXXFILT], input="\n".join(uniq) + "\n",
                         capture_output=True, text=True)
    if res.returncode != 0:
        return {}
    out = {}
    for mang, dem in zip(uniq, res.stdout.splitlines()):
        out[mang] = dem
    return out


def load_data(profdata, objects, sources):
    cmd = [LLVM_COV, "export", f"--instr-profile={profdata}"]
    cmd += [f"--object={o}" for o in objects]
    for s in sources:
        cmd += ["-sources", s]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"llvm-cov export failed:\n{res.stderr[:800]}")
    return json.loads(res.stdout)["data"][0]


def aggregate_functions(data, sources):
    """name -> dict(lines=set, hit=set, regions, r_hit) merged across objects."""
    agg = {}
    for fn in data.get("functions", []):
        if not any(f.endswith(s) for f in fn.get("filenames", []) for s in sources):
            continue
        a = agg.setdefault(fn["name"], {"lines": set(), "hit": set(), "regions": 0, "r_hit": 0})
        for r in fn.get("regions", []):
            ls, le, cnt = r[0], r[2], r[4]
            a["regions"] += 1
            if cnt > 0:
                a["r_hit"] += 1
            for ln in range(ls, le + 1):
                a["lines"].add(ln)
                if cnt > 0:
                    a["hit"].add(ln)
    return agg


def file_line_summary(data, sources):
    total = covered = 0
    for f in data.get("files", []):
        if any(f["filename"].endswith(s) for s in sources):
            s = f["summary"]["lines"]
            total += s["count"]
            covered += s["covered"]
    return (total, covered) if total else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("profdata", help="merged .profdata (e.g. target/coverage/merged/unit.profdata)")
    ap.add_argument("--objects", nargs="+", required=True, help="instrumented binaries (bin + lib test bin)")
    ap.add_argument("--sources", nargs="+", default=["secretspec/src/provider/bw.rs"],
                    help="files to drill into (default: bw.rs)")
    ap.add_argument("--n", type=int, default=20)
    ap.add_argument("--targets", default="80,90", help="comma-separated line-coverage goals")
    ap.add_argument("--short", action="store_true", help="shorten bw:: name prefix")
    ap.add_argument("--sort", choices=["pct", "missed"], default="pct",
                    help="pct = worst line coverage first; missed = most uncovered lines first")
    args = ap.parse_args()

    data = load_data(args.profdata, args.objects, args.sources)
    agg = aggregate_functions(data, args.sources)
    demap = demangle_map(agg.keys())
    # The bin and the lib-test binary each carry their own copy of bw.rs, so
    # the same source function appears under two mangled names (different
    # crate hashes). Merge by demangled name so the list shows unique functions.
    merged = {}
    for mang, a in agg.items():
        key = demap.get(mang, mang)
        m = merged.setdefault(key, {"lines": set(), "hit": set(), "regions": 0, "r_hit": 0})
        m["lines"] |= a["lines"]
        m["hit"] |= a["hit"]
        m["regions"] += a["regions"]
        m["r_hit"] += a["r_hit"]
    agg = merged

    def pretty(name):
        if args.short:
            name = name.replace("secretspec::provider::bw::", "bw::")
        return name

    rows = []
    for name, a in agg.items():
        total, hit = len(a["lines"]), len(a["hit"])
        pct = (hit / total * 100) if total else 100.0
        rows.append((pct, total - hit, hit, total, a["r_hit"], a["regions"], name))
    # worst first: lowest line %, then most missed lines, then name
    if args.sort == "missed":
        rows.sort(key=lambda r: (-r[1], r[0], r[6]))
    else:
        rows.sort(key=lambda r: (r[0], -r[1], r[6]))

    summary = file_line_summary(data, args.sources)
    print(f"Worst {args.n} functions by line coverage — {', '.join(os.path.basename(s) for s in args.sources)} ({os.path.basename(args.profdata)})")
    if summary:
        total, covered = summary
        print(f"file lines: {covered}/{total} ({covered * 100.0 / total:.2f}%)")
        goals = []
        for g in args.targets.split(","):
            g = int(g)
            need = max(0, math.ceil(g * total / 100.0) - covered)
            goals.append(f"{g}%: +{need} lines ({(covered + need)}/{total})")
        print("to reach " + " | ".join(goals))
    print()
    print(f"{'#':>3}  {'lines':>8}  {'line%':>6}  {'regions':>8}  {'region%':>7}  function")
    for i, (pct, missed, hit, total, r_hit, regions, name) in enumerate(rows[: args.n], 1):
        rpct = (r_hit / regions * 100) if regions else 100.0
        print(f"{i:>3}  {hit:>3}/{total:<4}  {pct:>5.1f}%  {r_hit:>3}/{regions:<4}  {rpct:>6.1f}%  {pretty(name)}")


if __name__ == "__main__":
    main()
