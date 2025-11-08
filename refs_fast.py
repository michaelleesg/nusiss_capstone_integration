#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

EXCLUDES = [
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".aider.tags.cache.v4",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
]


def run(cmd, cwd):
    return subprocess.run(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )


def main():
    ap = argparse.ArgumentParser(description="Single-pass ripgrep ref counter (tracked files only)")
    ap.add_argument("--root", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / "refs_summary_fast.csv"

    r = run(["git", "ls-files", "-z"], cwd=root)
    files = [p for p in r.stdout.split("\0") if p]
    if not files:
        print("[refs_fast] no tracked files?", file=sys.stderr)
        return 1

    terms_by_file = {}
    all_terms = set()
    for rel in files:
        name = Path(rel).name
        stem = Path(rel).stem
        ts = {name}
        if stem and stem != name:
            ts.add(stem)
        terms_by_file[rel] = ts
        all_terms.update(ts)

    pat_path = out_dir / "refs_fast_patterns.txt"
    with pat_path.open("w", encoding="utf-8") as f:
        for term in sorted(all_terms):
            f.write(term + "\n")

    globs = []
    for ex in EXCLUDES:
        globs += ["--glob", f"!**/{ex}/**"]
    cmd = ["rg", "-n", "-S", "--no-ignore-vcs", "--json", "-f", str(pat_path), str(root)]
    cmd = cmd[:3] + globs + cmd[3:]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    term_counts = {t: 0 for t in all_terms}
    term_first_hit = {}

    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("type") != "match":
            continue
        data = obj.get("data", {})
        path = data.get("path", {}).get("text", "")
        subs = data.get("submatches", [])
        if not subs:
            continue
        matched = subs[0].get("match", {}).get("text", "")
        if matched in term_counts:
            term_counts[matched] += 1
            term_first_hit.setdefault(matched, path)

    proc.wait()

    rows = []
    for rel, ts in terms_by_file.items():
        total = sum(term_counts.get(t, 0) for t in ts)
        first = ""
        for t in ts:
            p = term_first_hit.get(t, "")
            if p:
                first = p
                break
        rows.append({"path": rel, "ref_count_approx": total, "first_hit": first})

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["path", "ref_count_approx", "first_hit"])
        w.writeheader()
        w.writerows(rows)

    print(f"[refs_fast] wrote {out_csv}  files={len(rows)}  terms={len(all_terms)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("[refs_fast] interrupted", file=sys.stderr)
        raise SystemExit(130)
