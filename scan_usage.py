#!/usr/bin/env python3
"""
scan_usage.py — repo inventory & naive reference scan (symlink-aware)
Usage:
  python3 scan_usage.py --root /home/mike/capstone_win --out out_dir
Outputs:
  files_inventory.csv, refs_summary.csv
"""
import argparse, csv, os, sys, subprocess, time
from pathlib import Path

EXCLUDES = {'.git', '.venv', 'venv', 'node_modules', '.aider.tags.cache.v4', '__pycache__', '.pytest_cache', '.mypy_cache'}
LEGACY_REMOVE = {
  "0b_fix_json.py",
  "1_generate_bio_ner_training.py",
  "2_ingest_vector.py",
  "2_ingest_vector_wsl.py",
}

def has_cmd(name: str) -> bool:
    from shutil import which
    return which(name) is not None

def list_lfs(cwd: Path) -> set[str]:
    try:
        out = subprocess.check_output(['git','lfs','ls-files'], cwd=cwd, stderr=subprocess.DEVNULL).decode('utf-8','replace')
        paths = set()
        for line in out.splitlines():
            parts = line.strip().split()
            if parts:
                paths.add(parts[-1])
        return paths
    except Exception:
        return set()

def is_binary(file_path: Path) -> bool:
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(2048)
        if b'\0' in chunk:
            return True
        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
        non_text = sum(c not in text_chars for c in chunk)
        return (non_text / max(1, len(chunk))) > 0.30
    except Exception:
        return True

def ref_count_rg(root: Path, path: Path) -> tuple[int, str]:
    globs = []
    for ex in EXCLUDES:
        globs.extend(['--glob', f'!**/{ex}/**'])
    patterns = [path.name]
    stem = path.stem
    if stem and stem != path.name:
        patterns.append(stem)
    total = 0
    first_hit = ""
    for pat in patterns:
        cmd = ['rg','-n','-S','--no-ignore-vcs'] + globs + ['--', pat, str(root)]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        lines = [ln for ln in proc.stdout.splitlines() if ln]
        total += len(lines)
        if not first_hit and lines:
            first_hit = lines[0].split(':', 1)[0]
    return total, first_hit

def ref_count_py(root: Path, path: Path) -> tuple[int,str]:
    target_terms = [path.name]
    stem = path.stem
    if stem and stem != path.name:
        target_terms.append(stem)
    total = 0
    first_hit = ""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDES]
        for fn in filenames:
            fp = Path(dirpath) / fn
            try:
                if is_binary(fp): 
                    continue
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                for term in target_terms:
                    if term in text:
                        total += text.count(term)
                        if not first_hit:
                            first_hit = str(fp)
            except Exception:
                continue
    return total, first_hit

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    supplied_root = Path(args.root)
    resolved_root = supplied_root.resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[scan] Supplied root : {supplied_root}")
    print(f"[scan] Resolved root : {resolved_root}")
    if supplied_root != resolved_root:
        print("[scan] Note: root is a symlink; scanning resolved target.")

    root = resolved_root
    lfs_set = list_lfs(root)

    inv_path = out_dir / 'files_inventory.csv'
    refs_path = out_dir / 'refs_summary.csv'

    use_rg = has_cmd('rg')
    ref_counter = ref_count_rg if use_rg else ref_count_py

    files_rows, refs_rows = [], []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDES]
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = str(p.relative_to(root))

            try:
                st = p.stat()
                size = st.st_size
                is_exec = bool(st.st_mode & 0o111)
            except Exception:
                size = 0
                is_exec = False

            # git-tracked?
            try:
                subprocess.check_output(['git','ls-files','--error-unmatch', rel], cwd=root, stderr=subprocess.DEVNULL)
                tracked = 'y'
            except Exception:
                tracked = ''

            try:
                status_out = subprocess.check_output(['git','status','--porcelain','--', rel], cwd=root, stderr=subprocess.DEVNULL).decode('utf-8','replace').strip()
                status = status_out[:2].strip() if status_out else ""
            except Exception:
                status = ""

            last_dt, last_author = "",""
            try:
                out = subprocess.check_output(['git','log','-1','--pretty=%cI|%an','--', rel], cwd=root, stderr=subprocess.DEVNULL).decode('utf-8','replace').strip()
                if '|' in out:
                    last_dt, last_author = out.split('|', 1)
            except Exception:
                pass

            files_rows.append({
                'path': rel,
                'ext': p.suffix.lower(),
                'size_bytes': size,
                'exec': 'y' if is_exec else '',
                'git_tracked': tracked,
                'git_status': status,
                'lfs_pointer': 'y' if rel in lfs_set else '',
                'last_commit': last_dt,
                'last_author': last_author,
                'legacy_should_remove': 'y' if fn in LEGACY_REMOVE or rel.startswith('legacy/2_ingest_vector') else '',
            })

            if not is_binary(p):
                cnt, first = ref_counter(root, p)
                refs_rows.append({
                    'path': rel,
                    'ref_count_approx': cnt,
                    'first_hit': first,
                })

    with open(inv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['path','ext','size_bytes','exec','git_tracked','git_status','lfs_pointer','last_commit','last_author','legacy_should_remove'])
        w.writeheader()
        w.writerows(files_rows)

    with open(refs_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['path','ref_count_approx','first_hit'])
        w.writeheader()
        w.writerows(refs_rows)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
