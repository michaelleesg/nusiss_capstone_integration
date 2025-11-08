import csv
import pathlib
import subprocess

root = pathlib.Path("/home/mike/capstone_win").resolve()
out = pathlib.Path("_inventory/files_inventory_quick.csv")
out.parent.mkdir(parents=True, exist_ok=True)
lfs = set()
try:
    for ln in subprocess.check_output(["git", "lfs", "ls-files"], cwd=root, text=True).splitlines():
        if ln.strip():
            lfs.add(ln.split()[-1])
except Exception:
    pass
rows = []
for b in subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0"):
    if not b:
        continue
    rel = b.decode("utf-8", "replace")
    p = root / rel
    try:
        st = p.stat()
        size = st.st_size
        execf = "y" if (st.st_mode & 0o111) else ""
    except Exception:
        size, execf = 0, ""
    last_dt, last_author = "", ""
    try:
        s = subprocess.check_output(
            ["git", "log", "-1", "--pretty=%cI|%an", "--", rel], cwd=root, text=True
        ).strip()
        if "|" in s:
            last_dt, last_author = s.split("|", 1)
    except Exception:
        pass
    rows.append(
        {
            "path": rel,
            "size_bytes": size,
            "exec": execf,
            "git_tracked": "y",
            "git_status": "",
            "lfs_pointer": "y" if rel in lfs else "",
            "last_commit": last_dt,
            "last_author": last_author,
        }
    )
with out.open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(
        f,
        fieldnames=[
            "path",
            "size_bytes",
            "exec",
            "git_tracked",
            "git_status",
            "lfs_pointer",
            "last_commit",
            "last_author",
        ],
    )
    w.writeheader()
    w.writerows(rows)
print("[write]", out)
