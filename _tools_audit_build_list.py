import csv, pathlib, fnmatch
root = pathlib.Path("_inventory")
refs = {r['path']: int((r['ref_count_approx'] or 0)) for r in csv.DictReader(open(root/"refs_summary_fast.csv", encoding='utf-8'))}
inv  = list(csv.DictReader(open(root/"files_inventory.csv", encoding='utf-8')))
INCLUDE_PATTERNS = [
  ".aider*", ".coverage", ".env", ".ruff_cache/**",
  "dir_listing.txt", "latest_recommendations.txt", "lands.csv",
  "Makefile.bak.*", "Makefile.addon",
  "capstone_agent_a/out/*.json", "capstone_agent_a/output.txt",
  "tests/test_all.py.tmp", "cybersage_deploy_bundle.zip", "IS06_*.pdf",
  "qdrant_storage/.lock", "qdrant_storage/.qdrant_fs_check",
]
def match_any(path):
    for pat in INCLUDE_PATTERNS:
        if fnmatch.fnmatch(path, pat) or ("/**" in pat and path.startswith(pat.replace("/**",""))):
            return True
    return False
cand=set()
for r in inv:
    p=r['path']
    if p.startswith("_inventory/"): continue
    if match_any(p) or refs.get(p,0)==0:
        cand.add(p)
out = root/"to_remove.csv"
with out.open('w', newline='', encoding='utf-8') as f:
    w=csv.writer(f); w.writerow(["path"]); [w.writerow([p]) for p in sorted(cand)]
print("[write]", out, "count=", len(cand))
