import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
PROMPT_AGENT = (ROOT / "PROMPT_AGENT_B.md").read_text()
PROMPT_ITER = (ROOT / "PROMPT_ITERATION.md").read_text()
TEST_SUMMARY = ""
for p in [ROOT / "artifacts/pytest.xml", ROOT / "artifacts/report.html", ROOT / "coverage.xml"]:
    if p.exists():
        TEST_SUMMARY += f"\n=== {p.name} ===\n{p.read_text()[:100000]}"


# Limit file size to avoid huge prompts; adjust as needed
def repo_snapshot():
    files = []
    for path in ROOT.rglob("*.py"):
        if any(seg in {".venv", "__pycache__", ".git"} for seg in path.parts):
            continue
        try:
            txt = path.read_text()
        except:
            continue
        if len(txt) > 100_000:  # skip huge files
            continue
        files.append({"path": str(path.relative_to(ROOT)), "content": txt})
    return files[:60]  # safety cap


client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

system_msg = "You are a meticulous code assistant. Only produce a unified diff patch."

user_msg = f"""
Repo goals:
{PROMPT_AGENT}

Iteration guidance:
{PROMPT_ITER}

Test results & artifacts (truncated):
{TEST_SUMMARY}

Provide a unified diff (git patch) that:
- Fixes failing tests or makes small safe improvements if all green.
- Keeps endpoints stable and validations explicit.
- Adds/updates tests when you change behavior.
- Does NOT touch .venv/, .git/, or notebooks.
"""

files = repo_snapshot()
user_msg += "\n\nFiles:\n" + json.dumps(files)  # model reads current codebase snapshot

resp = client.responses.create(
    model="gpt-4o-mini",
    input=[{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
)

patch = resp.output_text.strip()

if not patch.startswith("---") and "diff --git" not in patch:
    print("No patch detected. Exiting.")
    sys.exit(0)

with tempfile.NamedTemporaryFile("w", delete=False, suffix=".patch") as f:
    f.write(patch)
    patch_path = f.name

# apply patch in a branch
subprocess.run(["git", "checkout", "-b", "llm/iteration"], check=False)
rc = subprocess.run(["git", "apply", "--whitespace=fix", patch_path]).returncode
if rc != 0:
    print("Patch failed to apply.")
    sys.exit(0)

subprocess.run(["git", "add", "-A"], check=True)
subprocess.run(["git", "commit", "-m", "llm: iteration patch"], check=True)

# push and open PR
origin = os.getenv("GITHUB_SERVER_URL", "https://github.com")
repo = os.getenv("GITHUB_REPOSITORY")
if repo:
    subprocess.run(["git", "push", "origin", "HEAD:llm/iteration"], check=False)
    title = "LLM iteration patch"
    body = "Automated patch from LLM based on tests & prompts."
    subprocess.run(["gh", "pr", "create", "--fill", "--title", title, "--body", body], check=False)
