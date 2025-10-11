# Iteration Tasking

- If tests fail, propose minimal diffs to fix.
- If all tests pass, make small refactors: typing, docstrings, tighten validation, better error messages.
- Ensure `/search` supports ?q= or ?query= and returns 400 if neither is provided.
- Keep FastAPI TestClient for unit/service tests; keep exactly one external smoke test.
- Keep ingestion path: POST /ingest and/or background pickup watcher.
- Update or add tests as needed to keep behavior covered.
- Never touch .venv, do not reformat notebooks.

