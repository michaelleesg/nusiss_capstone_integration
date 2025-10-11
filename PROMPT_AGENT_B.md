# Agent B: Requirements

## Purpose
- Serve RAG APIs for Agent C: /health, /search, /ingest status.
- Ingest normalized JSON either via:
  - webhook from Agent A, or
  - polling a folder/bucket for new normalized JSON (pickup).

## Interfaces
- /search accepts ?q= or ?query= and returns 200 with results, 400 if missing query.
- /ingest POST (JSON list or single doc) adds docs to the vector store and returns counts.
- Optional: background polling job to pickup normalized JSON.

## Constraints
- Only commit changes that keep `pytest -q` green.
- Preserve public endpoints & response shapes used in tests.
- No secret rotation, infra changes, or vendoring big models.

## Tests / Technical report (due 6-Oct)
- Unit + service tests must validate ingestion/search and produce:
  - coverage,
  - pytest JUnit XML,
  - an HTML/Markdown report in `capstone_report/`.

