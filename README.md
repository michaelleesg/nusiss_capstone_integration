[![Smoke CI](https://github.com/michaelleesg/nus-iss-test/actions/workflows/smoke.yml/badge.svg)](https://github.com/michaelleesg/nus-iss-test/actions/workflows/smoke.yml)

# Agent B — HEVA Search API (FastAPI + Qdrant)

> Historical Evidence Vector Archive (HEVA): semantic search and threat‑intel helpers powering CyberSage Agent B.

[![Built with FastAPI](https://img.shields.io/badge/Built%20with-FastAPI-109989.svg)](#) [![Python](https://img.shields.io/badge/Python-3.11+-3776AB)](#) [![Docker Compose](https://img.shields.io/badge/Docker-Compose-blue)](#) [![License](https://img.shields.io/badge/License-Your%20Choice-informational)](#)

Agent B exposes a minimal, production‑lean **HTTP API** for **semantic retrieval** over a Qdrant collection populated by Agent A. It is designed for:
- **Local dev** (venv + uvicorn)
- **Containerized** runs (Docker/Compose)
- **CI‑friendly** testing (mockable dependencies, `HEVA_SKIP_QDRANT`)
- **Evidence‑driven** triage (filters for KEV/IOC/assets/CVEs/time windows)

---

## Contents
- [TL;DR](#tldr)
- [Install & Run](#install--run)
  - [Quick start (Docker Compose)](#quick-start-docker-compose)
  - [Local development (venv)](#local-development-venv)
  - [Single container](#single-container)
- [Configuration](#configuration)
- [Ingest / Seed](#ingest--seed)
- [API](#api)
  - [OpenAPI & discovery](#openapi--discovery)
  - [`GET /health`](#get-health)
  - [`GET /version`](#get-version)
  - [`GET /search`](#get-search)
  - [Error model](#error-model)
- [Observability](#observability)
- [Testing](#testing)
- [Security & Hardening](#security--hardening)
- [Performance Notes](#performance-notes)
- [FAQ](#faq)
- [Makefile (optional)](#makefile-optional)
- [Changelog](#changelog)
- [License](#license)

---

## TL;DR

```bash
# compose: API + Qdrant
cp .env.example .env
docker compose up --build

# then visit:
#   http://localhost:8000/docs
# or curl:
curl "http://localhost:8000/search?q=cve&min_score=0.25&tags=kev,blog&has_ioc=true"
```

---

## Install & Run

### Quick start (Docker Compose)

Runs **Agent B** (FastAPI) and **Qdrant** together.

```bash
git clone https://github.com/<your-org>/<repo>.git agent-b
cd agent-b
cp .env.example .env
docker compose up --build
```

Endpoints:
- Swagger UI: <http://localhost:8000/docs>  
- Health: `GET http://localhost:8000/health`  
- Version: `GET http://localhost:8000/version`

Stop/clean:
```bash
docker compose down
```

> **Heads‑up (WSL2/Windows):** If Compose warns about a symlink‑derived project name, it’s safe to ignore. Or set an explicit `name:` in `compose.yaml`.

### Local development (venv)

```bash
git clone https://github.com/<your-org>/<repo>.git agent-b
cd agent-b
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
# Ensure Qdrant is reachable (local or remote)
# e.g. docker run -p 6333:6333 qdrant/qdrant:latest

uvicorn api.search_api_rich:app --host 0.0.0.0 --port 8000
```

### Single container

```bash
docker build -t agent-b-api .
docker run -d --name agent-b   --env-file .env   -p 8000:8000   agent-b-api
# stop & remove
docker stop agent-b && docker rm agent-b
```

---

## Configuration

Create `.env` from `.env.example` and adjust as needed.

```ini
# API
APP_ENV=dev
APP_PORT=8000
HOST=0.0.0.0

# Vector DB (Qdrant)
QDRANT_URL=http://localhost:6333     # host usage
# QDRANT_URL=http://qdrant:6333      # service name inside Compose network
QDRANT_API_KEY=                      # set if secured
QDRANT_COLLECTION=heva_docs

# Embeddings / model
EMBEDDING_MODEL=all-MiniLM-L6-v2

# Feature flags
HEVA_SKIP_QDRANT=0                   # 1: allow tests without live Qdrant
SEARCH_DEFAULT_LIMIT=10
SEARCH_DEFAULT_MIN_SCORE=0.0
```

**Networking tip:** Inside Docker Compose, use `http://qdrant:6333`; from host, use `http://localhost:6333`.

---

## Ingest / Seed

Populate the collection **after** Qdrant is up. Your project may expose one or more of the following:

```bash
# Generic example
python scripts/chunk_and_ingest.py --input data/raw --collection $QDRANT_COLLECTION

# Wrapper
python ingest_wrapper.py --input data/raw --collection $QDRANT_COLLECTION

# Project‑specific
python 2_ingest_vector.py            # or 2_ingest_vector_wsl.py
```

Skip if your collection is already populated.

---

## API

### OpenAPI & discovery
- Swagger UI: `/docs`
- OpenAPI JSON: `/openapi.json`

> Use `/openapi.json` in downstream clients to generate typed SDKs.

### `GET /health`
Health probe for liveness/readiness.

**200 OK**
```json
{"status":"ok"}
```

### `GET /version`
Returns app build/version metadata.

**200 OK**
```json
{"name":"agent-b-heva","version":"2025.10.11","commit":"<git-sha>"}
```

### `GET /search`

**Query parameters**

| Name          | Type    | Default | Notes |
|---------------|---------|---------|------|
| `q`/`query`   | string  | —       | Required search text. |
| `limit`       | int     | `10`    | Max results to return. |
| `min_score`   | float   | `0.0`   | Filter out hits below this score. |
| `after`       | RFC3339 | —       | Include docs created/updated at or after this timestamp. |
| `before`      | RFC3339 | —       | Include docs created/updated at or before this timestamp. |
| `tags`        | csv     | —       | e.g. `kev,blog,advisory`. |
| `has_ioc`     | bool    | `false` | Require presence of IOCs. |
| `assets`      | csv     | —       | e.g. `veeam,cisco,exchange`. |
| `cves`        | csv     | —       | e.g. `CVE-2024-1234,CVE-2017-0199`. |
| `offset`      | int     | `0`     | Pagination offset (if supported). |

**Examples**

```bash
# Tuned search with filters
curl "http://localhost:8000/search?q=cve&min_score=0.25&tags=kev,blog&has_ioc=true"

# Time‑bounded
curl "http://localhost:8000/search?q=veeam&after=2025-01-01T00:00:00Z&before=2025-12-31T23:59:59Z"

# Specific CVEs and assets
curl "http://localhost:8000/search?q=remote%20code%20exec&cves=CVE-2017-0199&assets=office"
```

**Response (200 OK)**
```json
{
  "query": "cve",
  "count": 2,
  "results": [
    {
      "id": "doc-123",
      "score": 0.78,
      "title": "Remote Code Execution in XYZ",
      "summary": "…",
      "created_at": "2025-09-30T12:34:56Z",
      "tags": ["kev","advisory"],
      "ioc": {"cves":["CVE-2017-0199"], "domains":["…"], "hashes":["…"]},
      "assets": ["office","exchange"],
      "url": "https://…"
    }
  ]
}
```

### Error model

| Code | When                          | Body (shape) |
|------|-------------------------------|--------------|
| 400  | Missing/invalid query params  | `{"error":"<message>","field":"<name>"}` |
| 401  | Auth required (if enabled)    | `{"error":"unauthorized"}` |
| 404  | Resource not found            | `{"error":"not_found"}` |
| 5xx  | Upstream/Qdrant/network issues| `{"error":"internal","trace_id":"<id>"}` |

---

## Observability

- **Logging:** structured logs to stdout; include `trace_id` for correlation.
- **Metrics (optional):** expose Prometheus at `/metrics` (if `prometheus_client` enabled).
- **Tracing (optional):** OpenTelemetry exporter can be wired for Qdrant calls + request spans.

---

## Testing

```bash
# full test suite
pytest -q

# skip live Qdrant calls
export HEVA_SKIP_QDRANT=1
pytest -q -m "not external"
```

Suggested markers:
- `external`: hits live Qdrant; guard behind env flags
- `unit`: pure python tests for ranking/merging
- `api`: tests for FastAPI routes and validation

---

## Security & Hardening

- Use `QDRANT_API_KEY` and TLS on managed Qdrant.
- Run containers as non‑root; add a read‑only FS where possible.
- Rate‑limit `/search` in front (API gateway / reverse proxy).
- Sanitize outbound links in results; avoid leaking tenant‑specific data.
- Consider RBAC for future multi‑tenant deployments.

---

## Performance Notes

- Prefer compact models in dev (`all-MiniLM-L6-v2`); switch to higher‑capacity embeddings only if justified.
- Batch Qdrant queries and use `limit` conservatively.
- Apply `min_score` to reduce downstream rendering payloads.
- Cache hot queries at the edge (e.g., Cloudflare/NGINX micro‑cache).

---

## FAQ

**Q: I get port collisions on 8000/6333.**  
A: Change `APP_PORT`, use `uvicorn … --port 8001`, or map `-p 8001:8000`. For Qdrant, map `-p 6334:6333` and set `QDRANT_URL=http://localhost:6334`.

**Q: Compose can’t reach Qdrant.**  
A: Inside the compose network the hostname is `qdrant`, not `localhost`. Use `http://qdrant:6333` in the API container.

**Q: How do I paginate?**  
A: Use `offset` + `limit`. Depending on your store, you may also add `next_token` in the future for cursor‑based paging.

---

## Makefile (optional)

```Makefile
.PHONY: dev test build up down fmt lint

dev:        ## run local uvicorn dev server
	uvicorn api.search_api_rich:app --host 0.0.0.0 --port \$(APP_PORT)

test:       ## run tests
	pytest -q

build:      ## docker build
	docker build -t agent-b-api .

up:         ## docker compose up
	docker compose up --build -d

down:       ## docker compose down
	docker compose down

fmt:        ## format
	rufflehog >/dev/null 2>&1 || true
	black . && isort .

lint:       ## lint
	flake8 .
```

---

## Changelog

- **2025‑10‑11**
  - Tightened structure & anchors (TOC, sections).
  - Clarified `/search` params and examples.
  - Added error model, observability, security, performance notes.
  - Added optional Makefile targets and FAQ.
  - Documented `HEVA_SKIP_QDRANT` and common WSL2/Compose gotchas.

---

## License

Insert your license (MIT/Apache‑2.0/Proprietary).

---

## TODO (post-rebase): Eval symlink & export instructions
This section conflicted during rebase. Re-add the intended guidance here post-rebase.

- Eval symlink: (add exact command/path you want)
- Export instructions: (add your steps)
