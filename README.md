# Agent B — README

Agent B is a lightweight FastAPI service that exposes semantic search and threat-intel helpers over an indexed corpus. It ships with a clean local/dev workflow, optional Docker & Compose setups, and a simple test suite so you can verify everything is working end-to-end. The steps below turn a fresh machine into a working Agent B instance with reproducible commands.

---

## Contents
- [What you’ll install](#what-youll-install)
- [Quick start (best path)](#quick-start-best-path)
- [Local dev setup (Python venv)](#local-dev-setup-python-venv)
- [Run with Docker](#run-with-docker)
- [Run with Docker Compose](#run-with-docker-compose)
- [Environment variables](#environment-variables)
- [Seed / ingest data (optional)](#seed--ingest-data-optional)
- [API usage](#api-usage)
- [Run tests & tooling](#run-tests--tooling)
- [Troubleshooting](#troubleshooting)

---

## What you’ll install

> Tested on Linux/WSL2 & macOS with Python 3.11+

- **Python 3.11+** and **pip**
- **Git**
- **Docker** and (optional) **Docker Compose** (v2+)
- (Dev only) **uvicorn** (installed via `requirements.txt`)

---

## Quick start (best path)

Use Docker Compose to bring up **Agent B** (API) and its vector DB in one go.

```bash
# 1) Clone and enter the repo
git clone https://github.com/<your-org-or-user>/<your-repo>.git agent-b
cd agent-b

# 2) Copy default envs (edit values if needed)
cp .env.example .env

# 3) Start everything (builds images on first run)
docker compose up --build
```

When it’s ready, visit:

- API docs: http://localhost:8000/docs  
- Health check: `curl http://localhost:8000/health`  
- Version: `curl http://localhost:8000/version`  

> You can stop everything with `Ctrl+C`, then `docker compose down`.

---

## Local dev setup (Python venv)

Prefer this path if you’re developing code, running tests, or iterating quickly.

```bash
# 1) Clone and enter the repo
git clone https://github.com/<your-org-or-user>/<your-repo>.git agent-b
cd agent-b

# 2) Create & activate a virtual environment
python3 -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows (PowerShell):
# .\.venv\Scripts\Activate.ps1

# 3) Upgrade pip and install deps
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4) Copy default envs (then edit if needed)
cp .env.example .env

# 5) (Optional) make sure your vector DB is reachable (local or remote)

# 6) Run the API with uvicorn
uvicorn api.search_api_rich:app --host 0.0.0.0 --port 8000
```

---

## Run with Docker

Build a single container for **Agent B** (assumes you already have a running vector DB reachable via env vars).

```bash
# From repo root
docker build -t agent-b-api .
docker run -d --name agent-b   --env-file .env   -p 8000:8000   agent-b-api
```

Stop and remove:

```bash
docker stop agent-b && docker rm agent-b
```

---

## Run with Docker Compose

If your repo includes a `docker-compose.yml` with both the API and vector DB:

```bash
docker compose up --build
# Stop & clean:
# docker compose down
```

---

## Environment variables

Create `.env` from `.env.example` and adjust as needed:

```bash
cp .env.example .env
```

Typical keys you’ll see:

```
# API
APP_ENV=dev
APP_PORT=8000

# Vector DB (Qdrant or compatible)
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=            # if your instance is secured
QDRANT_COLLECTION=heva_docs

# Embeddings / model (example)
EMBEDDING_MODEL=all-MiniLM-L6-v2
```

> If you run Qdrant in Compose alongside the API, the `QDRANT_URL` might be `http://qdrant:6333` inside the Docker network and `http://localhost:6333` for your host.

---

## Seed / ingest data (optional)

If the project contains scripts for ingesting documents (common examples below), run them **after** your vector DB is up:

```bash
# Example 1: one-shot ingestion
python scripts/chunk_and_ingest.py --input data/raw/ --collection $QDRANT_COLLECTION

# Example 2: wrapper
python ingest_wrapper.py --input data/raw/ --collection $QDRANT_COLLECTION

# Example 3: platform-specific
python 2_ingest_vector.py          # or 2_ingest_vector_wsl.py
```

> Adjust script names/paths for your repo. If you don’t need ingestion (e.g., your collection is already populated), skip this section.

---

## API usage

Start the API (any method above), then:

```bash
# Health
curl http://localhost:8000/health

# Version
curl http://localhost:8000/version

# Search (vector search over your collection)
curl "http://localhost:8000/search?q=cve"

# With filters (examples)
curl "http://localhost:8000/search?q=cve&min_score=0.25&tags=kev,blog&has_ioc=true"
curl "http://localhost:8000/search?q=cve&after=2025-01-01T00:00:00Z&before=2025-12-31T23:59:59Z"
```

Open the interactive docs at **`/docs`** to explore endpoints via Swagger UI.

---

## Run tests & tooling

```bash
# In your venv
pytest -q

# If you have pre-commit hooks configured:
pre-commit install
pre-commit run -a
```

---

## Troubleshooting

**Port in use**  
- Change `APP_PORT` in `.env`, or pass `--port 8001` to `uvicorn`, or `-p 8001:8000` in Docker/Compose.

**Auth or connection errors to vector DB**  
- Verify `QDRANT_URL` and `QDRANT_API_KEY` (if applicable).  
- Make sure the DB is running and reachable from where the API runs (host vs. container networking).

**Search call returns 400 (“Missing search query”)**  
- Use `?q=...` or `?query=...` in the request. Both are accepted.

**Large files in Git / CI failures**  
- Use `.gitignore` to exclude installers or datasets.  
- Use Git LFS for artifacts <100 MB; avoid committing >100 MB files altogether.

---

## What changed since Oct 9, 2025 (high level)

- Polished `/search` endpoint parameter handling and unified response field behavior.
- Migrated Qdrant client usage to prefer `query_points` API while retaining backward compatibility.
- Improved local/dev and Docker paths; standardized `.env` loading.
- Smoothed test and pre-commit flows for cleaner CI integration.

---

## License

Add your project license here (e.g., MIT/Apache-2.0).
