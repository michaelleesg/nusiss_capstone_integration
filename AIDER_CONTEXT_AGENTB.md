# Aider Context: CyberSage – Agent B (HEVA)

## 🧩 Repository
This aider session operates on:
**REPO_A = /mnt/c/Users/mike/Downloads/capstone**

This is the primary code repository for the **CyberSage** platform, an NUS-ISS MTech (AI Systems) capstone project.  
CyberSage is a multi-agent threat-intelligence analysis system built with FastAPI + Qdrant + LangChain.  
Do not modify or reference the evaluation or report repository unless explicitly told (`/mnt/c/Users/mike/Downloads/cybersage_eval`).

---

## 🧠 Current Focus – Agent B (HEVA)
You are working on **Agent B: Historical Evidence Vector Agent (HEVA)**.  
HEVA ingests CTI artifacts (CVE, ATT&CK, MISP, vendor advisories), vectorizes them, and exposes a retrieval API for Agent C (Threat Scoring) and Agent D (Assurance).

### Responsibilities
- Ingest → normalize → chunk → embed → index (dense + sparse).  
- Support IOC filtering, hybrid retrieval, reranking, and provenance-aware explanations.  
- Provide observability metrics, governance metadata, and evaluation hooks.  
- Integrate with CI (pytest + DeepEval) and output model/version info for traceability.  
- Comply with IMDA Responsible-AI and AIC Practice Module standards (Explainability, Fairness, Security, Governance).

---

## 🧱 Project Baseline
- **Language:** Python 3.11  
- **Framework:** FastAPI  
- **Vector DB:** Qdrant 1.11+ (via `qdrant-client`)  
- **Embedding Model:** MiniLM-L6-v2 (384 dims, configurable via env)  
- **Collections:** Dual index (dense + sparse BM25)  
- **Chunk size:** 512 tokens + 128 overlap  
- **Date-decay:** λ = 0.05, half-life = 180 days  
- **Scoring:** S = 0.6 *dense + 0.4 *sparse + 1.0 *ioc + decay  
- **API limit:** 1 MB ingest, 64 KB search, 60 rpm rate limit  
- **Metrics:** Prometheus /metrics exporter + Grafana dashboard JSON  

---

## 🚀 Objectives for This Sprint (week of 22 Oct 2025)
1. **Implement validated ingest schema** (`schemas/ingest_artifact.schema.json` + Pydantic model).  
2. **Add FastAPI endpoints:**
   - `/ingest/artifact`, `/search`, `/version`, `/metrics`, `/admin/remove|purge`.  
3. **Wire Qdrant dual-index creation** (`heva_v1`, dense 384 + sparse bm25).  
4. **Hybrid retrieval logic** (dense + sparse merge + IOC fallback + date-decay + explanations).  
5. **Test & Evaluation suite** under `eval/`: pytest + DeepEval (Recall@10 ≥ 0.85, nDCG@10 ≥ 0.75, IOC F1 ≥ 0.9).  
6. **Observability** (Prometheus metrics + Grafana JSON panels).  
7. **Governance & Model Card** under `docs/` (model_card_heva.md, governance_imda.md).  
8. **Client Library** (`clients/agent_b_client.py`) + OpenAPI YAML.  
9. **Makefile + CI workflow** for reproducible evaluation.

---

## 🧩 Guidance to Aider
- Treat this as a live, code-first engineering task.
- Assume FastAPI app in `/app/main.py`; create submodules (`qdrant_setup.py`, `indexer.py`, `retrieval.py`).  
- Use PEP 8 and Ruff lint.  
- If directories don’t exist, create them.  
- Only modify **Agent B-related files**. Do NOT change Agents A, C, D.  
- Add docstrings, type hints, and minimal example tests.
- Add examples and metrics in README.md.

---

## ✅ Acceptance criteria
- `/version` returns model, collection, and weights.  
- `/ingest/artifact` creates ≥1 chunk with metadata matching Agent C schema.  
- `/search` returns explanation.signal_breakdown and provenance_bundle.  
- `pytest` + `deepeval` pass with required thresholds.  
- `/metrics` exports the 5 named Prometheus series.  
- Grafana dashboard JSON exists and is loadable.  
- Governance docs present and referenced in README.  
- CI pipeline enforces eval thresholds.

---

## 🏁 Next step
After this context, immediately apply the **“Detailed Agent B Implementation Plan”** prompt (the one starting with “You are Aider, working in the repo at /mnt/c/Users/mike/Downloads/capstone…”).

Execute all steps, create every missing folder/file, and ensure tests pass locally.
Commit with message:  
`feat(heva): implement validated ingest, hybrid retrieval, observability, eval & governance`
