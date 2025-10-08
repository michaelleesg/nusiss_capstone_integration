# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    TRANSFORMERS_NO_ADVISORY_WARNINGS=1

# System deps (curl for healthchecks, git optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# Create app dir
WORKDIR /app

# ----- Python deps -----
# Torch CPU wheel first (fast, smaller)
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch

# Core libs
RUN pip install --no-cache-dir \
    fastapi uvicorn[standard] \
    qdrant-client \
    sentence-transformers \
    numpy httpx tqdm pydantic

# ----- App files -----
# Copy only what we need
COPY 3_search_api_rich.py /app/3_search_api_rich.py
# A tiny ingestion wrapper that reads env vars (see below). If you already
# have a suitable script, copy that instead and adjust compose command.
COPY ingest_wrapper.py /app/ingest_wrapper.py

# Default to API server; ingestion will override the CMD in docker-compose
EXPOSE 8000
CMD ["uvicorn", "3_search_api_rich:app", "--host", "0.0.0.0", "--port", "8000"]
