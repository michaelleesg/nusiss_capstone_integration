# syntax=docker/dockerfile:1

FROM python:3.11-slim AS base

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

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# ----- Python deps -----
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ----- App files -----
COPY 3_search_api_rich.py /app/3_search_api_rich.py
COPY api/qdrant_client.py /app/api/qdrant_client.py

# Default to API server
EXPOSE 8000
CMD ["uvicorn", "3_search_api_rich:app", "--host", "0.0.0.0", "--port", "8000"]
