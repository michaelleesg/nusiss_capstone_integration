#!/usr/bin/env bash
set -euo pipefail

HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8000/health}"
SEARCH_URL="${SEARCH_URL:-http://127.0.0.1:8000/search}"
SMOKE_Q="${SMOKE_Q:-"cve"}"     # a query that should always return something
TIMEOUT="${TIMEOUT:-5}"

echo "[healthcheck] Checking ${HEALTH_URL}"
code=$(curl -sS -m "$TIMEOUT" -o /dev/null -w "%{http_code}" "$HEALTH_URL")
if [[ "$code" != "200" ]]; then
  echo "[healthcheck] FAIL: /health returned $code"
  exit 1
fi

echo "[healthcheck] Checking ${SEARCH_URL}?q=${SMOKE_Q}"
resp=$(curl -sS -m "$TIMEOUT" "${SEARCH_URL}?q=${SMOKE_Q}" || true)
# VERY loose check: non-empty JSON-ish response
if [[ -z "$resp" || "$resp" != *"{"* ]]; then
  echo "[healthcheck] FAIL: /search empty or non-json"
  exit 2
fi

echo "[healthcheck] OK"

