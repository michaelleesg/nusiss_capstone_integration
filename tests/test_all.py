"""
Unified tests for CyberNER API

- Unit & service tests (default): run fast, offline, no Qdrant required.
  We set HEVA_SKIP_QDRANT=1 and use FastAPI TestClient.

- External smoke tests (opt-in): set RUN_EXTERNAL=1 to hit a live server.
  Optionally set RUN_EXTERNAL_INLINE=1 to boot uvicorn in-thread for local smoke.

Env knobs:
  HEVA_SKIP_QDRANT=1     # used for unit/service client fixture
  RUN_EXTERNAL=1         # enable external smoke tests
  RUN_EXTERNAL_INLINE=1  # start uvicorn in-thread for external tests
"""

import os
import threading
import time
from typing import Dict, Any, List

import pytest
import requests
from fastapi.testclient import TestClient

# -------- Unit/Service fixtures (offline) --------
# Force the app to skip real Qdrant for unit tests (fast & deterministic)
os.environ.setdefault("HEVA_SKIP_QDRANT", "1")

from api.search_api_rich import app  # noqa: E402  (import after env set)


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


# =========================
# Unit / Service-style tests
# (adapted from your existing test files)
# =========================

def test_health_unit(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}  # from test_app.py :contentReference[oaicite:3]{index=3}


def test_version_unit(client: TestClient):
    r = client.get("/version")
    assert r.status_code == 200
    assert r.json() == {"name": "agent-b-heva", "version": "0.1.0"}  # :contentReference[oaicite:4]{index=4}


def test_openapi_has_ingest_unit(client: TestClient):
    spec = client.get("/openapi.json").json()
    assert "/ingest" in spec.get("paths", {})


def test_ingest_stub_and_search_unit(client: TestClient):
    docs: List[Dict[str, Any]] = [
        {"id": "t-1", "text": "CVE-2021-44228 issue", "metadata": {"cves": ["CVE-2021-44228"]}},
        {"id": "t-2", "text": "beaconing to 203.0.113.10", "metadata": {"ips": ["203.0.113.10"]}},
    ]
    r = client.post("/ingest", json=docs)
    assert r.status_code == 200
    out = r.json()
    # In skip mode, endpoint reports success; schema includes "ingested"
    assert "ingested" in out and out["ingested"] == 2

    r2 = client.get("/search", params={"q": "CVE-2021-44228", "limit": 3})
    assert r2.status_code == 200
    js = r2.json()
    assert js.get("query") == "CVE-2021-44228"


def test_search_empty_query_validation_unit(client: TestClient):
    # Mirrors your service test expectation (422 on empty query) :contentReference[oaicite:5]{index=5}
    r = client.get("/search", params={"q": ""})
    assert r.status_code == 422


def test_search_smoke_unit(client: TestClient):
    # Don’t overfit assertions—just check JSON-ish response (from your tests) :contentReference[oaicite:6]{index=6}
    r = client.get("/search", params={"q": "cve"})
    assert r.status_code == 200
    assert r.text.strip().startswith("{") or r.text.strip().startswith("[")


# =========================
# External smokes (opt-in)
# =========================

RUN_EXTERNAL = os.getenv("RUN_EXTERNAL") == "1"
pytestmark_external = pytest.mark.skipif(not RUN_EXTERNAL, reason="Set RUN_EXTERNAL=1 to run external smoke tests.")


def _wait_for_health(url: str, timeout_s: float = 10.0):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            r = requests.get(url, timeout=0.5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.2)
    raise AssertionError(f"Health check not ready at {url}")


@pytest.mark.usefixtures()
@pytest.mark.skipif(not RUN_EXTERNAL, reason="Set RUN_EXTERNAL=1 to run external smoke tests.")
def test_external_health():
    """
    External health check:
      - If RUN_EXTERNAL_INLINE=1, we boot uvicorn in-thread and hit 127.0.0.1:8000.
      - Otherwise, assume a live server is already running (e.g., via docker compose).
    """
    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8000"))
    url = f"http://{host}:{port}/health"

    if os.getenv("RUN_EXTERNAL_INLINE") == "1":
        # Start uvicorn in another thread (pattern adapted from your smoke test) :contentReference[oaicite:7]{index=7}
        import uvicorn

        def _run_server():
            config = uvicorn.Config(app, host=host, port=port, log_level="error", reload=False)
            server = uvicorn.Server(config)
            # avoid signal handlers in tests
            server.install_signal_handlers = lambda: None
            server.run()

        t = threading.Thread(target=_run_server, daemon=True)
        t.start()

    _wait_for_health(url)
    r = requests.get(url, timeout=2)
    assert r.status_code == 200
    assert r.json() == {"ok": True}  # :contentReference[oaicite:8]{index=8}


@pytest.mark.skipif(not RUN_EXTERNAL, reason="Set RUN_EXTERNAL=1 to run external smoke tests.")
def test_external_ingest_then_search():
    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8000"))
    base = f"http://{host}:{port}"

    _wait_for_health(f"{base}/health")

    # Ingest one doc (server accepts string ids; in prod compose this hits real Qdrant)
    docs = [{"id": "ext-1", "text": "CVE-2021-44228 hello", "metadata": {"cves": ["CVE-2021-44228"]}}]
    r = requests.post(f"{base}/ingest", json=docs, timeout=5)
    assert r.status_code == 200

    # Basic search smoke (pattern adapted from your external test) :contentReference[oaicite:9]{index=9}
    r2 = requests.get(f"{base}/search", params={"q": "CVE-2021-44228", "limit": 3}, timeout=5)
    assert r2.status_code == 200
    assert r2.text.strip().startswith("{") or r2.text.strip().startswith("[")
