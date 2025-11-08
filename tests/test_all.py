"""
Unified tests for CyberNER API.

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
from typing import Any

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
# =========================


def test_health_unit(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_openapi_has_ingest_unit(client: TestClient):
    spec = client.get("/openapi.json").json()
    assert "/ingest" in spec.get("paths", {})


def test_ingest_stub_and_search_unit(client: TestClient):
    docs: list[dict[str, Any]] = [
        {"id": "t-1", "text": "CVE-2021-44228 issue", "metadata": {"cves": ["CVE-2021-44228"]}},
        {"id": "t-2", "text": "beaconing to 203.0.113.10", "metadata": {"ips": ["203.0.113.10"]}},
    ]
    r = client.post("/ingest", json=docs)
    assert r.status_code == 200
    out = r.json()
    # In skip mode, endpoint reports success; schema includes "ingested"
    assert out.get("ingested") == 2

    r2 = client.get("/search", params={"q": "CVE-2021-44228", "limit": 3})
    assert r2.status_code == 200
    js = r2.json()
    assert js.get("query") == "CVE-2021-44228"


def test_search_empty_query_validation_unit(client: TestClient):
    # Mirrors your service test expectation (422 on empty query)
    r = client.get("/search", params={"q": ""})
    assert r.status_code in (400, 422)


def test_search_smoke_unit(client: TestClient):
    # Just check we get JSON-ish output
    r = client.get("/search", params={"q": "cve"})
    assert r.status_code == 200
    txt = r.text.strip()
    assert txt.startswith("{") or txt.startswith("[")


# =========================
# External smokes (opt-in)
# =========================

RUN_EXTERNAL = os.getenv("RUN_EXTERNAL") == "1"


def _wait_for_health(url: str, timeout_s: float = 10.0) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            resp = requests.get(url, timeout=0.5)
            if resp.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise AssertionError(f"Health check not ready at {url}")


@pytest.mark.skipif(not RUN_EXTERNAL, reason="Set RUN_EXTERNAL=1 to run external smoke tests.")
def test_external_health():
    """
    External health check:
      - If RUN_EXTERNAL_INLINE=1, boot uvicorn in-thread and hit 127.0.0.1:8000.
      - Otherwise, assume a live server is already running (e.g., docker compose).
    """
    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8000"))
    url = f"http://{host}:{port}/health"

    if os.getenv("RUN_EXTERNAL_INLINE") == "1":
        import uvicorn

        def _run_server():
            config = uvicorn.Config(app, host=host, port=port, log_level="error", reload=False)
            server = uvicorn.Server(config)
            server.install_signal_handlers = lambda: None  # avoid signal handlers in tests
            server.run()

        t = threading.Thread(target=_run_server, daemon=True)
        t.start()

    _wait_for_health(url)
    assert requests.get(url, timeout=2).status_code == 200


@pytest.mark.skipif(not RUN_EXTERNAL, reason="Set RUN_EXTERNAL=1 to run external smoke tests.")
def test_external_ingest_then_search():
    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8000"))
    base = f"http://{host}:{port}"

    _wait_for_health(f"{base}/health")

    # Ingest one doc (server accepts string ids; in prod compose this hits real Qdrant)
    docs = [
        {"id": "ext-1", "text": "CVE-2021-44228 hello", "metadata": {"cves": ["CVE-2021-44228"]}}
    ]
    r_ing = requests.post(f"{base}/ingest", json=docs, timeout=5)
    assert r_ing.status_code in (200, 201)

    # Basic search smoke
    r2 = requests.get(f"{base}/search", params={"q": "CVE-2021-44228", "limit": 3}, timeout=5)
    assert r2.status_code == 200
    txt = r2.text.strip()
    assert txt.startswith("{") or txt.startswith("[")


def test_version_unit(client: TestClient):
    r = client.get("/version")
    assert r.status_code == 200
    data = r.json()
    assert data.get("name") == "agent-b-heva"
    assert data.get("version") == "0.1.0"


def test_version(client: TestClient):
    r = client.get("/version")
    assert r.status_code == 200
    data = r.json()
    assert data.get("name") == "agent-b-heva"
    assert data.get("version") == "0.1.0"
