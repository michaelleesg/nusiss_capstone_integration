import os
import requests
import pytest


@pytest.mark.skipif(os.getenv("RUN_EXTERNAL") != "1", reason="Set RUN_EXTERNAL=1 to run this test")
def test_health():
    r = requests.get("http://127.0.0.1:8000/health", timeout=5)
    assert r.status_code == 200
    assert r.json() == {"ok": True}


@pytest.mark.skipif(os.getenv("RUN_EXTERNAL") != "1", reason="Set RUN_EXTERNAL=1 to run this test")
def test_search_smoke():
    r = requests.get("http://127.0.0.1:8000/search", params={"q": "cve"})
    assert r.status_code == 200
    assert r.text.strip().startswith("{") or r.text.strip().startswith("[")


import os
import threading
import time

import pytest
import requests
import uvicorn

from api.search_api_rich import app

pytestmark = pytest.mark.skipif(
    not os.getenv("RUN_EXTERNAL"),
    reason="Set RUN_EXTERNAL=1 to run external smoke test.",
)


def _run_server():
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="error",
        reload=False,
    )
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    server.run()


def test_external_health():
    # Start server in background
    t = threading.Thread(target=_run_server, daemon=True)
    t.start()

    # Wait for it to be ready
    url = "http://127.0.0.1:8000/health"
    for _ in range(100):
        try:
            r = requests.get(url, timeout=0.3)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.05)

    r = requests.get(url, timeout=2)
    assert r.status_code == 200
    assert r.json() == {"ok": True}
