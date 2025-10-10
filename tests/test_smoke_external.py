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
