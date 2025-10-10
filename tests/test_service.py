import os

import requests

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000")


def test_health():
    r = requests.get(f"{BASE}/health", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True


def test_search_smoke():
    r = requests.get(f"{BASE}/search", params={"q": "cve"}, timeout=5)
    assert r.status_code == 200
    # Don’t overfit assertions—just check it’s JSON-ish:
    assert r.text.strip().startswith("{") or r.text.strip().startswith("[")
