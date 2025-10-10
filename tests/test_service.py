import os


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_search_empty_query(client):
    r = client.get("/search", params={"q": ""})
    assert r.status_code == 422  # Expecting a validation error for empty query

def test_search_smoke(client):
    r = client.get("/search", params={"q": "cve"})
    assert r.status_code == 200
    # Don’t overfit assertions—just check it’s JSON-ish:
    assert r.text.strip().startswith("{") or r.text.strip().startswith("[")
