from fastapi.testclient import TestClient

from api.search_api_rich import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}



def test_version_unit(client):
    r = client.get("/version")
    assert r.status_code == 200
    data = r.json()
    assert data.get("name") == "agent-b-heva"
    assert data.get("version") == "0.1.0"

def test_version(client):
    r = client.get("/version")
    assert r.status_code == 200
    data = r.json()
    assert data.get("name") == "agent-b-heva"
    assert data.get("version") == "0.1.0"
