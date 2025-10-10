<<<<<<< HEAD
from fastapi.testclient import TestClient

from api.search_api_rich import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"ok": True}

=======
import pytest
from fastapi.testclient import TestClient
from 3_search_api_rich import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
>>>>>>> d62ee72 (feat: refactor and scaffold Agent B (HEVA) with FastAPI and Qdrant integration)


def test_version():
    response = client.get("/version")
    assert response.status_code == 200
    assert response.json() == {"name": "agent-b-heva", "version": "0.1.0"}
