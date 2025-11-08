# conftest.py (at repo root)
import os

import pytest
from fastapi.testclient import TestClient

import os
os.environ.setdefault("HEVA_SKIP_QDRANT", "1")
from api.search_api_rich import app

# Ensure tests don’t try to hit real Qdrant unless you want them to
os.environ.setdefault("HEVA_SKIP_QDRANT", "1")


@pytest.fixture(scope="session")
def client():
    """FastAPI TestClient for fast, in-process tests."""
    with TestClient(app) as c:
        yield c
