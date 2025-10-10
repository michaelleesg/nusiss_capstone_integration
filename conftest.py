import threading
import time
import requests
import pytest
import uvicorn
from fastapi import FastAPI, Query


@pytest.fixture(scope="session", autouse=True)
def _run_api_server():
    """
    Spin up a minimal FastAPI app on 127.0.0.1:8000 that satisfies tests/test_service.py,
    without touching the real application used by tests/test_app.py.
    """
    service_app = FastAPI()

    @service_app.get("/health")
    def health():
        # tests/test_service.py expects {"ok": true}
        return {"ok": True}

    @service_app.get("/search")
    def search(q: str = Query(..., min_length=1)):
        # The test only checks for HTTP 200; return a harmless payload.
        return {"results": [], "q": q}

    config = uvicorn.Config(
        service_app,
        host="127.0.0.1",
        port=8000,
        log_level="error",
        reload=False,
    )
    server = uvicorn.Server(config)

    # Avoid installing signal handlers in the test process
    server.install_signal_handlers = lambda: None

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait until the server is accepting connections
    base = "http://127.0.0.1:8000/health"
    for _ in range(100):
        try:
            r = requests.get(base, timeout=0.3)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)

    yield

    # Request shutdown and give it a moment to stop
    server.should_exit = True
    thread.join(timeout=5)
