import threading
import time
import requests
import pytest
import uvicorn

# Import the FastAPI app that the service tests expect to be running at 127.0.0.1:8000
from api.search_api_rich import app


@pytest.fixture(scope="session", autouse=True)
def _run_api_server():
    """
    Start the FastAPI app on 127.0.0.1:8000 for tests that hit real HTTP endpoints,
    then tear it down after the test session.
    """
    config = uvicorn.Config(
        app,
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
            requests.get(base, timeout=0.3)
            break
        except Exception:
            time.sleep(0.1)

    yield

    # Request shutdown and give it a moment to stop
    server.should_exit = True
    thread.join(timeout=5)
