from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import SearchRequest
from fastapi.responses import JSONResponse
import logging
import httpx
import time

# === Config ===
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
QDRANT_URL = f"http://{QDRANT_HOST}:{QDRANT_PORT}"
COLLECTION_NAME = "ner_vectors"
MODEL_NAME = "all-MiniLM-L6-v2"
TOP_K = 5

# === FastAPI Init ===
app = FastAPI(title="CyberNER Vector Search API")
logger = logging.getLogger("uvicorn.error")

logger.info("🔍 Loading model...")
model = SentenceTransformer(MODEL_NAME)
embedding_size = model.get_sentence_embedding_dimension()
logger.info(f"✅ Loaded model '{MODEL_NAME}' with vector size {embedding_size}")

# === Wait for Qdrant ===
def wait_for_qdrant(url, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(f"{url}/collections", timeout=2.0)
            if r.status_code == 200:
                logger.info("✅ Qdrant is live.")
                return
        except:
            pass
        time.sleep(1)
    raise RuntimeError("❌ Qdrant not reachable.")

wait_for_qdrant(QDRANT_URL)

# === Connect Qdrant ===
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
logger.info(f"✅ Connected to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}")

# === Verify dimension match ===
try:
    info = client.get_collection(COLLECTION_NAME)
    qdrant_dim = info.model_dump()["config"]["params"]["vectors"]["size"]
    if qdrant_dim != embedding_size:
        raise ValueError(f"❌ Dimension mismatch: Qdrant={qdrant_dim} vs Model={embedding_size}")
    logger.info(f"✅ Vector size matches: {qdrant_dim}")
except Exception as e:
    logger.error(f"❌ Could not verify vector dimensions: {e}")

# === Enhanced Response Schemas ===
class SearchResult(BaseModel):
    text: str
    tokens: List[str]
    labels: List[str]
    tags: List[str] = []
    score: float

class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]

# === /search Endpoint ===

# @app.get("/search", response_model=SearchResponse)
# def search(query: str, limit: int = 5, min_score: float = 0.6, source: str | None = None):
#     ...
#     # post-filter by score; add optional source filter using Qdrant 'filter' if desired

@app.get("/search", response_model=SearchResponse)
def search(query: str = Query(..., description="Search sentence or phrase"), limit: int = TOP_K):
    try:
        vector = model.encode(query).tolist()
        search_result = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=vector,
            limit=limit
        )

        results = []
        for hit in search_result:
            payload = hit.payload or {}
            results.append(SearchResult(
                text=payload.get("text", "<missing>"),
                tokens=payload.get("tokens", []),
                labels=payload.get("labels", []),
                tags=payload.get("tags", []),
                score=round(hit.score, 4)
            ))

        return SearchResponse(query=query, results=results)

    except Exception as e:
        logger.error(f"❌ Search failed: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# === Health Check ===
@app.get("/")
def root():
    return {
        "message": "🧠 CyberNER Semantic Search is up",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME
    }