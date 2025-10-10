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
import os
from api.qdrant_client import QdrantWrapper

# === Config ===
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_PORT = 6333
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "heva_docs")
MODEL_NAME = "all-MiniLM-L6-v2"
TOP_K = 5

# === FastAPI Init ===
app = FastAPI(title="CyberNER Vector Search API")
logger = logging.getLogger("uvicorn.error")


# Health check endpoint
@app.get("/health")
def health():
    return {"status": "ok"}


# Version endpoint
@app.get("/version")
def version():
    return {"name": "agent-b-heva", "version": "0.1.0"}


logger.info("🔍 Loading model...")
model = SentenceTransformer(MODEL_NAME)
embedding_size = model.get_sentence_embedding_dimension()
logger.info(f"✅ Loaded model '{MODEL_NAME}' with vector size {embedding_size}")

# === Wait for Qdrant ===
qdrant_wrapper = QdrantWrapper()
if not qdrant_wrapper.ping():
    raise RuntimeError("❌ Qdrant not reachable.")

# Ensure collection exists
qdrant_wrapper.ensure_collection(size=embedding_size)

# === Connect Qdrant ===
client = QdrantClient(host=QDRANT_URL, port=QDRANT_PORT)
logger.info(f"✅ Connected to Qdrant at {QDRANT_URL}")

# === Verify dimension match ===
try:
    info = client.get_collection(COLLECTION_NAME)
    qdrant_dim = info.model_dump()["config"]["params"]["vectors"]["size"]
    if qdrant_dim != embedding_size:
        raise ValueError(
            f"❌ Dimension mismatch: Qdrant={qdrant_dim} vs Model={embedding_size}"
        )
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
@app.get("/search", response_model=SearchResponse)
def search(
    query: str = Query(..., description="Search sentence or phrase"), limit: int = TOP_K
):
    try:
        vector = model.encode(query).tolist()
        search_result = client.search(
            collection_name=COLLECTION_NAME, query_vector=vector, limit=limit
        )

        results = []
        for hit in search_result:
            payload = hit.payload or {}
            results.append(
                SearchResult(
                    text=payload.get("text", "<missing>"),
                    tokens=payload.get("tokens", []),
                    labels=payload.get("labels", []),
                    tags=payload.get("tags", []),
                    score=round(hit.score, 4),
                )
            )

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
        "collection": COLLECTION_NAME,
    }
