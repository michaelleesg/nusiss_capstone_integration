from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import SearchRequest, Filter, FieldCondition, MatchValue
from fastapi.responses import JSONResponse
import logging
import os

# === Config ===
QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "ner_vectors")
MODEL_NAME = "all-MiniLM-L6-v2"
TOP_K = 1

# === Initialize app ===
app = FastAPI(title="CyberNER Vector Search API")

# === Logging ===
logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.INFO)

# === Load model ===
logger.info("🔍 Loading model...")
model = SentenceTransformer(MODEL_NAME)
vector_size = model.get_sentence_embedding_dimension()
logger.info(f"✅ Loaded model '{MODEL_NAME}' with vector size {vector_size}")

# === Connect to Qdrant ===
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
logger.info(f"✅ Connected to Qdrant at {QDRANT_HOST}:{QDRANT_PORT}")

# === Validate Qdrant Collection Vector Size ===
try:
    collection_info = client.get_collection(COLLECTION_NAME)
    stored_size = collection_info.model_dump()["config"]["params"]["vectors"]["size"]

    if stored_size != vector_size:
        raise ValueError(
            f"❌ Vector size mismatch: model ({vector_size}) ≠ Qdrant collection ({stored_size}). "
            f"Please recreate the collection using correct vector size."
        )

    logger.info(f"✅ Vector size matches: {stored_size}")
except Exception as e:
    logger.error(f"❌ Failed to validate collection: {e}")
    raise

# === Response Schemas ===
class SearchResult(BaseModel):
    text: str
    score: float

class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]

# === IOC Detection ===
import re

CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOM_RE = re.compile(r"\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b", re.I)
HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)

def detect_ioc(q: str):
    if CVE_RE.search(q):   return ("ioc.cves", CVE_RE.search(q).group(0).upper())
    if IP_RE.search(q):    return ("ioc.ips", IP_RE.search(q).group(0))
    if DOM_RE.search(q):   return ("ioc.domains", DOM_RE.search(q).group(0).lower())
    if HASH_RE.search(q):  return ("ioc.hashes", HASH_RE.search(q).group(0).lower())
    return None

# === Search Endpoint ===
@app.get("/search", response_model=SearchResponse)
def search(query: str = Query(..., description="Search sentence or phrase"), limit: int = TOP_K):
    hit = detect_ioc(query)
    if hit:
        key, val = hit
        # exact payload-filter scroll
        qfilter = Filter(must=[FieldCondition(key=key, match=MatchValue(value=val))])
        scrolled = client.scroll(collection_name=COLLECTION_NAME, limit=limit, with_payload=True, filter=qfilter)
        payload_hits = []
        for pt in scrolled[0]:
            payload_hits.append(
                SearchResult(text=pt.payload.get("text", "<no text>"), score=1.0)
            )
        if payload_hits:
            return SearchResponse(query=query, results=payload_hits)
    # fall through to vector search if none found
    vector = model.encode(query).tolist()
    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector,
        limit=limit
    )

    results = [
        SearchResult(
            text=hit.payload.get("text", "<no text>"),
            score=round(hit.score, 4)
        )
        for hit in search_result
    ]

    return SearchResponse(query=query, results=results)

# === Health Check ===
@app.get("/")
def root():
    return {
        "message": "🧠 Semantic Search API is running",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME
    }
