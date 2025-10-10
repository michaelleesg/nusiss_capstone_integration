import logging
import os
from typing import List, Optional

from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.http.models import FieldCondition, Filter, MatchValue, Range
from sentence_transformers import SentenceTransformer

from api.qdrant_client import QdrantWrapper

# === Config ===
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "heva_docs")
MODEL_NAME = "all-MiniLM-L6-v2"
TOP_K = 5

# === FastAPI Init ===
app = FastAPI(title="CyberNER Vector Search API")
logger = logging.getLogger("uvicorn.error")


# Health check endpoint
@app.get("/health")
def health():
    # Align with tests expecting {"ok": True}
    return {"ok": True}


# Version endpoint
@app.get("/version")
def version():
    return {"name": "agent-b-heva", "version": "0.1.0"}


# === Initialize Qdrant Client ===
client = QdrantClient(url=QDRANT_URL)

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
    score: float
    payload: dict
    id: str


class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]


# === /search Endpoint ===
@app.get("/search", response_model=SearchResponse)
def search(
    q: Optional[str] = Query(None, min_length=1, description="Search term", alias="q"),
    query: Optional[str] = Query(None, min_length=1, description="Alias for q"),
    limit: int = Query(5, description="Number of results to return"),
    min_score: Optional[float] = Query(0, description="Minimum score for results"),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter"),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    doc_id: Optional[str] = Query(None, description="Filter by document ID"),
    after: Optional[str] = Query(None, description="Filter by published date after"),
    before: Optional[str] = Query(None, description="Filter by published date before"),
    has_ioc: Optional[bool] = Query(None, description="Filter by presence of IOCs"),
):
    term = q or query
    if not term:
        # Be explicit instead of letting Pydantic throw a 422
        raise HTTPException(status_code=400, detail="Missing search query ('q' or 'query')")
    
    # Build Qdrant Filter (must = AND of simple conditions)
    must = []
    tag_list = [t for t in (tags.split(",") if tags else []) if t]
    for t in tag_list:
        must.append(FieldCondition(key="tags", match=MatchValue(value=t)))
    if source_type:
        must.append(FieldCondition(key="source_type", match=MatchValue(value=source_type)))
    if doc_id:
        must.append(FieldCondition(key="doc_id", match=MatchValue(value=doc_id)))

    # Date filtering expects numeric; use published_at_ts in payload
    def to_ts(s: Optional[str]) -> Optional[int]:
        if not s:
            return None
        try:
            from datetime import datetime

            return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
        except Exception:
            return None

    gte = to_ts(after)
    lte = to_ts(before)
    if gte is not None or lte is not None:
        rng = Range(gte=gte, lte=lte)
        must.append(FieldCondition(key="published_at_ts", range=rng))
    qfilter = Filter(must=must) if must else None

    # Perform vector search
    vector = model.encode(term).tolist()
    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector,
        limit=limit,
        query_filter=qfilter,
    )

    def ioc_present(p: dict) -> bool:
        if not p:
            return False
        i = p.get("ioc", {})
        return any(i.get(k) for k in ("cves", "ips", "domains", "hashes"))

    results: List[SearchResult] = []
    for hit in search_result:
        if hit.score < (min_score or 0):
            continue
        if has_ioc and not ioc_present(hit.payload or {}):
            continue
        results.append(
            SearchResult(
                score=round(float(hit.score), 4),
                payload=hit.payload or {},
                id=str(hit.id),
            )
        )

    return SearchResponse(query=query, results=results)


# === Health Check ===
@app.get("/")
def root():
    return {
        "message": "🧠 CyberNER Semantic Search is up",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME,
    }
