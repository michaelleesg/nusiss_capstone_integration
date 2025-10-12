from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List, Optional
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import SearchRequest
from fastapi.responses import JSONResponse
import logging
import httpx
import os
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
    return {"status": "ok"}

# Version endpoint
@app.get("/version")
def version():
    return {"name": "agent-b-heva", "version": "0.1.0"}

# === Search Endpoint ===
class SearchResult(BaseModel):
    score: float
    payload: dict
    id: str

class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]

@app.get("/search", response_model=SearchResponse)
def search(
    query: str = Query(..., description="Search sentence or phrase"),
    limit: int = Query(5, description="Number of results to return"),
    min_score: Optional[float] = Query(0, description="Minimum score for results"),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter"),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    doc_id: Optional[str] = Query(None, description="Filter by document ID"),
    after: Optional[str] = Query(None, description="Filter by published date after"),
    before: Optional[str] = Query(None, description="Filter by published date before"),
    has_ioc: Optional[bool] = Query(None, description="Filter by presence of IOCs")
):
    # Build Qdrant filter
    filter_conditions = {}
    if tags:
        filter_conditions["tags"] = {"$all": tags.split(",")}
    if source_type:
        filter_conditions["source_type"] = source_type
    if doc_id:
        filter_conditions["doc_id"] = doc_id
    if after:
        filter_conditions["published_at"] = {"$gte": after}
    if before:
        filter_conditions["published_at"] = {"$lte": before}
    if has_ioc:
        filter_conditions["ioc.cves"] = {"$exists": True, "$ne": []}
        filter_conditions["ioc.ips"] = {"$exists": True, "$ne": []}
        filter_conditions["ioc.domains"] = {"$exists": True, "$ne": []}
        filter_conditions["ioc.hashes"] = {"$exists": True, "$ne": []}

    # Perform vector search
    vector = SentenceTransformer(MODEL_NAME).encode(query).tolist()
    search_result = client.search(
        collection_name=COLLECTION_NAME,
        query_vector=vector,
        limit=limit,
        filter=filter_conditions
    )

    results = []
    for hit in search_result:
        if hit.score >= min_score:
            results.append(SearchResult(score=hit.score, payload=hit.payload, id=hit.id))

    return SearchResponse(query=query, results=results)

# === Health Check ===
@app.get("/")
def root():
    return {
        "message": "🧠 CyberNER Semantic Search is up",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME
    }
