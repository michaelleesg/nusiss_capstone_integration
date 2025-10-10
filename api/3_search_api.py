from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List, Tuple, Optional
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import SearchRequest, Filter, FieldCondition, MatchValue
from fastapi.responses import JSONResponse
import logging
import os
import re

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
CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOM_RE = re.compile(r"\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b", re.I)
HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)

def detect_ioc(q: str) -> Optional[Tuple[str, str, str]]:
    """Return (payload_key, value, kind) or None."""
    m = CVE_RE.search(q)
    if m: return ("ioc.cves", m.group(0).upper(), "cve")
    m = IP_RE.search(q)
    if m: return ("ioc.ips", m.group(0), "ip")
    m = DOM_RE.search(q)
    if m: return ("ioc.domains", m.group(0).lower(), "domain")
    m = HASH_RE.search(q)
    if m: return ("ioc.hashes", m.group(0).lower(), "hash")
    return None

def key_from_hit_id_and_payload(hit) -> str:
    """Prefer chunk_id in payload; fallback to point id."""
    p = hit.payload or {}
    return p.get("chunk_id") or str(hit.id)

def merge_and_rank(ioc_hits, vec_hits, *, ioc_bonus=1.0, vec_weight=1.0, limit=10, min_score=0.0):
    """
    ioc_hits: iterable of Qdrant points (from scroll), treated as exact matches
    vec_hits: iterable of Qdrant scored points (from client.search)
    Returns list[SearchResult] sorted by final_score desc, truncated to limit.
    """
    merged: Dict[str, dict] = {}

    # Seed with IOC hits (deterministic, high base score)
    for pt in ioc_hits or []:
        k = key_from_hit_id_and_payload(pt)
        merged[k] = {
            "id": str(pt.id),
            "payload": pt.payload or {},
            "score": 1.0 * ioc_bonus,
            "sources": {"ioc"},
        }

    # Blend vector hits
    for h in vec_hits or []:
        k = key_from_hit_id_and_payload(h)
        score = float(h.score or 0.0) * vec_weight
        if k in merged:
            # Keep max score and mark source
            merged[k]["score"] = max(merged[k]["score"], score)
            merged[k]["sources"].add("vector")
        else:
            merged[k] = {
                "id": str(h.id),
                "payload": h.payload or {},
                "score": score,
                "sources": {"vector"},
            }

    # Optionally add a small bump if payload itself has IOCs
    for v in merged.values():
        p = v["payload"]
        if p.get("has_ioc"):
            v["score"] += 0.05

    # Sort, filter, truncate
    ranked = sorted(merged.values(), key=lambda x: x["score"], reverse=True)
    ranked = [r for r in ranked if r["score"] >= (min_score or 0)]
    ranked = ranked[:limit]

    # Adapt to your response model
    return [
        SearchResult(score=round(r["score"], 4), payload=r["payload"], id=r["id"])
        for r in ranked
    ]

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
