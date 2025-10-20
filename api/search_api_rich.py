# api/search_api_rich.py
import logging
import os
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    FieldCondition,
    Filter,
    MatchAny,
    MatchValue,
    PointStruct,
    Range,
)
from sentence_transformers import SentenceTransformer

from api.qdrant_client import QdrantWrapper

# === Config ===
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "heva_docs")
MODEL_NAME = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
TOP_K = int(os.getenv("TOP_K", "5"))
SKIP_QDRANT = os.getenv("HEVA_SKIP_QDRANT") == "1"

# === FastAPI Init ===
app = FastAPI(title="CyberNER Vector Search API")
logger = logging.getLogger("uvicorn.error")


# === Health/Version/Root ===
@app.get("/health")
def health():
    return {"ok": True}


@app.get("/version")
def version():
    return {
        "name": "agent-b-heva",
        "version": "0.1.0",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME,
    }


@app.get("/")
def root():
    return {
        "message": "🧠 CyberNER Semantic Search is up",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME,
    }


# === Model (load always for consistent embeddings) ===
logger.info("🔍 Loading model...")
model = SentenceTransformer(MODEL_NAME)
embedding_size = model.get_sentence_embedding_dimension()
logger.info(f"✅ Loaded model '{MODEL_NAME}' (dim={embedding_size})")

# === Qdrant (optional in tests) ===
client: Optional[QdrantClient] = None
if not SKIP_QDRANT:
    try:
        client = QdrantClient(url=QDRANT_URL)
        qwrap = QdrantWrapper()
        if not qwrap.ping():
            raise RuntimeError("Qdrant ping failed")
        qwrap.ensure_collection(size=embedding_size)

        # Verify vector dimension
        info = client.get_collection(COLLECTION_NAME)
        qdrant_dim = info.model_dump()["config"]["params"]["vectors"]["size"]
        if int(qdrant_dim) != int(embedding_size):
            raise ValueError(f"Vector dim mismatch: Qdrant={qdrant_dim} vs Model={embedding_size}")
        logger.info(f"✅ Vector size matches: {qdrant_dim}")
    except Exception as e:
        logger.error(f"❌ Qdrant init failed: {e}")
        raise
else:
    logger.info("⏭️ HEVA_SKIP_QDRANT=1 -> skipping Qdrant init for tests.")


# === Schemas (align with your current OpenAPI) ===
class SearchResult(BaseModel):
    text: str
    tokens: List[str] = []
    labels: List[str] = []
    tags: List[str] = []
    score: float


class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]


# === IOC detection (CVE/IP/domain/SHA256) ===
IOC_RE: Dict[str, re.Pattern] = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "domain": re.compile(r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+(?:[A-Za-z]{2,63})\b"),
}


def detect_iocs(text: str) -> Dict[str, List[str]]:
    text = text or ""
    found: Dict[str, List[str]] = {}
    for key, rx in IOC_RE.items():
        hits = rx.findall(text)
        if hits:
            found[key] = [h.upper() if key == "cve" else h for h in hits]
    return found


def _ioc_filter_for_value(key: str, values: List[str]) -> Filter:
    return Filter(must=[FieldCondition(key=key, match=MatchAny(any=values))])


def exact_hits_for_iocs(
    qdrant: QdrantClient,
    collection: str,
    iocs: Dict[str, List[str]],
    limit: int = 10,
):
    """
    Fetch exact matches for detected IOCs using payload filters. Tries common keys.
    """
    gathered: List[Any] = []
    seen = set()
    key_map: Dict[str, List[str]] = {
        "cve": ["cves", "CVE", "cve", "indicators", "tags"],
        "ip": ["ips", "ip", "indicators", "tags"],
        "domain": ["domains", "domain", "indicators", "tags"],
        "sha256": ["hashes", "sha256", "indicators", "tags"],
    }
    for ioc_type, vals in iocs.items():
        if not vals:
            continue
        for payload_key in key_map.get(ioc_type, []):
            try:
                flt = _ioc_filter_for_value(payload_key, vals)
                pts, _ = qdrant.scroll(
                    collection_name=collection,
                    limit=limit,
                    with_payload=True,
                    filter=flt,
                )
                for p in pts or []:
                    if p.id in seen:
                        continue
                    seen.add(p.id)
                    gathered.append(p)
                    if len(gathered) >= limit:
                        return gathered
            except Exception:
                continue
    return gathered


# --- ID normalizer (int OR stringified UUID) ---
def normalize_point_id(raw_id):
    """
    Return a Qdrant-compatible point ID:
    - int or digit-string -> int (unsigned)
    - uuid-like string -> str(UUID)
    - anything else -> str(UUIDv5) derived from the string (stable)
    """
    # int or digit-string -> int
    if isinstance(raw_id, int) or (isinstance(raw_id, str) and raw_id.isdigit()):
        i = int(raw_id)
        if i < 0:
            raise ValueError("Point ID must be an unsigned integer")
        return i

    # uuid-like string -> str(UUID), else derive stable UUIDv5
    s = str(raw_id)
    try:
        u = UUID(s)
    except Exception:
        u = uuid.uuid5(uuid.NAMESPACE_URL, s)
    return str(u)  # IMPORTANT: return *string*, not UUID object


# === Ingest ===
class IngestItem(BaseModel):
    id: str
    text: str
    metadata: Dict[str, Any] = {}


@app.post("/ingest", summary="Ingest texts into the vector collection")
def ingest(items: List[IngestItem]):
    if not items:
        return {"ingested": 0, "collection": COLLECTION_NAME}

    if client is None:
        # test mode: still encode to mirror workload
        _ = model.encode([it.text for it in items])
        return {"ingested": len(items), "collection": COLLECTION_NAME, "skipped": True}

    try:
        vectors = model.encode([it.text for it in items]).tolist()
        points = [
            PointStruct(
                id=normalize_point_id(it.id),
                vector=vec,
                payload={"text": it.text, **(it.metadata or {})},
            )
            for it, vec in zip(items, vectors)
        ]
        client.upsert(collection_name=COLLECTION_NAME, points=points, wait=True)
        return {"ingested": len(points), "collection": COLLECTION_NAME}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingest failed: {e}")


# === Search (accept BOTH ?query= and ?q=) ===
@app.get("/search", response_model=SearchResponse, summary="Search")
def search(
    request: Request,
    query: Optional[str] = Query(None, description="Search sentence or phrase"),
    q: Optional[str] = Query(None, description="Alias for query"),
    limit: int = Query(TOP_K, ge=1, le=50),
    # light filters
    min_score: Optional[float] = Query(0.0, ge=0.0, description="Minimum score for results"),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter"),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    doc_id: Optional[str] = Query(None, description="Filter by document ID"),
    after: Optional[str] = Query(None, description="Filter by published date after (ISO8601)"),
    before: Optional[str] = Query(None, description="Filter by published date before (ISO8601)"),
    has_ioc: Optional[bool] = Query(None, description="Filter by presence of IOCs"),
):
    term = query or q or request.query_params.get("q") or request.query_params.get("query")
    if not term:
        raise HTTPException(status_code=400, detail="Missing search query ('query' or 'q')")

    # In stub mode -> deterministic response
    if client is None:
        _ = model.encode(term)  # warm model
        return SearchResponse(query=term, results=[])

    # Build filter (AND of simple conditions)
    must = []
    tag_list = [t for t in (tags.split(",") if tags else []) if t]
    for t in tag_list:
        must.append(FieldCondition(key="tags", match=MatchValue(value=t)))
    if source_type:
        must.append(FieldCondition(key="source_type", match=MatchValue(value=source_type)))
    if doc_id:
        must.append(FieldCondition(key="doc_id", match=MatchValue(value=doc_id)))

    def to_ts(s: Optional[str]) -> Optional[int]:
        if not s:
            return None
        try:
            return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
        except Exception:
            return None

    gte = to_ts(after)
    lte = to_ts(before)
    if gte is not None or lte is not None:
        rng = Range(gte=gte, lte=lte)
        must.append(FieldCondition(key="published_at_ts", range=rng))
    qfilter = Filter(must=must) if must else None

    # Vector search baseline
    vec = model.encode([term]).tolist()[0]
    score_threshold = min_score if (min_score and min_score > 0) else None
    try:
        hits = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=vec,
            limit=limit,
            query_filter=qfilter,
            with_payload=True,
            with_vectors=False,
            score_threshold=score_threshold,
        )
    except TypeError:
        hits = client.search(
            collection_name=COLLECTION_NAME,
            query_vector=vec,
            limit=limit,
            query_filter=qfilter,
            with_payload=True,
        )

    # IOC-boosted merge: exact matches first, then vector hits (dedupe by id)
    merged: List[SearchResult] = []
    seen = set()

    iocs = detect_iocs(term)
    if any(iocs.values()):
        try:
            ioc_pts = exact_hits_for_iocs(client, COLLECTION_NAME, iocs, limit=limit)
        except Exception:
            ioc_pts = []
        for p in ioc_pts:
            if p.id in seen:
                continue
            seen.add(p.id)
            payload = p.payload or {}
            text = payload.get("text", "")
            tags_payload = payload.get("tags") or []
            if not isinstance(tags_payload, list):
                tags_payload = [str(tags_payload)]
            merged.append(
                SearchResult(
                    text=text,
                    score=1.5,  # boosted above similarity scores
                    tags=tags_payload,
                    tokens=[],
                    labels=[],
                )
            )

    # Vector hits (respect has_ioc filter and score threshold)
    def ioc_present(payload: dict) -> bool:
        if not payload:
            return False
        # Recognize common IOC-bearing fields or a tag that explicitly says IOC/CVE/etc.
        if any(payload.get(k) for k in ("cves", "ips", "domains", "hashes", "indicators")):
            return True
        tags_ = payload.get("tags") or []
        if not isinstance(tags_, list):
            tags_ = [str(tags_)]
        return any(t.upper() in {"IOC", "CVE", "INDICATOR"} for t in tags_)

    for h in hits:
        if h.id in seen:
            continue
        payload = h.payload or {}
        if (min_score or 0) and float(getattr(h, "score", 0.0)) < (min_score or 0):
            continue
        if has_ioc and not ioc_present(payload):
            continue
        text = payload.get("text", "")
        tags_payload = payload.get("tags") or []
        if not isinstance(tags_payload, list):
            tags_payload = [str(tags_payload)]
        merged.append(
            SearchResult(
                text=text,
                score=float(h.score),
                tags=tags_payload,
                tokens=[],
                labels=[],
            )
        )

    return SearchResponse(query=term, results=merged[:limit])
