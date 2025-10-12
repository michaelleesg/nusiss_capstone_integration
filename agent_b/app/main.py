import hashlib
import os
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    MatchValue,
    PointStruct,
    VectorParams,
)

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
COLL = os.getenv("QDRANT_COLL", "heva_docs")
VECTOR_SIZE = int(os.getenv("EMBED_DIM", "384"))  # stubbed size

app = FastAPI()
client = QdrantClient(url=QDRANT_URL)


def ensure_collection():
    try:
        client.get_collection(COLL)
    except Exception:
        client.recreate_collection(
            collection_name=COLL,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )


def make_doc_id(art: Dict[str, Any]) -> str:
    raw = (art.get("source_url", "") + art.get("content_sha256", "")).encode()
    return hashlib.sha256(raw).hexdigest()


def mk_embedding_text(art: Dict[str, Any]) -> str:
    i = art.get("iocs", {})
    ioc_flat = " ".join(
        i.get("urls", []) + i.get("domains", []) + i.get("ips", []) + i.get("hashes", [])
    )
    cves = " ".join(v.get("id", "") for v in art.get("cve", {}).get("vulnerabilities", []))
    ttps = " ".join(art.get("mitre_ttps", []))
    return "\n".join(
        [
            art.get("title", ""),
            art.get("summary", ""),
            art.get("markdown", ""),
            ttps,
            ioc_flat,
            cves,
        ]
    )


async def embed(_: str) -> List[float]:
    # stub: returns a zero vector; swap with real embeddings later
    return [0.0] * VECTOR_SIZE


def mk_payload(art: Dict[str, Any]) -> Dict[str, Any]:
    cves = [v.get("id", "") for v in art.get("cve", {}).get("vulnerabilities", [])]
    return {
        "tenant": next(
            (t.split(":")[1] for t in art.get("tags", []) if t.startswith("tenant:")), "default"
        ),
        "source_url": art.get("source_url"),
        "published_at": art.get("published_at"),
        "ttps": art.get("mitre_ttps", []),
        "cves": cves,
        "domains": art.get("iocs", {}).get("domains", []),
        "ips": art.get("iocs", {}).get("ips", []),
        "hashes": art.get("iocs", {}).get("hashes", []),
        "sev": art.get("cve", {}).get("highest_severity"),
        "kev": bool(art.get("cve", {}).get("active_exploitation")),
        "patch_availability": art.get("cve", {}).get("patch_availability"),
    }


@app.on_event("startup")
def startup():
    ensure_collection()


@app.get("/healthz")
def healthz():
    return {"ok": True, "collection": COLL}


@app.post("/ingest/artifact")
async def ingest_artifact(req: Request):
    art = await req.json()
    doc_id = make_doc_id(art)
    vec = await embed(mk_embedding_text(art))
    payload = mk_payload(art)
    client.upsert(
        collection_name=COLL, points=[PointStruct(id=doc_id, vector=vec, payload=payload)]
    )
    return {"status": "upserted", "doc_id": doc_id}


@app.post("/by-cves")
async def by_cves(body: Dict[str, Any]):
    tenant = body.get("tenant", "default")
    cves = body.get("cves", [])
    flt = Filter(must=[FieldCondition(key="tenant", match=MatchValue(value=tenant))])
    if cves:
        flt.must.append(FieldCondition(key="cves", match=MatchValue(value=cves[0])))
    points, _ = client.scroll(collection_name=COLL, with_payload=True, limit=50, scroll_filter=flt)
    return {"results": [{"doc_id": p.id, "payload": p.payload} for p in points]}
