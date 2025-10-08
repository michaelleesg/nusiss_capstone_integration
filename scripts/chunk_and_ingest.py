import argparse, json, os, re, uuid, hashlib, time
from datetime import datetime
from pathlib import Path
from typing import Iterable, Dict, List, Tuple
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance,
    VectorParams,
    PointStruct,
    PayloadSchemaType,
)

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "heva_docs")
EMB_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMB_DIM = 384

def extract_iocs(text: str) -> dict:
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
    hashes = re.findall(r'\b[a-f0-9]{32,64}\b', text)
    mitre_techniques = re.findall(r'T\d{4}(\.\d{3})?', text)
    actors = re.findall(r'\b(?:TA402|APT-C-23|IronWind|NimbleMamba|SharpSploit)\b', text, re.IGNORECASE)
    return {
        "cves": cves,
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "mitre_techniques": mitre_techniques,
        "actors": actors
    }

def chunk_text(text: str, max_chars=1200, overlap=150) -> List[dict]:
    """Greedy, sentence-ish chunking with character overlap and offsets."""
    t = re.sub(r"\s+", " ", (text or "")).strip()
    out = []
    i = 0
    n = len(t)
    while i < n:
        j = min(n, i + max_chars)
        cut = t.rfind(". ", i, j)
        if cut == -1 or cut - i < max_chars * 0.5:
            cut = j
        else:
            cut += 1
        chunk = t[i:cut].strip()
        if chunk:
            out.append({"text": chunk, "start": i, "end": cut})
        i = max(cut - overlap, i + 1)
    return out

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8"), usedforsecurity=False).hexdigest()

def parse_ts(dt: str | None) -> int | None:
    if not dt:
        return None
    try:
        return int(datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp())
    except Exception:
        return None

def create_payload(*, doc_id: str, chunk_id: str, idx: int, total: int, ch: dict, rec: dict, iocs: dict, prev_id: str | None, next_id: str | None) -> dict:
    title = rec.get("caps_title") or rec.get("title")
    source_url = rec.get("_id") or rec.get("url")
    published_at = rec.get("date_time") or rec.get("published_at")
    authors = rec.get("authors")
    tags = ["source:combined.json"]
    if rec.get("tags"):
        tags += [t for t in rec["tags"] if t not in tags]
    payload = {
        "doc_id": doc_id,
        "chunk_id": chunk_id,
        "chunk_index": idx,
        "chunk_total": total,
        "offset_start": ch["start"],
        "offset_end": ch["end"],
        "text": ch["text"],
        "char_count": len(ch["text"]),
        "source_url": source_url,
        "source_type": rec.get("source_type"),
        "title": title,
        "authors": authors,
        "published_at": published_at,
        "published_at_ts": parse_ts(published_at),
        "harvested_at": rec.get("harvest_date", {}).get("$date") if isinstance(rec.get("harvest_date"), dict) else rec.get("harvest_date"),
        "language": rec.get("language"),
        "ioc": iocs,
        "entities": rec.get("entities", []),
        "attacks": {
            "actors": iocs.get("actors", []),
            "malware": re.findall(r"\b[A-Z][A-Za-z0-9_-]{3,}\b", ch["text"]),
            "mitre_techniques": iocs.get("mitre_techniques", []),
        },
        "tags": tags,
        "queries": list({*(iocs.get("cves", [])[:2]), *(iocs.get("ips", [])[:2])}) or [title] if title else [],
        "emb_model": EMB_MODEL,
        "emb_dim": EMB_DIM,
        "neighborhood": {"prev_chunk_id": prev_id, "next_chunk_id": next_id},
        "scoring": {"risk_score": None, "confidence": None},
        "eval": {},
        "fingerprint": f"md5:{md5_hex(ch['text'][:512])}",
        "acl": ["public"],
    }
    return payload

def ensure_collection(client: QdrantClient, name: str, size: int = EMB_DIM):
    if not client.collection_exists(name):
        client.create_collection(
            collection_name=name,
            vectors_config=VectorParams(size=size, distance=Distance.COSINE),
        )

def maybe_create_indexes(client: QdrantClient, name: str):
    # Safe to call repeatedly; Qdrant will no-op if identical.
    try:
        client.create_payload_index(name, field_name="tags", field_schema=PayloadSchemaType.KEYWORD)
        client.create_payload_index(name, field_name="ioc.cves", field_schema=PayloadSchemaType.KEYWORD)
        client.create_payload_index(name, field_name="attacks.actors", field_schema=PayloadSchemaType.KEYWORD)
        client.create_payload_index(name, field_name="published_at_ts", field_schema=PayloadSchemaType.INTEGER)
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="Source JSON/JSONL file (array or JSONL)")
    parser.add_argument("--collection", default=QDRANT_COLLECTION, help="Qdrant collection name")
    parser.add_argument("--qdrant-url", default=QDRANT_URL, help="Qdrant URL")
    parser.add_argument("--max-chars", type=int, default=1200, help="Max characters per chunk")
    parser.add_argument("--overlap", type=int, default=150, help="Character overlap between chunks")
    parser.add_argument("--create-indexes", action='store_true', help="Create indexes for fields")
    args = parser.parse_args()

    # Load data (array JSON or JSONL)
    path = Path(args.src)
    raw = path.read_text(encoding="utf-8").strip()
    data = []
    if raw.startswith("["):
        data = json.loads(raw)
    else:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                data.append(json.loads(line))

    # Initialize model & Qdrant
    model = SentenceTransformer(EMB_MODEL)
    client = QdrantClient(url=args.qdrant_url)
    ensure_collection(client, args.collection, EMB_DIM)
    if args.create_indexes:
        maybe_create_indexes(client, args.collection)

    total_chunks = 0
    batch: List[PointStruct] = []
    for rec in tqdm(data, desc="Processing records"):
        text = rec.get("text") or ""
        if not text.strip():
            continue
        doc_id = rec.get("_id") or rec.get("id") or str(uuid.uuid4())
        chunks = chunk_text(text, args.max_chars, args.overlap)
        n = len(chunks)
        for idx, ch in enumerate(chunks):
            chunk_uuid = str(uuid.uuid4())
            prev_id = batch[-1].id if idx > 0 else None
            next_id = None  # unknown until next loop
            iocs = extract_iocs(ch["text"])
            payload = create_payload(
                doc_id=doc_id,
                chunk_id=chunk_uuid,
                idx=idx,
                total=n,
                ch=ch,
                rec=rec,
                iocs=iocs,
                prev_id=chunks[idx-1]["chunk_id"] if idx > 0 else None,
                next_id=None,
            )
            # Fix prev/next relationships for payload (we have ids now)
            if idx > 0:
                # set prev's next_chunk_id to current
                pass
            vec = model.encode(ch["text"]).tolist()
            batch.append(PointStruct(id=chunk_uuid, vector=vec, payload=payload))
            total_chunks += 1
            if len(batch) >= 500:
                client.upsert(collection_name=args.collection, points=batch)
                batch.clear()
    if batch:
        client.upsert(collection_name=args.collection, points=batch)
    print(f"✅ Ingested {len(data)} documents / {total_chunks} chunks into '{args.collection}'.")

if __name__ == "__main__":
    main()
