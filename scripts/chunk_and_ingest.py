#!/usr/bin/env python3
"""
HEVA chunk & ingest tool (Qdrant)

- Fast `--help`: heavy imports happen after argparse, so help is instant.
- Idempotent payload index creation.
- Rich payload with IoCs, tags, and HEVA-specific fields.
"""

import argparse
import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# ---- Light globals (stdlib only) ----
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "heva_docs")
EMB_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMB_DIM = 384

CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOM_RE = re.compile(r"\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b", re.I)
HASH_RE = re.compile(r"\b[a-f0-9]{32,64}\b", re.I)


# -----------------------------
# Helpers (stdlib only, fast)
# -----------------------------
def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8"), usedforsecurity=False).hexdigest()


def extract_iocs(text: str) -> dict[str, list[str]]:
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I)
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    domains = re.findall(r"\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b", text, flags=re.I)
    hashes = re.findall(r"\b[a-f0-9]{32,64}\b", text, flags=re.I)
    mitre = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)
    actors = re.findall(
        r"\b(?:TA402|APT-C-23|IronWind|NimbleMamba|SharpSploit|Molerats|Arid\s+Viper)\b",
        text,
        flags=re.I,
    )

    def dedup(xs):
        return list(dict.fromkeys(xs))

    return {
        "cves": dedup(cves),
        "ips": dedup(ips),
        "domains": dedup(domains),
        "hashes": dedup(hashes),
        "mitre_techniques": dedup(mitre),
        "actors": dedup(actors),
    }


def generate_queries(text: str, title: str = "") -> list[str]:
    qs: list[str] = []
    if title:
        qs.append(title)
    snippet = " ".join((text or "").split()[:40])
    if snippet:
        qs.append(snippet)
    qs += re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I)[:2]
    qs += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)[:2]
    qs += re.findall(r"\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b", text, flags=re.I)[:2]
    hashes = re.findall(r"\b[a-f0-9]{32,64}\b", text, flags=re.I)
    qs += hashes[:1]
    return list(dict.fromkeys(qs))[:6]


def chunk_text(text: str, max_chars=1200, overlap=150) -> list[dict[str, Any]]:
    t = re.sub(r"\s+", " ", (text or "")).strip()
    out: list[dict[str, Any]] = []
    i, n = 0, len(t)
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
        if cut >= n:
            break
        i = max(cut - overlap, i + 1)
    return out


def to_ts(dt_str: str | None) -> int | None:
    if not dt_str:
        return None
    try:
        return int(datetime.fromisoformat(dt_str.replace("Z", "+00:00")).timestamp())
    except Exception:
        return None


def load_records(path: str) -> Iterable[dict[str, Any]]:
    txt = Path(path).read_text(encoding="utf-8").strip()
    idx = 0

    def coerce(r, i):
        if isinstance(r, dict):
            return r
        if isinstance(r, str):
            return {"_id": f"string-{i}", "text": r}
        return {"_id": f"unknown-{i}", "text": str(r)}

    if txt.startswith("["):
        try:
            arr = json.loads(txt)
        except json.JSONDecodeError:
            arr = []
        for r in arr:
            yield coerce(r, idx)
            idx += 1
    else:
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                r = line
            yield coerce(r, idx)
            idx += 1


def build_payload(
    rec: dict[str, Any],
    ch: dict[str, Any],
    *,
    doc_id: str,
    idx: int,
    total: int,
    prev_id: str | None,
    chunk_id: str,
) -> dict[str, Any]:
    title = rec.get("caps_title") or rec.get("title") or ""
    source_url = rec.get("_id") or rec.get("url") or ""
    published_at_str = rec.get("published_at") or rec.get("date_time")

    ioc_chunk = extract_iocs(ch["text"])
    queries = generate_queries(ch["text"], title)
    has_ioc = any(ioc_chunk.get(k) for k in ("cves", "ips", "domains", "hashes"))

    payload: dict[str, Any] = {
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
        "published_at": published_at_str,
        "published_at_ts": to_ts(published_at_str),
        "tags": ["source:ingest"],
        "ioc": ioc_chunk,
        "queries": queries,
        "has_ioc": has_ioc,
        "neighborhood": {"prev_chunk_id": prev_id, "next_chunk_id": None},
        "emb_model": EMB_MODEL,
        "emb_dim": EMB_DIM,
        "fingerprint": f"md5:{md5_hex(ch['text'][:512])}",
        "eval": {},
        "scoring": {"risk_score": None, "confidence": None},
        "acl": ["public"],
    }
    if isinstance(rec.get("tags"), list):
        for t in rec["tags"]:
            if t not in payload["tags"]:
                payload["tags"].append(t)

    # HEVA-specific passthroughs
    for key in [
        "source",
        "folder_type",
        "context_category",
        "threat_actors",
        "mitre_ttps",
        "cve_vulns",
        "affected_products",
        "sectors",
        "affects_singapore",
        "affects_asean",
        "active_exploitation",
        "high_tension_event",
    ]:
        val = rec.get(key)
        if val is not None:
            payload[key] = val

    for k in ("tags", "threat_actors", "mitre_ttps", "cve_vulns", "affected_products", "sectors"):
        if k in payload and not isinstance(payload[k], list):
            payload[k] = [payload[k]]

    return payload


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def upsert_with_retry(client, collection, points, sub_batch=500, max_retries=3):
    for part in _chunks(points, sub_batch):
        for attempt in range(1, max_retries + 1):
            try:
                client.upsert(collection_name=collection, points=part, wait=True)
                break
            except Exception:
                if attempt == max_retries:
                    raise
                time.sleep(2**attempt)


# -----------------------------
# Main (heavy imports happen here)
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="JSON array or JSONL file")
    ap.add_argument("--collection", default=QDRANT_COLLECTION)
    ap.add_argument("--qdrant-url", default=QDRANT_URL)
    ap.add_argument("--max-chars", type=int, default=1200)
    ap.add_argument("--overlap", type=int, default=150)
    ap.add_argument("--create-indexes", "--create-index", "--create-indexs", dest="create_indexes", action="store_true", help="Create payload indexes (idempotent)")
    ap.add_argument("--max-docs", type=int, default=0, help="Stop after N docs (0 = all)")
    ap.add_argument(
        "--batch-chunks",
        type=int,
        default=1500,
        help="How many chunks per encode/upsert",
    )
    ap.add_argument(
        "--encode-batch-size",
        type=int,
        default=64,
        help="Mini-batches inside model.encode",
    )
    ap.add_argument("--normalize", action="store_true", help="L2-normalize embeddings")
    args = ap.parse_args()

    # Heavy stuff only after we know we're not just printing --help:
    import torch  # noqa: WPS433
    from qdrant_client import QdrantClient  # noqa: WPS433
    from qdrant_client.http.models import (  # noqa: WPS433
        Distance,
        PayloadSchemaType,
        PointStruct,
        VectorParams,
    )
    from sentence_transformers import SentenceTransformer  # noqa: WPS433
    from tqdm import tqdm  # noqa: WPS433

    def ensure_collection(client, name: str, size: int = EMB_DIM):
        if not client.collection_exists(name):
            client.create_collection(
                collection_name=name,
                vectors_config=VectorParams(size=size, distance=Distance.COSINE),
            )

    def maybe_create_indexes(client, name: str):
        fields = [
            ("tags", PayloadSchemaType.KEYWORD),
            ("doc_id", PayloadSchemaType.KEYWORD),
            ("source_type", PayloadSchemaType.KEYWORD),
            ("published_at_ts", PayloadSchemaType.INTEGER),
            ("ioc.cves", PayloadSchemaType.KEYWORD),
            ("ioc.ips", PayloadSchemaType.KEYWORD),
            ("ioc.domains", PayloadSchemaType.KEYWORD),
            ("ioc.hashes", PayloadSchemaType.KEYWORD),
            # HEVA pivots
            ("source", PayloadSchemaType.KEYWORD),
            ("folder_type", PayloadSchemaType.KEYWORD),
            ("context_category", PayloadSchemaType.KEYWORD),
            ("threat_actors", PayloadSchemaType.KEYWORD),
            ("mitre_ttps", PayloadSchemaType.KEYWORD),
            ("cve_vulns", PayloadSchemaType.KEYWORD),
            ("affected_products", PayloadSchemaType.KEYWORD),
            ("sectors", PayloadSchemaType.KEYWORD),
        ]
        for field, schema in fields:
            try:
                client.create_payload_index(
                    collection_name=name, field_name=field, field_schema=schema
                )
            except Exception:
                # already exists or not supported — ignore
                pass

    device = "cuda" if torch.cuda.is_available() else "cpu"
    client = QdrantClient(url=args.qdrant_url, timeout=60.0, prefer_grpc=True)
    ensure_collection(client, args.collection, EMB_DIM)
    if args.create_indexes:
        maybe_create_indexes(client, args.collection)
        maybe_create_indexes(client, args.collection)

    texts: list[str] = []
    metas: list[tuple[str, dict[str, Any]]] = []  # (point_id, payload)
    total_chunks = 0
    seen_docs = 0

    model = SentenceTransformer(EMB_MODEL, device=device)

    def flush_batch():
        nonlocal texts, metas, total_chunks
        if not texts:
            return
        vecs = model.encode(
            texts,
            batch_size=args.encode_batch_size,
            show_progress_bar=False,
            normalize_embeddings=args.normalize,
            convert_to_numpy=True,
        )
        points = [
            PointStruct(id=pid, vector=vec.tolist(), payload=pl)
            for (pid, pl), vec in zip(metas, vecs)
        ]
        upsert_with_retry(client, args.collection, points)
        total_chunks += len(points)
        texts.clear()
        metas.clear()

    for rec in tqdm(load_records(args.src), desc="Processing records"):
        if args.max_docs and seen_docs >= args.max_docs:
            break
        if isinstance(rec, str):
            rec = {"_id": f"string-{seen_docs}", "text": rec}
        text = rec.get("text") or ""
        if not text.strip():
            continue

        doc_id = rec.get("_id") or rec.get("id") or str(uuid.uuid4())
        chunks = chunk_text(text, args.max_chars, args.overlap)
        prev_id_for_doc = None
        n = len(chunks)

        for idx, ch in enumerate(chunks):
            pid = str(uuid.uuid4())
            payload = build_payload(
                rec,
                ch,
                doc_id=doc_id,
                idx=idx,
                total=n,
                prev_id=prev_id_for_doc,
                chunk_id=pid,
            )
            prev_id_for_doc = pid
            texts.append(ch["text"])
            metas.append((pid, payload))
            if len(texts) >= args.batch_chunks:
                flush_batch()

        seen_docs += 1  # per document

    flush_batch()
    print(
        "✅ Ingested "
        f"{seen_docs} documents with {total_chunks} chunks into "
        f"'{args.collection}' on device={device}."
    )


if __name__ == "__main__":
    main()
