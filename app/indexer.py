from __future__ import annotations

import uuid
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct

from .embeddings import embed_chunks


def derive_context_category(heading: str | None, text: str) -> str:
    """
    Heuristic categorizer so Agent B emits Agent C-style 'context_category' values.
    """
    t = f"{heading or ''} {text}".lower()
    if any(k in t for k in ["out-of-band", "patch", "workaround", "mitigation"]):
        return "mitigation"
    if any(k in t for k in ["exploited in the wild", "actively exploited"]):
        return "observed_in_wild"
    if "ioc" in t:
        return "ioc"
    if any(k in t for k in ["exploit", "rce", "poc", "weaponized"]):
        return "exploit"
    return "body"


def chunk_text(
    text: str,
    *,
    target_tokens: int = 512,
    overlap: int = 128,
    has_structured_data: bool = False,
    section: str | None = None,
) -> list[dict[str, Any]]:
    """
    Produce Agent-C-shaped chunks with:
      - type: 'report'
      - section: e.g., 'body'
      - context_category: derived via heuristic
      - chunk_metadata: { has_structured_data: bool, length: int }
      - text: content for embedding
    Token approximation: ~4 chars ≈ 1 token.
    """
    approx_chars = max(1, target_tokens) * 4
    step = max(1, approx_chars - overlap * 4)

    out: list[dict[str, Any]] = []
    for i in range(0, len(text), step):
        seg = text[i : i + approx_chars].strip()
        if not seg:
            continue
        sec = section or "body"
        out.append(
            {
                "type": "report",
                "section": sec,
                "context_category": derive_context_category(sec, seg),
                "chunk_metadata": {
                    "has_structured_data": bool(has_structured_data),
                    "length": len(seg),
                },
                "text": seg,
            }
        )

    if not out:
        sec = section or "body"
        seg = text
        out = [
            {
                "type": "report",
                "section": sec,
                "context_category": derive_context_category(sec, seg),
                "chunk_metadata": {
                    "has_structured_data": bool(has_structured_data),
                    "length": len(seg),
                },
                "text": seg,
            }
        ]
    return out


def upsert_artifact(
    client: QdrantClient,
    collection: str,
    artifact: dict[str, Any],
    *,
    filename: str | None = None,
    folder_type: str | None = None,
) -> int:
    """
    Chunk, embed, and upsert one artifact into Qdrant.
    Payload aligns with Agent C expectations:
      metadata = {
          'source': filename or source_name/url,
          'folder': folder_type or artifact.folder,
          'doc_type': chunk['type'],               # 'report'
          'section': chunk['section'],             # 'body' (default)
          'context_category': chunk['context_category'],
          'has_structured_data': chunk['chunk_metadata']['has_structured_data'],
          'chunk_length': chunk['chunk_metadata']['length'],
          'artifact_id': artifact.get("artifact_id"),  # Include artifact_id for traceability
          'published_at': artifact.get("published_at"),  # Include published_at for traceability
          'tags': artifact.get("tags", []),  # Include tags for additional context
          'artifact_id': artifact.get("artifact_id"),  # Include artifact_id for traceability
      }
    """
    text = artifact.get("text", "") or ""
    has_structured = bool(artifact.get("sections"))

    chunks = chunk_text(
        text,
        has_structured_data=has_structured,
        section=None,
    )

    vecs = embed_chunks([c["text"] for c in chunks])
    points: list[PointStruct] = []

    for ix, (chunk, vec) in enumerate(zip(chunks, vecs)):
        metadata = {
            "source": (filename or artifact.get("source_url") or artifact.get("source_name") or ""),
            "folder": folder_type or artifact.get("folder") or "osint",
            "doc_type": chunk["type"],  # 'report'
            "section": chunk["section"],  # e.g., 'body'
            "context_category": chunk["context_category"],
            "has_structured_data": chunk["chunk_metadata"]["has_structured_data"],
            "chunk_length": chunk["chunk_metadata"]["length"],
        }
        raw_id = f"{artifact.get('artifact_id', filename or 'doc')}:{ix}"
        metadata["artifact_id"] = artifact.get(
            "artifact_id"
        )  # Include artifact_id for traceability
        pid = str(uuid.uuid5(uuid.NAMESPACE_URL, raw_id))  # Deterministic UUID
        # >>> BEGIN HEVA METADATA PATCH (idempotent, placed before PointStruct) >>>
        metadata = {
            "source": (
                filename
                or artifact.get("source")
                or artifact.get("source_url")
                or artifact.get("source_name")
                or ""
            ),
            "folder": (
                folder_type or artifact.get("folder_type") or artifact.get("folder") or "osint"
            ),
            "doc_type": chunk["type"],
            "section": chunk["section"],
            "context_category": chunk.get("context_category", artifact.get("context_category")),
            "has_structured_data": chunk["chunk_metadata"]["has_structured_data"],
            "chunk_length": chunk["chunk_metadata"]["length"],
            # Traceability
            "artifact_id": artifact.get("artifact_id"),
            # NEW: temporal + enrichment
            "published_at": artifact.get("published_at"),
            "tags": artifact.get("tags", []),
            # Optional threat-intel pivots
            "threat_actors": artifact.get("threat_actors", []),
            "mitre_ttps": artifact.get("mitre_ttps", []),
            "cve_vulns": artifact.get("cve_vulns", []),
            "affected_products": artifact.get("affected_products", []),
            "sectors": artifact.get("sectors", []),
            # Optional booleans used downstream
            "affects_singapore": artifact.get("affects_singapore"),
            "affects_asean": artifact.get("affects_asean"),
            "active_exploitation": artifact.get("active_exploitation"),
            "high_tension_event": artifact.get("high_tension_event"),
        }

        for k in (
            "tags",
            "threat_actors",
            "mitre_ttps",
            "cve_vulns",
            "affected_products",
            "sectors",
        ):
            if metadata.get(k) is None:
                metadata[k] = []
        # <<< END HEVA METADATA PATCH <<<

        # >>> HEVA CLOCK GUARD >>>
        # preserve existing clocks if caller supplied them
        if "ingested_at_ts" in metadata and metadata["ingested_at_ts"] is None:
            metadata.pop("ingested_at_ts", None)
        if "published_at_ts" in metadata and metadata["published_at_ts"] is None:
            metadata.pop("published_at_ts", None)
        # <<< HEVA CLOCK GUARD <<<

        # Compute published_at_ts if present; always add ingested_at_ts as fallback
        try:
            from datetime import datetime
            from time import time as _now

            if metadata.get("published_at") and not metadata.get("published_at_ts"):
                _s = str(metadata["published_at"]).replace("Z", "")
                metadata["published_at_ts"] = int(datetime.fromisoformat(_s).timestamp())
        except Exception:
            pass
        # Always set ingested_at_ts if missing
        if not metadata.get("ingested_at_ts"):
            from time import time as _now

            metadata["ingested_at_ts"] = int(_now())

        # Normalize published_at → published_at_ts (unix int) if present
        try:
            if metadata.get("published_at") and not metadata.get("published_at_ts"):
                from datetime import datetime

                _dt = datetime.fromisoformat(str(metadata["published_at"]).replace("Z", ""))
                metadata["published_at_ts"] = int(_dt.timestamp())
        except Exception:
            pass

        points.append(PointStruct(id=pid, vector=vec, payload=metadata))

    if points:
        client.upsert(collection_name=collection, points=points, wait=True)
    return len(points)
