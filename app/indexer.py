from __future__ import annotations

from typing import Dict, Any, List, Optional
import uuid

from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct

from .embeddings import embed_chunks


def derive_context_category(heading: Optional[str], text: str) -> str:
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
    section: Optional[str] = None,
) -> List[Dict[str, Any]]:
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

    out: List[Dict[str, Any]] = []
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
    artifact: Dict[str, Any],
    *,
    filename: Optional[str] = None,
    folder_type: Optional[str] = None,
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
    points: List[PointStruct] = []

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
        raw_id = f'{artifact.get("artifact_id", filename or "doc")}:{ix}'
        metadata["artifact_id"] = artifact.get(
            "artifact_id"
        )  # Include artifact_id for traceability
        pid = str(uuid.uuid5(uuid.NAMESPACE_URL, raw_id))  # Deterministic UUID
        points.append(PointStruct(id=pid, vector=vec, payload=metadata))

    if points:
        client.upsert(collection_name=collection, points=points, wait=True)
    return len(points)
