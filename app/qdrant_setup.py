from __future__ import annotations

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, HnswConfigDiff

# Keep this in sync with app/embeddings.DIM (we default to 384 there).
DIM = 384

def ensure_collection(url: str = "http://localhost:6333", name: str = "heva_v1") -> bool:
    """
    Create/recreate a dense-only collection (COSINE). Sparse can be added later.
    """
    client = QdrantClient(url=url)
    client.recreate_collection(
        collection_name=name,
        vectors_config=VectorParams(size=DIM, distance=Distance.COSINE),
        hnsw_config=HnswConfigDiff(m=32, ef_construct=256),
        optimizers_config={"memmap_threshold": 20000},
    )
    return True
