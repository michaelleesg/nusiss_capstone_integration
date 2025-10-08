import os
import httpx
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "heva_docs")
VECTORS_SIZE = int(os.getenv("VECTORS_SIZE", 384))

class QdrantWrapper:
    def __init__(self):
        self.client = QdrantClient(url=QDRANT_URL)

    def ping(self):
        try:
            self.client.get_collections()
            return True
        except Exception as e:
            print(f"❌ Qdrant ping failed: {e}")
            return False

    def ensure_collection(self, size=VECTORS_SIZE, distance="Cosine"):
        if not self.client.collection_exists(QDRANT_COLLECTION):
            self.client.create_collection(
                collection_name=QDRANT_COLLECTION,
                vectors_config=VectorParams(size=size, distance=Distance.COSINE),
            )
            print(f"📦 Created collection: {QDRANT_COLLECTION}")
        else:
            print(f"✅ Collection '{QDRANT_COLLECTION}' already exists.")
