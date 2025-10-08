from fastapi import FastAPI, Query
from pydantic import BaseModel
from typing import List
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import SearchRequest
from fastapi.responses import JSONResponse
import logging

# === Config ===
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
COLLECTION_NAME = "ner_vectors"
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

# === Search Endpoint ===
@app.get("/search", response_model=SearchResponse)
def search(query: str = Query(..., description="Search sentence or phrase"), limit: int = TOP_K):
    try:
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
    except Exception as e:
        logger.error(f"❌ Search failed: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# === Health Check ===
@app.get("/")
def root():
    return {
        "message": "🧠 Semantic Search API is running",
        "model": MODEL_NAME,
        "collection": COLLECTION_NAME
    }
