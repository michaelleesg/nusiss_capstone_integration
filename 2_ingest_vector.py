import argparse
import time
import uuid
import httpx
import numpy as np
from tqdm import tqdm
from pathlib import Path
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct

# === Config ===
NER_BIO_SOURCE = "/mnt/c/Users/mike/Downloads/capstone/ner_training.txt"
COLLECTION_NAME = "ner_vectors"
MODEL_NAME = "all-MiniLM-L6-v2"
QDRANT_HOST = "localhost"
QDRANT_PORT = 6333
QDRANT_URL = f"http://{QDRANT_HOST}:{QDRANT_PORT}"
BATCH_SIZE = 1000
EMBEDDING_BACKUP_PATH = "embedding_backup.npy"

# === CLI Arguments ===
parser = argparse.ArgumentParser()
parser.add_argument("--skip-recreate", action="store_true", help="Skip collection deletion and recreation")
args = parser.parse_args()

# === Wait for Qdrant to be ready ===
def wait_for_qdrant(url, timeout=60):
    start = time.time()
    attempt = 0
    while time.time() - start < timeout:
        attempt += 1
        try:
            r = httpx.get(f"{url}/collections", timeout=3.0)
            if r.status_code == 200:
                print(f"✅ Qdrant is live after {attempt} attempt(s).")
                return
        except Exception as e:
            print(f"⏳ Waiting for Qdrant... attempt {attempt}: {e}")
        time.sleep(1)
    raise RuntimeError(f"❌ Qdrant not reachable after {timeout} seconds.")

wait_for_qdrant(QDRANT_URL)

# === Load BIO sentences ===
def load_bio_sentences(path):
    sentences = []
    current = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                if current:
                    sentence = " ".join(token for token, _ in current)
                    sentences.append(sentence)
                    current = []
            else:
                parts = line.split()
                if len(parts) == 2:
                    current.append((parts[0], parts[1]))
    return sentences

sentences = load_bio_sentences(NER_BIO_SOURCE)
print(f"✅ Loaded {len(sentences)} sentences.")

# === Encode with SentenceTransformer ===
model = SentenceTransformer(MODEL_NAME)
embedding_size = model.get_sentence_embedding_dimension()
vectors = model.encode(sentences, show_progress_bar=True)
print(f"✅ Encoded {len(vectors)} vectors with dimension {embedding_size}.")

# === Save embeddings backup ===
np.save(EMBEDDING_BACKUP_PATH, vectors)
print(f"💾 Saved embeddings to {EMBEDDING_BACKUP_PATH}")

# === Connect to Qdrant ===
client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)

# === Delete and recreate collection (if not skipped) ===
if not args.skip_recreate:
    if client.collection_exists(COLLECTION_NAME):
        print(f"⚠️ Collection '{COLLECTION_NAME}' already exists. Deleting...")
        client.delete_collection(COLLECTION_NAME)

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=embedding_size, distance=Distance.COSINE),
    )
    print(f"📦 Created new collection: {COLLECTION_NAME}")

# === Dimension check ===
try:
    info = client.get_collection(COLLECTION_NAME)
    qdrant_dim = info.model_dump()["config"]["params"]["vectors"]["size"]
    if qdrant_dim != embedding_size:
        raise ValueError(f"❌ Dimension mismatch: Qdrant={qdrant_dim} vs Model={embedding_size}")
    print(f"✅ Dimension verified: {qdrant_dim}")
except Exception as e:
    print(f"❌ Could not verify vector dimensions: {e}")

# === Upload in Batches (with retry) ===
def upload_batch(points, retries=3):
    for attempt in range(1, retries + 1):
        try:
            client.upsert(collection_name=COLLECTION_NAME, points=points)
            return
        except Exception as e:
            print(f"❌ Upload failed (attempt {attempt}): {e}")
            time.sleep(2 * attempt)
    raise RuntimeError("❌ All retries failed for batch upload.")

print("🚀 Uploading vectors in batches...")
for i in tqdm(range(0, len(sentences), BATCH_SIZE), desc="Ingesting", unit="batch"):
    batch_sentences = sentences[i:i + BATCH_SIZE]
    batch_vectors = vectors[i:i + BATCH_SIZE]
    payloads = [{"text": s} for s in batch_sentences]
    points = [
        PointStruct(id=str(uuid.uuid4()), vector=v.tolist(), payload=p)
        for v, p in zip(batch_vectors, payloads)
    ]
    upload_batch(points)

print(f"✅ Ingested {len(sentences)} total vectors into Qdrant.")

# === Final sanity check ===
try:
    time.sleep(1)
    count = client.count(COLLECTION_NAME, exact=True).count
    print(f"🔎 Qdrant confirms {count} vectors in collection '{COLLECTION_NAME}'.")
    if count != len(sentences):
        print(f"⚠️ Warning: Expected {len(sentences)} vectors, but found {count}!")
except Exception as e:
    print(f"❌ Could not verify vector count: {e}")
