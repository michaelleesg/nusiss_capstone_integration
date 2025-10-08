import os, time, uuid, argparse
import httpx, numpy as np
from tqdm import tqdm
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ---- Env / CLI ----
NER_BIO_SOURCE = os.getenv("NER_BIO_SOURCE", "/data/ner_training.txt")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "ner_vectors")
MODEL_NAME = os.getenv("MODEL_NAME", "all-MiniLM-L6-v2")
QDRANT_URL = os.getenv("QDRANT_URL", "http://qdrant:6333")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "1000"))
EMBEDDING_BACKUP_PATH = os.getenv("EMBEDDING_BACKUP_PATH", "/data/embedding_backup.npy")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

parser = argparse.ArgumentParser()
parser.add_argument("--skip-recreate", action="store_true", help="Skip collection deletion/recreation")
args = parser.parse_args()

def wait_for_qdrant(url, timeout=120):
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

def load_bio_sentences(path):
    sentences, current = [], []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                if current:
                    sentences.append(" ".join(tok for tok,_ in current))
                    current=[]
            else:
                parts = line.split()
                if len(parts)==2:
                    current.append((parts[0], parts[1]))
    return sentences

def upload_batch(client, collection, points, retries=3):
    for attempt in range(1, retries+1):
        try:
            client.upsert(collection_name=collection, points=points, wait=True)
            return
        except Exception as e:
            print(f"❌ Upload failed (attempt {attempt}): {e}")
            time.sleep(2*attempt)
    raise RuntimeError("❌ All retries failed for batch upload.")

def main():
    wait_for_qdrant(QDRANT_URL)
    print(f"📄 Loading BIO from {NER_BIO_SOURCE}")
    sentences = load_bio_sentences(NER_BIO_SOURCE)
    print(f"✅ Loaded {len(sentences)} sentences.")

    model = SentenceTransformer(MODEL_NAME)
    dim = model.get_sentence_embedding_dimension()
    vectors = model.encode(sentences, show_progress_bar=True)
    print(f"✅ Encoded {len(vectors)} vectors @ dim {dim}")

    np.save(EMBEDDING_BACKUP_PATH, vectors)
    print(f"💾 Saved embeddings to {EMBEDDING_BACKUP_PATH}")

    client = QdrantClient(url=QDRANT_URL)

    if not args.skip_recreate:
        if client.collection_exists(COLLECTION_NAME):
            print(f"⚠️ Collection '{COLLECTION_NAME}' exists. Deleting...")
            client.delete_collection(COLLECTION_NAME)
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
        )
        print(f"📦 Created collection: {COLLECTION_NAME}")

    # Dimension sanity check
    info = client.get_collection(COLLECTION_NAME)
    qdrant_dim = info.model_dump()["config"]["params"]["vectors"]["size"]
    if qdrant_dim != dim:
        raise ValueError(f"❌ Dimension mismatch: Qdrant={qdrant_dim} vs Model={dim}")
    print(f"✅ Dimension verified: {qdrant_dim}")

    print("🚀 Uploading vectors in batches...")
    for i in tqdm(range(0, len(sentences), BATCH_SIZE), desc="Ingesting", unit="batch"):
        batch_sents = sentences[i:i+BATCH_SIZE]
        batch_vecs = vectors[i:i+BATCH_SIZE]
        payloads = [{"text": s, "source": "bio", "offset": i+j} for j,s in enumerate(batch_sents)]
        points = [PointStruct(id=str(uuid.uuid4()), vector=v.tolist(), payload=p) for v,p in zip(batch_vecs, payloads)]
        upload_batch(client, COLLECTION_NAME, points)

    # Final count
    time.sleep(1)
    count = client.count(COLLECTION_NAME, exact=True).count
    print(f"🔎 Qdrant reports {count} vectors in '{COLLECTION_NAME}'")

if __name__ == "__main__":
    main()
