# Qdrant bench stub
from qdrant_client import QdrantClient
import numpy as np, time, json

client = QdrantClient("localhost", 6333)


def bench(n=5):
    results = []
    for ef in [16, 32, 64]:
        lat = []
        for _ in range(n):
            q = np.random.rand(384).tolist()
            t0 = time.time()
            client.search("ner_vectors", query_vector=q, limit=3)
            lat.append((time.time() - t0) * 1000)
        results.append({"ef": ef, "mean_ms": float(np.mean(lat))})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    bench()
