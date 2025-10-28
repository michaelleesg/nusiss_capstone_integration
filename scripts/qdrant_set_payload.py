from __future__ import annotations

import argparse
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
from app.qdrant_utils import set_payload_by_filter

def main():
    ap = argparse.ArgumentParser(description="Bulk set payload in Qdrant by filter")
    ap.add_argument("--url", default="http://localhost:6333")
    ap.add_argument("--collection", default="heva_v1")
    ap.add_argument("--filter-key", default="source", help="Payload key to match")
    ap.add_argument("--filter-val", required=True, help="Payload value to match")
    ap.add_argument("--set-key", required=True, help="Payload key to set")
    ap.add_argument("--set-val", required=True, help="Payload value to set")
    args = ap.parse_args()

    client = QdrantClient(url=args.url)
    flt = Filter(must=[FieldCondition(key=args.filter_key, match=MatchValue(value=args.filter_val))])
    n = set_payload_by_filter(
        client,
        collection=args.collection,
        payload={args.set_key: args.set_val},
        flt=flt,
    )
    print(f"updated points: {n}")

if __name__ == "__main__":
    main()
