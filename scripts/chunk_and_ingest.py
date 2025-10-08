import argparse
import json
import os
import re
import uuid
import numpy as np
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams, PointStruct
from tqdm import tqdm

# Load environment variables
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "heva_docs")

def extract_iocs(text):
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
    hashes = re.findall(r'\b[a-f0-9]{32,64}\b', text)
    mitre_techniques = re.findall(r'T\d{4}(\.\d{3})?', text)
    actors = re.findall(r'\b(?:TA402|APT-C-23|IronWind|NimbleMamba|SharpSploit)\b', text, re.IGNORECASE)
    return {
        "cves": cves,
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "mitre_techniques": mitre_techniques,
        "actors": actors
    }

def chunk_text(text, max_chars=1200, overlap=150):
    sentences = text.split('. ')
    chunks = []
    current_chunk = ""
    for sentence in sentences:
        if len(current_chunk) + len(sentence) + 1 > max_chars:
            chunks.append(current_chunk)
            current_chunk = sentence
        else:
            current_chunk += (". " + sentence) if current_chunk else sentence
    if current_chunk:
        chunks.append(current_chunk)
    
    # Create overlapping chunks
    final_chunks = []
    for i in range(len(chunks)):
        if i == 0:
            final_chunks.append(chunks[i])
        else:
            overlap_chunk = chunks[i-1][-overlap:] + chunks[i]
            final_chunks.append(overlap_chunk)
    
    return final_chunks

def create_payload(chunk, iocs, index, total_chunks, source_info):
    return {
        "doc_id": str(uuid.uuid4()),
        "chunk_id": str(uuid.uuid4()),
        "chunk_index": index,
        "chunk_total": total_chunks,
        "text": chunk,
        "ioc": iocs,
        "tags": ["source:combined.json"],
        "queries": [chunk[:50]],  # First 50 characters as a query
        "emb_model": "sentence-transformers/all-MiniLM-L6-v2",
        "emb_dim": 384,
        "scoring": {"risk_score": None, "confidence": None},
        "eval": {},
        "fingerprint": "md5:<hex>",
        "acl": ["public"]
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="Source JSON or JSONL file")
    parser.add_argument("--collection", default=QDRANT_COLLECTION, help="Qdrant collection name")
    parser.add_argument("--qdrant-url", default=QDRANT_URL, help="Qdrant URL")
    parser.add_argument("--max-chars", type=int, default=1200, help="Max characters per chunk")
    parser.add_argument("--overlap", type=int, default=150, help="Character overlap between chunks")
    parser.add_argument("--create-indexes", action='store_true', help="Create indexes for fields")
    args = parser.parse_args()

    # Load data
    with open(args.src, 'r') as f:
        if args.src.endswith('.jsonl'):
            data = [json.loads(line) for line in f]
        else:
            data = json.load(f)

    # Initialize Qdrant client
    client = QdrantClient(url=args.qdrant_url)

    # Process each document
    for record in tqdm(data, desc="Processing records"):
        text = record.get("text", "")
        iocs = extract_iocs(text)
        chunks = chunk_text(text, args.max_chars, args.overlap)

        for index, chunk in enumerate(chunks):
            payload = create_payload(chunk, iocs, index, len(chunks), record)
            client.upsert(collection_name=args.collection, points=[PointStruct(id=payload["chunk_id"], vector=None, payload=payload)])

    print(f"✅ Ingested {len(data)} documents and their chunks into Qdrant.")

if __name__ == "__main__":
    main()
