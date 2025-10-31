import os, time
from typing import List
from qdrant_client import QdrantClient

COL=os.environ.get("QDRANT_COLLECTION","heva_v1")  # set per run
URL=os.environ.get("QDRANT_URL","http://127.0.0.1:6333")
KEY=os.environ.get("QDRANT_API_KEY")
BATCH=int(os.environ.get("BACKFILL_BATCH","256"))
DRY=os.environ.get("DRY_RUN","0")=="1"

cli=QdrantClient(url=URL, api_key=KEY)

def scroll_page(offset):
    return cli.scroll(collection_name=COL, limit=BATCH, with_payload=True, with_vectors=False, offset=offset)

upd=0; seen=0; off=None
while True:
    pts, off = scroll_page(off)
    if not pts: break
    to_ids: List=[]; to_pl: List[dict]=[]
    now=int(time.time())
    for p in pts:
        seen+=1
        pl=dict(p.payload or {})
        if pl.get("ingested_at_ts") is None:
            pl["ingested_at_ts"]=now
            to_ids.append(p.id); to_pl.append(pl)
    if not to_ids: continue
    if DRY:
        print(f"[DRY] Would update {len(to_ids)} points (ex: {to_ids[0]})")
    else:
        for pid,pl in zip(to_ids,to_pl):
            cli.set_payload(collection_name=COL, points=[pid], payload=pl)
        upd+=len(to_ids)
print(f"{'Dry run' if DRY else 'Done'}: scanned={seen}, updated={upd}.")
