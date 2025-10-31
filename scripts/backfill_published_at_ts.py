import os
from datetime import datetime
from typing import List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qm
from pydantic import ValidationError

COLLECTION = os.environ.get("QDRANT_COLLECTION", "cybersage")
QDRANT_URL = os.environ.get("QDRANT_URL", "http://127.0.0.1:6333")
QDRANT_KEY = os.environ.get("QDRANT_API_KEY")
BATCH = int(os.environ.get("BACKFILL_BATCH", "256"))
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

cli = QdrantClient(url=QDRANT_URL, api_key=QDRANT_KEY)

def build_filter_with_is_null() -> qm.Filter:
    # published_at_ts IS NULL, published_at IS NOT NULL
    return qm.Filter(
        must=[
            qm.FieldCondition(
                key="published_at_ts",
                is_null=qm.IsNullCondition(is_null=True),
            ),
        ],
        must_not=[
            qm.FieldCondition(
                key="published_at",
                is_null=qm.IsNullCondition(is_null=True),
            ),
        ],
    )

def to_ts(val) -> Optional[int]:
    try:
        s = str(val).strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1]
        return int(datetime.fromisoformat(s).timestamp())
    except Exception:
        return None

# Try to construct the filter; fall back to None if unsupported
flt = None
try:
    flt = build_filter_with_is_null()
except (TypeError, ValidationError, AttributeError):
    flt = None

def scroll_page(offset, flt):
    """
    Compatibility helper:
    - Old clients use scroll_filter=
    - Newer clients use filter=
    """
    kwargs_base = dict(
        collection_name=COLLECTION,
        limit=BATCH,
        with_payload=True,
        with_vectors=False,
        offset=offset,
    )
    # Prefer old kw first for your environment (since 'filter' errored)
    try:
        return cli.scroll(**kwargs_base, scroll_filter=flt)
    except (AssertionError, TypeError):
        # Try new kw
        return cli.scroll(**kwargs_base, filter=flt)

updated = 0
scanned = 0
offset = None

while True:
    points, offset = scroll_page(offset, flt)
    if not points:
        break

    to_update_ids: List = []
    to_update_payloads: List[dict] = []

    for p in points:
        pl = dict(p.payload or {})
        scanned += 1

        # Guard (even if server-side filtered)
        if pl.get("published_at_ts") is not None:
            continue
        ts = to_ts(pl.get("published_at"))
        if ts is None:
            continue

        pl["published_at_ts"] = ts
        to_update_ids.append(p.id)
        to_update_payloads.append(pl)

    if not to_update_ids:
        continue

    if DRY_RUN:
        print(f"[DRY RUN] Would update {len(to_update_ids)} points (example id={to_update_ids[0]})")
    else:
        # set differing payloads per point
        for pid, pl in zip(to_update_ids, to_update_payloads):
            cli.set_payload(collection_name=COLLECTION, points=[pid], payload=pl)
        updated += len(to_update_ids)

print(
    f"{'Backfill dry-run complete.' if DRY_RUN else 'Backfill complete.'} "
    f"Scanned {scanned} points; updated {updated}."
)
