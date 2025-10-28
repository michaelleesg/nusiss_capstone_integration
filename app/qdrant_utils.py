from __future__ import annotations

from typing import Dict, Any, Optional
from qdrant_client import QdrantClient
from qdrant_client.models import Filter


def set_payload_by_filter(
    client: QdrantClient,
    collection: str,
    payload: Dict[str, Any],
    flt: Optional[Filter] = None,
    limit: int = 1000,
    wait: bool = True,
) -> int:
    """
    Bulk-update payload values for all points matching a filter.
    Returns the number of points updated.
    Compatible with Qdrant client versions that require explicit 'points' in set_payload().

    Args:
        client: The Qdrant client instance.
        collection_name: The name of the collection to update.
        filter_condition: The condition to filter the documents.
        payload: The new payload to set for the filtered documents.
    """
    # Use scroll to fetch all matching documents
    point_ids = []
    next_offset = None
    while True:
        points, next_offset = client.scroll(
            collection_name=collection,
            scroll_filter=flt,
            with_payload=False,
            limit=limit,
            offset=next_offset,
        )
        if not points:
            break
        point_ids.extend(p.id for p in points)
        if not next_offset:
            break

    # Update the payload for the fetched documents
    if not point_ids:
        return 0

    client.set_payload(
        collection_name=collection,
        points=point_ids,  # required by many client versions
        payload=payload,
        wait=wait,
    )
    return len(point_ids)
