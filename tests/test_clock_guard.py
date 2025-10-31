def apply_guard(md: dict):
    # mirror indexer.py guard
    if "ingested_at_ts" in md and md["ingested_at_ts"] is None:
        md.pop("ingested_at_ts", None)
    if "published_at_ts" in md and md["published_at_ts"] is None:
        md.pop("published_at_ts", None)
    return md

def test_preserves_existing_ingest_clock():
    md = {"ingested_at_ts": 123, "published_at_ts": None}
    out = apply_guard(md.copy())
    assert out["ingested_at_ts"] == 123
    assert "published_at_ts" not in out

def test_removes_none_fields_only():
    md = {"ingested_at_ts": None, "published_at_ts": None}
    out = apply_guard(md.copy())
    assert "ingested_at_ts" not in out
    assert "published_at_ts" not in out
