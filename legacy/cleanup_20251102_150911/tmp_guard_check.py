metadata = {"ingested_at_ts": 123, "published_at_ts": None}
if "ingested_at_ts" in metadata and metadata["ingested_at_ts"] is None:
    metadata.pop("ingested_at_ts", None)
if "published_at_ts" in metadata and metadata["published_at_ts"] is None:
    metadata.pop("published_at_ts", None)
assert metadata["ingested_at_ts"] == 123
assert "published_at_ts" not in metadata
print("OK")
