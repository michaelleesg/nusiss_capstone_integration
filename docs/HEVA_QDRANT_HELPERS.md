# Qdrant quick helpers

Make sure the helper functions are loaded:
```bash
source scripts/qdr_helpers.sh
```

## Count in a window (SGT)
```bash
START=$(date -d '2025-10-01T00:00:00+08:00' +%s)
END=$(date   -d '2025-11-01T00:00:00+08:00' +%s)
qdr_count_window heva_v1 ingested_at_ts "$START" "$END"
```

## Range scroll (last 7 days by ingest clock)
```bash
SINCE=$(( $(date +%s) - 7*86400 ))
qdr_range heva_docs ingested_at_ts "$SINCE" "" 5
```
