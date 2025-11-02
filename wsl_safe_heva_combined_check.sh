#!/usr/bin/env bash
# WSL-safe HEVA combined query check (no -euo pipefail; always ends with a prompt)
# Usage: chmod +x wsl_safe_heva_combined_check.sh && ./wsl_safe_heva_combined_check.sh

QDR="${QDR:-http://127.0.0.1:6333}"
COL="${COL:-heva_docs}"
SINCE="$(( $(date +%s) - 7*86400 ))"   # last 7 days (seconds)

echo "— Checking collection: $COL —"
curl -sS -o /tmp/qdr_check.body -w "HTTP %{http_code}\n" "$QDR/collections/$COL"
echo

if ! tail -n1 /tmp/qdr_check.body | grep -q "HTTP 200"; then
  echo "→ $COL not found (or server responded non-200). Creating…"
  curl -sS -X PUT "$QDR/collections/$COL" \
    -H 'Content-Type: application/json' \
    -d '{"vectors":{"size":384,"distance":"Cosine"},"on_disk_payload":true}' >/dev/null || true
  echo "→ Created (or already existed)."
fi

echo
echo "— Ensure there is at least one THREAT_ACTOR doc >= $SINCE —"
# Build a scroll request safely
jq -n --argjson since "$SINCE" '{
  limit: 1, with_payload: true, with_vectors: false,
  filter: { must: [
    { match: { key: "tags", value: "THREAT_ACTOR" } },
    { key: "ingested_at_ts", range: { gte: $since } }
  ] }
}' >/tmp/scroll_req.json

curl -sS -o /tmp/scroll_resp.body -w "%{http_code}" \
  -X POST "$QDR/collections/$COL/points/scroll" \
  -H 'Content-Type: application/json' \
  -d @/tmp/scroll_req.json >/tmp/scroll_resp.code || true

SCROLL_CODE="$(cat /tmp/scroll_resp.code)"
if [ "$SCROLL_CODE" != "200" ]; then
  echo "→ Scroll check returned HTTP $SCROLL_CODE (may be empty collection or filter mismatch). Seeding a demo point…"
  NOW="$(date +%s)"
  jq -n --argjson now "$NOW" '{
    points: [{
      id: (now|tostring|tonumber? // 1),
      vector: ( [0,0,0,0] ),
      payload: {
        text: "Seed THREAT_ACTOR doc",
        source: "seed",
        tags: ["THREAT_ACTOR"],
        threat_actors: ["TA505"],
        ingested_at_ts: $now
      }
    }]
  }' >/tmp/upsert_req.json
  curl -sS -X PUT "$QDR/collections/'"$COL"'/points" \
    -H 'Content-Type: application/json' \
    -d @/tmp/upsert_req.json >/dev/null || true
else
  COUNT="$(jq -r '(.result.points // []) | length' </tmp/scroll_resp.body 2>/dev/null)"
  if [ -z "$COUNT" ] || [ "$COUNT" = "0" ]; then
    echo "→ No matching docs yet; seeding one demo point…"
    NOW="$(date +%s)"
    jq -n --argjson now "$NOW" '{
      points: [{
        id: (now|tostring|tonumber? // 1),
        vector: ( [0,0,0,0] ),
        payload: {
          text: "Seed THREAT_ACTOR doc",
          source: "seed",
          tags: ["THREAT_ACTOR"],
          threat_actors: ["TA505"],
          ingested_at_ts: $now
        }
      }]
    }' >/tmp/upsert_req.json
    curl -sS -X PUT "$QDR/collections/'"$COL"'/points" \
      -H 'Content-Type: application/json' \
      -d @/tmp/upsert_req.json >/dev/null || true
  else
    echo "→ Found existing matching doc(s): $COUNT"
  fi
fi

echo
echo "— Running combined query (tags=THREAT_ACTOR AND ingested_at_ts >= $SINCE) —"
jq -n --argjson since "$SINCE" '{
  limit: 10, with_payload: true, with_vectors: false,
  filter: { must: [
    { match: { key: "tags", value: "THREAT_ACTOR" } },
    { key: "ingested_at_ts", range: { gte: $since } }
  ] }
}' >/tmp/combined_req.json

CODE="$(curl -sS -o /tmp/combined_resp.body -w "%{http_code}" \
  -X POST "$QDR/collections/$COL/points/scroll" \
  -H 'Content-Type: application/json' \
  -d @/tmp/combined_req.json || true)"

echo "HTTP $CODE"
if [ "$CODE" = "200" ]; then
  jq -c '{count: ((.result.points // []) | length),
          items: ((.result.points // []) | map({id, payload}))}' \
     </tmp/combined_resp.body 2>/dev/null \
     || { echo "[warn] jq failed to parse body (see /tmp/combined_resp.body)"; }
else
  echo "[error] Server responded with HTTP $CODE"
  head -200 </tmp/combined_resp.body
fi

echo
read -rp "Press Enter to exit…"
