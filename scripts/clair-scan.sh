#!/bin/bash
set -euo pipefail

IMG="$1"
OUT="${2:-clair-report.json}"
MANIFEST_FILE="${3:-}"
API="${CLAIR_API:-http://localhost:6060}"

if [ -n "$MANIFEST_FILE" ]; then
  MANIFEST=$(cat "$MANIFEST_FILE")
else
  MANIFEST=$(clairctl manifest "$IMG")
fi
HASH=$(echo "$MANIFEST" | jq -r .hash)

INICIO=$(date +%s%N)

HTTP=$(curl -s -o /tmp/index-report.json -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -d "$MANIFEST" "$API/indexer/api/v1/index_report")
[ "$HTTP" = "201" ] || [ "$HTTP" = "200" ] || { echo "ERRO: indexação retornou $HTTP" >&2; exit 1; }

HTTP=$(curl -s -o "$OUT" -w "%{http_code}" \
  "$API/matcher/api/v1/vulnerability_report/$HASH")
[ "$HTTP" = "200" ] || { echo "ERRO: matcher retornou $HTTP" >&2; exit 1; }

FIM=$(date +%s%N)
MS=$(( (FIM - INICIO) / 1000000 ))
PKGS=$(jq '.packages | length' /tmp/index-report.json)
VULNS=$(jq '.vulnerabilities | length' "$OUT")
echo "imagem=$IMG digest=$HASH pacotes=$PKGS vulnerabilidades=$VULNS tempo_ms=$MS"
