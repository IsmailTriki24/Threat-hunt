#!/usr/bin/env sh
# Download the free DB-IP Lite City + ASN databases (CC BY 4.0: https://db-ip.com/db/lite.php) into ./data/geoip for the threat map.
# Prefer MaxMind GeoLite2? Put GeoLite2-City.mmdb / GeoLite2-ASN.mmdb in ./data/geoip and set GEOIP_DB_PATH / GEOIP_ASN_DB_PATH instead.
set -eu
cd "$(dirname "$0")/.."
mkdir -p data/geoip
for k in city asn; do
  ok=""
  for back in 0 1 2; do   # databases are published monthly; fall back to the previous months
    ym=$(date -u -d "$(date -u +%Y-%m-15) -$back month" +%Y-%m 2>/dev/null || date -u -v-"${back}"m +%Y-%m)
    url="https://download.db-ip.com/free/dbip-$k-lite-$ym.mmdb.gz"
    if curl -fsSL --max-time 600 -o "data/geoip/dbip-$k-lite.mmdb.gz" "$url"; then
      gunzip -f "data/geoip/dbip-$k-lite.mmdb.gz"; echo "dbip-$k-lite.mmdb <- $url"; ok=1; break
    fi
  done
  [ -n "$ok" ] || { echo "could not download dbip-$k-lite" >&2; exit 1; }
done
echo "Restart the backend to pick the databases up: docker compose restart backend"
