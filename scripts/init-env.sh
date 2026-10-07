#!/usr/bin/env sh
# Create .env from .env.example with freshly generated random secrets.
set -eu
cd "$(dirname "$0")/.."
[ -e .env ] && { echo ".env already exists; not overwriting" >&2; exit 1; }
rand() { openssl rand -hex 24; }
sed \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand)|" \
  -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(rand)|" \
  -e "s|^MINIO_ROOT_PASSWORD=.*|MINIO_ROOT_PASSWORD=$(rand)|" \
  -e "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -hex 32)|" \
  -e "s|^SEED_PASSWORD=.*|SEED_PASSWORD=|" \
  .env.example > .env
chmod 600 .env
echo "Wrote .env. Demo user password will be printed in the 'init' service logs: docker compose logs init"
