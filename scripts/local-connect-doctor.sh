#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "missing .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

if [[ ! -f 1password-credentials.json ]]; then
  echo "missing 1password-credentials.json" >&2
  exit 1
fi

if [[ -z "${OP_CONNECT_TOKEN:-}" ]]; then
  echo "missing OP_CONNECT_TOKEN in .env" >&2
  exit 1
fi

docker compose --env-file .env -f docker-compose.local.yml config --quiet

echo "checking 1Password Connect API..."
curl -fsS \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
  http://localhost:8081/v1/vaults >/dev/null

echo "checking Secret Gate..."
curl -fsS http://localhost:8080/health >/dev/null

echo "local Secret Gate stack is healthy"
