#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  echo "missing .env" >&2
  exit 1
fi

if [[ ! -f 1password-credentials.json ]]; then
  echo "missing 1password-credentials.json" >&2
  exit 1
fi

check_mode_600() {
  local path="$1"
  local mode

  if mode="$(stat -c '%a' "$path" 2>/dev/null)"; then
    :
  elif mode="$(stat -f '%Lp' "$path" 2>/dev/null)"; then
    :
  else
    echo "cannot determine permissions for ${path}" >&2
    exit 1
  fi

  if [[ "$mode" != "600" ]]; then
    echo "${path} must have mode 600 (found ${mode})" >&2
    exit 1
  fi
}

check_mode_600 .env
check_mode_600 1password-credentials.json

set -a
# shellcheck disable=SC1091
. ./.env
set +a

if [[ -z "${OP_CONNECT_TOKEN:-}" ]]; then
  echo "missing OP_CONNECT_TOKEN in .env" >&2
  exit 1
fi

sudo docker compose --env-file .env -f docker-compose.local.yml config --quiet

echo "checking 1Password Connect API..."
curl -fsS \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${OP_CONNECT_TOKEN}" \
  http://localhost:18081/v1/vaults >/dev/null

echo "checking Secret Gate..."
curl -fsS http://localhost:18080/health >/dev/null

echo "local Secret Gate stack is healthy"
