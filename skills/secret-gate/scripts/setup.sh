#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${HOME}/.config/secret-gate"
CONFIG_FILE="${CONFIG_DIR}/config.json"
BIN_DIR="${CONFIG_DIR}/bin"
BIN_PATH="${BIN_DIR}/secret-gate"
GITHUB_REPO="nerveband/secret-gate"

usage() {
  echo "Usage: setup.sh [--server <url>]"
  echo "Downloads the Secret Gate client and saves its server URL."
}

server_url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) server_url="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$server_url" ]]; then
  server_url="${SECRET_GATE_URL:-${OP_APPROVAL_PROXY_URL:-}}"
fi
if [[ -z "$server_url" && -f "$CONFIG_FILE" ]]; then
  server_url=$(sed -n 's/.*"server_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -1)
fi
if [[ -z "$server_url" ]]; then
  echo "Enter the Secret Gate server URL:"
  read -r server_url
fi
if [[ -z "$server_url" ]]; then
  echo "Error: server URL is required" >&2
  exit 1
fi
server_url="${server_url%/}"

case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
  linux) client_os="linux" ;;
  darwin) client_os="darwin" ;;
  *) echo "Unsupported operating system" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) client_arch="amd64" ;;
  aarch64|arm64) client_arch="arm64" ;;
  *) echo "Unsupported architecture" >&2; exit 1 ;;
esac

mkdir -p "$CONFIG_DIR" "$BIN_DIR"
chmod 700 "$CONFIG_DIR"
umask 077
printf '{"server_url":"%s"}\n' "$server_url" > "$CONFIG_FILE"

download_url="$server_url/client/$client_os/$client_arch"
http_code=$(curl -sSL -w '%{http_code}' -o "$BIN_PATH" "$download_url")
if [[ "$http_code" != "200" ]]; then
  rm -f "$BIN_PATH"
  download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/secret-gate-${client_os}-${client_arch}"
  http_code=$(curl -sSL -w '%{http_code}' -o "$BIN_PATH" "$download_url")
fi
if [[ "$http_code" != "200" ]]; then
  rm -f "$BIN_PATH"
  echo "Error: client download failed with HTTP $http_code" >&2
  exit 1
fi
chmod 755 "$BIN_PATH"

echo "Installed $BIN_PATH for $client_os/$client_arch"
if curl -fsS --max-time 5 "$server_url/health" >/dev/null; then
  echo "Secret Gate server is healthy."
else
  echo "Warning: the client is installed, but the server health check failed." >&2
fi
