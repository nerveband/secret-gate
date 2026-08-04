# Secret Gate

**Human-in-the-loop secret approval for AI coding agents. Retrieve secrets from 1Password with Telegram-based approval.**

![CI](https://github.com/nerveband/secret-gate/actions/workflows/test.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## Why Secret Gate?

AI coding agents need credentials — SSH keys, API tokens, database passwords — but giving them free access to your secrets is a non-starter. Secret Gate puts you in control:

- **Approve every secret access from your phone** via Telegram, with full context on what the agent needs and why
- **Secrets never touch disk** — cached in memory only, with automatic expiry
- **MCP integration** — agents use secrets without you approving every single shell command. One Telegram tap, then the agent runs autonomously
- **Works with any AI coding tool** — Claude Code, Codex, Cline, OpenCode, Roo Code

### Without Secret Gate

Your agent needs credentials, and your options are bad:

- **1Password CLI locally** — requires the agent's machine to have `op` installed and authenticated. Works on your laptop, breaks on remote VMs, CI runners, and cloud dev environments.
- **Service account with vault access** — gives the agent (and anyone who compromises it) access to your *entire vault*. One leaked token = all secrets exposed.
- **Manual copy-paste** — you become the bottleneck. Every credential request interrupts your flow.

In all cases, secrets end up in plaintext — written to temp files, exported as env vars in shell history, or pasted into the conversation.

### With Secret Gate (CLI)

```
Agent: "I need the deploy SSH key"
→ You approve once on Telegram
→ Agent writes key to /tmp/key ← still on disk
→ Agent runs: export TOKEN=sk-... ← needs your approval
→ Agent runs: ssh -i /tmp/key ... ← needs your approval
→ Agent runs: rm /tmp/key ← needs your approval
```

Better — approval is remote and per-secret — but still four manual shell approvals and secrets on disk.

### With Secret Gate + MCP

```
Agent: "I need the deploy SSH key"
→ You approve once on Telegram
→ Agent calls exec_with_secret() ← zero interaction, secret never visible
→ Done.
```

One tap on your phone. Zero secrets on disk. Zero manual shell approvals. Commands can receive values without putting them in model context; approved notes and OTP codes can be returned when the task requires them.

## How It Works

1. Your AI coding agent detects it needs a credential
2. The agent searches for the secret in 1Password via the Secret Gate server
3. The agent requests access — you receive a Telegram notification with **Approve** / **Deny** buttons
4. On approval, the agent retrieves the secret through a one-time-use token
5. SSH keys are automatically added to ssh-agent with TTL-matched expiry; secrets are cached in memory by the local daemon

## Quick Start

```bash
# 1. Clone and start the server
git clone https://github.com/nerveband/secret-gate.git
cd secret-gate
cp .env.example .env  # Edit with your credentials
docker compose up -d

# 2. Install the client + AI tool integration
curl -sL https://raw.githubusercontent.com/nerveband/secret-gate/main/install.sh | bash -s -- --server http://localhost:8080

# 3. That's it — your AI coding tool will auto-detect the skill
```

## Prerequisites

- **1Password Connect server** — a running instance that Secret Gate queries for secrets ([setup guide](https://developer.1password.com/docs/connect/get-started/))
- **Telegram bot** — created via [@BotFather](https://t.me/BotFather) to send approval notifications
- **Docker** (recommended) or Go 1.25+ for building from source

### Supported client platforms

The client supports Linux and macOS on amd64 and arm64. Release binaries for macOS are cross-built on Linux, while portable client tests also run natively on GitHub-hosted macOS runners. The project does not provide macOS signing or notarization.

Windows is not supported. The cache daemon relies on Unix sockets and POSIX process controls, and MCP command execution uses `sh`. No Windows binaries or Windows service integration are published.

## Server Deployment

### Docker Compose (recommended)

Create a `.env` file with your configuration (see [Server Configuration](#server-configuration)), then:

```bash
docker compose up -d
```

### Docker

```bash
docker run -d \
  -p 127.0.0.1:8080:8080 \
  -e OP_CONNECT_HOST=https://connect.example.com \
  -e OP_CONNECT_TOKEN=your-token \
  -e TELEGRAM_BOT_TOKEN=your-bot-token \
  -e TELEGRAM_CHAT_ID=your-chat-id \
  -e WEBHOOK_BASE_URL=https://gate.example.com \
  ghcr.io/nerveband/secret-gate:latest
```

### Binary

```bash
go install github.com/johnuopini/secret-gate/cmd/server@latest
```

Then run the `server` binary with the required environment variables set.

## Server Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OP_CONNECT_HOST` | Yes | — | 1Password Connect server URL |
| `OP_CONNECT_TOKEN` | Yes | — | 1Password Connect API token |
| `TELEGRAM_BOT_TOKEN` | Yes | — | Telegram bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Yes | — | Telegram chat ID for approval notifications |
| `WEBHOOK_BASE_URL` | Yes | — | Public URL where this server is accessible |
| `PORT` | No | `8080` | HTTP listen port |
| `REQUEST_TTL` | No | `15m` | How long approval requests remain valid |
| `CLEANUP_INTERVAL` | No | `5m` | Interval for cleaning up expired requests |
| `AUTO_APPROVE_TTL` | No | `30m` | Duration for Telegram "Approve window" sessions |

## Client Installation

The CLI is a complete approval-request fallback and does not require MCP. It can search items, inspect field metadata, submit a Telegram request, wait for approval, and retrieve the approved response. MCP is recommended when an agent needs process-only injection, SSH-agent integration, current OTP generation, structured request context, or approval-gated writes.

```bash
secret-gate --server https://your-server --search "release account" --format json
secret-gate --server https://your-server --secret "release-account" --vault "Agents" --fields --format json
secret-gate --server https://your-server --secret "release-account" --vault "Agents" --field password --reason "publish the release"
```

The client binary (`secret-gate`) runs on the machine where your AI coding agent operates. It handles communication with the server and manages a local caching daemon.

### From the server

The server hosts pre-compiled client binaries for Linux and macOS at `/client/{os}/{arch}`:

```bash
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sL "https://your-server/client/${OS}/${ARCH}" -o secret-gate
chmod +x secret-gate
sudo mv secret-gate /usr/local/bin/
```

### From GitHub Releases

Download the latest release from [github.com/nerveband/secret-gate/releases](https://github.com/nerveband/secret-gate/releases).

### From source

```bash
go install github.com/johnuopini/secret-gate/cmd/client@latest
```

## AI Tool Integration

Secret Gate integrates with AI coding agents in two ways: **MCP** (recommended) and **Skills** (fallback).

### MCP Server (recommended)

The client binary includes a built-in [MCP](https://modelcontextprotocol.io/) server. When configured, your AI agent uses secrets through structured tool calls — no shell commands needed, no secrets visible in the conversation.

**Claude Code setup:**

Add to `~/.claude.json`:
```json
{
  "mcpServers": {
    "secret-gate": {
      "command": "secret-gate",
      "args": ["mcp"]
    }
  }
}
```

Add to `~/.claude/settings.json` under `permissions.allow`:
```json
"mcp__secret-gate__*"
```

**MCP Tools:**

| Tool | Description |
|------|-------------|
| `search_secrets` | Search 1Password items by name |
| `inspect_fields` | List field names/types without values |
| `request_secret` | Request access with Telegram approval (returns status, not the value) |
| `read_item_fields` | Read any approved field by label, ID, or `section.label`; omit fields to read the whole item |
| `get_otp` | Generate the current MFA/OTP/TOTP/2FA code from an approved OTP field |
| `write_item` | Create or update a 1Password item after Telegram approval |
| `exec_with_secret` | Run a command with a secret injected as an env var |
| `ssh_with_secret` | SSH to a host using an approved SSH key |
| `daemon_status` | Check cache daemon status |

**Example flow:**

```
search_secrets(query="deploy ssh key")
→ [{name: "prod-deploy-key", vault: "infra"}]

request_secret(secret_name="prod-deploy-key", reason="deploy app to production")
→ Telegram approval → {status: "approved", cached: true}

ssh_with_secret(secret_name="prod-deploy-key", host="deploy@prod", command="kubectl rollout restart deployment/app")
→ {exit_code: 0, stdout: "deployment.apps/app restarted"}
```

For a secure note or custom context field:

```
inspect_fields(secret_name="release-account", vault="Agents")
→ fields include IDs, labels, types, purposes, sections, and references

request_secret(
  secret_name="release-account",
  vault="Agents",
  fields=["notes", "context"],
  reason="read the release instructions",
  context={agent: "Codex", model: "gpt-5.6-luna", think: "low", project: "ts-project", task: "publish the release"}
)
→ Telegram explains who needs which fields and why

read_item_fields(secret_name="release-account", vault="Agents", fields=["notes", "context"])
→ returns only the approved fields
```

For MFA, request any OTP alias and then generate the current code:

```
request_secret(secret_name="release-account", vault="Agents", fields=["mfa"], reason="complete sign-in")
get_otp(secret_name="release-account", vault="Agents", field="2fa")
→ {code: "…", expires_at: "…"}
```

Writes also use Telegram approval. Create and update values stay in server memory while the request is pending. Write requests never qualify for an approval window.

Use `exec_with_secret` when the agent does not need to see a value. `read_item_fields` intentionally returns approved values to the agent for tasks that require their contents, such as reading a secure note. Request only the fields needed for the task.

Field matching is case-insensitive and ignores spaces, hyphens, and underscores. `mfa`, `otp`, `totp`, `2fa`, and `one-time password` are aliases. `note`, `notes`, `secure note`, and `notesPlain` are aliases. Duplicate labels can be addressed by field ID or `section.label`.

### Passkeys

Secret Gate reports passkey fields during inspection, but 1Password Connect cannot perform a WebAuthn ceremony or export a passkey private key. Passkey sign-in still requires the 1Password browser extension or app on an interactive device. Secret Gate returns this boundary instead of exposing passkey material or claiming a login succeeded.

### Skill Files (fallback)

For tools that don't support MCP, Secret Gate ships with skill files that teach agents how to use the CLI client. The `install.sh` script places these in the correct location.

**Supported tools:** Claude Code, OpenAI Codex, OpenCode, Cline, Roo Code.

```bash
# Auto-detect and install for all detected tools
curl -sL https://raw.githubusercontent.com/nerveband/secret-gate/main/install.sh | bash -s -- \
  --server https://your-server

# Install for a specific tool
curl -sL https://raw.githubusercontent.com/nerveband/secret-gate/main/install.sh | bash -s -- \
  --server https://your-server --tool claude-code
```

## Client Configuration

The client reads its configuration from `~/.config/secret-gate/config.json`. Environment variables override file values.

```json
{
  "server_url": "https://your-server",
  "cache_ttl": "1h",
  "daemon_idle_timeout": "5m",
  "ssh_agent_integration": true
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `server_url` | — | Secret Gate server URL (also set via `SECRET_GATE_URL` env var) |
| `cache_ttl` | `1h` | How long secrets are cached locally by the daemon |
| `daemon_idle_timeout` | `5m` | Daemon exits after this period of inactivity |
| `ssh_agent_integration` | `true` | Automatically add SSH keys to ssh-agent on retrieval |

## Daemon (Caching)

The client includes a background daemon that caches approved secrets in memory, eliminating redundant approval prompts for recently used credentials.

- The daemon starts automatically on the first secret request
- Secrets are cached for the configured `cache_ttl` (default: 1 hour)
- The daemon exits automatically after `daemon_idle_timeout` of inactivity (default: 5 minutes)
- Communication between the client and daemon uses a Unix socket with `0600` permissions

**Daemon commands:**

```bash
secret-gate daemon status    # Check daemon status and cache entries
secret-gate daemon flush     # Clear all cached secrets
secret-gate daemon stop      # Stop the daemon
```

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/search` | None | Search for secrets across all vaults (no approval required) |
| `POST` | `/fields` | None | Get field metadata for a secret without exposing values |
| `POST` | `/request` | None | Request access to one or more secrets (triggers Telegram approval) |
| `GET` | `/status/{token}` | Token | Check approval status of a pending request |
| `GET` | `/secret/{token}` | Token | Retrieve the approved secret (one-time use) |
| `GET` | `/client/{os}/{arch}` | None | Download the pre-compiled client binary (linux/darwin, amd64/arm64) |
| `GET` | `/health` | None | Health check |
| `GET` | `/openapi.json` | None | Full OpenAPI 3.0 specification |

For detailed request/response schemas, see the OpenAPI spec at `/openapi.json` on a running server.

## Security

- **Memory-only cache.** Cached secret values stay in the daemon process. SSH-agent integration uses a mode-`0600` temporary private-key file because `ssh-add` accepts a path; the file is removed immediately after `ssh-add` returns. If `ssh-add` fails, `ssh_with_secret` uses another short-lived mode-`0600` file with `ssh -i` and removes it when SSH exits.
- **Controlled agent visibility.** `exec_with_secret` and `ssh_with_secret` keep values out of agent context. `read_item_fields` and `get_otp` return only values covered by the approved item/field request because some tasks require the agent to read them.
- **Approval-gated writes.** Create and update values stay in server memory while pending, are omitted from Telegram and logs, and are sent to 1Password only after approval.
- **Unix socket IPC.** The daemon listens on a Unix socket with `0600` permissions, accessible only to the owning user.
- **SSH agent integration.** SSH keys are added to ssh-agent with a TTL that matches the cache expiry, so they are automatically removed.
- **Telegram approval gate.** Secret access requires explicit human approval through Telegram inline buttons. The optional "Approve window" button creates a global, in-memory approval session that approves all requests until the window expires.
- **One-time tokens.** Secret retrieval tokens can only be used once. A second fetch returns an error.
- **Configurable TTL.** All approval requests expire after a configurable duration (default: 15 minutes).
- **Configurable approval windows.** `AUTO_APPROVE_TTL` controls how long Telegram approval-window sessions remain active (default: 30 minutes).

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit your changes
4. Push to the branch and open a Pull Request

Please include tests for new functionality and ensure existing tests pass (`go test ./...`).

## License

MIT — see [LICENSE](LICENSE) for details.
