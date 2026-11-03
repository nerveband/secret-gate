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

The maintained installation runs on `mac-server` under Colima. See the
[deployment and release guide](deploy/README.md) for the live Compose owner,
release steps, verification, and rollback. The Linux devbox is retired.

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
| `AUTO_APPROVE_TTL` | No | `30m` | Duration for Telegram "Approve window" sessions (reads only) |
| `WRITE_REQUEST_TTL` | No | `1h` | How long a write request waits for a tap |
| `WRITE_REMINDER_BEFORE` | No | `10m` | When to send the Telegram reminder for a pending write; `0` disables it |
| `WRITE_WINDOW_TTL` | No | `15m` | Length of the "Approve + writes" window; `0` hides the button |
| `WRITE_FOLLOWUP_TTL` | No | `15m` | How long updates to an item just written by the same requester ride on that approval; `0` disables it |
| `OP_SERVICE_ACCOUNT_TOKEN` | No | unset | 1Password service account token used only to attach files (Connect has no upload endpoint). Needs read and write access to the target vaults. Without it, writes with files are refused before approval |
| `PUSHWARD_API_KEY` | No | unset | PushWard integration key (`hlk_...`) for approval Live Activities and audit notifications (may run alongside Telegram or standalone) |
| `PUSHWARD_E2E_KEY` | No | unset | Optional 64-hex PushWard end-to-end encryption key (`pw1` format) used to seal audit and reminder notifications |
| `SECRET_GATE_APPROVER_TOKEN` | No | unset | Bearer token enabling the authenticated Approver API (`/approvals/*`) for first-party apps and gateways (such as Voice Workspace) to stream and decide approvals inline. See [docs/approver-api.md](docs/approver-api.md) |

## Client Usage

The CLI is noun-verb, emitting one JSON envelope on stdout and structured errors on stderr. See [`docs/exit-codes.md`](docs/exit-codes.md) for the frozen exit codes (0–6).

```bash
# 1. Find the item (metadata only)
secret-gate item search --query "deploy"

# 2. Inspect its fields (labels and types, no values)
secret-gate item fields --item "deploy-key"

# 3. Request approval (blocks up to --timeout; Telegram approver decides)
secret-gate request submit --item "deploy-key" --reason "deploy the api service" --fields "private key"

# 3b. Async variant: take a token now, resume later
secret-gate request submit --item "deploy-key" --reason "deploy the api service" --no-wait
secret-gate request status tok123
secret-gate request wait tok123 --timeout 10m
secret-gate request cancel tok123

# 4. Use the narrowest tool (value never enters model context)
secret-gate exec --item "prod-api" --field credential --env API_KEY -- curl -s https://api.example.com/v1/me
secret-gate ssh --item "deploy-key" --host deploy@web1.example.com --command "uptime"
secret-gate otp exec --item "github" --env OTP_CODE -- gh auth login --with-token

# 5. Only when you must read the value yourself
secret-gate item read --item "wifi-guest" --fields "note" --reveal
secret-gate otp show --item "github" --reveal
```

The client binary (`secret-gate`) runs on the machine where your AI coding agent operates. It handles communication with the server and manages a local caching daemon.

Pending approvals are recorded in `requests.json` under the client state directory. The daemon also persists metadata-only watcher records, restores non-expired watches after a restart, and updates request state when background work completes. Secret values remain memory-only and are never written to either state file.

Tracked requests move monotonically from `pending` to `approved` (read), `completed` (write), `denied`, `expired`, `failed`, or `cancelled`. Concurrent client and daemon updates are serialized with a process-shared file lock and crash-durable atomic writes.

Equivalent pending requests reuse the original request ID and token, extend
its expiry, and refresh the existing Telegram message in place. The response
includes `request_reused: true`; Secret Gate never sends a duplicate approval
or reminder for the same operation, resolved vault, fields, reason, and
requester context.

Approver context is displayed as runtime, provider, model, thinking level,
and project. MCP callers can pass these fields directly. CLI callers can
set `SECRET_GATE_RUNTIME`, `SECRET_GATE_PROVIDER`, `SECRET_GATE_MODEL`, and
`SECRET_GATE_THINK`; explicit request context takes precedence.

Write requests are checked against the target vault before approval. If
Connect reports read-only access, or write access cannot be verified
without mutation, Secret Gate rejects the request and sends a Telegram
audit warning with no approval buttons.

Writes take values on stdin only. Several items known together go into one
approval with `write batch` (up to 10 items in one vault). `--no-wait`
returns a token at once; the server keeps the values while approval is
pending and the local daemon finishes the write after the tap, so the agent
does not have to hold them:

```bash
echo '{"fields":{"otp":"<seed>"}}' \
  | secret-gate write create --item "WordPress.org 2FA" --vault "AI Agents" --reason "store 2FA seed" --stdin --no-wait
secret-gate request wait <token>

echo '{"items":[{"item":"Play key","operation":"create","fields":{"credential":"<json>"}},
                {"item":"Expo token","operation":"create","fields":{"token":"<value>"}}]}' \
  | secret-gate write batch --vault "AI Agents" --reason "store release credentials" --stdin
```

Write approvals in Telegram offer `Approve once`, `Approve + writes 15m`,
and `Deny`. Pending writes wait up to an hour, get one reminder ten minutes
before expiry, and the message changes to "Expired" when the request lapses.
See [docs/write-ux.md](docs/write-ux.md) for what each approval covers.

### Cards, API credentials, and secure notes

`--category card|api|note|login|password` creates items in the native
1Password category, so they look right in the 1Password app. Friendly labels
map onto the native fields (cards: `cardholder`, `number`, `cvv`, `expiry`,
`type`, `pin`, `bank`, `billing_address`, `city`, `state`, `zip`, `country`;
API credentials: `credential`, `username`, `hostname`, `expires`, `scopes`).
Card numbers are Luhn-checked and the card type is detected when omitted.
Values the agent does not have are typed by the approver:
`--owner-fields cvv` puts an "Enter values" link on the Telegram approval,
and saving that page on the phone approves the write.

```bash
secret-gate item fields --item "Visa travel"          # masked: type, last 4, expiry; no approval
secret-gate write update --item "Visa travel" --vault "AI Agents" --owner-fields cvv --reason "add the CVV" --no-wait
secret-gate request submit --item "Visa travel" --fields number,cvv,expiry,cardholder \
  --purpose "aa.com checkout" --amount '$412.30' --reason "pay for the DFW flight"
secret-gate browser fill --item "Visa travel" --cdp "$(agent-browser get cdp-url)" --page-url aa.com \
  --field 'number=#cardNumber' --field 'cvv=#cvv' --field 'expiry:MM/YY=#exp'
```

Card numbers, CVVs, and PINs are process-only: `exec` and `browser fill`
use them, `item read` and `read_item_fields` never return them. Reading them
needs `--purpose`; with `--amount` Telegram shows "Approve $412.30 at aa.com checkout, Visa ending 1111" and an "Approve $412.30" button;
card reads and card writes always need a tap on that request (no read or
write windows), and card values stay cached for at most 15 minutes. See
[docs/typed-items.md](docs/typed-items.md).

### Attachments

`item fields` lists an item's attachments (name, size, ID). Approve one by
naming it, then hand it to a command; the content never enters model
context:

```bash
secret-gate request submit --item "release keys" --fields "file:release.jks" --reason "sign the release"
secret-gate attachment exec --item "release keys" --file release.jks --env KEYSTORE -- ./gradlew assembleRelease
secret-gate attachment exec --item "release keys" --file release.jks --stdin -- shasum -a 256
```

`--env` writes a mode-`0600` temporary file in a private directory and
deletes it when the command exits. To attach files, add
`"files":[{"path":"./release.jks"}]` to the stdin JSON of `write create`,
`write update`, or each `write batch` item. Telegram shows file names and
sizes, never content. Limit: 10 MiB per request. Attaching needs
`OP_SERVICE_ACCOUNT_TOKEN` on the server; reading uses Connect.

Managed SSH commands use an isolated OpenSSH configuration (`-F /dev/null`) with explicit host, port, identity, batch mode, and host-key options. User-level `Include`, `ProxyJump`, and host aliases are intentionally not applied; pass the concrete destination to `--host`.

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

| Tool | Description |
|------|-------------|
| `search_secrets` | Search 1Password items by name |
| `inspect_fields` | List field names/types and attachments without values |
| `request_secret` | Request access with Telegram approval (returns status, not the value); name attachments as `file:<name>` |
| `read_item_fields` | Read any approved field by label, ID, or `section.label`; omit fields to read the whole item (never attachments) |
| `get_otp` | Generate the current MFA/OTP/TOTP/2FA code from an approved OTP field |
| `write_item` | Create or update a 1Password item after Telegram approval, optionally attaching local files |
| `write_items` | Up to 10 creates or updates behind one approval |
| `attach_file` | Attach a local file to an item after Telegram approval |
| `read_attachment` | Run a command with an approved attachment as a temporary file or on stdin |
| `exec_with_secret` | Run a command with a secret injected as an env var |
| `ssh_with_secret` | SSH to a host using an approved SSH key |
| `passkey_arm` / `passkey_register` | Capture a passkey a site registers in a browser tab and store it as an item |
| `passkey_load` / `passkey_release` | Put an approved passkey into a browser tab for sign-in, then remove it |
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

Telegram keeps the full request narrative after a decision. Approved, denied, and auto-approved messages still show the agent, model, project, requested fields, and original reason, followed by who made the decision.

### Passkeys

Passkeys that 1Password itself saved cannot be used through any 1Password
developer API: Connect, the 1Password CLI, and the SDKs cannot export their
private key or perform a WebAuthn ceremony (sources in
[docs/passkeys-attachments.md](docs/passkeys-attachments.md)). Those still
need the 1Password browser extension.

Secret Gate can create and use its own passkeys instead. The local daemon
opens a Chrome DevTools session to a tab of a browser that exposes a
DevTools endpoint on this machine (for example agent-browser:
`agent-browser get cdp-url`) and adds a WebAuthn virtual authenticator:

```bash
CDP="$(agent-browser get cdp-url)"
secret-gate passkey arm --cdp "$CDP" --page-url webauthn.io            # then register on the site
secret-gate passkey register --session <id> --item "webauthn.io passkey" --vault "AI Agents" --reason "save the agent's passkey"
secret-gate passkey release --session <id>

secret-gate request submit --item "webauthn.io passkey" --vault "AI Agents" --reason "sign in"
secret-gate passkey load --item "webauthn.io passkey" --vault "AI Agents" --cdp "$CDP" --page-url webauthn.io   # then sign in
secret-gate passkey release --session <id>
```

The item stores `passkey credential id`, `passkey private key`
(concealed), `passkey rp id`, `passkey user handle`, and
`passkey sign count`. The private key travels 1Password → daemon → browser
and is never printed. A loaded passkey stays usable for `--hold` (default
10 minutes, maximum 30) or until released. ego lite and Aside do not expose
a DevTools endpoint and cannot be used for this.

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
- Pending watcher metadata is persisted with `0600` permissions and restored after daemon restarts
- Completed reads and writes update the durable request ledger before notifying the requesting agent
- Failed write completion is retried until request expiry and reported as `failed`, never as a successful approval

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
| `GET` | `/approvals` | Bearer `SECRET_GATE_APPROVER_TOKEN` | List pending approval requests (metadata only, never secret values) |
| `GET` | `/approvals/events` | Bearer `SECRET_GATE_APPROVER_TOKEN` | Real-time SSE stream of approval lifecycle events (`snapshot`, `approval.created`, `approval.approved`, `approval.denied`, `approval.expired`, `window.revoked`) |
| `POST` | `/approvals/{id}/decide` | Bearer `SECRET_GATE_APPROVER_TOKEN` | Approve (`approve`, `approve_window`, `approve_writes`) or `deny` a pending request from an external app |
| `POST` | `/approvals/windows/{id}/revoke` | Bearer `SECRET_GATE_APPROVER_TOKEN` | Revoke an active write auto-approval window |
| `GET` | `/client/{os}/{arch}` | None | Download the pre-compiled client binary (linux/darwin, amd64/arm64) |
| `GET` | `/health` | None | Health check |
| `GET` | `/openapi.json` | None | Full OpenAPI 3.0 specification |

For detailed request/response schemas, see the OpenAPI spec at `/openapi.json` on a running server.

## Security

- **Memory-only cache.** Cached secret values stay in the daemon process. SSH-agent integration uses a mode-`0600` temporary private-key file because `ssh-add` accepts a path; the file is removed immediately after `ssh-add` returns. If `ssh-add` fails, `ssh_with_secret` uses another short-lived mode-`0600` file with `ssh -i` and removes it when SSH exits.
- **Controlled agent visibility.** `exec_with_secret` and `ssh_with_secret` keep values out of agent context. `read_item_fields` and `get_otp` return only values covered by the approved item/field request because some tasks require the agent to read them.
- **Approval-gated writes.** Create and update values stay in server memory while pending, are omitted from Telegram and logs, are sent to 1Password only after approval, and are dropped from memory once written, denied, or expired. Telegram shows item names and field labels so the approver knows what is being stored. Attached files follow the same rules; Telegram shows file names and sizes only.
- **Attachments stay out of model context.** Attachment content is released only when the request names it (`file:<name>`), is cached in daemon memory like other values, is never returned by `item read` or `read_item_fields`, and reaches commands as a mode-`0600` temporary file that is deleted afterwards, or on stdin.
- **Passkeys are held, not printed.** Passkey keys go only from the daemon to a loopback DevTools endpoint and the tab's virtual authenticator, which is removed on release or after the hold time. Anything else with DevTools access to the same browser could read a loaded key, so the browser endpoint must be trusted like the agent itself.
- **Scoped write grants.** Writes never ride on the read window. A write is approved by a tap, by an "Approve + writes" window (new items only, same machine, requester IP, Paseo agent ID, and vault, revocable from Telegram), or by a same-item follow-up grant (updates to an item that requester just wrote). Each auto-approved write posts a Telegram audit message, and the write falls back to a normal approval if that message cannot be sent. Grants are in memory and end on server restart. See [docs/write-ux.md](docs/write-ux.md).
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
