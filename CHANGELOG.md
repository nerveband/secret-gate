# Changelog

## v0.5.2 — 2026-09-02

### Fixed
- Equivalent pending requests now refresh the original Telegram approval in place without sending a duplicate reminder.

## v0.5.1 — 2026-08-29

### Added
- Root-owned systemd timer for automatic deployment of verified release tags on DevBox.
- One-command bootstrap installer for the automatic deployment service.

### Fixed
- DevBox deployments authenticate private GitHub fetches, create writable service state, and build the server for amd64.
- Daemon shutdown no longer races with server goroutine registration.

## v0.5.0 — 2026-08-28

### Added
- Target-vault capability checks reject unavailable or unverifiable writes before Telegram approval.
- Equivalent pending requests renew the original request and send one compact reminder instead of creating duplicate approvals.
- Approver context identifies runtime, provider, model, thinking level, and project separately.

### Changed
- Telegram requests use fixed labels, one status emoji, and bold only the reason.
- Approved and denied messages lead with a deterministic short purpose.

### Fixed
- Telegram delivery failures no longer leave an apparently submitted request with no actionable message.
- CLI and MCP responses preserve structured write-capability errors and report `request_reused`.

## 0.4.1 — Instant Push, Hybrid Wait, and Agent Activation

### Added
- Long-polling push notification (`GET /status/{token}?wait=25`) for instant (<1ms) approval delivery.
- In-memory watch hub in the server store to publish status updates immediately on approval/denial/expiry.
- Hybrid wait & safe yield in core proxy and MCP tools: returns a clean `pending` result with resume command after the sync wait window (default 40s in MCP) instead of timing out.
- Daemon background watcher (`watch` and `unwatch` verbs) to maintain background long-polling and auto-cache approved secrets.
- Agent activation bridge: automatically wakes Paseo agents (`paseo send <agent-id> "..."`) or runs configured activation commands when approval is granted on Telegram.
- Environment detection for `PASEO_AGENT_ID` and `SECRET_GATE_ACTIVATE`.

## 0.4.0 — Agent-native CLI ("One Binary, Three Faces")

### Breaking
- Removed the legacy flag invocation (`--secret`, `--search`, `--server`, ...).
  It printed secret values to stdout with no confirmation. Flag-style calls now
  exit 2 with a structured migration hint.
- `daemon flush` is a dry run by default; pass `--commit` to flush.

### Added
- Noun-verb CLI: `item search|fields|read`, `exec`, `ssh`, `otp show|exec`,
  `write create|update`, `request submit|status|wait|cancel`,
  `daemon status|start|flush|stop`, `agent-context`, `schema`, `version`.
- JSON envelope on stdout (`schema_version`, `ok`, `command`, `data`, `meta`);
  structured errors on stderr; frozen exit codes 0–6 (docs/exit-codes.md).
- Visibility classes: metadata-only / process-only / model-visible (`--reveal`)
  / value-input (`--stdin`).
- Exact-match output redaction (`[REDACTED:item/field]`) on all child output.
- Direct argv execution (no `sh -c`) with opt-in `--shell`.
- Async recovery: `request submit --no-wait` + local ledger + `request wait`.
- `internal/core`: single domain layer shared by CLI and MCP; `secret-gate mcp`
  is now a thin adapter.
- `scripts/audit.sh`: executable agent-CLI audit subset.

### Unchanged
- MCP tool names, schemas, and behavior (exec_with_secret keeps documented
  `sh -c` semantics, now with output redaction).
- `secret-gate daemon run` internals, server HTTP API, Telegram flow.

## v0.3.2 — 2026-08-04

### Fixed

- Approved, denied, and auto-approved Telegram messages keep the agent, model, project, requested fields, and original reason after the buttons are removed.

## v0.3.1 — 2026-08-04

### Fixed

- MCP now decodes field-filtered HTTP responses correctly instead of caching an empty item.

## v0.3.0 — 2026-08-04

### Added

- Agents can read any approved item field by label, field ID, or `section.label`, including secure notes and duplicate labels in separate sections.
- MFA, OTP, TOTP, 2FA, and one-time-password aliases resolve to the same field; `get_otp` generates RFC 6238 codes with expiry timestamps.
- `write_item` creates or updates 1Password items after Telegram approval without showing values in Telegram or logs.
- Approval requests accept agent, model, thinking level, project, and task context.

### Changed

- Telegram approval messages now read as short human requests with selective emphasis instead of a label/value form.
- The Telegram approval window now approves all secret requests for its full duration. It is not limited by requester, IP address, vault, item, or field.
- The local Docker Compose stack now binds its published ports to loopback and its setup checks use the published `18080`/`18081` ports.
- CI now uses Go 1.25 and runs the portable client tests natively on macOS.
- Linux and macOS are documented as the supported client platforms; Windows remains unsupported.
- Generic Docker Compose and Docker examples bind to loopback by default.

### Fixed

- Stopping the client daemon during startup no longer races with Unix socket listener initialization.
- Local stack checks now require mode `0600` on credential files.
- `ssh_with_secret` now uses a short-lived mode-`0600` identity file when `ssh-add` is unavailable or disabled.

## v0.2.1 — Cross-Platform & SSH Fixes

### Added

- **macOS client binaries** — Docker image and server now build and serve darwin/amd64 and darwin/arm64 binaries alongside Linux. Download via `/client/{os}/{arch}`.
- **OS detection** in setup.sh and SKILL.md — `uname -s` is used to auto-detect platform when downloading the client binary.
- Legacy `/client/{arch}` path still works (assumes Linux) for backwards compatibility.

### Fixed

- **SSH agent fallback** — `ssh_with_secret` MCP tool now falls back to a temp key file with `ssh -i` when `ssh-add` fails (e.g., locked agents), instead of returning an error. The temp file is cleaned up immediately after use.
- **README "Without Secret Gate" section** — rewritten to explain actual alternatives (local 1Password CLI, service accounts, manual copy-paste) and their security tradeoffs.
- Removed OpenFaaS deployment section from public README (internal-only deployment).

## v0.2.0 — MCP Server

### Added

- **MCP server** (`secret-gate mcp`) — built-in [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio. AI agents can now search, request, and use secrets through structured MCP tool calls instead of shell commands.
- **6 MCP tools**: `search_secrets`, `inspect_fields`, `request_secret`, `exec_with_secret`, `ssh_with_secret`, `daemon_status`
- **`exec_with_secret`** — run any shell command with a secret injected as an environment variable. The secret value never appears in the agent's context.
- **`ssh_with_secret`** — SSH to a host using an approved SSH key. The key is added to ssh-agent automatically.
- **`request_secret`** — trigger Telegram approval and cache the result. Returns approval status only, never the secret value.
- Output truncation (1MB cap) for `exec_with_secret` and `ssh_with_secret` to prevent memory issues with large command output.
- SSH `BatchMode=yes` and `StrictHostKeyChecking=accept-new` for non-interactive SSH via MCP.
- Context cancellation support in the approval polling loop.
- Thread-safe daemon client with `sync.Mutex` for concurrent MCP tool calls.

### Changed

- SKILL.md updated with MCP-first workflow — MCP is now the recommended integration path, with CLI as fallback.
- README rewritten with MCP setup instructions, before/after comparison, and updated architecture.

## v0.1.0 — Initial Release

### Added

- Secret Gate server with 1Password Connect integration and Telegram approval flow.
- Client binary with search, field inspection, and secret request commands.
- Background caching daemon with Unix socket IPC and configurable TTL.
- Automatic SSH key detection and ssh-agent integration with TTL-matched expiry.
- Skill files for Claude Code, Codex, OpenCode, Cline, and Roo Code.
- One-time-use tokens for secret retrieval.
- OpenAPI 3.0 specification at `/openapi.json`.
- Docker Compose, Docker, OpenFaaS, and binary deployment options.
- GitHub Actions CI/CD with multi-platform release builds.
