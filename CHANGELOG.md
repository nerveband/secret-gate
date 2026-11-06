# Changelog

## v0.8.3 (2026-11-06)

### Added
- `exec`, `exec --dry-run`, `exec_with_secret`, and `browser fill` return `alternatives`: names of other fields that match the requested name with a different, non-empty value (a saved web-form `Password` next to the login password). An agent whose login fails requests one (`request submit --fields Password`) and retries. The server lists them, names only, when it releases a field; the cached value never answers for an alternative.
- `item fields` shows each field's `selector`. Fields without an ID whose label repeats (saved web-form fields) are now addressable as `label#n`.

### Changed
- An exact field name now wins over the 1Password purpose: `Password` reaches a non-empty field labeled exactly `Password`. `password` (the login field's ID) and other spellings still reach the login password, and an empty value still never wins.

## v0.8.2 (2026-11-06)

### Fixed
- A login whose saved web-form fields include an empty "Password" next to the real password released the empty one at random: field names match without case, and the first match in map order won. Resolution is now deterministic: a non-empty value beats an empty one, then the field with the matching 1Password purpose (PASSWORD, USERNAME, NOTES), then a CONCEALED field for `password`, then the exact name. Names that still match several different values fail with a validation error that lists them; use the field ID or `section.label`.
- A field label no longer replaces another field's value under that field's ID key.

### Changed
- Released values carry each key's 1Password field ID, type, and purpose under the reserved `_secret_gate.fields` key, and the daemon cache keeps it. Reserved `_secret_gate.*` keys never resolve as fields and never appear in reads or field lists.

## v0.8.1 (2026-11-03)

### Added
- `request submit --amount '$412.30'` (`context.amount` in MCP). Card approvals read "Approve $412.30 at aa.com checkout, Visa ending 1111, expires 08/2027", with an "Approve $412.30" button in Telegram and PushWard. Purpose and amount are limited to one line (80 and 24 characters).

### Fixed
- Skill: card items carry the CVV and agents fill it at checkout; agents no longer send the owner to the entry page for a CVV, and say which field is missing from 1Password instead.
- PushWard rejected the Live Activity of entry-page writes (one option; approval cards need two to four). Those requests now skip PushWard; the Telegram link approves them.
- The attachment temp-file test failed on Linux CI since v0.7.0 (`stat -f` means filesystem stat there); it now tries GNU `stat` first.

## v0.8.0 (2026-11-03)

Typed items: credit cards, API credentials, and secure notes in their native 1Password categories, with card numbers and CVVs kept out of model context. Design and threat model: [docs/typed-items.md](docs/typed-items.md).

### Added
- `--category card|api|note|login|password` on `write create` (and `category` in `write batch`, `write_item`, `write_items`) maps friendly labels onto native fields: cards (`cardholder`, `number`, `cvv`, `expiry`, `type`, `pin`, `bank`, billing address section), API credentials (`credential`, `username`, `hostname`, `expires`, `scopes`). Card numbers are Luhn-checked, the card type is detected from the number, and CVV, expiry, and date formats are validated before any approval. Updates match existing fields by alias, so `cvv` updates "verification number".
- Owner entry: `--owner-fields cvv` (`owner_fields` in JSON and MCP) lets the approver type values the agent does not have. Telegram shows an "✍️ Enter values" button that opens a one-time page on `WEBHOOK_BASE_URL/entry/<token>`; submitting it approves the write. `--stdin` is optional with owner fields.
- Masked card view without approval: `item fields` returns `card: {type, last4, expiry}` and marks number, CVV, and PIN fields `process_only`.
- `request submit --purpose "<where>"` (`context.purpose` in MCP). Telegram, PushWard, and the Approver API show it next to the masked card: "aa.com checkout, Visa ending 1111, expires 08/2027".
- `browser fill` (CLI) and `browser_fill` (MCP): type approved values into form fields over a loopback DevTools session (same-origin frames, shadow roots, cross-origin payment iframes with `--frame-url`, `<select>` menus, expiry formats like `expiry:MM/YY`). Card values only go to https pages. Output lists selectors, never values.
- Approver API: `items[].card`, `items[].owner_fields`, `sensitive`, and `entry_url`.

### Changed
- Card number, CVV, and PIN values are process-only: `item read --reveal` and `read_item_fields` refuse them and leave them out of full reads; `exec` and `browser fill` use them. Reading them needs a purpose, and clients before 0.8.0 are refused.
- Card reads that release a number, CVV, or PIN, card and bank account writes, and owner-entry writes need a tap on that request: read windows, write windows, and follow-ups never cover them, and those buttons are not offered. Secure notes keep the normal write rules.
- Cached items with process-only values expire after 15 minutes.
- Released DATE fields read as `YYYY-MM-DD` and MONTH_YEAR fields as `MM/YYYY` (Connect returns Unix seconds and `YYYYMM`).
- The redactor also catches card numbers printed in groups of four.
- Telegram write approvals name the item type when the server knows it.

## v0.7.0 (2026-10-25)

File attachments and agent-owned passkeys. Research, design, and threat model: [docs/passkeys-attachments.md](docs/passkeys-attachments.md).

### Added
- Attachments in `item fields` / `inspect_fields`: name, size, and ID, never content.
- Read an attachment by naming it in a request (`--fields "file:<name>"`); Telegram shows "📎 name (size)". `attachment exec` (CLI) and `read_attachment` (MCP) hand it to a command as a mode-0600 temporary file (path in `--env VAR`, deleted when the command exits) or on stdin. Attachment content is never returned by `item read` or `read_item_fields`.
- Attach files on `write create`, `write update`, and `write batch` (`"files":[{"path":...}]` in the stdin JSON), `write_item`/`write_items` (`files`), and `attach_file` (MCP). Telegram shows file names and sizes only. Limit 10 MiB per request. A failed upload resumes at that file on retry without creating the item twice.
- Uploads use the 1Password Go SDK with a service account (`OP_SERVICE_ACCOUNT_TOKEN`), because 1Password Connect has no upload endpoint. Without the token, writes with files return `attachments_unavailable` before any approval.
- Agent-owned passkeys over the Chrome DevTools WebAuthn domain: `passkey arm`, `passkey register`, `passkey load`, `passkey release`, `passkey list` (CLI) and `passkey_arm`, `passkey_register`, `passkey_load`, `passkey_release` (MCP). The local daemon holds its own DevTools session to the tab; the private key goes 1Password → daemon → browser and is never printed. Loopback DevTools endpoints only. Loaded passkeys start at a sign count of the current Unix time, so later sign-ins need no counter write; `passkey release --save-counter` stores the count and rides the same-item follow-up approval right after registration.
- Optional PushWard approval channel (`PUSHWARD_API_KEY` and optional `PUSHWARD_E2E_KEY`): starts an `approval` Live Activity on the Lock Screen and Dynamic Island with server-recorded options (`Approve once`, `Approve <window>`, `Deny`), long-polls `GET /activities/{slug}?wait=25` without exposing a public webhook, dismisses the Live Activity when Telegram resolves the request first, and seals audit/reminder notifications with PushWard's `pw1` end-to-end encryption envelope when `PUSHWARD_E2E_KEY` is set.
- Authenticated Approver API (`SECRET_GATE_APPROVER_TOKEN`): `GET /approvals`, `GET /approvals/events` (SSE), `POST /approvals/{id}/decide`, and `POST /approvals/windows/{id}/revoke` so first-party apps (such as Voice Workspace) can render inline approval buttons and Live Activities directly from thread metadata (`context.paseo_agent_id`, `requester_machine`) without exposing secret values. See [docs/approver-api.md](docs/approver-api.md).

### Changed
- Connect updates send the item's `files` array back unchanged instead of omitting it from the replacement item.
- The local daemon accepts socket messages up to 32 MiB (was 64 KiB) so cached attachments fit, and stays running while a passkey is held.

## v0.6.0 (2026-10-25)

Fewer Telegram taps for writes without letting writes approve silently. Design and threat model: [docs/write-ux.md](docs/write-ux.md).

### Added
- `write batch` (CLI) and `write_items` (MCP): up to 10 creates or updates in one vault behind one approval. Telegram lists every item and field label, never values. A partial failure resumes at the first unwritten item on retry.
- "✅ Approve + writes 15m" on write approvals (`WRITE_WINDOW_TTL`, `0` hides it). The window approves new items from the same machine, requester IP, Paseo agent ID, and vault. Each covered write posts an audit message with a "🛑 Revoke write window" button.
- Same-item follow-up (`WRITE_FOLLOWUP_TTL`, default 15m): after an approved write, the same requester may update those items without a tap. Audited; follow-ups do not extend themselves.
- `--no-wait` on `write create`, `write update`, and `write batch`: returns a token and the local daemon completes the write after approval, so the agent can drop the values. Resume with `request wait <token>`.
- Write requests wait `WRITE_REQUEST_TTL` (default 1h) and get one Telegram reminder `WRITE_REMINDER_BEFORE` (default 10m) before expiry. Expired requests have their Telegram message changed to "Expired" with no buttons.
- Write approval messages show field labels.

### Changed
- Pending write values are dropped from server memory as soon as the write completes, is denied, or expires.
- Submission log lines include the action, item count, and expiry; expiries, reminders, write windows, auto-approvals, and revocations are logged.

### Fixed
- Tapping Approve on an expired request no longer shows "Approved" for a write that can never run; the tap is refused and the message is marked expired.
- An identical request made after an earlier one was approved no longer receives the old request's token (the fingerprint index went stale on update).
- Telegram transport errors no longer write the bot API URL, which contains the bot token, to the server log.

## v0.5.5 (2026-10-24)

### Fixed
- `write create` with category PASSWORD (and LOGIN) no longer fails after approval: `password` and `username` fields carry the Connect purposes the template requires (#11). Purposes are not sent for SERVER, DATABASE, EMAIL_ACCOUNT, or WIRELESS_ROUTER, which Connect rejects.
- Connect validation failures on writes return a `validation` error with Connect's message instead of `network`.
- Writes are checked before the Telegram approval (unsupported category, missing password, empty values, existing or missing or duplicated title, double quote in title) so approvals are not spent on requests that cannot succeed. Categories are normalized to upper case.
- `credential`, `clientsecret`, `secretkey`, and token-style fields are stored as concealed fields.
- Reusing a pending approval no longer fails when Telegram answers "message is not modified", and refresh errors are logged (#13).

### Known issues
- Connect read-after-write lag, titles containing a double quote, duplicate-title reads, and a possible duplicate on retry after an ambiguous write failure are tracked in #12.

## v0.5.4 (2026-10-22)

### Fixed
- OTP aliases (`otp`, `totp`, `mfa`, `2fa`, `one-time password`) and `otp exec` without `--field` now resolve to the item's single OTP-type field even when it has no label, at both approval and use. Several unlabeled OTP fields return a validation error listing their field IDs; the field ID still works.

## v0.5.3 (2026-10-21)

### Fixed
- Upgrade the MCP Go SDK to v1.4.1 to address the three advisories flagged by govulncheck.
- Build the Docker server for the requested platform instead of defaulting to ARM64.
- Exclude Git metadata and runtime credential files from Docker build contexts.
- Let the optional local Compose stack use the host architecture.

### Documentation
- Document mac-server as the active deployment host and the server workspace as the live Compose owner.
- Mark the retired DevBox deployment helpers as historical.

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
