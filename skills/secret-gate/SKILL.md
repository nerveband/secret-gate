---
name: secret-gate
description: Request and use 1Password items through Telegram approval. CLI-first with JSON envelopes and deterministic exit codes; also available as MCP tools. Supports arbitrary fields, secure notes, OTP codes, SSH keys, and approval-gated item writes.
---

# Secret Gate

Use Secret Gate whenever a task needs a credential or context stored in
1Password. Prefer the CLI: it emits one JSON envelope per invocation on
stdout, structured errors on stderr, and deterministic exit codes. The
MCP tools (`secret-gate mcp`) expose the same core with the same rules.

Setup: `SECRET_GATE_URL` (or `~/.config/secret-gate/config.json`) must
point at the server. Run `secret-gate agent-context --json` first in a
new environment — it returns the workflow, exit codes, and visibility
classes. `secret-gate schema` returns the full command manifest.

## Exit codes

`0` ok · `1` internal/child failure (see `data.exit_code`) · `2` usage ·
`3` approval denied · `4` approval expired or wait timeout · `5` network ·
`6` not found / not cached.

## Visibility classes — pick the narrowest

- `metadata-only`: search, fields, request, daemon — never touches values.
- `process-only`: `exec`, `ssh`, `otp exec` — value goes to a child
  process env var; exact occurrences in output come back as
  `[REDACTED:item/field]`.
- `model-visible`: `item read --reveal`, `otp show --reveal` — the value
  enters your context. Requires the explicit `--reveal` flag.
- `value-input`: `write create/update --stdin` — values are piped in,
  never placed in argv.

## CLI workflow

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

# 4. Use the narrowest tool (value never enters your context)
secret-gate exec --item "prod-api" --field credential --env API_KEY -- curl -s https://api.example.com/v1/me
secret-gate ssh --item "deploy-key" --host deploy@web1.example.com --command "uptime"
secret-gate otp exec --item "github" --env OTP_CODE -- gh auth login --with-token

# 5. Only when you must read the value yourself
secret-gate item read --item "wifi-guest" --fields "note" --reveal
secret-gate otp show --item "github" --reveal
```

Argv after `--` is executed directly (no shell). Add `--shell 'cmd'`
only when you need pipes or expansion. Use `--dry-run` on `exec`, `ssh`,
`write`, and `request submit` to preview without side effects.

## Writes

```bash
echo '{"category":"API_CREDENTIAL","fields":{"credential":"<value>"}}' \
  | secret-gate write create --item "ci-token" --vault "Infra" --reason "store the new CI token" --stdin
```

Writes always need one-request approval and an explicit `--vault`.
Preview with `--dry-run` (labels only). Never put values in the reason.

## Daemon

```bash
secret-gate daemon status
secret-gate daemon flush            # dry-run preview
secret-gate daemon flush --commit   # actually flush cached approvals
```

## Field aliases

Fields match by label, ID, or `section.label`, ignoring case, spaces,
hyphens, underscores. Interchangeable groups:
- `mfa`, `otp`, `totp`, `2fa`, `one-time password`
- `note`, `notes`, `secure note`, `notesPlain`

## MCP workflow (fallback)

`search_secrets` → `inspect_fields` → `request_secret` (with reason and
narrow `fields`) → `exec_with_secret` / `ssh_with_secret` /
`read_item_fields` / `get_otp` → `write_item` for writes. Same rules.

## Do not

- Do not print, log, commit, or persist secret values — the redactor is
  a backstop, not permission.
- Do not use `--reveal` when `exec`/`ssh`/`otp exec` can do the job.
- Do not put secret values in `--reason` or any argv.
- Do not retry a denied request (exit 3) with a different reason to
  evade the approver; surface the denial to the user.
- Do not parse human help text — use `schema` / `agent-context --json`.

Passkeys are visible during inspection, but 1Password Connect cannot
export a passkey private key or complete a WebAuthn ceremony. Use an
interactive browser with the 1Password extension for passkey sign-in.
