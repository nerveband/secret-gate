---
name: secret-gate
description: Request and use 1Password items through Telegram approval. Supports arbitrary fields, secure notes, OTP codes, SSH keys, and approval-gated item writes.
---

# Secret Gate

Use Secret Gate whenever a task needs a credential or context stored in 1Password. Prefer its MCP tools when available. They keep values in memory and make every read or write visible to the Telegram approver.

## MCP workflow

1. Find the item with `search_secrets`.
2. Inspect it with `inspect_fields`. Results include field IDs, labels, types, purposes, sections, and references, but no values.
3. Call `request_secret` with a plain-language reason, only the required fields, and agent context when known.
4. After approval, choose the narrowest use tool:
   - `exec_with_secret` injects one field into a subprocess without returning it to the model.
   - `ssh_with_secret` uses an approved SSH key.
   - `read_item_fields` returns approved notes or fields that the agent must read. Omit `fields` to read every approved field.
   - `get_otp` generates the current code from an approved OTP seed.
5. Use `write_item` to create or update an item. Writes always need one-request approval and an explicit vault.

Fields can be addressed by label, stable field ID, or `section.label`. Matching ignores case, spaces, hyphens, and underscores. These aliases are interchangeable:

- `mfa`, `otp`, `totp`, `2fa`, `one-time password`
- `note`, `notes`, `secure note`, `notesPlain`

Include context that helps the person approve quickly:

```text
agent: Codex
model: gpt-5.6-luna
think: low
project: ts-project
task: publish the release
```

Passkeys are visible during inspection, but 1Password Connect cannot export a passkey private key or complete a WebAuthn ceremony. Use an interactive browser with the 1Password extension for passkey sign-in.

## CLI fallback

Resolve the server from `SECRET_GATE_URL`, the legacy `OP_APPROVAL_PROXY_URL`, or `~/.config/secret-gate/config.json`. The client normally lives at `~/.config/secret-gate/bin/secret-gate`.

```bash
secret-gate --server "$SECRET_GATE_URL" --search "deploy" --format json
secret-gate --server "$SECRET_GATE_URL" --secret "deploy-key" --fields --format json
secret-gate --server "$SECRET_GATE_URL" --secret "deploy-key" --field private_key --reason "deploy the service"
```

## Security rules

- Request only the fields needed for the stated task.
- Never print, log, commit, or persist secret values.
- Prefer command injection or SSH-agent use when the model does not need the value.
- Tell the user which item and field were used, without revealing the value.
- Write requests must explain what will be stored and why. Values never belong in the Telegram explanation.
