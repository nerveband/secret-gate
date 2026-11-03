---
name: secret-gate
description: Request and use 1Password items through Telegram approval. CLI-first with JSON envelopes and deterministic exit codes; also available as MCP tools. Supports credit cards (masked view, owner-typed CVV, checkout browser fill), API credentials, secure notes, arbitrary fields, OTP codes, SSH keys, file attachments, agent-owned passkeys, and approval-gated item writes.
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

Include explicit approver context when the interface supports it:

```json
{
  "runtime": "Paseo",
  "provider": "Oh My Pi",
  "model": "gpt-5.6-sol",
  "think": "high",
  "project": "secret-gate",
  "task": "deploy the release"
}
```

Use runtime, provider, model, thinking level, and project in that order.
Do not label the requester `Codex` unless Codex is the actual runtime or
provider. Repeating an equivalent pending request renews the original
request and returns `request_reused: true`; it does not create another
approval.

## Exit codes

`0` ok · `1` internal/child failure (see `data.exit_code`) · `2` usage ·
`3` approval denied · `4` approval expired or wait timeout · `5` network ·
`6` not found / not cached.

## Visibility classes — pick the narrowest

- `metadata-only`: search, fields, request, daemon — never touches values.
- `process-only`: `exec`, `ssh`, `otp exec`, `attachment exec`,
  `passkey load`, `browser fill`: the value goes to a child process or the browser;
  exact occurrences in output come back as `[REDACTED:item/field]`.
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
  | secret-gate write create --item "ci-token" --vault "Infra" --reason "store the new CI token" --stdin --no-wait
secret-gate request wait <token>

# Several values known together: one approval for all of them
echo '{"items":[{"item":"Play key","operation":"create","fields":{"credential":"<json>"}},{"item":"Expo token","operation":"create","fields":{"token":"<value>"}}]}' \
  | secret-gate write batch --vault "Infra" --reason "store release credentials" --stdin --no-wait
```

Every write needs a human approval and an explicit `--vault`. To keep
taps down:
- Put values you already have into one `write batch` (up to 10 items, each
  item once). The approver sees item names and field labels, never values.
- Use `--no-wait`, then drop the values: the server holds them while
  approval is pending (up to 1 hour by default) and the local daemon
  finishes the write after the tap. Resume with `request wait <token>`.
- An update to an item you just wrote (for example recovery codes added to
  a new 2FA item) is approved automatically for 15 minutes, from the same
  machine and agent only. Other updates still need a tap.
- If the approver tapped `Approve + writes`, new items you create in the
  same vault during that window are approved automatically and audited in
  Telegram. Do not rely on it: it can be revoked at any time.

Before creating an approval, Secret Gate verifies that the configured
1Password Connect token can write to that vault. An unavailable or
unverifiable capability returns `vault_write_unavailable` or
`write_capability_unverified` and sends a Telegram audit warning without
approval buttons. Preview with `--dry-run` (labels only). Never put values
in the reason or in field labels.

Secret Gate also checks the item against 1Password Connect before asking for
approval, and returns `validation` without sending a Telegram message when:
the category is unsupported (DOCUMENT, CUSTOM), a PASSWORD item has no
non-empty `password` field, a value is empty, `create` targets a title that
already exists, `update` targets a missing or duplicated title, or the title
contains a double quote. Categories are case-insensitive. Connect makes a
new item visible to reads after a few seconds; wait before reading it back.

## Cards, API keys, secure notes (typed items)

Use `--category card|api|note|login|password` so items land in the native
1Password category. Friendly labels map onto native fields:
- `card`: `cardholder`, `number`, `cvv`, `expiry` (MM/YY), `type` (detected
  when omitted), `pin`, `bank`, `billing_address`, `city`, `state`, `zip`,
  `country`. Numbers are Luhn-checked before any approval.
- `api`: `credential` (key/secret/token), `username` (key id/client id),
  `hostname` (host/base_url), `expires` (YYYY-MM-DD), `scopes`.
- `note`: `note` plus any custom labels.

Never ask the user to paste a card number, CVV, PIN, or key into chat. If
you do not have a value, let the owner type it on their phone with
`--owner-fields`: Telegram shows an "Enter values" link, and saving that
page approves the write. You never see the value.

```bash
# save a card: values you have via stdin, the rest typed by the owner
echo '{"fields":{"cardholder":"<name>","billing_address":"<street>","zip":"<zip>"}}' \
  | secret-gate write create --item "Visa travel" --vault "AI Agents" --category card --owner-fields number,cvv,expiry --reason "store the travel card" --stdin --no-wait
# add a missing CVV to an existing card (no stdin needed)
secret-gate write update --item "Visa travel" --vault "AI Agents" --owner-fields cvv --reason "add the CVV for checkout" --no-wait
# API credential and a secure note in one approval
echo '{"items":[{"item":"Stripe live","operation":"create","category":"api","fields":{"credential":"<key>","hostname":"https://api.stripe.com"}},{"item":"Trip notes","operation":"create","category":"note","fields":{"note":"<text>"}}]}' \
  | secret-gate write batch --vault "AI Agents" --reason "store Stripe key and trip notes" --stdin --no-wait
```

Card rules: `item fields` shows the masked card (`card.type`, `card.last4`,
`card.expiry`) with no approval; use it to confirm the right card and to
type the expiry. The number, CVV, and PIN are process-only: `item read`
refuses them; only `browser fill` and `exec` can use them. Requesting them
needs `--purpose` naming the merchant; the approver sees "aa.com checkout,
Visa ending 1111". Card requests need their own tap (no windows), and card
values stay cached for 15 minutes.

### Recipe: pay at a checkout with a stored card (CVV included)

```bash
# 1. pick the card without approval (masked: type, last 4, expiry)
secret-gate item fields --item "Visa travel" --vault "AI Agents"
# 2. approve exactly the fields the form needs, naming the merchant
secret-gate request submit --item "Visa travel" --vault "AI Agents" --fields cardholder,number,cvv,expiry,zip \
  --purpose "aa.com checkout" --reason "pay for flight AA 1234 DFW-LGA"
# 3. get refs for the card form and the Pay button BEFORE filling
agent-browser snapshot -i
# 4. type the values into the page (selectors, not refs); nothing is printed
secret-gate browser fill --item "Visa travel" --vault "AI Agents" --cdp "$(agent-browser get cdp-url)" --page-url aa.com \
  --field 'cardholder=#nameOnCard' --field 'number=#cardNumber' --field 'expiry:MM/YY=#expiration' \
  --field 'cvv=#securityCode' --field 'zip=#billingZip'
# 5. click Pay by the ref from step 3; do not snapshot or screenshot the filled form
agent-browser click @e42
```

- Separate month and year menus: `--field 'expiry:MM=#expMonth' --field 'expiry:YYYY=#expYear'`.
- A card form inside a cross-origin payment iframe (Stripe, Adyen,
  Braintree): add `--frame-url js.stripe.com` (substring of the iframe URL).
- Check `data.results[].filled` in the output; `exit 1` means a selector
  matched nothing. Values never appear in the output.
- Without a DevTools browser, pass values to a script with `exec` instead,
  one field per call (nest calls for several fields).
- If the card has no CVV stored, run the `write update ... --owner-fields cvv`
  command above and wait for the owner; do not ask for it in chat.

## Attachments

```bash
# item fields lists attachments by name, size, and ID (never content)
secret-gate item fields --item "release keys"

# approve one attachment by naming it, then hand it to a command
secret-gate request submit --item "release keys" --fields "file:release.jks" --reason "sign the release"
secret-gate attachment exec --item "release keys" --file release.jks --env KEYSTORE -- ./gradlew assembleRelease
secret-gate attachment exec --item "release keys" --file release.jks --stdin -- shasum -a 256

# attach local files on create/update (or per item in write batch)
echo '{"fields":{"note":"release keystore"},"files":[{"path":"./release.jks"}]}' \
  | secret-gate write create --item "Android keystore" --vault "Infra" --reason "store the keystore" --stdin
```

`--env VAR` writes a mode-0600 temporary file in a private directory, puts
its path in `VAR`, and deletes it when the command exits. Attachment
content is never returned by `item read` or `read_item_fields`. The limit
is 10 MiB per request. Attaching needs a 1Password service account on the
server (Connect cannot upload); without one the write returns
`attachments_unavailable` before any approval.

## Passkeys (agent-owned)

Secret Gate cannot use passkeys that 1Password itself saved. It can create
and use its own passkeys through a Chrome DevTools endpoint on this machine
(agent-browser: `agent-browser get cdp-url`). ego lite and Aside do not
expose one.

```bash
CDP="$(agent-browser get cdp-url)"
# register: arm the tab, click the site's "create passkey", then store it
secret-gate passkey arm --cdp "$CDP" --page-url webauthn.io
secret-gate passkey register --session 3f2a9c1d --item "webauthn.io passkey" --vault "AI Agents" --reason "save the agent's passkey"
secret-gate passkey release --session 3f2a9c1d --save-counter --reason "store the sign count after the first sign-in"

# sign in later: approve the item, load it, sign in on the site, release
secret-gate request submit --item "webauthn.io passkey" --vault "AI Agents" --reason "sign in to webauthn.io"
secret-gate passkey load --item "webauthn.io passkey" --vault "AI Agents" --cdp "$CDP" --page-url webauthn.io
secret-gate passkey release --session 9b1c2d3e
secret-gate passkey list
```

The key goes from Secret Gate into the browser over its own DevTools
session and is never printed. A loaded passkey can sign in to its site
until `passkey release` or `--hold` (default 10m, max 30m) ends.

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
`read_item_fields` / `get_otp` → `write_item` or `write_items` (batch) for
writes. Attachments: `request_secret(fields=["file:<name>"])` →
`read_attachment`; `attach_file` or `files` on `write_item(s)`. Passkeys:
`passkey_arm` → `passkey_register` → `passkey_load` → `passkey_release`.
Cards: `inspect_fields` (masked `card`) → `request_secret` with
`context.purpose` → `browser_fill`; save with `write_item(category="card",
owner_fields=["cvv"])`. Same rules.

## Do not

- Do not print, log, commit, or persist secret values — the redactor is
  a backstop, not permission.
- Do not ask a person to paste a card number, CVV, PIN, or key into chat;
  use `--owner-fields`. Do not snapshot or screenshot a form after
  `browser fill` put card values in it.
- Do not use `--reveal` when `exec`/`ssh`/`otp exec` can do the job.
- Do not put secret values in `--reason` or any argv.
- Do not retry a denied request (exit 3) with a different reason to
  evade the approver; surface the denial to the user.
- Do not parse human help text — use `schema` / `agent-context --json`.

Passkeys that 1Password itself saved are visible during inspection, but no
1Password API (Connect, CLI, SDKs) can export their private key or complete
a WebAuthn ceremony with them. Use the 1Password browser extension for
those, or an agent-owned passkey as above.
