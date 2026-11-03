# Typed items: cards, API credentials, secure notes (v0.8.0)

Why: on 2026-11-02 a flight booking stalled because a card's CVV was not in
Secret Gate. The agent asked for it in chat and it was pasted into a
message. Card items were free-form secure notes (number, expiry, billing
address, zip), so nothing marked the number as sensitive and nothing
offered a safe way to add the CVV.

## Item types

Writes pick a native 1Password category with `--category` (or `category`
in stdin JSON / MCP). Friendly labels map onto the category's native fields,
so the item looks like one made in the 1Password app.

| Type (`--category`) | 1Password category | Labels → native field |
|---|---|---|
| `card` | `CREDIT_CARD` | `cardholder` → cardholder name, `number` → `ccnum` (CREDIT_CARD_NUMBER), `cvv`/`cvc` → verification number (CONCEALED), `expiry` (MM/YY, MM/YYYY, YYYY-MM) → `expiry` (MONTH_YEAR, stored YYYYMM), `type` → CREDIT_CARD_TYPE (`visa`, `mc`, `amex`, `discover`, `diners`, `jcb`, `unionpay`, `maestro`), `pin` → PIN (Additional Details), `bank` → issuing bank (Contact Information), `billing_address`, `city`, `state`, `zip`, `country` → section "Billing Address" |
| `api` | `API_CREDENTIAL` | `credential`/`key`/`secret`/`token` → credential (CONCEALED), `username`/`key_id`/`client_id` → username, `hostname`/`host`/`base_url`/`url` → hostname, `expires` (YYYY-MM-DD) → expires (DATE), `valid_from`, `scopes` (section Details) |
| `note` | `SECURE_NOTE` | `note` → notesPlain; other labels are custom fields |
| `login` | `LOGIN` | `username`, `password` (purposes set), `url` |
| `password` | `PASSWORD` | `password` |

Card numbers must pass the Luhn check; the card type is detected from the
number when omitted; CVVs are 3 or 4 digits; expiry months are 1 to 12.
Errors name the field, never the value. Labels outside the template are
added as custom fields. On update, a label matches an existing field by
label, ID, or template alias, so `cvv` updates "verification number"
instead of adding a second field.

Live probe (Connect 1.x, vault "AI Agents", throwaway items): Connect
accepts `CREDIT_CARD` with `ccnum`, `cvv`, `expiry` = `202708`, `type` =
`visa`, and a custom `billing` section, and adds `notesPlain` itself.
`API_CREDENTIAL` `DATE` fields accept `YYYY-MM-DD` and come back as Unix
seconds; Secret Gate presents them as `YYYY-MM-DD` (and month-year fields
as `MM/YYYY`) when values are released.

Worth adding next, same pattern: Bank Account (`BANK_ACCOUNT`: bank name,
name on account, routing and account number, SWIFT, IBAN, PIN; the
category alias `bank` exists and its writes already need a tap),
Identity and Passport (`IDENTITY`, `PASSPORT`: names, dates, document
numbers; mark document numbers process-only), and SSH Key (`SSH_KEY`:
Connect support for creating the SSHKEY field type is unverified; probe
first). Driver License and Membership follow the Identity pattern.

## Saving without exposing values

- `--stdin` JSON, as before. Values never appear in argv, logs, or Telegram.
- `--owner-fields a,b` (`owner_fields` in JSON / MCP): the approver types
  these on their own device. The Telegram approval gets an "✍️ Enter values"
  URL button to `WEBHOOK_BASE_URL/entry/<token>` (tailnet only on
  mac-server). The page shows item, vault, reason, requester, and one
  input per label (password inputs for number/CVV/PIN); submitting it
  validates the values, approves the write, and closes the PushWard Live
  Activity. `Approve once` is not offered and refused until values are
  entered; `Deny` still works. The agent never holds the values, so this is
  how a CVV gets into Secret Gate. `--stdin` is optional with owner fields.
  The token is 256 random bits, single use, and expires with the request
  (`WRITE_REQUEST_TTL`, 1h). It is never returned to the agent; it is in the
  Telegram button and the authenticated Approver API (`entry_url`). The page
  sends `Cache-Control: no-store`, a `default-src 'none'` CSP, no referrer,
  and cannot be framed.
- A TTY prompt was not added: agents have no terminal, and owner entry
  covers the case where a person types the value.

## Approval policy

| Request | Needs |
|---|---|
| Card read that releases number, CVV, or PIN (or all fields) | `--purpose`, then a tap on that request. Read windows never cover it and none is offered. |
| Card read of other fields (expiry, cardholder, billing) | Normal read rules |
| Card or bank account write | A tap on that request. Write windows and follow-ups never cover it; `Approve + writes` is not offered. Batches still work: several cards in one `write batch` need one tap. |
| Write with owner fields | Submitting the entry page |
| Secure note write | Normal write rules (tap, write window, or follow-up) |

Secure notes keep the "fewer approvals" rules on purpose: `SECURE_NOTE` is
the default category of every untyped write, so making notes tap-only would
end write windows for nearly all writes. This is a decision for Ashraf; the
switch is one line (`opconnect.SensitiveWriteCategory`).

Telegram shows card reads as "💳 aa.com checkout, Visa ending 1111, expires
08/2027" with a separate "Purpose:" block; PushWard uses the same line as
the Live Activity state; the Approver API adds `items[].card`, `sensitive`,
and `entry_url`.

## Reading

- Masked view without approval: `item fields` returns
  `card: {type, last4, expiry}` and marks number, CVV, and PIN fields
  `process_only: true`.
- The server lists the keys of a card's number, CVV, and PIN under the
  reserved key `_secret_gate.process_only` when it releases values. The
  client then refuses them in `item read --reveal` and `read_item_fields`
  (and leaves them out of full reads), while `exec`, `browser fill`, and
  `browser_fill` (MCP) can use them. The redactor also catches the number
  written in groups of four with spaces or dashes.
- Cached card values expire after 15 minutes (client and daemon cap), so
  one approval covers one checkout.
- `browser fill` opens its own DevTools session to the tab (loopback
  endpoints only, same client as passkeys), finds each selector in the
  page, same-origin frames, and open shadow roots (or a cross-origin
  payment iframe with `--frame-url`), focuses it, and types the value with
  `Input.insertText`, so React-style inputs see real input events. Menus
  pick the matching option. Expiry takes `:MM`, `:YY`, `:YYYY`, `:MM/YY`,
  and similar formats. Card values go only to https pages (loopback
  excepted). Output lists selectors and whether each was filled.

## Threat model notes

- Enforcement of process-only values is in the client. An agent that calls
  the HTTP API directly still gets values after approval; the server-side
  controls are the purpose requirement, the per-request tap, and the masked
  card in the approval message. Clients before 0.8.0 cannot send a purpose,
  so card number/CVV reads from them are refused.
- After `browser fill` the page holds the number. A snapshot or screenshot
  of the form shows it to the model. The skill recipe takes element refs
  before filling and clicks Pay by ref afterwards.
- Anyone with both the Telegram chat and tailnet access could open an
  entry link and submit values. They could only write values into the
  requested item, not read any.
- Existing free-form card items are unchanged; they are not process-only
  until migrated to `CREDIT_CARD` (needs Ashraf's go).
