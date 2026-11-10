# Owner windows and Telegram controls

Until v0.8.3 a read window opened only after an agent asked: you tapped "Approve 30m" on a pending request. An **owner window** lets you open one yourself, ahead of time, from your phone, so agents that need credentials from your vault do not stop and wait while you are away. Telegram also became a control surface: commands and buttons for windows, a settings panel, and an alert mode that lets you keep Telegram for control and receive notifications somewhere else, such as PushWard.

## What a window covers

A window covers a read only when every rule holds. Otherwise the request gets the normal approval card, and the card says why ("Window open, not covering this request: Secret Gate credentials are never covered").

| Rule | Detail |
|---|---|
| Vault | The item is in a vault listed in `OWNER_WINDOW_VAULTS`. The vault comes from 1Password Connect, not from the client. **Every item in that vault is covered**, apart from the rows below. Nothing needs tagging. |
| Never Secret Gate's own credentials | Titles matching `secret gate` or `pushward` (the approver and opener tokens, the Connect token and credentials file, the service account token, the PushWard key) are never covered. They would let an agent approve its own requests, cards and writes included. The rule is narrow on purpose: an item that merely mentions Telegram, Connect, or a service account is covered. `OWNER_WINDOW_DENY` adds a pattern; it cannot remove these. If a Secret Gate credential has a title without those words, add it there. |
| Never cards, bank, identity | `CREDIT_CARD`, `BANK_ACCOUNT`, `IDENTITY`, `PASSPORT`, `DRIVER_LICENSE`, `SOCIAL_SECURITY_NUMBER`, `MEDICAL_RECORD` items are never covered. Card reads that release a number, CVV, or PIN also keep needing their own tap. |
| Never passkeys or attachments | A request for a `passkey*` field, a request with no field list on an item that holds one, or a `file:` selector is not covered. |
| Reads only | Writes never ride a read window. |
| Budget | At most `OWNER_WINDOW_MAX_REQUESTS` (30) covered requests and `OWNER_WINDOW_MAX_ITEMS` (10) distinct items. A request over budget needs a tap and closes the window. |
| Length | `OWNER_WINDOW_TTL` (30m) by default; `/open <minutes>` may ask for 5 minutes up to `OWNER_WINDOW_MAX` (60m, never above 2 hours). A window never extends: opening again while one is open returns the same window. |
| Limits on opening | One window per vault, 6 opens per hour, `OWNER_WINDOW_DAILY_MAX` (4h) of window time per rolling 24 hours. |
| Process-only values | Every value released under a window is marked process-only. Clients refuse `item read --reveal` and `read_item_fields` for it; `exec`, `ssh`, `otp exec`, and `browser fill` work. The client cache keeps it at most 15 minutes, and never past the window's end plus 5 minutes (also applies to keys loaded into ssh-agent). |
| Closed windows release nothing | A read approved under a window that was revoked or ran out of budget before the client fetched the value is refused. |

Windows live in memory only. A restart closes every window, and the server says so in Telegram and PushWard.

Process-only is enforced by the client, not the server. An agent that calls the HTTP API directly receives the values of a covered read. With the whole vault in reach, the server-side controls that remain are the exclusions above, the budget, the short fixed length, and the audit trail. Machine and agent pins (`machine`, `agent_id` on the API) are self-reported by clients and only advisory.

### Optional: narrow it to tagged items

Set `OWNER_WINDOW_TAG` (for example `sg-window`) and a window covers only items that carry that 1Password tag. The confirm card then says "items tagged ... only", and other items need a tap. This is off by default.

## Telegram

Only the approver (`TELEGRAM_APPROVER_USER_ID`, which defaults to `TELEGRAM_CHAT_ID` when that is a private chat) is obeyed, and only in the configured chat. Messages from anyone else, in a group, forwarded, sent via a bot, or older than 2 minutes are ignored without an answer. Updates that queued while the server was down are dropped at startup, so an old tap or command cannot fire after a restart. If `TELEGRAM_CHAT_ID` is a group, `TELEGRAM_APPROVER_USER_ID` is required and the controls below work only in a private chat.

| Command | Does |
|---|---|
| `/panel` | Posts a control message with buttons. Pin it. |
| `/open [minutes] [vault]` | Asks to open a window. Nothing opens until you tap the confirm card. |
| `/close` | Closes every open window. |
| `/windows` | Lists open windows with a close button each. |
| `/pending` | Puts every request that is waiting for a decision into this chat, with approve buttons, silently if alerts are off. |
| `/settings` | The settings panel. |
| `/set <name> <value>` | Changes a setting. `default` clears the change. |
| `/help` | Lists the commands (also in Telegram's `/` menu). |

**Opening a window is two taps.** Tap "🔓 Open reads 30m" on the pinned panel (or send `/open`). A confirm card arrives with the vault, what is covered and excluded, the budget, and the end time. Tap "✅ Open until 14:35". The card has a single-use nonce, bound to your account and that message, and expires after 2 minutes. The card then becomes the window card with a "🛑 Close now" button and a running counter. The first read of each item sends a short audit message with the same button; later reads of that item only move the counter.

### Alerts: on, silent, off

`/settings` (or `/set notifications on|silent|off`) decides what Telegram does unprompted:

| Mode | Behavior |
|---|---|
| `on` | Every approval card, reminder, and audit message pushes. |
| `silent` | The same messages arrive in the chat without a push or sound. |
| `off` | Nothing is sent unprompted: approval cards go to PushWard only, audit alerts go to PushWard only. Commands, buttons, replies, `/pending`, and approvals tapped in Telegram keep working. |

`off` holds only while another channel (PushWard) is configured. With no other channel it acts as `silent`, so a request is never left without a message. Requests that are approved from a link in Telegram (owner-entry writes) always go to Telegram. If PushWard cannot take a request, Telegram posts it silently rather than dropping it.

Settings changes are announced on PushWard and in the audit log.

### Settings

| Name (aliases) | Values | Default | Effect |
|---|---|---|---|
| `telegram_notifications` (`notifications`, `alerts`) | `on`, `silent`, `off` | `TELEGRAM_NOTIFICATIONS` (`on`) | See above. |
| `owner_windows` (`windows`, `phone_windows`) | `on`, `off` | `OWNER_WINDOW_ENABLED` (`off`) | Whether you can open windows from the phone. Turning it off closes open windows. Needs `OWNER_WINDOW_VAULTS`. |
| `tap_windows` (`tap`) | `on`, `off` | `on` | Whether approval cards offer "Approve 30m" and "Approve + writes". Turning it off hides the buttons, refuses the actions, and ends any open tap window. |

Changes are saved to `SETTINGS_PATH` (the Docker image sets `/app/state/settings.json`). They survive a container restart. To survive a redeploy that recreates the container, mount a volume at `/app/state`. Without a writable path a change lasts until the next restart, and the panel says so.

## Approver API (backup trigger)

`POST /approvals/windows` opens a window from another client, such as a Shortcut or the Voice Workspace gateway. It takes the approver token or the **opener token**, which can open, list, and close windows and nothing else (403 on every other route). Details and examples: [approver-api.md](approver-api.md#owner-windows). An API-opened window sends a loud alert to every channel, which is your alarm if anything but you used the token.

Store tokens as digests. Keep the token in your password manager and put only its SHA-256 in the server's env file:

```sh
TOKEN=$(openssl rand -hex 32)      # store this in your password manager; do not paste it anywhere else
printf '%s' "$TOKEN" | shasum -a 256
```

Use the digest as `SECRET_GATE_OPENER_TOKEN_SHA256` (or `SECRET_GATE_APPROVER_TOKEN_SHA256`). Reading the env file then does not reveal the token. Keep the token item's title matching the deny pattern above (for example "Secret Gate Opener Token").

## Fail closed

- A window opens only if at least one channel (Telegram card, Telegram alert, or PushWard) delivers its announcement. Otherwise it is closed again and the API answers `503 audit_unavailable`.
- The first read of an item under a window needs a delivered audit message. If none can be delivered, the request falls back to a normal approval and the window's budget is given back.
- A server restart, `/close`, turning the feature off, expiry, or an exhausted budget all end a window.

## Audit trail

Every event goes to the server log. Set `AUDIT_LOG_PATH` to also append JSON lines (mode 0600) that survive a restart. Events carry ids, names, and counts, never values.

| Event | When |
|---|---|
| `window.open_requested` | A confirm card was sent. |
| `window.opened` | A window opened: source, opener, vault, expiry, budget. |
| `window.rejected` | An open was refused (reason). |
| `window.used` | A read was covered: request, items, field names, machine, agent, counts. |
| `window.not_covered` | An open window did not cover a read (reason). The older tap window logs this too when it refuses a Secret Gate credential. |
| `window.closed` | Reason (`expired`, `revoked`, `budget_requests`, `budget_items`, `audit_unavailable`), who closed it, final counts. |
| `settings.changed` | Setting, old and new value, who, whether it was saved. |
| `telegram.rejected` | A tap or message from anyone but the approver (once a minute per sender). |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_APPROVER_USER_ID` | the private chat id | Telegram user whose taps and commands are obeyed. Required for group chats. |
| `TELEGRAM_NOTIFICATIONS` | `on` | Default alert mode: `on`, `silent`, `off`. |
| `OWNER_WINDOW_ENABLED` | `false` | Default for the `owner_windows` setting. |
| `OWNER_WINDOW_VAULTS` | unset | Comma-separated vault names a window may cover. Empty disables the feature. |
| `OWNER_WINDOW_TAG` | unset | Optional 1Password tag. When set, only items with it are covered. Unset covers every item in the vault. |
| `OWNER_WINDOW_DENY` | unset | Extra case-insensitive title pattern that is never covered. Adds to the built-in one. |
| `OWNER_WINDOW_TTL` | `30m` | Default length. |
| `OWNER_WINDOW_MAX` | `60m` | Longest length `/open` or the API may ask for (never above 2h). |
| `OWNER_WINDOW_MAX_REQUESTS` | `30` | Covered requests per window. |
| `OWNER_WINDOW_MAX_ITEMS` | `10` | Distinct items per window. |
| `OWNER_WINDOW_DAILY_MAX` | `4h` | Total window time per rolling 24 hours. |
| `SECRET_GATE_OPENER_TOKEN_SHA256` | unset | SHA-256 (hex) of the opener token. |
| `SECRET_GATE_APPROVER_TOKEN_SHA256` | unset | SHA-256 (hex) of the approver token, as an alternative to `SECRET_GATE_APPROVER_TOKEN`. |
| `SETTINGS_PATH` | `/app/state/settings.json` in the image | Where `/set` changes are saved. |
| `AUDIT_LOG_PATH` | unset | Append-only JSON-lines audit file. |

## Limits worth knowing

- The server cannot see `--reveal`; the client enforces process-only. A hostile agent can still pipe a value through a command it runs. The window's blast radius is every ordinary item in the vault, bounded by the window length and the request and item budgets.
- If agents run as the same OS user that owns the server's env file, a compromised agent can read plain-text tokens in that file, with or without Secret Gate. Storing the approver and opener tokens as digests helps; running the server under a different account than the agents is the stronger fix.
- Agents that were already waiting on a pending card when you opened a window stay pending until you tap or they resubmit; a window covers new requests.
