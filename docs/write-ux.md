# Write approval UX (v0.6.0)

Status: implemented in v0.6.0. Owner: nerveband fork.

## Problem

On 2026-10-25, enrolling WordPress.org 2FA and publishing one plugin needed
three separate write taps in Telegram: create the 2FA seed item, update the
same item with recovery codes, create the SVN password item. Two earlier
attempts expired while the approver was away, and the agent kept the seed in
browser memory so it could resubmit. The same pattern hit the Play service
account key, Expo token, and App Store Connect key earlier that week.

The read path already had an "Approve 30m" window. Writes did not, by design.

## Evidence

Server log (`docker logs secret-gate-secret-gate-1`, which only
covers the current container, started 2026-10-24 05:25 UTC):

| Time (UTC) | Request | What happened |
|---|---|---|
| 10-25 13:45:11 | `34f53b3f…` | Submitted, never approved or denied, expired |
| 10-25 14:00:23 | `24b8be7e…` | Submitted, never approved or denied, expired |
| 10-25 15:32:49 | `d547b619…` | 2FA item create submitted |
| 10-25 15:38:16 | `d547b619…` | Tap 1, "WordPress.org 2FA (nerveband)" created (5.5 min wait) |
| 10-25 15:38:54 | `76235a3d…` | Read of the new item, approved with the read window at 15:40:41 |
| 10-25 15:39:34 → 15:40:38 | `1e55ad73…` | Tap 2, recovery codes update to the same item |
| 10-25 15:42:37 → 15:43:55 | `e227f621…` | Tap 3, "WordPress.org SVN password (nerveband)" created |

The two expired requests do not appear in the client read ledger
(`~/.local/state/secret-gate/requests.json`), which records every CLI read,
so they were write submissions. That they were the earlier 2FA attempts is an
inference from timing; the log line did not record the action. Server logs
from before 10-24 05:25 (the Play, Expo, and ASC writes) were lost on the
container restart.

## Pain points found in the code

1. Every write needed its own tap. `HandleRequest` skipped the read window for
   mutations, and the Telegram keyboard offered no window for writes.
2. One item per write request (`writes require exactly one item`), so values
   known together still cost one tap each.
3. Writes used the read TTL (15 min), with no reminder, and the Telegram
   message kept live buttons after expiry.
4. Bug: tapping Approve on an expired message marked it "Approved" in
   Telegram, but `CanRetrieveSecret` refused it, so nothing was written.
5. `write create` blocked for up to 15 min. Agent tool calls time out sooner,
   so agents kept values in memory to resubmit. `--no-wait` existed only for
   reads.
6. Submission log lines had no action, and expiry was never logged, so
   expired writes were invisible in the server log.
7. Bug: `Store.Update` replaced the record without updating the fingerprint
   index. An identical request after an approval could be handed the old,
   already-approved token.
8. Write values stayed in server memory until cleanup, up to one hour after
   the request expired or completed.
9. Security bug (fixed separately): Telegram transport errors logged the bot
   API URL, which contains the bot token. The current container log contains
   one such line; rotating the bot token is the approver's decision.

## Options

| Option | Taps saved | Threat-model tradeoff | Decision |
|---|---|---|---|
| Batch write (`write batch`, MCP `write_items`) | N items → 1 tap when values are known together | None new: the approver sees every item name and field label before the single tap. Values never shown. | **Adopt** |
| Write window ("Approve + writes 15m") | Later creates in the window → 0 taps | A compromised agent on that machine could add new items to that vault for 15 min. It cannot overwrite existing items (window covers creates only), every write is audited in Telegram with a revoke button, and scope is machine + IP + Paseo agent ID + vault. | **Adopt, opt-in per tap** |
| Same-item follow-up | Update right after a create → 0 taps | The requester can only change an item it just wrote with an approved value, within 15 min, same scope. Follow-up approvals do not extend the grant, so it cannot chain forever. Audited. | **Adopt, default on** |
| Longer write TTL + reminder | Fewer expiries, fewer resubmits | Pending values sit in server memory up to 1 h instead of 15 min. Server memory already holds them; values are now dropped as soon as a write completes, is denied, or expires. | **Adopt** (1 h, reminder 10 min before) |
| Pending-approvals digest | None directly | More Telegram noise. The per-request reminder covers the need. | Reject |
| Client auto-resubmit on expiry | Avoids manual resubmit | Requires the agent to keep the secret for the whole wait, which is the problem we want to remove. | Reject; use `--no-wait` instead so the agent can drop values after submit |
| Read window covers writes | Most | One tap would allow overwriting any item from any requester for 30 min. | Reject |

## What changed

- **Batch writes.** `secret-gate write batch --vault V --reason R --stdin`
  with `{"items":[{"item","operation","category","fields"}]}`; up to 10
  items, each once; one Telegram message lists every item and its field
  labels. Items are prechecked before approval and written in order. A
  partial failure records which items were written; a retry resumes at the
  first unwritten item instead of creating duplicates. Server wire format:
  `mutations[]` with a top-level `vault` and no `secret_name`, so an older
  server rejects it instead of reading it as a read request.
- **Write window.** Write approvals show `✅ Approve once`,
  `✅ Approve + writes 15m`, `❌ Deny`. The window approves new items
  (creates) from the same machine, requester IP, Paseo agent ID, and vault.
  Updates are covered only for items written under the window (via the
  follow-up rule). Each covered write posts "✅ Auto-approved write" with the
  item, field labels, scope, and a `🛑 Revoke write window` button. Revoking
  also removes follow-up grants that came from the window. The read window
  never covers writes.
- **Same-item follow-up.** After a tapped or window-approved write completes,
  the same requester may update those items for `WRITE_FOLLOWUP_TTL` (15 min)
  without a tap. Each one is audited. Follow-up writes do not create new
  grants.
- **Fail closed on audit.** If the audit message cannot be sent, the write
  falls back to a normal approval request.
- **TTL, reminder, expiry.** Writes wait `WRITE_REQUEST_TTL` (1 h). Ten
  minutes before expiry the bot replies to the original message with a
  reminder. On expiry the message is edited to "⌛ Expired … Nothing was
  written", and its buttons are removed. Taps on expired requests are
  refused. Pending values are dropped on completion, denial, or expiry.
- **`--no-wait` for writes.** `write create|update|batch --no-wait` returns a
  token, registers the write with the local daemon, and the daemon completes
  it after approval. Resume with `request wait <token>`.
- **Logs.** Submissions log `action`, item count, and `expires_at`. New lines:
  `Write approved with write window`, `Write auto-approved`,
  `Write window revoked`, `Sent write approval reminder`, `Request expired`.
- **Bug fixes.** Expired-tap approval, stale fingerprint index, token in
  transport errors.

## Taps for the WordPress.org scenario

| | Before | After, "Approve once" | After, "Approve + writes" |
|---|---|---|---|
| 2FA seed create | tap | tap | tap |
| Recovery codes update (same item) | tap | follow-up, 0 | follow-up, 0 |
| SVN password create | tap | tap | window, 0 |
| **Total write taps** | **3** (plus 2 expired requests) | **2** | **1** |

Play key + Expo token + ASC key with values in hand: 3 taps before, 1 tap
with `write batch`.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `WRITE_REQUEST_TTL` | `1h` | Pending write lifetime |
| `WRITE_REMINDER_BEFORE` | `10m` | Reminder lead time; `0` disables |
| `WRITE_WINDOW_TTL` | `15m` | Write window length; `0` hides the button |
| `WRITE_FOLLOWUP_TTL` | `15m` | Same-item follow-up length; `0` disables |

Grants and windows live in server memory only and end on restart.

## Not changed

- The read window stays global across requesters (`AUTO_APPROVE_TTL`).
- `machine` and Paseo agent ID are self-reported by the client. The window
  also pins the requester IP seen by the server, but two agents on one host
  without distinct Paseo agent IDs share a window.
