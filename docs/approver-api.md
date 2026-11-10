# Approver API and Voice Workspace Integration Guide

Secret Gate exposes an authenticated **Approver API** (`/approvals/*`) so first-party apps and gateways (such as **Voice Workspace**) can display inline approval buttons, drive iOS Live Activities, and approve or deny requests without needing Telegram or PushWard.

## Security Model

1. **Zero secret exposure**: `/approvals` and `/approvals/events` emit **metadata only** (request ID, item title, vault, field labels, attachment names/sizes, reason, requester machine, and `context.paseo_agent_id`). Secret values, file contents, and one-time retrieval `/secret/{token}` URLs never appear on the Approver API.
2. **Bearer authentication**: Every `/approvals*` endpoint requires `Authorization: Bearer <SECRET_GATE_APPROVER_TOKEN>` (or `X-Approver-Token: <token>`), verified in constant time. Agent clients do not hold this token and cannot call `/approvals/*`. The window routes (`/approvals/windows*`) also accept a separate **opener token** that can do nothing else.
3. **Single-winner synchronization**: A decision from `/approvals/{id}/decide`, Telegram, or PushWard atomically resolves the request, wakes the waiting agent, updates/dismisses the other channels, and broadcasts an `approval.approved` or `approval.denied` SSE event so every connected client clears its UI immediately.

---

## Server Configuration

Set `SECRET_GATE_APPROVER_TOKEN` in the server environment (for example `~/.config/secret-gate/server.env`). Generate a long random token and keep a copy in your password manager:

```env
SECRET_GATE_APPROVER_TOKEN=<token>
```

To keep the token itself out of the env file, set its SHA-256 digest (64 hex characters) instead, as `SECRET_GATE_APPROVER_TOKEN_SHA256`. Clients still send the token; the server compares digests in constant time.

Secret Gate can run with Telegram, PushWard, and the Approver API all active at once, or with `SECRET_GATE_APPROVER_TOKEN` alone.

---

## Endpoints

Base URL:
- Loopback on the Secret Gate host: `http://127.0.0.1:18080`
- Across a tailnet or reverse proxy: `https://secret-gate.example.ts.net`

All requests require:

```http
Authorization: Bearer <SECRET_GATE_APPROVER_TOKEN>
```

### 1. Real-time Event Stream: `GET /approvals/events` (SSE)

Opens a Server-Sent Events stream (`Content-Type: text/event-stream`).
- Immediately emits a `snapshot` event containing all currently pending requests in `pending`.
- Emits `: ping` comments every 20 seconds.
- Broadcasts `data: <JSON>\n\n` on every state transition:
  - `snapshot`: `{ "type": "snapshot", "ts": "...", "pending": [ApprovalView, ...] }`
  - `approval.created`: `{ "type": "approval.created", "ts": "...", "approval": ApprovalView }`
  - `approval.updated`: `{ "type": "approval.updated", "ts": "...", "approval": ApprovalView }` (when a duplicate request renews TTL)
  - `approval.approved`: `{ "type": "approval.approved", "ts": "...", "approval": ApprovalView }`
  - `approval.denied`: `{ "type": "approval.denied", "ts": "...", "approval": ApprovalView }`
  - `approval.expired`: `{ "type": "approval.expired", "ts": "...", "approval": ApprovalView }`
  - `window.revoked`: `{ "type": "window.revoked", "ts": "...", "window_id": "...", "approver": "..." }`

#### `ApprovalView` JSON shape

```json
{
  "id": "6bb311e04b4c90a6ef550fe29f8a48fa",
  "status": "pending",
  "action": "create",
  "title": "Create Example NAS",
  "summary": "Create Example NAS in AI Agents: Save the NAS admin login",
  "vault": "AI Agents",
  "reason": "Save the NAS admin login",
  "requester_machine": "mac-server",
  "requester_ip": "100.64.0.3",
  "context": {
    "runtime": "paseo",
    "provider": "omp",
    "model": "google-antigravity/gemini-4-argon",
    "think": "low",
    "project": "infra",
    "paseo_agent_id": "8e1cb89a-4097-4356-b652-cbd397ace5e1"
  },
  "items": [
    {
      "item": "Example NAS",
      "vault": "AI Agents",
      "operation": "create",
      "category": "LOGIN",
      "fields": ["one-time password", "password", "username"]
    }
  ],
  "options": [
    { "id": "approve", "label": "Approve", "style": "primary" },
    { "id": "approve_writes", "label": "Approve + 15m", "style": "secondary" },
    { "id": "deny", "label": "Deny", "style": "destructive" }
  ],
  "requested_at": "2026-10-27T17:20:00Z",
  "expires_at": "2026-10-27T18:20:00Z"
}
```

### 2. List Pending Approvals: `GET /approvals`

Returns `{ "pending": [ApprovalView, ...] }`.

### 3. Get Single Approval: `GET /approvals/{id}`

Returns `{ "approval": ApprovalView }`, or `404` if unknown.

### 4. Decide an Approval: `POST /approvals/{id}/decide`

Request body:

```json
{
  "action": "approve",
  "approver": "voice-workspace"
}
```

Valid `action` values (matching `approval.options[].id`):
- `"approve"`: Approve this single request.
- `"approve_window"`: Approve this read request and open the read auto-approval window (`AUTO_APPROVE_TTL`). Rejected with `400 unknown_option` on writes, and while tap windows are off (`/set tap_windows off`). The window never covers Secret Gate's own credentials, passkeys, or attachments.
- `"approve_writes"`: Approve this write request and open a scoped write window (`WRITE_WINDOW_TTL`) for new items from the same machine, IP, Paseo agent ID, and vault. Rejected while tap windows are off.
- `"deny"`: Deny the request and scrub any pending write values from memory.

Responses:
- `200 OK`: `{ "ok": true, "message": "Approved", "approval": ApprovalView }` (if `action` was `"approve_writes"`, `approval.write_window_id` holds the new window ID).
- `409 Conflict` (`already_processed`): Already approved or denied elsewhere (e.g. Telegram or PushWard).
- `410 Gone` (`alert_moved_on`): Request expired before the tap arrived.
- `404 Not Found` (`not_found`): Unknown request ID.

### 5. Revoke a Window: `POST /approvals/windows/{windowId}/revoke`

Closes an owner window or a write window. Accepts the approver token or the opener token.

Request body:

```json
{
  "approver": "voice-workspace"
}
```

Response (`200 OK`) for a write window:

```json
{
  "ok": true,
  "window_id": "77a722cdd4acb2b3",
  "follow_up_grants_removed": 2
}
```

For an owner window the response is `{ "ok": true, "window_id": "..." }`. `409 already_closed` if it is no longer open.

### 6. Owner Windows: `POST /approvals/windows`, `GET /approvals/windows`

<a id="owner-windows"></a>

An owner window lets reads in the configured vault proceed without a tap, from before any request exists. Rules, limits, and the Telegram side: [owner-window.md](owner-window.md). These two routes accept the approver token or the **opener token** (`SECRET_GATE_OPENER_TOKEN_SHA256`). The opener token can use these routes and the revoke route above and nothing else: `GET /approvals`, `/approvals/events`, and `decide` answer `403` for it.

Open (needs `OWNER_WINDOW_VAULTS` and the `owner_windows` setting on):

```http
POST /approvals/windows
Authorization: Bearer <opener or approver token>

{ "minutes": 30, "vault": "AI Agents", "approver": "voice-workspace (control)" }
```

`minutes` is `0` or omitted for the default (`OWNER_WINDOW_TTL`), otherwise 5 up to `OWNER_WINDOW_MAX`. `vault` defaults to the first configured vault. Optional advisory pins: `machine`, `agent_id` (clients report these themselves). `approver` is a label shown in alerts and the audit log.

| Status | Meaning |
|---|---|
| `201` | `{ "ok": true, "window": WindowInfo }` |
| `409 already_open` | A window is already open for the vault. It comes back unchanged; it is never extended. |
| `422 invalid_minutes`, `422 unknown_vault` | The request is outside the configured limits. |
| `403 owner_windows_off` | The feature is off or no vault is configured. |
| `429 rate_limited` | Too many windows in the last hour or day. |
| `503 audit_unavailable` | No channel could announce the window, so nothing was opened. |

Every window opened this way sends a loud alert to Telegram and PushWard with a close button. That alert is your alarm if anything but you used the token.

List: `GET /approvals/windows` returns `{ "windows": [WindowInfo, ...] }`.

```json
{
  "id": "9f1c2e7a5b3d4e60",
  "vault": "AI Agents",
  "tag": "",
  "source": "api",
  "opener": "voice-workspace (control)",
  "opened_at": "2026-11-10T14:00:00Z",
  "expires_at": "2026-11-10T14:30:00Z",
  "requests": 3,
  "max_requests": 30,
  "items": 1,
  "max_items": 10
}
```

`WindowInfo` has counts only, never item names.

SSE events on `/approvals/events` (approver token): `window.opened`, `window.used` (counts moved), and `window.closed` (`reason`: `expired`, `revoked`, `budget_requests`, `budget_items`, `audit_unavailable`), each with `window: WindowInfo`.

Store the opener (and optionally the approver) token as a SHA-256 digest on the server; see [owner-window.md](owner-window.md#approver-api-backup-trigger).

---

## How to Integrate into Voice Workspace (`~/code/voice-workspace`)

Voice Workspace already has the exact UI, notification, CallKit, and Live Activity machinery needed (`ThreadActivityAttributes.ContentState.Ask`, `AnswerAlertIntent`, and `POST /v1/alerts/:id/answer`). You do **not** need a new WidgetKit extension or a new AppIntent; Secret Gate approvals map directly onto `AlertEngine` in `services/gateway/src/alerts/engine.ts`.

### Step 1: Config (`services/gateway/src/config.ts`)

Add two optional environment settings (loaded from `~/Library/Application Support/voice-workspace/services.env` or retrieved via Secret Gate):
- `VW_SECRET_GATE_URL` (default `https://secret-gate.example.ts.net`, or `http://127.0.0.1:18080` on the Secret Gate host)
- `VW_SECRET_GATE_APPROVER_TOKEN` (the same value as `SECRET_GATE_APPROVER_TOKEN`)

### Step 2: Map Secret Gate Approvals to `ThreadRef` in the Gateway

Every `ApprovalView` from Secret Gate includes:
- `approval.context.paseo_agent_id`: the Paseo agent UUID (e.g. `"8e1cb89a-4097-4356-b652-cbd397ace5e1"`)
- `approval.requester_machine`: the hostname (e.g. `"mac-server"`)

In `AlertEngine`, resolve the `ThreadRef { hostId, agentId }`:
1. If `approval.context.paseo_agent_id` is non-empty, look up the tracked agent in `this.tracked` whose `agentId === approval.context.paseo_agent_id` (preferring the host profile matching `approval.requester_machine`).
2. If found, attach the alert to that exact `ThreadRef`.

### Step 3: Raise & Close Alerts from `GET /approvals/events`

Subscribe to `GET ${VW_SECRET_GATE_URL}/approvals/events` with `Authorization: Bearer ${VW_SECRET_GATE_APPROVER_TOKEN}`:

1. **On `snapshot` / `approval.created` / `approval.updated`**:
   Build an `Alert` in `AlertEngine` without calling the LLM summarizer (the metadata is already structured and concise):
   - `status`: `"question"` (using `"question"` with `options` lets `ThreadActivityAttributes.ContentState.Ask` render all 3 buttons: `Approve`, `Approve 30m` / `Approve + 15m`, and `Deny`, because `ThreadActivity` already supports up to 3 `options` with `kind: "options"`).
   - `bold`: `approval.title.slice(0, 30)` (e.g. `"Create NAS admin"`).
   - `body`: `${approval.vault} · ${fieldsList}${approval.reason ? `: ${approval.reason}` : ""}`.slice(0, 120).
   - `activity_row`: `approval.title.slice(0, 40)`.
   - `options`: `approval.options.map(o => ({ id: o.id, label: o.label }))` (`approve`, `approve_window` / `approve_writes`, `deny`).
   - `reply`: `false` (so `other` is omitted and no free-text button is shown on the Live Activity).
   - `spoken_open`: `Secret Gate needs 1Password approval for ${approval.title}.`
   - `spoken_ask`: `${approval.reason || approval.summary}. Say approve, approve window, or deny.`
   - Store `"sg:" + approval.id` in `alert.permissionId` (or a dedicated `secretGateId: string | null` field on `Alert`).
   - Call `this.deliver(alert)`, `this.armLadder(alert)`, `this.startWanted.add(threadKey(ref))`, and `this.scheduleActivity(ref)`.
     - If the thread is followed on the Lock Screen, its existing Live Activity immediately switches to `phase: "ask"` at APNs priority 10 and relevance 100.
     - If the thread is not followed and `device.prefs.liveQuestions` is true, the gateway push-starts a Question Live Activity on the Lock Screen automatically!

2. **On `approval.approved` / `approval.denied` / `approval.expired`**:
   Find the open alert with `secretGateId === approval.id` and call `await this.closeAlert(alert, `secret-gate ${approval.status}`)`.
   - This immediately ends any question Live Activity (with a past dismissal date so it disappears from the Lock Screen at once), updates any followed-thread Live Activity back to `working`/`idle`, and sends a background push to remove delivered iOS/macOS notifications.

### Step 4: Route Button Taps (`POST /v1/alerts/:id/answer`) to Secret Gate

In `AlertEngine.answer(alertId, input)` (`services/gateway/src/alerts/engine.ts`):
When the alert has `secretGateId`:
1. Map `input`:
   - `input.action === "approve"` -> `sgAction = "approve"`
   - `input.action === "deny"` -> `sgAction = "deny"`
   - `input.action === "option"` -> `sgAction = input.optionId` (`"approve"`, `"approve_window"`, `"approve_writes"`, or `"deny"`)
2. Send:
   ```ts
   const res = await fetch(`${secretGateUrl}/approvals/${alert.secretGateId}/decide`, {
     method: "POST",
     headers: {
       "Authorization": `Bearer ${approverToken}`,
       "Content-Type": "application/json",
     },
     body: JSON.stringify({
       action: sgAction,
       approver: `voice-workspace (${input.via})`,
     }),
   });
   if (res.status === 410 || res.status === 404) {
     await this.closeAlert(alert, "expired");
     throw new GatewayError(410, "alert_moved_on", "That approval request expired.");
   }
   if (res.status === 409) {
     await this.closeAlert(alert, "answered elsewhere");
     throw new GatewayError(410, "alert_moved_on", "That approval request was already answered.");
   }
   ```
3. Close the alert locally and return `{ confirm: "Done. Approved.", next: "The agent is continuing.", row: `Sent: ${chosenLabel}` }`.
   - Because `AnswerAlertIntent` in the iPhone Widget extension already calls `POST /v1/alerts/:id/answer` with `{ action: "option", optionId, via: "activity" }`, **zero Swift changes are required** for Lock Screen Live Activity buttons, Dynamic Island buttons, interactive notifications, or CallKit voice approvals to work.
