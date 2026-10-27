# Approver API and Voice Workspace Integration Guide

Secret Gate exposes an authenticated **Approver API** (`/approvals/*`) so first-party apps and gateways (such as **Voice Workspace**) can display inline approval buttons, drive iOS Live Activities, and approve or deny requests without needing Telegram or PushWard.

## Security Model

1. **Zero secret exposure**: `/approvals` and `/approvals/events` emit **metadata only** (request ID, item title, vault, field labels, attachment names/sizes, reason, requester machine, and `context.paseo_agent_id`). Secret values, file contents, and one-time retrieval `/secret/{token}` URLs never appear on the Approver API.
2. **Bearer authentication**: Every `/approvals*` endpoint requires `Authorization: Bearer <SECRET_GATE_APPROVER_TOKEN>` (or `X-Approver-Token: <token>`), verified in constant time. Agent clients do not hold this token and cannot call `/approvals/*`.
3. **Single-winner synchronization**: A decision from `/approvals/{id}/decide`, Telegram, or PushWard atomically resolves the request, wakes the waiting agent, updates/dismisses the other channels, and broadcasts an `approval.approved` or `approval.denied` SSE event so every connected client clears its UI immediately.

---

## Server Configuration

Set `SECRET_GATE_APPROVER_TOKEN` in `~/.config/secret-gate/server.env` (on `mac-server`, this is already configured and stored in 1Password vault `AI Agents` under item `Secret Gate Approver Token`, field `credential`):

```env
SECRET_GATE_APPROVER_TOKEN=<token>
```

Secret Gate can run with Telegram, PushWard, and the Approver API all active at once, or with `SECRET_GATE_APPROVER_TOKEN` alone.

---

## Endpoints

Base URL:
- Loopback on `mac-server`: `http://127.0.0.1:18080`
- Across the tailnet (e.g. from `mac-laptop`): `https://secret-gate.example.ts.net`

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
- `"approve_window"`: Approve this read request and open the global read auto-approval window (`AUTO_APPROVE_TTL`). Rejected with `400 unknown_option` on writes.
- `"approve_writes"`: Approve this write request and open a scoped write window (`WRITE_WINDOW_TTL`) for new items from the same machine, IP, Paseo agent ID, and vault.
- `"deny"`: Deny the request and scrub any pending write values from memory.

Responses:
- `200 OK`: `{ "ok": true, "message": "Approved", "approval": ApprovalView }` (if `action` was `"approve_writes"`, `approval.write_window_id` holds the new window ID).
- `409 Conflict` (`already_processed`): Already approved or denied elsewhere (e.g. Telegram or PushWard).
- `410 Gone` (`alert_moved_on`): Request expired before the tap arrived.
- `404 Not Found` (`not_found`): Unknown request ID.

### 5. Revoke a Write Window: `POST /approvals/windows/{windowId}/revoke`

Request body:

```json
{
  "approver": "voice-workspace"
}
```

Response (`200 OK`):

```json
{
  "ok": true,
  "window_id": "77a722cdd4acb2b3",
  "follow_up_grants_removed": 2
}
```

---

## How to Integrate into Voice Workspace (`~/code/voice-workspace`)

Voice Workspace already has the exact UI, notification, CallKit, and Live Activity machinery needed (`ThreadActivityAttributes.ContentState.Ask`, `AnswerAlertIntent`, and `POST /v1/alerts/:id/answer`). You do **not** need a new WidgetKit extension or a new AppIntent; Secret Gate approvals map directly onto `AlertEngine` in `services/gateway/src/alerts/engine.ts`.

### Step 1: Config (`services/gateway/src/config.ts`)

Add two optional environment settings (loaded from `~/Library/Application Support/voice-workspace/services.env` or retrieved via Secret Gate):
- `VW_SECRET_GATE_URL` (default `https://secret-gate.example.ts.net` or `http://127.0.0.1:18080` when on `mac-server`)
- `VW_SECRET_GATE_APPROVER_TOKEN` (the token stored in 1Password item `Secret Gate Approver Token` in vault `AI Agents`)

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
