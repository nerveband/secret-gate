# Passkeys and attachments (v0.7.0)

Status: implemented in v0.7.0. Owner: nerveband fork.

## What 1Password's developer APIs allow (checked 2026-10-25)

| Capability | Connect API | 1Password CLI | SDKs (Go, JS, Python) |
|---|---|---|---|
| List attachments | Yes: `GET /v1/vaults/{vault}/items/{item}/files` [1] | Yes | Yes [3] |
| Download attachment | Yes: `GET .../files/{file}/content` [1] | Yes | Yes: `Items().Files().Read` [3] |
| Upload attachment | **No** endpoint [1][2] | Yes: `file` field assignment [6] | Yes: `Items().Files().Attach`, or `Files` in `ItemCreateParams` [3] |
| Use a passkey that 1Password saved | **No** | **No**: JSON templates do not support passkeys and overwrite them [5] | **No**: "Passkeys" is listed as unsupported [4] |

Sources:

1. Connect Server API reference, "List files", "Get File details", "Get file content", "Add an item", "Replace an item": https://developer.1password.com/docs/connect/api-reference/ and the OpenAPI spec 1.8.1: https://i.1password.com/media/1password-connect/1password-connect-api_1.8.1.yaml . Inline content (`inline_files=true`) is limited to `OP_MAX_INLINE_FILE_SIZE_KB`, 100 KB by default; the content endpoint has no documented size limit. No operation accepts file content.
2. 1Password staff on the 1Password Community: "the current version of Connect does not support uploading files to 1Password": https://www.1password.community/developers-69/how-do-you-upload-a-file-via-the-connect-server-api-10235
3. Manage files using 1Password SDKs (attach, read, delete; 50 MB per file and per item message; storage 1 GB per person on Teams/Families, 5 GB on Business): https://developer.1password.com/docs/sdks/files . Go API: https://pkg.go.dev/github.com/1password/onepassword-sdk-go@v0.4.1
4. SDK supported functionality, field types, "[ ] Passkeys": https://www.1password.dev/sdks/functionality
5. 1Password CLI, Edit items: "JSON item templates do not support passkeys. If you use a JSON template to update an item that contains a passkey, the passkey will be overwritten.": https://developer.1password.com/docs/cli/item-edit
6. 1Password CLI, Create items, "Attach a file to an item": https://developer.1password.com/docs/cli/item-create
7. Service accounts (token, vault permissions): https://developer.1password.com/docs/service-accounts/get-started
8. Chrome DevTools Protocol, WebAuthn domain (`enable`, `addVirtualAuthenticator`, `addCredential`, `getCredentials`, `removeVirtualAuthenticator`): https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/
9. WebAuthn Level 3, signature counter: https://www.w3.org/TR/webauthn-3/#sctn-sign-counter

Conclusion: the README boundary holds. No official route lets Secret Gate
use a passkey that 1Password saved, so Secret Gate uses its own
("agent-owned") passkeys. Attachments can be read through Connect, but
uploading needs the SDK or CLI with a service account.

## Attachments

### Read

- `/fields` (CLI `item fields`, MCP `inspect_fields`) returns `files`:
  name, size, ID, section. Never content.
- A request names an attachment as a field selector `file:<name or id>`.
  The server resolves it against the item before approval, refuses unknown
  or ambiguous names, and refuses requests whose attachments exceed
  10 MiB. Telegram shows `📎 name (size)`.
- After approval the server downloads the content from the Connect content
  endpoint and returns it base64-encoded under the `file:<selector>` key.
  Whole-item reads never include attachments.
- The client caches it in daemon memory like other values (the socket
  message limit is now 32 MiB). `item read` and `read_item_fields` refuse
  `file:` keys and drop them from whole-item reads; `exec` refuses them.
- `attachment exec` / `read_attachment` writes a mode-0600 file in a
  private `MkdirTemp` directory, passes its path in `--env VAR`, runs the
  command, and deletes the directory. `--stdin` pipes the content instead.
  Text content is registered with the output redactor.

### Write

- `files: [{path, name?}]` on `write create|update|batch` stdin JSON,
  `write_item`, `write_items`, and MCP `attach_file`. The client reads the
  file (10 MiB per request) and sends name + content; the path never
  reaches the server.
- Server prechecks, before any Telegram message: plain file name, not empty,
  no duplicate names, size limit, a service account is configured, it can
  see the vault, and an update does not add a name the item already has.
- After approval: Connect creates or updates the item's fields, then the
  1Password Go SDK attaches each file to section `attachments`. Progress is
  recorded per file, so a failed upload releases the claim and a retry
  resumes at that file without creating the item again.
- Content is held in server memory only while the write is pending and is
  dropped on completion, denial, or expiry, like field values.
- Connect updates send the existing `files` array back with the item.

### Cost of enabling uploads

- A 1Password service account with read and write access to the vaults that
  receive files (`OP_SERVICE_ACCOUNT_TOKEN` in the server env file). This is
  a second credential with write access, separate from the Connect token.
- The SDK runs a WebAssembly core. Measured on mac-server: about 170 MB
  peak RSS to start a client. The live container has `mem_limit: 256m`;
  raise it to 512m before enabling uploads.
- Uploads go to 1Password.com directly, not through Connect, so the
  Connect cache sees the file after its next sync.

## Passkeys

### Options considered

| Option | Verdict |
|---|---|
| Use passkeys 1Password saved, through Connect, CLI, or SDK | Not possible (sources 1, 4, 5). |
| Agent-owned passkey, key in a 1Password item, used through a CDP virtual authenticator | **Adopted.** |
| ego lite (`ego-browser nodejs`, `page.cdp`) | Not usable. `page.cdp` accepts `WebAuthn.*`, but the authenticator does not survive across scripts, and inside one script `navigator.credentials.create` fails at once with `NotAllowedError` on webauthn.io, with and without focus emulation. ego lite exposes no DevTools endpoint for another client. |
| Aside (`aside repl`) | Not usable. No `newCDPSession` and no `page.cdp`; no DevTools endpoint. |
| agent-browser (`agent-browser get cdp-url`) | **Works.** Exposes a loopback browser WebSocket. Verified: register and sign in on webauthn.io. |
| Any Chrome with `--remote-debugging-port` on loopback | Works the same way. |

### Flow

1. `passkey arm --cdp <endpoint> --page-url <substring>`: the local daemon
   opens its own DevTools session to the tab (`Target.attachToTarget`,
   flatten), turns on focus emulation, `WebAuthn.enable`, and adds a
   ctap2 internal authenticator with resident keys and user verification.
2. The agent clicks the site's "create passkey". The browser creates the
   credential in the virtual authenticator.
3. `passkey register --session <id> --item --vault --reason`: the daemon
   reads the credential (`WebAuthn.getCredentials`) and returns it to the
   CLI over the 0600 socket; the CLI submits a `create` write with fields
   `passkey credential id`, `passkey private key` (concealed),
   `passkey rp id`, `passkey user handle`, `passkey sign count`. One tap.
4. `passkey release --session <id> [--save-counter]` removes the
   authenticator. `--save-counter` writes the final count as an `update`,
   which rides the v0.6.0 same-item follow-up grant for 15 minutes after
   the create.
5. Later: `request submit --item` (read approval, or the read window), then
   `passkey load --item --cdp`: the daemon builds the credential from the
   cached fields and calls `WebAuthn.addCredential`. The agent signs in.
   `passkey release` or the hold timer (default 10 min, max 30) removes it.

Sign counter: a loaded credential starts at `max(stored, current Unix
time)`. Every later load is above any count the site has seen (WebAuthn
only requires the counter to increase, source 9), so sign-ins do not need a
counter write and do not cost a write tap. uint32 seconds last until 2106.

Only loopback DevTools endpoints are accepted, so key material cannot be
sent to another host. The daemon stays running while a session is held and
releases every session when it stops.

### Threat model

- While loaded, the agent can sign in to that one relying party (the RP ID
  binds the credential) as the passkey's account, and do anything the
  account allows, until release or the hold timer ends (at most 30 min).
- Loading needs a read approval of the item (a tap or the read window), and
  registering needs a write approval; Telegram names the item and fields,
  never the key.
- The key never appears in CLI/MCP output or logs. It is not a hard
  barrier: any client with DevTools access to the same browser and the
  authenticator ID can call `WebAuthn.getCredentials` (verified). Secret
  Gate never returns the authenticator ID, and a guessed ID is refused, but
  treat the browser's DevTools endpoint as trusted as the agent itself.
- Revocation: deny further reads, delete or rotate the passkey on the site,
  or delete the 1Password item.

## Verification

- Unit tests: `internal/handlers/attachments_test.go` (approval-gated
  release, rejection before Telegram, service account requirement,
  validation, resume without duplicate create, content scrubbed after
  completion), `internal/opconnect/attachments_test.go` (download by name
  or ID, size limit, files kept on update), `internal/core/attachments_test.go`
  (no attachment in model-visible reads, 0600 temp file removed, stdin,
  content not path on the wire, size limit), `internal/daemon/attachment_test.go`
  (3 MiB value over the socket), `internal/telegram/attachments_test.go`
  (names and sizes only), `internal/passkey/manager_test.go` (fake
  DevTools browser: counter floor, release, hold expiry, collect, loopback
  only, tab selection).
- Live, before deploy: the passkey manager against agent-browser on
  webauthn.io registered a credential, released it, loaded it into a fresh
  session, and signed in; the sign count advanced from the Unix-time floor.
- Live end-to-end results after deploy are in
  `reports/2026-10-25-passkeys-attachments.md`.
