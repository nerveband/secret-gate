package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/daemon"
)

func init() {
	const writeUsage = `Usage: secret-gate write %[1]s --item <name> --vault <vault> --reason <why> --stdin
                          [--category card|api|note|login|password] [--owner-fields a,b]
                          [--no-wait] [--dry-run]

%[2]s a 1Password item after Telegram approval. Field values are read
from stdin as JSON (value-input class — values never appear in argv):

  echo '{"category":"API_CREDENTIAL","fields":{"credential":"<value>"}}' \
    | secret-gate write %[1]s --item "ci-token" --vault "Infra" --reason "store the new CI token" --stdin

Typed items use the native 1Password category, so they look right in the
1Password app. Friendly labels map onto native fields:
  card (CREDIT_CARD): cardholder, number, cvv, expiry (MM/YY), type, pin,
                      bank, billing_address, city, state, zip, country
  api (API_CREDENTIAL): credential (key/secret/token), username (key id),
                      hostname (host/base_url), expires (YYYY-MM-DD), scopes
  note (SECURE_NOTE): note;  login: username, password, url;  password: password
Card numbers are checked (Luhn) and the card type is detected when omitted.

Values the agent does not have (a CVV only the owner knows) are typed by
the approver: --owner-fields cvv sends Telegram an "Enter values" link to a
page on the approval device; saving it approves the write. --stdin is then
optional (pipe only the fields you have):

  echo '{"fields":{"cardholder":"A. Ali","billing_address":"<street>","zip":"<zip>"}}' \
    | secret-gate write %[1]s --item "Visa travel" --vault "AI Agents" --category card \
      --owner-fields number,cvv,expiry --reason "store the travel card" --stdin

Card and bank account writes, and writes with owner fields, always need a
tap on that request; write windows and follow-ups never cover them.

Use --no-wait to hand the pending write to the local daemon and return a
token at once (resume with: secret-gate request wait <token>). The server
holds the values while approval is pending, so the caller can drop them.
Use --dry-run to preview the operation (field labels only, no values).

Attach files with a "files" list of local paths (up to 10 MiB per request;
Telegram shows names and sizes only). The server needs a 1Password service
account for this, because 1Password Connect cannot upload files:

  echo '{"fields":{"note":"release keystore"},"files":[{"path":"./release.jks"}]}' \
    | secret-gate write %[1]s --item "Android keystore" --vault "Infra" --reason "store the keystore" --stdin`
	usageText["write create"] = fmt.Sprintf(writeUsage, "create", "Create")
	usageText["write update"] = fmt.Sprintf(writeUsage, "update", "Update")
	usageText["write batch"] = `Usage: secret-gate write batch --vault <vault> --reason <why> --stdin [--no-wait] [--dry-run]

Create or update up to 10 items in one vault behind ONE Telegram approval.
The approver sees every item name and field label, never the values.
Items are read from stdin as JSON (value-input class):

  echo '{"items":[
    {"item":"Play service account","operation":"create","category":"API_CREDENTIAL","fields":{"credential":"<json>"}},
    {"item":"Expo token","operation":"create","fields":{"token":"<value>"}}]}' \
    | secret-gate write batch --vault "AI Agents" --reason "store release credentials" --stdin

Each item may appear once; merge fields for one item into one entry. Items
may carry "files":[{"path":"./cert.p12","name":"cert.p12"}] to attach and
"owner_fields":["cvv"] for values the approver types on the entry page.`
}

// stdinWritePayload is the JSON document accepted on stdin.
type stdinWritePayload struct {
	Category    string            `json:"category"`
	Fields      map[string]string `json:"fields"`
	Files       []core.FileWrite  `json:"files"`
	OwnerFields []string          `json:"owner_fields"`
}

type stdinBatchPayload struct {
	Items []core.ItemWrite `json:"items"`
}

func (a *App) runWrite(args []string) int {
	if len(args) == 0 {
		return a.fail("write", "usage", "write requires an operation: create, update, or batch",
			"run: secret-gate write create --help")
	}
	op := args[0]
	if op != "create" && op != "update" && op != "batch" {
		return a.fail("write", "usage",
			fmt.Sprintf("operation must be create, update, or batch, got %q", op),
			"valid operations: create, update, batch")
	}
	command := "write " + op

	fs := a.newFlagSet(command)
	var item, category, ownerCSV *string
	if op != "batch" {
		item = fs.String("item", "", "item title")
		category = fs.String("category", "", "1Password category for new items: card, api, note, login, password, or a native name (default SECURE_NOTE)")
		ownerCSV = fs.String("owner-fields", "", "comma-separated labels the approver types on the Telegram-linked entry page (e.g. cvv)")
	}
	vault := fs.String("vault", "", "explicit vault name or ID")
	reason := fs.String("reason", "", "why this write is needed (shown to the approver)")
	stdin := fs.Bool("stdin", false, "read field values as JSON from stdin")
	noWait := fs.Bool("no-wait", false, "return a token at once; the local daemon finishes the write after approval")
	dryRun := fs.Bool("dry-run", false, "preview the operation without submitting")
	if code, done := a.parse(fs, command, args[1:]); done {
		return code
	}
	if (item != nil && *item == "") || *vault == "" || *reason == "" {
		if op == "batch" {
			return a.fail(command, "usage", "vault and reason are required", "pass --vault <vault> --reason <why>")
		}
		return a.fail(command, "usage", "item, vault, and reason are required",
			"pass --item <name> --vault <vault> --reason <why>")
	}
	var owner []string
	if ownerCSV != nil {
		for _, f := range strings.Split(*ownerCSV, ",") {
			if f = strings.TrimSpace(f); f != "" {
				owner = append(owner, f)
			}
		}
	}
	if !*stdin && len(owner) == 0 {
		return a.fail(command, "usage",
			"field values must arrive via stdin (value-input class), never argv",
			`pipe JSON and pass --stdin: echo '{"fields":{"label":"value"}}' | secret-gate `+command+` --vault ... --stdin, or let the approver type them with --owner-fields`)
	}

	var raw []byte
	if *stdin {
		var err error
		raw, err = io.ReadAll(a.Stdin)
		if err != nil {
			return a.fail(command, "usage", "failed to read stdin: "+err.Error(), "")
		}
	}
	var items []core.ItemWrite
	if op == "batch" {
		var payload stdinBatchPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			return a.fail(command, "usage", "stdin is not valid JSON: "+err.Error(),
				`expected: {"items":[{"item":"name","operation":"create","fields":{"label":"value"}}]}`)
		}
		if len(payload.Items) == 0 {
			return a.fail(command, "usage", "stdin JSON must contain a non-empty \"items\" array",
				`expected: {"items":[{"item":"name","operation":"create","fields":{"label":"value"}}]}`)
		}
		items = payload.Items
	} else {
		var payload stdinWritePayload
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &payload); err != nil {
				return a.fail(command, "usage", "stdin is not valid JSON: "+err.Error(),
					`expected: {"category":"SECURE_NOTE","fields":{"label":"value"}}`)
			}
		}
		owner = append(owner, payload.OwnerFields...)
		if len(payload.Fields) == 0 && len(payload.Files) == 0 && len(owner) == 0 {
			return a.fail(command, "usage", "stdin JSON must contain a non-empty \"fields\" object or \"files\" list",
				`expected: {"fields":{"label":"value"}} or {"files":[{"path":"./file"}]}`)
		}
		cat := *category
		if cat == "" {
			cat = payload.Category
		}
		items = []core.ItemWrite{{Item: *item, Operation: op, Category: cat, Fields: payload.Fields, Files: payload.Files, OwnerFields: owner}}
	}

	if *dryRun {
		return a.ok(command, writePreview(op, *vault, items), &Meta{Visibility: VisibilityMetadataOnly})
	}

	if *noWait {
		return a.submitWriteNoWait(command, *vault, *reason, items)
	}

	var out *core.RequestResult
	var err error
	if op == "batch" || len(items[0].Files) > 0 || len(items[0].OwnerFields) > 0 {
		out, err = a.Service.WriteItems(context.Background(), *vault, *reason, items, core.RequestContext{})
	} else {
		it := items[0]
		out, err = a.Service.Write(context.Background(), it.Item, *vault, *reason, op, it.Category, it.Fields, core.RequestContext{})
	}
	if err != nil {
		return a.failErr(command, err)
	}
	switch out.Status {
	case "denied", "expired", "timeout":
		return a.fail(command, out.Status, out.Message, "")
	}
	return a.ok(command, out, &Meta{Visibility: VisibilityValueInput})
}

// writePreview describes a write by item names, field labels, and file
// names only.
func writePreview(op, vault string, items []core.ItemWrite) map[string]interface{} {
	preview := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		labels := make([]string, 0, len(it.Fields))
		for k := range it.Fields {
			labels = append(labels, k)
		}
		sort.Strings(labels)
		entry := map[string]interface{}{
			"secret_name": it.Item, "operation": it.Operation, "category": it.Category, "field_labels": labels,
		}
		if len(it.Files) > 0 {
			files := make([]string, 0, len(it.Files))
			for _, f := range it.Files {
				name := f.Name
				if name == "" {
					name = filepath.Base(f.Path)
				}
				files = append(files, name)
			}
			entry["files"] = files
		}
		if len(it.OwnerFields) > 0 {
			entry["owner_fields"] = it.OwnerFields
		}
		preview = append(preview, entry)
	}
	if op != "batch" {
		single := preview[0]
		single["dry_run"] = true
		single["vault"] = vault
		return single
	}
	return map[string]interface{}{"dry_run": true, "operation": "batch", "vault": vault, "items": preview}
}

// submitWriteNoWait submits the write, records it in the ledger, and hands
// completion to the local daemon so the agent does not keep the values.
func (a *App) submitWriteNoWait(command, vault, reason string, items []core.ItemWrite) int {
	if a.Admin == nil {
		return a.fail(command, "internal", "--no-wait needs the local daemon to finish the write after approval", "run: secret-gate daemon start")
	}
	if err := a.Admin.EnsureRunning(); err != nil {
		return a.fail(command, "internal", "local daemon could not start: "+err.Error(), "run: secret-gate daemon start")
	}
	pending, err := a.Service.SubmitWrite(context.Background(), vault, reason, items, core.RequestContext{})
	if err != nil {
		return a.failErr(command, err)
	}
	names := make([]string, 0, len(items))
	for _, it := range items {
		names = append(names, it.Item)
	}
	label := strings.Join(names, ", ")
	entry := LedgerEntry{
		Token: pending.Token, SecretName: label, Vault: vault, StatusURL: pending.StatusURL,
		SubmittedAt: a.Now().UTC().Format(time.RFC3339), ExpiresAt: pending.ExpiresAt,
		Operation: "write", State: "pending",
	}
	l, err := OpenLedger(a.StateDir)
	if err == nil {
		err = l.Put(entry)
	}
	if err != nil {
		return a.fail(command, "internal", "write was submitted but local recovery state could not be saved: "+err.Error(),
			"approve or deny it in Telegram; the token is "+pending.Token)
	}
	if err := a.Admin.Watch(daemon.WatchSpec{
		Token: pending.Token, StatusURL: pending.StatusURL, SecretName: label, Vault: vault,
		IsMutation: true, ExpiresAt: pending.ExpiresAt,
		Activation: daemon.SniffActivationSpec(), StateDir: a.StateDir,
	}); err != nil {
		return a.fail(command, "internal", "write was submitted but background completion could not be registered: "+err.Error(),
			"resume with: secret-gate request wait "+pending.Token)
	}
	return a.ok(command, map[string]interface{}{
		"token":          pending.Token,
		"items":          names,
		"vault":          vault,
		"expires_at":     pending.ExpiresAt,
		"state":          "pending",
		"request_reused": pending.RequestReused,
		"resume":         "secret-gate request wait " + pending.Token,
		"check":          "secret-gate request status " + pending.Token,
	}, &Meta{Visibility: VisibilityValueInput})
}
