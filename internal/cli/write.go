package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/daemon"
)

func init() {
	const writeUsage = `Usage: secret-gate write %[1]s --item <name> --vault <vault> --reason <why> --stdin
                          [--category SECURE_NOTE] [--no-wait] [--dry-run]

%[2]s a 1Password item after Telegram approval. Field values are read
from stdin as JSON (value-input class — values never appear in argv):

  echo '{"category":"API_CREDENTIAL","fields":{"credential":"<value>"}}' \
    | secret-gate write %[1]s --item "ci-token" --vault "Infra" --reason "store the new CI token" --stdin

Use --no-wait to hand the pending write to the local daemon and return a
token at once (resume with: secret-gate request wait <token>). The server
holds the values while approval is pending, so the caller can drop them.
Use --dry-run to preview the operation (field labels only, no values).`
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

Each item may appear once; merge fields for one item into one entry.`
}

// stdinWritePayload is the JSON document accepted on stdin.
type stdinWritePayload struct {
	Category string            `json:"category"`
	Fields   map[string]string `json:"fields"`
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
	var item, category *string
	if op != "batch" {
		item = fs.String("item", "", "item title")
		category = fs.String("category", "", "1Password category for new items (default SECURE_NOTE)")
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
	if !*stdin {
		return a.fail(command, "usage",
			"field values must arrive via stdin (value-input class), never argv",
			`pipe JSON and pass --stdin: echo '{"fields":{"label":"value"}}' | secret-gate `+command+` --vault ... --stdin`)
	}

	raw, err := io.ReadAll(a.Stdin)
	if err != nil {
		return a.fail(command, "usage", "failed to read stdin: "+err.Error(), "")
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
		if err := json.Unmarshal(raw, &payload); err != nil {
			return a.fail(command, "usage", "stdin is not valid JSON: "+err.Error(),
				`expected: {"category":"SECURE_NOTE","fields":{"label":"value"}}`)
		}
		if len(payload.Fields) == 0 {
			return a.fail(command, "usage", "stdin JSON must contain a non-empty \"fields\" object",
				`expected: {"fields":{"label":"value"}}`)
		}
		cat := *category
		if cat == "" {
			cat = payload.Category
		}
		items = []core.ItemWrite{{Item: *item, Operation: op, Category: cat, Fields: payload.Fields}}
	}

	if *dryRun {
		return a.ok(command, writePreview(op, *vault, items), &Meta{Visibility: VisibilityMetadataOnly})
	}

	if *noWait {
		return a.submitWriteNoWait(command, *vault, *reason, items)
	}

	var out *core.RequestResult
	if op == "batch" {
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

// writePreview describes a write by item names and field labels only.
func writePreview(op, vault string, items []core.ItemWrite) map[string]interface{} {
	preview := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		labels := make([]string, 0, len(it.Fields))
		for k := range it.Fields {
			labels = append(labels, k)
		}
		sort.Strings(labels)
		preview = append(preview, map[string]interface{}{
			"secret_name": it.Item, "operation": it.Operation, "category": it.Category, "field_labels": labels,
		})
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
