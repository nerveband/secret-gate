package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/johnuopini/secret-gate/internal/core"
)

func init() {
	const writeUsage = `Usage: secret-gate write %[1]s --item <name> --vault <vault> --reason <why> --stdin
                          [--category SECURE_NOTE] [--dry-run]

%[2]s a 1Password item after Telegram approval. Field values are read
from stdin as JSON (value-input class — values never appear in argv):

  echo '{"category":"API_CREDENTIAL","fields":{"credential":"<value>"}}' \
    | secret-gate write %[1]s --item "ci-token" --vault "Infra" --reason "store the new CI token" --stdin

Use --dry-run to preview the operation (field labels only, no values).`
	usageText["write create"] = fmt.Sprintf(writeUsage, "create", "Create")
	usageText["write update"] = fmt.Sprintf(writeUsage, "update", "Update")
}

// stdinWritePayload is the JSON document accepted on stdin.
type stdinWritePayload struct {
	Category string            `json:"category"`
	Fields   map[string]string `json:"fields"`
}

func (a *App) runWrite(args []string) int {
	if len(args) == 0 {
		return a.fail("write", "usage", "write requires an operation: create or update",
			"run: secret-gate write create --help")
	}
	op := args[0]
	if op != "create" && op != "update" {
		return a.fail("write", "usage",
			fmt.Sprintf("operation must be create or update, got %q", op),
			"valid operations: create, update")
	}
	command := "write " + op

	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item title")
	vault := fs.String("vault", "", "explicit vault name or ID")
	reason := fs.String("reason", "", "why this write is needed (shown to the approver)")
	category := fs.String("category", "", "1Password category for new items (default SECURE_NOTE)")
	stdin := fs.Bool("stdin", false, "read {\"category\":..., \"fields\":{...}} JSON from stdin")
	dryRun := fs.Bool("dry-run", false, "preview the operation without submitting")
	if code, done := a.parse(fs, command, args[1:]); done {
		return code
	}
	if *item == "" || *vault == "" || *reason == "" {
		return a.fail(command, "usage", "item, vault, and reason are required",
			"pass --item <name> --vault <vault> --reason <why>")
	}
	if !*stdin {
		return a.fail(command, "usage",
			"field values must arrive via stdin (value-input class), never argv",
			`pipe JSON and pass --stdin: echo '{"fields":{"label":"value"}}' | secret-gate `+command+` --item ... --stdin`)
	}

	raw, err := io.ReadAll(a.Stdin)
	if err != nil {
		return a.fail(command, "usage", "failed to read stdin: "+err.Error(), "")
	}
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

	if *dryRun {
		labels := make([]string, 0, len(payload.Fields))
		for k := range payload.Fields {
			labels = append(labels, k)
		}
		sort.Strings(labels)
		return a.ok(command, map[string]interface{}{
			"dry_run":      true,
			"operation":    op,
			"secret_name":  *item,
			"vault":        *vault,
			"category":     cat,
			"field_labels": labels,
		}, &Meta{Visibility: VisibilityMetadataOnly})
	}

	out, err := a.Service.Write(context.Background(), *item, *vault, *reason, op, cat, payload.Fields, core.RequestContext{})
	if err != nil {
		return a.failErr(command, err)
	}
	switch out.Status {
	case "denied", "expired", "timeout":
		return a.fail(command, out.Status, out.Message, "")
	}
	return a.ok(command, out, &Meta{Visibility: VisibilityValueInput})
}
