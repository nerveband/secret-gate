package cli

import (
	"fmt"
	"strings"
)

func init() {
	usageText["item search"] = `Usage: secret-gate item search --query <text> [--limit 10]

Find 1Password items by name. Metadata only — no values.

Examples:
  secret-gate item search --query "deploy"
  secret-gate item search --query "github" --limit 5`

	usageText["item fields"] = `Usage: secret-gate item fields --item <name> [--vault <vault>]

List an item's field labels and types without revealing values.

Examples:
  secret-gate item fields --item "deploy-key"
  secret-gate item fields --item "prod-api" --vault "Infra"`

	usageText["item read"] = `Usage: secret-gate item read --item <name> [--vault <vault>] [--fields a,b] --reveal

Read cached field values. Values enter model context, so --reveal is
required. Prefer 'secret-gate exec' when the value is only needed by a
command.

Examples:
  secret-gate item read --item "wifi-guest" --fields "note" --reveal
  secret-gate item read --item "prod-api" --reveal`
}

func (a *App) runItem(args []string) int {
	if len(args) == 0 {
		return a.fail("item", "usage", "item requires a subcommand: search, fields, read",
			"run: secret-gate item search --help")
	}
	switch args[0] {
	case "search":
		return a.itemSearch(args[1:])
	case "fields":
		return a.itemFields(args[1:])
	case "read":
		return a.itemRead(args[1:])
	default:
		return a.fail("item", "usage", fmt.Sprintf("unknown item subcommand %q", args[0]),
			"valid subcommands: search, fields, read")
	}
}

func (a *App) itemSearch(args []string) int {
	const command = "item search"
	fs := a.newFlagSet(command)
	query := fs.String("query", "", "search query")
	limit := fs.Int("limit", 10, "maximum number of results")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if *query == "" && fs.NArg() == 1 {
		*query = fs.Arg(0)
	}
	out, err := a.Service.Search(*query, *limit)
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, out, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) itemFields(args []string) int {
	const command = "item fields"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	out, err := a.Service.InspectFields(*item, *vault)
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, out, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) itemRead(args []string) int {
	const command = "item read"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	fieldsCSV := fs.String("fields", "", "comma-separated field labels (default: all approved fields)")
	reveal := fs.Bool("reveal", false, "confirm that secret values may enter model context")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if !*reveal {
		return a.fail(command, "usage",
			"item read returns secret values into model context; pass --reveal to confirm",
			"prefer: secret-gate exec --item <name> --field <field> --env VAR -- <cmd> (value never enters model context)")
	}
	var want []string
	if *fieldsCSV != "" {
		for _, f := range strings.Split(*fieldsCSV, ",") {
			want = append(want, strings.TrimSpace(f))
		}
	}
	out, err := a.Service.ReadFields(*item, *vault, want)
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, map[string]interface{}{
		"secret_name": *item,
		"fields":      out,
	}, &Meta{Visibility: VisibilityModelVisible, Cache: "hit"})
}
