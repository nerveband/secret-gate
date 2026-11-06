package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
)

func init() {
	usageText["exec"] = `Usage: secret-gate exec --item <name> --field <label> --env <VAR>
                        [--vault <vault>] [--cwd <dir>] [--timeout 30s] [--dry-run]
                        [--shell '<command string>' | -- <cmd> [args...]]

Run a command with one cached secret field injected as an environment
variable. The value never enters model context; exact occurrences in the
child's output are replaced with [REDACTED:item/field]. Argv after -- is
passed directly to the OS (no shell); --shell opts into 'sh -c'.

Examples:
  secret-gate exec --item "prod-api" --field credential --env API_KEY -- curl -s -H "Authorization: Bearer $API_KEY" https://api.example.com/v1/me
  secret-gate exec --item "prod-api" --field credential --env API_KEY --shell 'curl -s https://api.example.com | jq .status'
  secret-gate exec --item "prod-api" --field credential --env API_KEY --dry-run -- deploy.sh`
}

func (a *App) runExec(args []string) int {
	const command = "exec"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	field := fs.String("field", "", "field label to inject")
	env := fs.String("env", "", "environment variable name for the injected value")
	shell := fs.String("shell", "", "run this string via sh -c instead of direct argv")
	cwd := fs.String("cwd", "", "working directory")
	timeout := fs.Duration("timeout", 30*time.Second, "command timeout")
	dryRun := fs.Bool("dry-run", false, "validate and describe what would run without executing")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	argv := fs.Args()
	if *shell != "" && len(argv) > 0 {
		return a.fail(command, "usage", "--shell and positional argv are mutually exclusive",
			"use either --shell '<command string>' or -- <cmd> [args...]")
	}
	if *shell == "" && len(argv) == 0 {
		return a.fail(command, "usage", "no command given",
			"pass the command after --, e.g. exec --item prod-api --field credential --env API_KEY -- curl -s https://api.example.com")
	}

	if *dryRun {
		values, err := a.Service.CachedFields(*item, *vault)
		if err != nil {
			return a.failErr(command, err)
		}
		actual, _, ok := core.ResolveField(values, *field)
		if !ok {
			if err := core.FieldAmbiguity(values, *field); err != nil {
				return a.failErr(command, err)
			}
			return a.fail(command, "not_found",
				fmt.Sprintf("field %q not found in item %q", *field, *item),
				"available fields: "+strings.Join(core.FieldNames(values), ", "))
		}
		return a.ok(command, map[string]interface{}{
			"dry_run":     true,
			"argv":        argv,
			"shell":       *shell,
			"env_var":     *env,
			"secret_used": *item + "/" + actual,
			"cwd":         *cwd,
			"timeout":     timeout.String(),
		}, &Meta{Visibility: VisibilityMetadataOnly, Cache: "hit"})
	}

	out, err := a.Service.Exec(context.Background(), core.ExecRequest{
		SecretName:   *item,
		Vault:        *vault,
		Field:        *field,
		EnvVar:       *env,
		Argv:         argv,
		ShellCommand: *shell,
		WorkingDir:   *cwd,
		Timeout:      *timeout,
	})
	if err != nil {
		return a.failErr(command, err)
	}
	exit := ExitOK
	if out.ExitCode != 0 {
		exit = ExitFailure
	}
	return a.okWithExit(command, out, &Meta{Visibility: VisibilityProcessOnly, Cache: "hit"}, exit)
}
