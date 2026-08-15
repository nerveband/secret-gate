package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/daemon"
)

func init() {
	usageText["ssh"] = `Usage: secret-gate ssh --item <name> --host <user@host> [--command <cmd>]
                       [--port 22] [--vault <vault>] [--timeout 120s] [--dry-run]

SSH using a cached key item. The key goes to ssh-agent (or a temp
identity file), never into model context.

Examples:
  secret-gate ssh --item "deploy-key" --host deploy@web1.example.com --command "uptime"
  secret-gate ssh --item "deploy-key" --host deploy@web1.example.com --port 2222 --dry-run`
}

func (a *App) runSSH(args []string) int {
	const command = "ssh"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "SSH key item name")
	vault := fs.String("vault", "", "vault name")
	host := fs.String("host", "", "SSH destination (user@host)")
	remoteCmd := fs.String("command", "", "remote command to execute")
	port := fs.Int("port", 22, "SSH port")
	timeout := fs.Duration("timeout", 120*time.Second, "timeout")
	dryRun := fs.Bool("dry-run", false, "validate and preview the ssh invocation without connecting")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if *host == "" {
		return a.fail(command, "usage", "host is required", "pass --host user@host")
	}

	if *dryRun {
		values, err := a.Service.CachedFields(*item, *vault)
		if err != nil {
			return a.failErr(command, err)
		}
		fieldName, _, found := daemon.FindSSHKeyField(values)
		if !found {
			return a.fail(command, "not_found",
				fmt.Sprintf("no SSH private key found in item %q", *item),
				"available fields: "+strings.Join(core.FieldNames(values), ", "))
		}
		return a.ok(command, map[string]interface{}{
			"dry_run":     true,
			"argv":        core.BuildSSHArgs(*host, *port, *remoteCmd),
			"secret_used": *item + "/" + fieldName,
			"timeout":     timeout.String(),
		}, &Meta{Visibility: VisibilityMetadataOnly, Cache: "hit"})
	}

	out, err := a.Service.SSH(context.Background(), core.SSHRequest{
		SecretName: *item,
		Vault:      *vault,
		Host:       *host,
		Command:    *remoteCmd,
		Port:       *port,
		Timeout:    *timeout,
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
