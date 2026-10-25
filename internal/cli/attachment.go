package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
)

func init() {
	usageText["attachment exec"] = `Usage: secret-gate attachment exec --item <name> --file <name or id>
                                  (--env <VAR> | --stdin) [--vault <vault>]
                                  [--cwd <dir>] [--timeout 30s]
                                  [--shell '<command string>' | -- <cmd> [args...]]

Run a command with one approved attachment. With --env the file is written
to a mode-0600 temporary file in a private directory, its path is put in
<VAR>, and the file is deleted when the command exits. With --stdin the
content is piped to the command. Content never enters model context; exact
copies of text content are redacted from captured output.

Approve the attachment first by naming it in the request:
  secret-gate request submit --item "release keys" --fields "file:release.jks" --reason "sign the release"

Examples:
  secret-gate attachment exec --item "release keys" --file release.jks --env KEYSTORE -- ./gradlew assembleRelease
  secret-gate attachment exec --item "release keys" --file notes.txt --stdin -- shasum -a 256`
}

func (a *App) runAttachment(args []string) int {
	if len(args) == 0 || args[0] != "exec" {
		return a.fail("attachment", "usage", "attachment requires a subcommand: exec",
			"run: secret-gate attachment exec --help")
	}
	const command = "attachment exec"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	file := fs.String("file", "", "attachment name or ID, as approved")
	env := fs.String("env", "", "environment variable that receives the temporary file path")
	stdin := fs.Bool("stdin", false, "pipe the content to the command's stdin instead")
	shell := fs.String("shell", "", "run this string via sh -c instead of direct argv")
	cwd := fs.String("cwd", "", "working directory")
	timeout := fs.Duration("timeout", 30*time.Second, "command timeout")
	if code, done := a.parse(fs, command, args[1:]); done {
		return code
	}
	argv := fs.Args()
	if *shell != "" && len(argv) > 0 {
		return a.fail(command, "usage", "--shell and positional argv are mutually exclusive",
			"use either --shell '<command string>' or -- <cmd> [args...]")
	}
	if *shell == "" && len(argv) == 0 {
		return a.fail(command, "usage", "no command given",
			fmt.Sprintf("pass the command after --, e.g. attachment exec --item %q --file <name> --stdin -- shasum -a 256", *item))
	}
	out, err := a.Service.AttachmentExec(context.Background(), core.AttachmentExecRequest{
		SecretName:   *item,
		Vault:        *vault,
		File:         *file,
		PathEnv:      *env,
		Stdin:        *stdin,
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
