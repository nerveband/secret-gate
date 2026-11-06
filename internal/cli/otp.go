package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/nerveband/secret-gate/internal/core"
)

func init() {
	usageText["otp show"] = `Usage: secret-gate otp show --item <name> [--vault <vault>] [--field <label>] --reveal

Print the current OTP/MFA/TOTP/2FA code from an approved item. The code
enters model context, so --reveal is required. Prefer 'otp exec' when a
command can consume the code directly.

Examples:
  secret-gate otp show --item "github" --reveal`

	usageText["otp exec"] = `Usage: secret-gate otp exec --item <name> --env <VAR> [--vault <vault>]
                            [--field <label>] [--timeout 30s]
                            [--shell '<command string>' | -- <cmd> [args...]]

Run a command with the current OTP code injected as an environment
variable. The code never enters model context.

Examples:
  secret-gate otp exec --item "github" --env OTP_CODE -- gh auth login --with-token
  secret-gate otp exec --item "github" --env OTP_CODE --shell 'login-helper --otp "$OTP_CODE"'`
}

func (a *App) runOTP(args []string) int {
	if len(args) == 0 {
		return a.fail("otp", "usage", "otp requires a subcommand: show, exec",
			"run: secret-gate otp show --help")
	}
	switch args[0] {
	case "show":
		return a.otpShow(args[1:])
	case "exec":
		return a.otpExec(args[1:])
	default:
		return a.fail("otp", "usage", fmt.Sprintf("unknown otp subcommand %q", args[0]),
			"valid subcommands: show, exec")
	}
}

func (a *App) otpShow(args []string) int {
	const command = "otp show"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	field := fs.String("field", "", "OTP field label (mfa/otp/totp/2fa aliases accepted)")
	reveal := fs.Bool("reveal", false, "confirm that the code may enter model context")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if !*reveal {
		return a.fail(command, "usage",
			"otp show returns the code into model context; pass --reveal to confirm",
			"prefer: secret-gate otp exec --item <name> --env OTP_CODE -- <cmd>")
	}
	// Use the injected clock so codes are deterministic under test.
	a.Service.Now = a.Now
	out, err := a.Service.GetOTP(*item, *vault, *field)
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, out, &Meta{Visibility: VisibilityModelVisible, Cache: "hit"})
}

func (a *App) otpExec(args []string) int {
	const command = "otp exec"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	field := fs.String("field", "", "OTP field label")
	env := fs.String("env", "", "environment variable name for the code")
	shell := fs.String("shell", "", "run this string via sh -c instead of direct argv")
	timeout := fs.Duration("timeout", 30*time.Second, "command timeout")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if *env == "" {
		return a.fail(command, "usage", "env var name is required", "pass --env <NAME>")
	}
	argv := fs.Args()
	if *shell != "" && len(argv) > 0 {
		return a.fail(command, "usage", "--shell and positional argv are mutually exclusive",
			"use either --shell '<command string>' or -- <cmd> [args...]")
	}
	if *shell == "" && len(argv) == 0 {
		return a.fail(command, "usage", "no command given",
			"pass the command after --, e.g. otp exec --item github --env OTP_CODE -- gh auth login --with-token")
	}

	a.Service.Now = a.Now
	res, err := a.Service.GetOTP(*item, *vault, *field)
	if err != nil {
		return a.failErr(command, err)
	}
	redactor := core.NewRedactor()
	redactor.Add(res.Code, *item+"/otp")
	out, err := core.ExecCommand(context.Background(), core.ExecSpec{
		Argv:         argv,
		ShellCommand: *shell,
		Env:          map[string]string{*env: res.Code},
		Timeout:      *timeout,
		Redactor:     redactor,
	})
	if err != nil {
		return a.failErr(command, err)
	}
	exit := ExitOK
	if out.ExitCode != 0 {
		exit = ExitFailure
	}
	return a.okWithExit(command, map[string]interface{}{
		"exit_code":   out.ExitCode,
		"stdout":      out.Stdout,
		"stderr":      out.Stderr,
		"secret_used": res.SecretUsed,
		"expires_at":  res.ExpiresAt,
	}, &Meta{Visibility: VisibilityProcessOnly, Cache: "hit"}, exit)
}
