package cli

import (
	"context"
	"flag"
	"fmt"

	"github.com/nerveband/secret-gate/internal/core"
	"github.com/nerveband/secret-gate/internal/passkey"
)

func init() {
	const target = `The browser must expose a Chrome DevTools endpoint on this machine, for
example agent-browser ("agent-browser get cdp-url") or Chrome started with
--remote-debugging-port. Secret Gate opens its own DevTools session to the
tab, so the key goes from Secret Gate to the browser and never through the
agent. Pick the tab with --page-url (URL substring) or --target (target ID);
with one open tab neither is needed.`
	usageText["passkey arm"] = `Usage: secret-gate passkey arm --cdp <endpoint> [--page-url <substring>] [--target <id>] [--hold 10m]

Add an empty virtual authenticator to the tab before the site creates a
passkey. Then register on the site, and store the result with
"passkey register".

` + target + `

Example:
  secret-gate passkey arm --cdp "$(agent-browser get cdp-url)" --page-url webauthn.io`
	usageText["passkey register"] = `Usage: secret-gate passkey register --session <id> --item <name> --vault <vault> --reason <why>
                                   [--category SECURE_NOTE] [--no-wait]

Store the passkey the site registered on an armed session as a new
1Password item (one Telegram approval). The private key goes from the
browser to the server without being printed. The authenticator stays in
the tab so a sign-in can be tested right away.

Example:
  secret-gate passkey register --session 3f2a9c1d --item "webauthn.io passkey" --vault "AI Agents" --reason "save the agent's passkey"`
	usageText["passkey load"] = `Usage: secret-gate passkey load --item <name> --cdp <endpoint> [--vault <vault>]
                               [--page-url <substring>] [--target <id>] [--hold 10m]

Put an approved passkey item into the tab as a virtual authenticator so the
agent can sign in. Approve the item first with "request submit". The
authenticator is removed after --hold (max 30m) or "passkey release". Its
sign count starts at the current Unix time, so it always exceeds the count
the site last saw without a 1Password write.

` + target + `

Example:
  secret-gate request submit --item "webauthn.io passkey" --vault "AI Agents" --reason "sign in to webauthn.io"
  secret-gate passkey load --item "webauthn.io passkey" --vault "AI Agents" --cdp "$(agent-browser get cdp-url)" --page-url webauthn.io`
	usageText["passkey release"] = `Usage: secret-gate passkey release --session <id> [--save-counter --reason <why>] [--no-wait]

Remove the authenticator from the tab and close the DevTools session.
--save-counter writes the final sign count to the item; right after
"passkey register" this rides the same-item follow-up approval.

Example:
  secret-gate passkey release --session 3f2a9c1d --save-counter --reason "store the sign count after the first sign-in"`
	usageText["passkey list"] = `Usage: secret-gate passkey list

List authenticators the local daemon holds (session, tab, RP ID, expiry).
Never prints key material.

Example:
  secret-gate passkey list`
}

func (a *App) runPasskey(args []string) int {
	if len(args) == 0 {
		return a.fail("passkey", "usage", "passkey requires a subcommand: arm, register, load, release, list",
			"run: secret-gate passkey arm --help")
	}
	switch args[0] {
	case "arm":
		return a.passkeyArm(args[1:])
	case "register":
		return a.passkeyRegister(args[1:])
	case "load":
		return a.passkeyLoad(args[1:])
	case "release":
		return a.passkeyRelease(args[1:])
	case "list":
		return a.passkeyList(args[1:])
	default:
		return a.fail("passkey", "usage", fmt.Sprintf("unknown passkey subcommand %q", args[0]),
			"valid subcommands: arm, register, load, release, list")
	}
}

func targetFlags(fs *flag.FlagSet) func() core.PasskeyTarget {
	cdp := fs.String("cdp", "", "Chrome DevTools endpoint on this machine (ws:// URL, http://host:port, or port)")
	pageURL := fs.String("page-url", "", "substring of the tab URL")
	target := fs.String("target", "", "DevTools target ID of the tab")
	hold := fs.Duration("hold", passkey.DefaultHold, "how long the authenticator stays in the tab (max 30m)")
	return func() core.PasskeyTarget {
		return core.PasskeyTarget{Endpoint: *cdp, PageURL: *pageURL, TargetID: *target, Hold: *hold}
	}
}

func (a *App) passkeyArm(args []string) int {
	const command = "passkey arm"
	fs := a.newFlagSet(command)
	target := targetFlags(fs)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	info, err := a.Service.PasskeyArm(target())
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, map[string]interface{}{
		"passkey": info,
		"next":    "register the passkey on the site, then: secret-gate passkey register --session " + info.Session + " --item <name> --vault <vault> --reason <why>",
	}, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) passkeyRegister(args []string) int {
	const command = "passkey register"
	fs := a.newFlagSet(command)
	session := fs.String("session", "", "session ID from passkey arm")
	item := fs.String("item", "", "title of the new 1Password item")
	vault := fs.String("vault", "", "explicit vault name or ID")
	reason := fs.String("reason", "", "why this passkey is stored (shown to the approver)")
	category := fs.String("category", "", "1Password category (default SECURE_NOTE)")
	noWait := fs.Bool("no-wait", false, "return a token; the local daemon finishes the write after approval")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if *reason == "" {
		return a.fail(command, "usage", "reason is required", "pass --reason <why>")
	}
	info, write, err := a.Service.PasskeyCollect(*session, *item, *vault, *category)
	if err != nil {
		return a.failErr(command, err)
	}
	items := []core.ItemWrite{write}
	if *noWait {
		return a.submitWriteNoWait(command, *vault, *reason, items)
	}
	out, err := a.Service.WriteItems(context.Background(), *vault, *reason, items, core.RequestContext{})
	if err != nil {
		return a.failErr(command, err)
	}
	switch out.Status {
	case "denied", "expired", "timeout":
		return a.fail(command, out.Status, out.Message, "")
	}
	return a.ok(command, map[string]interface{}{"passkey": info, "write": out}, &Meta{Visibility: VisibilityValueInput})
}

func (a *App) passkeyLoad(args []string) int {
	const command = "passkey load"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "approved passkey item")
	vault := fs.String("vault", "", "vault name (needed for --save-counter on release)")
	target := targetFlags(fs)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	info, err := a.Service.PasskeyLoad(*item, *vault, target())
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, map[string]interface{}{
		"passkey": info,
		"next":    "sign in on the site, then: secret-gate passkey release --session " + info.Session,
	}, &Meta{Visibility: VisibilityProcessOnly, Cache: "hit"})
}

func (a *App) passkeyRelease(args []string) int {
	const command = "passkey release"
	fs := a.newFlagSet(command)
	session := fs.String("session", "", "session ID from passkey arm or load")
	saveCounter := fs.Bool("save-counter", false, "write the final sign count to the item")
	reason := fs.String("reason", "", "why the counter is written (with --save-counter)")
	noWait := fs.Bool("no-wait", false, "with --save-counter: return a token; the daemon finishes the write")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if *saveCounter && *reason == "" {
		return a.fail(command, "usage", "--save-counter needs --reason", "pass --reason <why>")
	}
	info, write, err := a.Service.PasskeyRelease(*session, *saveCounter)
	if err != nil {
		return a.failErr(command, err)
	}
	if write == nil {
		return a.ok(command, map[string]interface{}{"passkey": info, "released": true}, &Meta{Visibility: VisibilityMetadataOnly})
	}
	items := []core.ItemWrite{*write}
	if *noWait {
		return a.submitWriteNoWait(command, info.Vault, *reason, items)
	}
	out, err := a.Service.WriteItems(context.Background(), info.Vault, *reason, items, core.RequestContext{})
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, map[string]interface{}{"passkey": info, "released": true, "write": out}, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) passkeyList(args []string) int {
	const command = "passkey list"
	fs := a.newFlagSet(command)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	list, err := a.Service.PasskeyList()
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, map[string]interface{}{"passkeys": list, "count": len(list)}, &Meta{Visibility: VisibilityMetadataOnly})
}
