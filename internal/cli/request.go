package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/daemon"
)

func init() {
	usageText["request submit"] = `Usage: secret-gate request submit --item <name> --reason <why>
                                  [--vault <vault>] [--fields a,b] [--no-wait]
                                  [--timeout 15m] [--poll-interval 5s] [--dry-run]

Submit a Telegram approval request. Blocks until a terminal state unless
--no-wait is given, in which case the token is printed for later resume.

Examples:
  secret-gate request submit --item "deploy-key" --reason "deploy the api service" --fields "private key"
  secret-gate request submit --item "prod-api" --reason "rotate token" --no-wait`

	usageText["request status"] = `Usage: secret-gate request status <token>

Check a previously submitted request by token.

Examples:
  secret-gate request status tok123`

	usageText["request wait"] = `Usage: secret-gate request wait <token> [--timeout 15m] [--poll-interval 5s]

Resume waiting on a previously submitted request. On approval the item
is retrieved and cached.

Examples:
  secret-gate request wait tok123 --timeout 10m`

	usageText["request cancel"] = `Usage: secret-gate request cancel <token>

Cancel the local wait for a token. The server-side request still expires
on its own schedule.

Examples:
  secret-gate request cancel tok123`
}

func (a *App) runRequest(args []string) int {
	if len(args) == 0 {
		return a.fail("request", "usage", "request requires a subcommand: submit, status, wait, cancel",
			"run: secret-gate request submit --help")
	}
	switch args[0] {
	case "submit":
		return a.requestSubmit(args[1:])
	case "status":
		return a.requestStatus(args[1:])
	case "wait":
		return a.requestWait(args[1:])
	case "cancel":
		return a.requestCancel(args[1:])
	default:
		return a.fail("request", "usage", fmt.Sprintf("unknown request subcommand %q", args[0]),
			"valid subcommands: submit, status, wait, cancel")
	}
}

func (a *App) requestSubmit(args []string) int {
	const command = "request submit"
	fs := a.newFlagSet(command)
	item := fs.String("item", "", "item name")
	vault := fs.String("vault", "", "vault name")
	reason := fs.String("reason", "", "why access is needed (shown to the approver)")
	fieldsCSV := fs.String("fields", "", "comma-separated field labels to approve")
	noWait := fs.Bool("no-wait", false, "return the token immediately instead of blocking")
	timeout := fs.Duration("timeout", 15*time.Minute, "maximum time to wait for approval")
	pollInterval := fs.Duration("poll-interval", 5*time.Second, "interval between status polls")
	dryRun := fs.Bool("dry-run", false, "preview the request payload without submitting")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if *item == "" {
		return a.fail(command, "usage", "item name is required", "pass --item <name>")
	}
	if *reason == "" {
		return a.fail(command, "usage", "reason is required",
			"explain why you need this item so the approver can make an informed decision")
	}
	var fields []string
	if *fieldsCSV != "" {
		for _, f := range strings.Split(*fieldsCSV, ",") {
			fields = append(fields, strings.TrimSpace(f))
		}
	}

	if *dryRun {
		hostname, _ := os.Hostname()
		return a.ok(command, map[string]interface{}{
			"dry_run":     true,
			"secret_name": *item,
			"vault":       *vault,
			"reason":      *reason,
			"fields":      fields,
			"machine":     hostname,
		}, &Meta{Visibility: VisibilityMetadataOnly})
	}

	// Cache short-circuit: an already-approved item needs no new request.
	if values, err := a.Service.CachedFields(*item, *vault); err == nil {
		available := true
		for _, f := range fields {
			if _, _, ok := core.ResolveField(values, f); !ok {
				available = false
				break
			}
		}
		if available {
			return a.ok(command, map[string]interface{}{
				"status": "approved", "secret_name": *item, "cached": true,
				"fields_available": core.FieldNames(values),
			}, &Meta{Visibility: VisibilityMetadataOnly, Cache: "hit"})
		}
	}

	if a.Async == nil {
		return a.fail(command, "internal", "async proxy is not configured", "")
	}
	pending, err := a.Async.Submit(context.Background(), *item, *vault, *reason, fields, core.RequestContext{})
	if err != nil {
		return a.failErr(command, err)
	}
	entry := LedgerEntry{
		Token:       pending.Token,
		SecretName:  *item,
		Vault:       *vault,
		StatusURL:   pending.StatusURL,
		SubmittedAt: a.Now().UTC().Format(time.RFC3339),
		ExpiresAt:   pending.ExpiresAt,
		Operation:   "read",
		State:       "pending",
	}
	l, ledgerErr := OpenLedger(a.StateDir)
	if ledgerErr != nil {
		return a.fail(command, "internal", "request was submitted but local recovery state could not be opened: "+ledgerErr.Error(),
			"save the token and status URL from the approver notification")
	}
	if err := l.Put(entry); err != nil {
		return a.fail(command, "internal", "request was submitted but local recovery state could not be saved: "+err.Error(),
			"save the token and status URL from the approver notification")
	}
	if *noWait {
		if a.Admin == nil {
			return a.fail(command, "internal", "request was submitted but the local daemon is unavailable", "")
		}
		if err := a.Admin.Watch(daemon.WatchSpec{
			Token:       pending.Token,
			StatusURL:   pending.StatusURL,
			SecretName:  *item,
			Vault:       *vault,
			Fields:      fields,
			CacheTTLSec: a.Service.Config.CacheTTLSec,
			Activation:  daemon.SniffActivationSpec(),
			ExpiresAt:   pending.ExpiresAt,
			StateDir:    a.StateDir,
		}); err != nil {
			return a.fail(command, "internal", "request was submitted but background recovery could not be registered: "+err.Error(),
				"resume with: secret-gate request wait "+pending.Token)
		}
		return a.ok(command, map[string]interface{}{
			"token":          pending.Token,
			"status_url":     pending.StatusURL,
			"expires_at":     pending.ExpiresAt,
			"state":          "pending",
			"request_reused": pending.RequestReused,
			"resume":         "secret-gate request wait " + pending.Token,
			"check":          "secret-gate request status " + pending.Token,
		}, &Meta{Visibility: VisibilityMetadataOnly})
	}
	return a.waitForApproval(command, entry, *timeout, *pollInterval)
}

func (a *App) requestStatus(args []string) int {
	const command = "request status"
	fs := a.newFlagSet(command)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if fs.NArg() != 1 {
		return a.fail(command, "usage", "exactly one token argument is required",
			"usage: secret-gate request status <token>")
	}
	token := fs.Arg(0)
	entry, err := a.ledgerEntry(token)
	if err != nil {
		return a.fail(command, "internal", "cannot read request ledger: "+err.Error(), "")
	}
	if entry == nil {
		return okOrNotFound(a, command, token)
	}
	if code, done := a.terminalRequest(command, entry); done {
		return code
	}
	st, err := a.Async.Status(context.Background(), entry.StatusURL)
	if err != nil {
		if core.CodeOf(err) == core.ErrNotFound {
			if result, ok := a.reconcileCached(entry); ok {
				return a.ok(command, result, &Meta{Visibility: VisibilityMetadataOnly, Cache: "hit"})
			}
			a.ledgerSetState(token, "expired")
		}
		return a.failErr(command, err)
	}
	if st.Status == "denied" || st.Status == "expired" || st.Status == "approved" {
		a.ledgerSetState(token, st.Status)
	}
	return a.ok(command, map[string]interface{}{
		"token":       token,
		"secret_name": entry.SecretName,
		"status":      st.Status,
	}, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) requestWait(args []string) int {
	const command = "request wait"
	fs := a.newFlagSet(command)
	timeout := fs.Duration("timeout", 15*time.Minute, "maximum time to wait for approval")
	pollInterval := fs.Duration("poll-interval", 5*time.Second, "interval between status polls")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if fs.NArg() != 1 {
		return a.fail(command, "usage", "exactly one token argument is required",
			"usage: secret-gate request wait <token>")
	}
	token := fs.Arg(0)
	entry, err := a.ledgerEntry(token)
	if err != nil {
		return a.fail(command, "internal", "cannot read request ledger: "+err.Error(), "")
	}
	if entry == nil {
		return okOrNotFound(a, command, token)
	}
	return a.waitForApproval(command, *entry, *timeout, *pollInterval)
}

func (a *App) requestCancel(args []string) int {
	const command = "request cancel"
	fs := a.newFlagSet(command)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if fs.NArg() != 1 {
		return a.fail(command, "usage", "exactly one token argument is required",
			"usage: secret-gate request cancel <token>")
	}
	token := fs.Arg(0)
	l, err := OpenLedger(a.StateDir)
	if err != nil {
		return a.fail(command, "internal", "cannot open request ledger: "+err.Error(), "")
	}
	if _, ok, err := l.Get(token); err != nil {
		return a.fail(command, "internal", "cannot read request ledger: "+err.Error(), "")
	} else if !ok {
		return a.fail(command, "not_found", fmt.Sprintf("unknown token %q", token),
			"tokens are recorded by request submit on this machine")
	}
	if a.Admin != nil {
		if err := a.Admin.Unwatch(token); err != nil {
			return a.fail(command, "internal", "could not durably cancel background recovery: "+err.Error(), "")
		}
	}
	if err := l.SetState(token, "cancelled"); err != nil {
		return a.fail(command, "internal", "background recovery was cancelled but request state could not be updated: "+err.Error(), "")
	}
	return a.ok(command, map[string]interface{}{
		"token":   token,
		"state":   "cancelled",
		"message": "local wait cancelled; the server-side request still expires on its own",
	}, &Meta{Visibility: VisibilityMetadataOnly})
}

// ledgerEntry loads a token's entry. A nil entry with nil error means the
// token is unknown; malformed or unreadable state is preserved as an error.
func (a *App) ledgerEntry(token string) (*LedgerEntry, error) {
	l, err := OpenLedger(a.StateDir)
	if err != nil {
		return nil, err
	}
	entry, ok, err := l.Get(token)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return entry, nil
}

func okOrNotFound(a *App, command, token string) int {
	return a.fail(command, "not_found", fmt.Sprintf("unknown token %q", token),
		"tokens are recorded by request submit on this machine; list the ledger at $SECRET_GATE_STATE_DIR/requests.json")
}

func (a *App) ledgerSetState(token, state string) {
	if l, err := OpenLedger(a.StateDir); err == nil {
		_ = l.SetState(token, state)
	}
}

// waitForApproval polls until a terminal state or timeout.
func (a *App) waitForApproval(command string, entry LedgerEntry, timeout, poll time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		if latest, ledgerErr := a.ledgerEntry(entry.Token); ledgerErr != nil {
			return a.fail(command, "internal", "cannot read request ledger: "+ledgerErr.Error(), "")
		} else if latest != nil {
			entry = *latest
			if code, done := a.terminalRequest(command, latest); done {
				return code
			}
		}
		st, err := a.Async.StatusWait(context.Background(), entry.StatusURL, 25)
		if err == nil {
			switch st.Status {
			case "approved":
				if entry.Operation == "write" {
					time.Sleep(poll)
					continue
				}
				res, retrieveErr := a.Async.Retrieve(context.Background(), st.SecretURL, entry.SecretName, entry.Vault)
				if retrieveErr != nil {
					if core.CodeOf(retrieveErr) == core.ErrNotFound {
						if result, ok := a.reconcileCached(&entry); ok {
							return a.ok(command, result, &Meta{Visibility: VisibilityMetadataOnly, Cache: "hit"})
						}
					}
					return a.failErr(command, retrieveErr)
				}
				a.ledgerSetState(entry.Token, "approved")
				if !a.Quiet {
					fmt.Fprintln(a.Stderr, "approved")
				}
				return a.ok(command, res, &Meta{Visibility: VisibilityMetadataOnly})
			case "denied":
				a.ledgerSetState(entry.Token, "denied")
				return a.fail(command, "denied", "request was denied by the approver", "")
			case "expired":
				a.ledgerSetState(entry.Token, "expired")
				return a.fail(command, "expired", "request expired before approval",
					"submit a new request with: secret-gate request submit")
			}
			if !a.Quiet {
				fmt.Fprint(a.Stderr, ".")
			}
		} else if core.CodeOf(err) == core.ErrNotFound {
			if latest, ledgerErr := a.ledgerEntry(entry.Token); ledgerErr == nil && latest != nil {
				entry = *latest
				if code, done := a.terminalRequest(command, latest); done {
					return code
				}
			}
			if entry.Operation == "write" {
				time.Sleep(poll)
				continue
			}
			if result, ok := a.reconcileCached(&entry); ok {
				return a.ok(command, result, &Meta{Visibility: VisibilityMetadataOnly, Cache: "hit"})
			}
			a.ledgerSetState(entry.Token, "expired")
			return a.fail(command, "expired", "request is no longer available and no cached result exists",
				"submit a new request")
		}
		if time.Now().After(deadline) {
			return a.fail(command, "timeout", "timed out waiting for approval",
				"resume with: secret-gate request wait "+entry.Token)
		}
		if err != nil {
			time.Sleep(poll)
		}
	}
}

func (a *App) terminalRequest(command string, entry *LedgerEntry) (int, bool) {
	switch entry.State {
	case "completed":
		return a.ok(command, map[string]interface{}{
			"token": entry.Token, "secret_name": entry.SecretName, "status": "completed",
			"message": "1Password item written after approval.",
		}, &Meta{Visibility: VisibilityMetadataOnly}), true
	case "denied":
		return a.fail(command, "denied", "request was denied by the approver", ""), true
	case "expired":
		return a.fail(command, "expired", "request expired before approval", "submit a new request"), true
	case "failed":
		return a.fail(command, "internal", "approved request failed during background completion", "submit a new request"), true
	case "cancelled":
		return a.fail(command, "not_found", "local request tracking was cancelled", "submit a new request"), true
	default:
		return 0, false
	}
}

func (a *App) reconcileCached(entry *LedgerEntry) (*core.RequestResult, bool) {
	fields, err := a.Service.CachedFields(entry.SecretName, entry.Vault)
	if err != nil {
		return nil, false
	}
	a.ledgerSetState(entry.Token, "approved")
	return &core.RequestResult{
		Status:          "approved",
		SecretName:      entry.SecretName,
		Cached:          true,
		FieldsAvailable: core.FieldNames(fields),
		Message:         "Secret approved and cached by the background watcher.",
	}, true
}
