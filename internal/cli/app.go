package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
)

// App wires the CLI face. All fields are injected so tests can run the
// full command surface against fakes.
type App struct {
	Version   string
	ServerURL string
	Service   *core.Service
	Async     core.AsyncProxyClient
	Admin     core.AdminDaemonClient
	StateDir  string
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Quiet     bool
	Now       func() time.Time

	started time.Time
}

// usageText holds human help (with realistic examples) per command.
// The machine-readable equivalents come from Manifest / schema.
var usageText = map[string]string{}

const rootHelp = `secret-gate — approval-gated 1Password access for agents (v%s)

Usage: secret-gate <noun> <verb> [flags]

Commands:
  item search        Find items by name (metadata only)
  item fields        List an item's field labels and types (no values)
  item read          Read cached field values into model context (requires --reveal)
  exec               Run a command with a secret injected as an env var (value never printed)
  attachment exec    Run a command with an approved attachment as a temp file or stdin
  ssh                SSH using a cached key item
  otp show           Print the current OTP code (requires --reveal)
  otp exec           Run a command with the current OTP code as an env var
  passkey arm        Add an empty virtual authenticator to a browser tab (CDP)
  passkey register   Store the passkey a site registered as a new item (Telegram-approved)
  passkey load       Put an approved passkey item into a browser tab for sign-in
  passkey release    Remove the authenticator; optionally save the sign count
  passkey list       List authenticators the daemon holds
  browser fill       Type approved values (card number, CVV) into a browser form over DevTools
  write create       Create a 1Password item (values via --stdin, Telegram-approved)
  write update       Update a 1Password item (values via --stdin, Telegram-approved)
  write batch        Create or update up to 10 items behind one Telegram approval
  request submit     Submit an approval request (--no-wait for async)
  request status     Check a submitted request by token
  request wait       Resume waiting on a submitted request
  request cancel     Cancel the local wait for a token
  daemon status      Cache daemon status
  daemon start       Ensure the cache daemon is running
  daemon flush       Flush the cache (dry-run by default; --commit to apply)
  daemon stop        Stop the cache daemon
  agent-context      Machine-readable orientation for agents
  schema             Full machine-readable command manifest
  version            Print version
  mcp                Run as an MCP stdio server

Global flags: --json (default output; accepted for compatibility), --quiet

Exit codes: 0 ok · 1 internal/child failure · 2 usage · 3 denied · 4 expired/timeout · 5 network · 6 not found

Output: one JSON envelope per invocation on stdout; errors as JSON on stderr.
Run 'secret-gate <command> --help' for examples, or 'secret-gate schema' for the manifest.
`

// Run dispatches argv and returns the process exit code.
func (a *App) Run(args []string) int {
	a.started = time.Now()
	if a.Now == nil {
		a.Now = time.Now
	}

	rest := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--quiet", "-q":
			a.Quiet = true
		case "--json":
			// JSON envelopes are the default; flag accepted for compatibility.
		default:
			rest = append(rest, arg)
		}
	}
	args = rest

	if len(args) == 0 {
		fmt.Fprintf(a.Stderr, rootHelp, a.Version)
		return ExitUsage
	}

	switch args[0] {
	case "version":
		return a.ok("version", map[string]string{
			"version": a.Version, "schema_version": SchemaVersion,
		}, &Meta{Visibility: VisibilityMetadataOnly})
	case "item":
		return a.runItem(args[1:])
	case "exec":
		return a.runExec(args[1:])
	case "attachment":
		return a.runAttachment(args[1:])
	case "passkey":
		return a.runPasskey(args[1:])
	case "browser":
		return a.runBrowser(args[1:])
	case "ssh":
		return a.runSSH(args[1:])
	case "otp":
		return a.runOTP(args[1:])
	case "write":
		return a.runWrite(args[1:])
	case "request":
		return a.runRequest(args[1:])
	case "daemon":
		return a.runDaemon(args[1:])
	case "agent-context":
		return a.runAgentContext()
	case "schema":
		return a.runSchema()
	case "help", "--help", "-h":
		fmt.Fprintf(a.Stdout, rootHelp, a.Version)
		return ExitOK
	default:
		return a.fail("cli", "usage", fmt.Sprintf("unknown command %q", args[0]), "run: secret-gate --help")
	}
}

// --- envelope helpers ---

func (a *App) ok(command string, data interface{}, meta *Meta) int {
	return a.okWithExit(command, data, meta, ExitOK)
}

// okWithExit writes a success envelope but returns a custom exit code
// (used by exec/ssh to propagate child failure as exit 1).
func (a *App) okWithExit(command string, data interface{}, meta *Meta, exit int) int {
	if meta != nil {
		meta.DurationMS = time.Since(a.started).Milliseconds()
	}
	_ = WriteResult(a.Stdout, command, data, meta)
	return exit
}

func (a *App) fail(command, code, message, hint string) int {
	_ = WriteError(a.Stderr, command, code, message, hint)
	return ExitCodeFor(code)
}

func (a *App) failErr(command string, err error) int {
	return a.fail(command, string(core.CodeOf(err)), core.MessageOf(err), core.HintOf(err))
}

// --- flag helpers ---

func (a *App) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

type boolFlag interface {
	flag.Value
	IsBoolFlag() bool
}

func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags []string
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i:]...)
			break
		}
		if len(arg) > 1 && (arg[0] == '-' || strings.HasPrefix(arg, "--")) {
			flags = append(flags, arg)
			name := strings.TrimLeft(arg, "-")
			if eq := strings.Index(name, "="); eq != -1 {
				name = name[:eq]
			} else {
				fl := fs.Lookup(name)
				if fl != nil {
					if _, isBool := fl.Value.(boolFlag); !isBool {
						if i+1 < len(args) {
							i++
							flags = append(flags, args[i])
						}
					}
				}
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

// parse converts flag errors into structured usage errors. The bool
// result is true when the caller must return the int immediately.
func (a *App) parse(fs *flag.FlagSet, command string, args []string) (int, bool) {
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return a.helpFor(command), true
		}
		return a.fail(command, "usage", err.Error(), "run: secret-gate "+command+" --help"), true
	}
	return 0, false
}

func (a *App) helpFor(command string) int {
	text, ok := usageText[command]
	if !ok {
		text = "secret-gate " + command
	}
	fmt.Fprintln(a.Stdout, text)
	return ExitOK
}

