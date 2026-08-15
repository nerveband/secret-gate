package cli

// FlagSpec describes one flag in the machine-readable manifest.
type FlagSpec struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Default  string `json:"default,omitempty"`
	Summary  string `json:"summary"`
	Required bool   `json:"required,omitempty"`
}

// CommandSpec describes one command with safety metadata.
type CommandSpec struct {
	Name           string     `json:"name"`
	Summary        string     `json:"summary"`
	Visibility     string     `json:"visibility"`
	ReadOnly       bool       `json:"readonly"`
	Destructive    bool       `json:"destructive"`
	Idempotent     bool       `json:"idempotent"`
	SupportsDryRun bool       `json:"supports_dry_run"`
	Flags          []FlagSpec `json:"flags,omitempty"`
	Examples       []string   `json:"examples,omitempty"`
}

// ExitCodeTable documents the frozen exit codes.
func ExitCodeTable() map[string]string {
	return map[string]string{
		"0": "success",
		"1": "internal error, or child process exited non-zero (see data.exit_code)",
		"2": "usage or validation error",
		"3": "approval denied",
		"4": "approval expired or wait timed out",
		"5": "network or server error",
		"6": "item, field, token, or cache entry not found",
	}
}

func flagItem() FlagSpec {
	return FlagSpec{Name: "item", Type: "string", Summary: "item name", Required: true}
}
func flagVault() FlagSpec {
	return FlagSpec{Name: "vault", Type: "string", Summary: "vault name"}
}

// Manifest returns the full command manifest. TestManifestVocabulary,
// TestManifestSafetyMetadata, and TestManifestMatchesRouterAndHelp keep
// it mechanically in sync with the router, help text, and vocabulary.
func Manifest() []CommandSpec {
	return []CommandSpec{
		{Name: "item search", Summary: "Find items by name (no values)", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Flags: []FlagSpec{
				{Name: "query", Type: "string", Summary: "search query", Required: true},
				{Name: "limit", Type: "int", Default: "10", Summary: "maximum number of results"},
			},
			Examples: []string{`secret-gate item search --query "deploy"`}},
		{Name: "item fields", Summary: "List an item's field labels and types (no values)", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Flags:    []FlagSpec{flagItem(), flagVault()},
			Examples: []string{`secret-gate item fields --item "deploy-key"`}},
		{Name: "item read", Summary: "Read cached field values into model context (requires --reveal)", Visibility: VisibilityModelVisible,
			ReadOnly: true, Idempotent: true,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "fields", Type: "csv", Summary: "comma-separated field labels"},
				{Name: "reveal", Type: "bool", Summary: "confirm values may enter model context", Required: true}},
			Examples: []string{`secret-gate item read --item "wifi-guest" --fields "note" --reveal`}},
		{Name: "exec", Summary: "Run a command with a secret injected as an env var (value never printed)", Visibility: VisibilityProcessOnly,
			SupportsDryRun: true, Idempotent: false,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "field", Type: "string", Summary: "field label to inject", Required: true},
				{Name: "env", Type: "string", Summary: "environment variable name", Required: true},
				{Name: "shell", Type: "string", Summary: "opt-in: run string via sh -c"},
				{Name: "cwd", Type: "string", Summary: "working directory"},
				{Name: "timeout", Type: "duration", Default: "30s", Summary: "command timeout"},
				{Name: "dry-run", Type: "bool", Summary: "describe without executing"}},
			Examples: []string{`secret-gate exec --item "prod-api" --field credential --env API_KEY -- curl -s https://api.example.com/v1/me`}},
		{Name: "ssh", Summary: "SSH using a cached key item", Visibility: VisibilityProcessOnly,
			SupportsDryRun: true,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "host", Type: "string", Summary: "SSH destination user@host", Required: true},
				{Name: "command", Type: "string", Summary: "remote command"},
				{Name: "port", Type: "int", Default: "22", Summary: "SSH port"},
				{Name: "timeout", Type: "duration", Default: "120s", Summary: "timeout"},
				{Name: "dry-run", Type: "bool", Summary: "preview the ssh argv without connecting"}},
			Examples: []string{`secret-gate ssh --item "deploy-key" --host deploy@web1.example.com --command "uptime"`}},
		{Name: "otp show", Summary: "Print the current OTP code (requires --reveal)", Visibility: VisibilityModelVisible,
			ReadOnly: true, Idempotent: true,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "field", Type: "string", Summary: "OTP field label (aliases: mfa/otp/totp/2fa)"},
				{Name: "reveal", Type: "bool", Summary: "confirm the code may enter model context", Required: true}},
			Examples: []string{`secret-gate otp show --item "github" --reveal`}},
		{Name: "otp exec", Summary: "Run a command with the current OTP code as an env var", Visibility: VisibilityProcessOnly,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "field", Type: "string", Summary: "OTP field label"},
				{Name: "env", Type: "string", Summary: "environment variable name", Required: true},
				{Name: "shell", Type: "string", Summary: "opt-in: run string via sh -c"},
				{Name: "timeout", Type: "duration", Default: "30s", Summary: "command timeout"}},
			Examples: []string{`secret-gate otp exec --item "github" --env OTP_CODE -- gh auth login --with-token`}},
		{Name: "write create", Summary: "Create a 1Password item after approval (values via --stdin)", Visibility: VisibilityValueInput,
			SupportsDryRun: true, Idempotent: false,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "reason", Type: "string", Summary: "why this write is needed", Required: true},
				{Name: "category", Type: "string", Default: "SECURE_NOTE", Summary: "1Password category"},
				{Name: "stdin", Type: "bool", Summary: "read field values as JSON from stdin", Required: true},
				{Name: "dry-run", Type: "bool", Summary: "preview labels without submitting"}},
			Examples: []string{`echo '{"fields":{"credential":"<value>"}}' | secret-gate write create --item "ci-token" --vault "Infra" --reason "store the new CI token" --stdin`}},
		{Name: "write update", Summary: "Update a 1Password item after approval (values via --stdin)", Visibility: VisibilityValueInput,
			SupportsDryRun: true, Idempotent: true,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "reason", Type: "string", Summary: "why this write is needed", Required: true},
				{Name: "stdin", Type: "bool", Summary: "read field values as JSON from stdin", Required: true},
				{Name: "dry-run", Type: "bool", Summary: "preview labels without submitting"}},
			Examples: []string{`echo '{"fields":{"credential":"<value>"}}' | secret-gate write update --item "ci-token" --vault "Infra" --reason "rotate token" --stdin`}},
		{Name: "request submit", Summary: "Submit a Telegram approval request", Visibility: VisibilityMetadataOnly,
			SupportsDryRun: true, Idempotent: true,
			Flags: []FlagSpec{flagItem(), flagVault(),
				{Name: "reason", Type: "string", Summary: "why access is needed", Required: true},
				{Name: "fields", Type: "csv", Summary: "field labels to approve"},
				{Name: "no-wait", Type: "bool", Summary: "return the token immediately"},
				{Name: "timeout", Type: "duration", Default: "15m", Summary: "maximum wait"},
				{Name: "poll-interval", Type: "duration", Default: "5s", Summary: "status poll interval"},
				{Name: "dry-run", Type: "bool", Summary: "preview the request payload"}},
			Examples: []string{`secret-gate request submit --item "deploy-key" --reason "deploy the api service" --no-wait`}},
		{Name: "request status", Summary: "Check a submitted request by token", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Examples: []string{`secret-gate request status tok123`}},
		{Name: "request wait", Summary: "Resume waiting on a submitted request", Visibility: VisibilityMetadataOnly,
			Idempotent: true,
			Flags: []FlagSpec{
				{Name: "timeout", Type: "duration", Default: "15m", Summary: "maximum wait"},
				{Name: "poll-interval", Type: "duration", Default: "5s", Summary: "status poll interval"}},
			Examples: []string{`secret-gate request wait tok123 --timeout 10m`}},
		{Name: "request cancel", Summary: "Cancel the local wait for a token", Visibility: VisibilityMetadataOnly,
			Idempotent: true,
			Examples:   []string{`secret-gate request cancel tok123`}},
		{Name: "daemon status", Summary: "Cache daemon status", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Examples: []string{`secret-gate daemon status`}},
		{Name: "daemon start", Summary: "Ensure the cache daemon is running", Visibility: VisibilityMetadataOnly,
			Idempotent: true,
			Examples:   []string{`secret-gate daemon start`}},
		{Name: "daemon flush", Summary: "Flush the cache (dry-run by default, --commit to apply)", Visibility: VisibilityMetadataOnly,
			Destructive: true, SupportsDryRun: true, Idempotent: true,
			Flags:    []FlagSpec{{Name: "commit", Type: "bool", Summary: "actually flush"}},
			Examples: []string{`secret-gate daemon flush`, `secret-gate daemon flush --commit`}},
		{Name: "daemon stop", Summary: "Stop the cache daemon", Visibility: VisibilityMetadataOnly,
			Idempotent: true,
			Examples:   []string{`secret-gate daemon stop`}},
		{Name: "agent-context", Summary: "Machine-readable orientation for agents", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Examples: []string{`secret-gate agent-context --json`}},
		{Name: "schema", Summary: "Full machine-readable command manifest", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Examples: []string{`secret-gate schema`}},
		{Name: "version", Summary: "Print version", Visibility: VisibilityMetadataOnly,
			ReadOnly: true, Idempotent: true,
			Examples: []string{`secret-gate version`}},
	}
}

func (a *App) runSchema() int {
	const command = "schema"
	return a.ok(command, map[string]interface{}{
		"schema_version": SchemaVersion,
		"binary":         "secret-gate",
		"version":        a.Version,
		"commands":       Manifest(),
		"exit_codes":     ExitCodeTable(),
	}, &Meta{Visibility: VisibilityMetadataOnly})
}

// AgentContext is the compact orientation document for agents.
type AgentContext struct {
	Binary            string            `json:"binary"`
	Version           string            `json:"version"`
	SchemaVersion     string            `json:"schema_version"`
	Description       string            `json:"description"`
	Env               map[string]string `json:"env"`
	ExitCodes         map[string]string `json:"exit_codes"`
	VisibilityClasses map[string]string `json:"visibility_classes"`
	Workflow          []string          `json:"workflow"`
	Commands          []string          `json:"commands"`
}

func (a *App) runAgentContext() int {
	const command = "agent-context"
	names := make([]string, 0, len(Manifest()))
	for _, c := range Manifest() {
		names = append(names, c.Name)
	}
	return a.ok(command, AgentContext{
		Binary:        "secret-gate",
		Version:       a.Version,
		SchemaVersion: SchemaVersion,
		Description:   "Approval-gated 1Password access. Every read/write is approved by a human via Telegram. Output is one JSON envelope on stdout; errors are JSON on stderr.",
		Env: map[string]string{
			"SECRET_GATE_URL":       "server base URL (or ~/.config/secret-gate/config.json)",
			"SECRET_GATE_STATE_DIR": "request ledger dir (default ~/.local/state/secret-gate)",
			"SECRET_GATE_AGENT":     "agent name shown to the approver",
			"SECRET_GATE_MODEL":     "model name shown to the approver",
		},
		ExitCodes: ExitCodeTable(),
		VisibilityClasses: map[string]string{
			VisibilityMetadataOnly: "never touches secret values",
			VisibilityProcessOnly:  "values reach a child process, never the model; output is redacted",
			VisibilityModelVisible: "values printed only behind an explicit --reveal",
			VisibilityValueInput:   "values enter only via --stdin, never argv",
		},
		Workflow: []string{
			"1. item search --query <q> to find the item",
			"2. item fields --item <name> to see labels/types (no values)",
			"3. request submit --item <name> --reason <why> [--fields a,b] (--no-wait + request wait to resume)",
			"4. prefer exec/ssh/otp exec (process-only); use item read/otp show --reveal only when the value itself is required",
			"5. write create/update with values piped via --stdin",
		},
		Commands: names,
	}, &Meta{Visibility: VisibilityMetadataOnly})
}
