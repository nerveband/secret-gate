// Package mcpserver is the thin MCP stdio adapter over internal/core.
// It owns only tool registration and result mapping; all domain logic
// lives in core.Service.
package mcpserver

import (
	"context"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Aliases: the MCP face shares the core domain vocabulary ---

type DaemonClient = core.DaemonClient
type FullDaemonClient = core.FullDaemonClient
type ProxyClient = core.ProxyClient
type Config = core.Config

type DaemonStatusResult = core.DaemonStatusResult
type SearchResultItem = core.SearchResultItem
type FieldInfo = core.FieldInfo
type RequestContext = core.RequestContext
type FieldsResult = core.FieldsResult
type RequestResult = core.RequestResult
type ExecResult = core.ExecResult

// NewHTTPProxyClient forwards to core so existing callers keep working.
func NewHTTPProxyClient(serverURL string, dc FullDaemonClient, cacheTTLSec int) ProxyClient {
	return core.NewHTTPProxyClient(serverURL, dc, cacheTTLSec)
}

// NewRealDaemonClient forwards to core.
func NewRealDaemonClient() FullDaemonClient { return core.NewRealDaemonClient() }

// NewRealDaemonClientWithConfig forwards to core.
func NewRealDaemonClientWithConfig(cacheTTLSec int) FullDaemonClient {
	return core.NewRealDaemonClientWithConfig(cacheTTLSec)
}

// --- Tool input/output types (unchanged wire schemas) ---

type DaemonStatusInput struct{}

type SearchSecretsInput struct {
	Query string `json:"query" jsonschema:"search query for finding secrets in 1Password"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of results (default 10)"`
}

type InspectFieldsInput struct {
	SecretName string `json:"secret_name" jsonschema:"name of the secret to inspect"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name (optional, searches all vaults if omitted)"`
}

type RequestSecretInput struct {
	SecretName string         `json:"secret_name" jsonschema:"name of the secret to request"`
	Vault      string         `json:"vault,omitempty" jsonschema:"vault name (optional)"`
	Reason     string         `json:"reason" jsonschema:"reason for requesting access (shown in Telegram approval)"`
	Fields     []string       `json:"fields,omitempty" jsonschema:"specific field labels or IDs to approve"`
	Context    RequestContext `json:"context,omitempty"`
}

type WriteItemInput struct {
	SecretName string            `json:"secret_name" jsonschema:"item title"`
	Vault      string            `json:"vault" jsonschema:"explicit vault name or ID"`
	Operation  string            `json:"operation" jsonschema:"create or update"`
	Category   string            `json:"category,omitempty" jsonschema:"1Password category for new items; defaults to SECURE_NOTE"`
	Fields     map[string]string `json:"fields" jsonschema:"field labels mapped to values to store"`
	Reason     string            `json:"reason" jsonschema:"why this write is needed"`
	Context    RequestContext    `json:"context,omitempty"`
}

type ReadFieldsInput struct {
	SecretName string   `json:"secret_name"`
	Vault      string   `json:"vault,omitempty"`
	Fields     []string `json:"fields,omitempty"`
}
type ReadFieldsOutput struct {
	SecretName string            `json:"secret_name"`
	Fields     map[string]string `json:"fields"`
}
type GetOTPInput struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
	Field      string `json:"field,omitempty" jsonschema:"OTP field; mfa, otp, totp, 2fa, and one-time password are aliases"`
}
type GetOTPOutput struct {
	Code       string `json:"code"`
	ExpiresAt  string `json:"expires_at"`
	SecretUsed string `json:"secret_used"`
}

type ExecWithSecretInput struct {
	SecretName string `json:"secret_name" jsonschema:"name of the previously approved secret"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name (optional)"`
	Field      string `json:"field" jsonschema:"field name to inject as environment variable"`
	EnvVar     string `json:"env_var" jsonschema:"environment variable name to set"`
	Command    string `json:"command" jsonschema:"shell command to execute (runs via sh -c)"`
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"working directory for the command"`
	TimeoutSec int    `json:"timeout_sec,omitempty" jsonschema:"command timeout in seconds (default 30)"`
}

type SSHWithSecretInput struct {
	SecretName string `json:"secret_name" jsonschema:"SSH key secret name (must be approved and cached)"`
	Host       string `json:"host" jsonschema:"SSH destination (user@host format)"`
	Command    string `json:"command,omitempty" jsonschema:"remote command to execute"`
	Vault      string `json:"vault,omitempty" jsonschema:"vault name"`
	Port       int    `json:"port,omitempty" jsonschema:"SSH port (default 22)"`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"timeout in seconds (default 120)"`
}

type DaemonStatusOutput = DaemonStatusResult

type SearchSecretsOutput struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
	Count   int                `json:"count"`
}

type InspectFieldsOutput = FieldsResult
type RequestSecretOutput = RequestResult

type ExecWithSecretOutput struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	SecretUsed string `json:"secret_used"`
}

type SSHWithSecretOutput struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	SecretUsed string `json:"secret_used"`
}

// --- Server construction ---

// New creates the MCP server with all secret-gate tools registered.
func New(cfg Config, dc FullDaemonClient, pc ProxyClient) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "secret-gate",
		Version: version.Version,
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "daemon_status",
		Description: "Check the status of the secret-gate cache daemon. Returns whether it is running, uptime, cached entry count, and socket path.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input DaemonStatusInput) (*mcp.CallToolResult, DaemonStatusOutput, error) {
		return handleDaemonStatus(ctx, dc)
	})

	mcp.AddTool(server, &mcp.Tool{Name: "read_item_fields", Description: "Read fields from a previously approved and cached 1Password item. Omit fields to read every approved field. Fields can be addressed by label, field ID, or section.label; notes aliases are accepted. Returned values enter model context."}, func(ctx context.Context, req *mcp.CallToolRequest, input ReadFieldsInput) (*mcp.CallToolResult, ReadFieldsOutput, error) {
		return handleReadFields(ctx, dc, input)
	})

	mcp.AddTool(server, &mcp.Tool{Name: "write_item", Description: "Create or update a 1Password item after Telegram approval. Values are held only in server memory while pending and are never shown in Telegram or logs. An explicit vault is required."}, func(ctx context.Context, req *mcp.CallToolRequest, input WriteItemInput) (*mcp.CallToolResult, RequestSecretOutput, error) {
		return handleWriteItem(ctx, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{Name: "get_otp", Description: "Generate the current MFA/OTP/TOTP/2FA code from a previously approved 1Password OTP field. These terms are interchangeable."}, func(ctx context.Context, req *mcp.CallToolRequest, input GetOTPInput) (*mcp.CallToolResult, GetOTPOutput, error) {
		return handleGetOTP(ctx, dc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "search_secrets",
		Description: "Search for secrets in 1Password by name. Returns matching secret names, vault names, and match scores. Use this to find the correct secret name before requesting it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input SearchSecretsInput) (*mcp.CallToolResult, SearchSecretsOutput, error) {
		return handleSearchSecrets(ctx, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "inspect_fields",
		Description: "List the field names and types for a secret WITHOUT revealing any values. Use this to discover which fields a secret has before requesting or executing with it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input InspectFieldsInput) (*mcp.CallToolResult, InspectFieldsOutput, error) {
		return handleInspectFields(ctx, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "request_secret",
		Description: "Request access to a secret. Triggers a Telegram approval flow. Returns the request status (approved/pending/denied) but NEVER the secret value. After approval, the secret is cached locally. Use exec_with_secret or ssh_with_secret to use the cached secret.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input RequestSecretInput) (*mcp.CallToolResult, RequestSecretOutput, error) {
		return handleRequestSecret(ctx, dc, pc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "exec_with_secret",
		Description: "Execute a shell command with a secret field injected as an environment variable. The secret must be previously approved and cached (use request_secret first). The secret value is NEVER returned - it is only available to the subprocess via the environment variable, and exact occurrences are redacted from captured output.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExecWithSecretInput) (*mcp.CallToolResult, ExecWithSecretOutput, error) {
		return handleExecWithSecret(ctx, dc, input)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "ssh_with_secret",
		Description: "SSH to a host using an SSH key from a previously approved secret. The key is added to ssh-agent temporarily, then SSH is executed. The secret must be approved and cached first (use request_secret first).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input SSHWithSecretInput) (*mcp.CallToolResult, SSHWithSecretOutput, error) {
		return handleSSHWithSecret(ctx, dc, cfg, input)
	})

	return server
}

// svc builds a core.Service around the injected clients. Handlers keep
// their pre-0.4.0 signatures so existing tests and callers are unchanged.
func svc(dc FullDaemonClient, pc ProxyClient, cfg Config) *core.Service {
	return &core.Service{Daemon: dc, Proxy: pc, Config: cfg, Now: time.Now}
}

// toolError creates a tool error result (not a protocol error), carrying
// the core hint when present.
func toolError(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

func coreError(err error) *mcp.CallToolResult {
	msg := core.MessageOf(err)
	if hint := core.HintOf(err); hint != "" {
		msg += " (" + hint + ")"
	}
	return toolError(msg)
}

// --- Handlers (thin delegation) ---

func handleDaemonStatus(_ context.Context, dc DaemonClient) (*mcp.CallToolResult, DaemonStatusOutput, error) {
	s := &core.Service{Daemon: readOnly{dc}, Now: time.Now}
	status, err := s.DaemonStatus()
	if err != nil {
		return coreError(err), DaemonStatusOutput{}, nil
	}
	return nil, *status, nil
}

// readOnly adapts a DaemonClient to FullDaemonClient for status-only use.
type readOnly struct{ DaemonClient }

func (readOnly) Get(string, string) (map[string]string, error) {
	return nil, core.E(core.ErrNotFound, "read access not available", "")
}
func (readOnly) Store(string, string, map[string]string, int) error { return nil }
func (readOnly) EnsureRunning() error                               { return nil }

func handleSearchSecrets(_ context.Context, pc ProxyClient, input SearchSecretsInput) (*mcp.CallToolResult, SearchSecretsOutput, error) {
	out, err := svc(nil, pc, Config{}).Search(input.Query, input.Limit)
	if err != nil {
		return coreError(err), SearchSecretsOutput{}, nil
	}
	return nil, SearchSecretsOutput{Results: out.Results, Query: out.Query, Count: out.Count}, nil
}

func handleInspectFields(_ context.Context, pc ProxyClient, input InspectFieldsInput) (*mcp.CallToolResult, InspectFieldsOutput, error) {
	out, err := svc(nil, pc, Config{}).InspectFields(input.SecretName, input.Vault)
	if err != nil {
		return coreError(err), InspectFieldsOutput{}, nil
	}
	return nil, *out, nil
}

func handleRequestSecret(ctx context.Context, dc FullDaemonClient, pc ProxyClient, input RequestSecretInput) (*mcp.CallToolResult, RequestSecretOutput, error) {
	out, err := svc(dc, pc, Config{}).Request(ctx, input.SecretName, input.Vault, input.Reason, input.Fields, input.Context)
	if err != nil {
		return coreError(err), RequestSecretOutput{}, nil
	}
	return nil, *out, nil
}

func handleReadFields(_ context.Context, dc FullDaemonClient, input ReadFieldsInput) (*mcp.CallToolResult, ReadFieldsOutput, error) {
	out, err := svc(dc, nil, Config{}).ReadFields(input.SecretName, input.Vault, input.Fields)
	if err != nil {
		return coreError(err), ReadFieldsOutput{}, nil
	}
	return nil, ReadFieldsOutput{SecretName: input.SecretName, Fields: out}, nil
}

func handleGetOTP(_ context.Context, dc FullDaemonClient, input GetOTPInput) (*mcp.CallToolResult, GetOTPOutput, error) {
	out, err := svc(dc, nil, Config{}).GetOTP(input.SecretName, input.Vault, input.Field)
	if err != nil {
		return coreError(err), GetOTPOutput{}, nil
	}
	return nil, GetOTPOutput{Code: out.Code, ExpiresAt: out.ExpiresAt, SecretUsed: out.SecretUsed}, nil
}

func handleWriteItem(ctx context.Context, pc ProxyClient, input WriteItemInput) (*mcp.CallToolResult, RequestSecretOutput, error) {
	out, err := svc(nil, pc, Config{}).Write(ctx, input.SecretName, input.Vault, input.Reason, input.Operation, input.Category, input.Fields, input.Context)
	if err != nil {
		return coreError(err), RequestSecretOutput{}, nil
	}
	return nil, *out, nil
}

func handleExecWithSecret(ctx context.Context, dc FullDaemonClient, input ExecWithSecretInput) (*mcp.CallToolResult, ExecWithSecretOutput, error) {
	out, err := svc(dc, nil, Config{}).Exec(ctx, core.ExecRequest{
		SecretName:   input.SecretName,
		Vault:        input.Vault,
		Field:        input.Field,
		EnvVar:       input.EnvVar,
		ShellCommand: input.Command, // MCP tool contract keeps sh -c semantics
		WorkingDir:   input.WorkingDir,
		Timeout:      time.Duration(input.TimeoutSec) * time.Second,
	})
	if err != nil {
		return coreError(err), ExecWithSecretOutput{}, nil
	}
	return nil, ExecWithSecretOutput{ExitCode: out.ExitCode, Stdout: out.Stdout, Stderr: out.Stderr, SecretUsed: out.SecretUsed}, nil
}

func handleSSHWithSecret(ctx context.Context, dc FullDaemonClient, cfg Config, input SSHWithSecretInput) (*mcp.CallToolResult, SSHWithSecretOutput, error) {
	out, err := svc(dc, nil, cfg).SSH(ctx, core.SSHRequest{
		SecretName: input.SecretName,
		Vault:      input.Vault,
		Host:       input.Host,
		Command:    input.Command,
		Port:       input.Port,
		Timeout:    time.Duration(input.Timeout) * time.Second,
	})
	if err != nil {
		return coreError(err), SSHWithSecretOutput{}, nil
	}
	return nil, SSHWithSecretOutput{ExitCode: out.ExitCode, Stdout: out.Stdout, Stderr: out.Stderr, SecretUsed: out.SecretUsed}, nil
}
