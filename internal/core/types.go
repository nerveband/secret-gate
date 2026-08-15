package core

import (
	"context"

	"github.com/johnuopini/secret-gate/internal/daemon"
)

// --- Daemon interfaces ---

// DaemonClient provides read-only daemon access.
type DaemonClient interface {
	IsRunning() bool
	StatusInfo() (*DaemonStatusResult, error)
}

// FullDaemonClient provides full daemon access including cache operations.
type FullDaemonClient interface {
	DaemonClient
	Get(secretName, vault string) (map[string]string, error)
	Store(secretName, vault string, fields map[string]string, ttl int) error
	EnsureRunning() error
}

// AdminDaemonClient adds the cache administration verbs used by the CLI
// daemon subcommands.
type AdminDaemonClient interface {
	FullDaemonClient
	List() ([]daemon.CacheEntryInfo, error)
	Flush() error
	StopDaemon() error
}

// --- Proxy interfaces ---

// ProxyClient provides blocking HTTP proxy access to the secret-gate
// server. Its shape is unchanged from the pre-0.4.0 mcpserver interface
// so existing MCP mocks keep compiling.
type ProxyClient interface {
	Search(query string, limit int) ([]SearchResultItem, error)
	GetFields(secretName, vault string) (*FieldsResult, error)
	Request(ctx context.Context, secretName, vault, reason string, fields []string, requestContext RequestContext) (*RequestResult, error)
	Write(ctx context.Context, secretName, vault, reason, operation, category string, fields map[string]string, requestContext RequestContext) (*RequestResult, error)
}

// AsyncProxyClient exposes the non-blocking approval primitives used by
// the CLI request subcommands (--no-wait / status / wait).
type AsyncProxyClient interface {
	Submit(ctx context.Context, secretName, vault, reason string, fields []string, requestContext RequestContext) (*PendingRequest, error)
	Status(ctx context.Context, statusURL string) (*StatusResult, error)
	Retrieve(ctx context.Context, secretURL, secretName, vault string) (*RequestResult, error)
}

// --- Shared data types (moved verbatim from internal/mcpserver) ---

// DaemonStatusResult holds daemon status information.
type DaemonStatusResult struct {
	Running    bool   `json:"running"`
	Uptime     string `json:"uptime,omitempty"`
	EntryCount int    `json:"entry_count"`
	SocketPath string `json:"socket_path,omitempty"`
	PID        int    `json:"pid,omitempty"`
}

// SearchResultItem is a single search result from the proxy.
type SearchResultItem struct {
	SecretName string  `json:"secret_name"`
	VaultName  string  `json:"vault_name"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"`
}

// FieldInfo holds field metadata (name and type, no values).
type FieldInfo struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Type      string `json:"type"`
	Purpose   string `json:"purpose,omitempty"`
	Section   string `json:"section,omitempty"`
	Reference string `json:"reference,omitempty"`
}

// RequestContext describes the requesting agent for the Telegram approver.
type RequestContext struct {
	Agent   string `json:"agent,omitempty" jsonschema:"agent name, such as Codex"`
	Model   string `json:"model,omitempty" jsonschema:"model name"`
	Think   string `json:"think,omitempty" jsonschema:"thinking level"`
	Project string `json:"project,omitempty" jsonschema:"project or repository name"`
	Task    string `json:"task,omitempty" jsonschema:"plain-language description of what the agent will do"`
}

// FieldsResult holds the result of inspecting fields.
type FieldsResult struct {
	SecretName string      `json:"secret_name"`
	VaultName  string      `json:"vault_name"`
	Fields     []FieldInfo `json:"fields"`
}

// RequestResult holds the result of a secret request.
type RequestResult struct {
	Status          string   `json:"status"`
	SecretName      string   `json:"secret_name"`
	Cached          bool     `json:"cached"`
	FieldsAvailable []string `json:"fields_available,omitempty"`
	Message         string   `json:"message,omitempty"`
}

// ExecResult holds the redacted result of command execution.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// PendingRequest is a submitted, not-yet-resolved approval request.
type PendingRequest struct {
	Token     string `json:"token"`
	StatusURL string `json:"status_url"`
	ExpiresAt string `json:"expires_at"`
}

// StatusResult is a point-in-time approval status.
type StatusResult struct {
	Status    string `json:"status"` // pending|approved|denied|expired
	Message   string `json:"message,omitempty"`
	SecretURL string `json:"secret_url,omitempty"`
}
