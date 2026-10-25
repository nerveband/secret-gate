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
	Watch(spec daemon.WatchSpec) error
	Unwatch(token string) error
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
	StatusWait(ctx context.Context, statusURL string, waitSec int) (*StatusResult, error)
	Retrieve(ctx context.Context, secretURL, secretName, vault string) (*RequestResult, error)
}

// ItemWrite is one item create or update. Values travel only to the server.
type ItemWrite struct {
	Item      string            `json:"item"`
	Operation string            `json:"operation"`
	Category  string            `json:"category,omitempty"`
	Fields    map[string]string `json:"fields"`
}

// WriteClient submits one approval for one or more item writes in a vault.
// WriteItems blocks like Write; SubmitWrite returns the pending request so
// the local daemon can finish the write after approval.
type WriteClient interface {
	WriteItems(ctx context.Context, vault, reason string, items []ItemWrite, requestContext RequestContext) (*RequestResult, error)
	SubmitWrite(ctx context.Context, vault, reason string, items []ItemWrite, requestContext RequestContext) (*PendingRequest, error)
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
	Runtime      string `json:"runtime,omitempty" jsonschema:"requesting runtime, such as Paseo"`
	Provider     string `json:"provider,omitempty" jsonschema:"agent provider, such as Oh My Pi"`
	Model        string `json:"model,omitempty" jsonschema:"model name"`
	Think        string `json:"think,omitempty" jsonschema:"thinking level"`
	Project      string `json:"project,omitempty" jsonschema:"project or repository name"`
	Task         string `json:"task,omitempty" jsonschema:"plain-language description of what the agent will do"`
	PaseoAgentID string `json:"paseo_agent_id,omitempty" jsonschema:"optional Paseo agent ID for push activation"`
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
	RequestReused   bool     `json:"request_reused,omitempty"`
	FieldsAvailable []string `json:"fields_available,omitempty"`
	Message         string   `json:"message,omitempty"`
	Token           string   `json:"token,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	Resume          string   `json:"resume,omitempty"`
}

// ExecResult holds the redacted result of command execution.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// PendingRequest is a submitted, not-yet-resolved approval request.
type PendingRequest struct {
	Token         string `json:"token"`
	StatusURL     string `json:"status_url"`
	ExpiresAt     string `json:"expires_at"`
	RequestReused bool   `json:"request_reused,omitempty"`
}

// StatusResult is a point-in-time approval status.
type StatusResult struct {
	Status    string `json:"status"` // pending|approved|denied|expired
	Message   string `json:"message,omitempty"`
	SecretURL string `json:"secret_url,omitempty"`
}
