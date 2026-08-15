// Package cli is the agent-native noun-verb face of secret-gate. It owns
// the JSON envelope, deterministic exit codes, flag parsing, the request
// ledger, and the machine-readable manifest. All domain logic lives in
// internal/core.
package cli

import (
	"encoding/json"
	"io"
)

// SchemaVersion versions the envelope and manifest wire format.
const SchemaVersion = "1.0"

// Deterministic exit codes. Frozen — documented in docs/exit-codes.md,
// AGENTS.md, and `agent-context`.
const (
	ExitOK       = 0 // success
	ExitFailure  = 1 // internal error, or child process exited non-zero
	ExitUsage    = 2 // usage / validation error
	ExitDenied   = 3 // approval denied
	ExitExpired  = 4 // approval expired or wait timed out
	ExitNetwork  = 5 // network / server error
	ExitNotFound = 6 // item, field, token, or cache entry not found
)

// Visibility classes — every command declares exactly one.
const (
	VisibilityMetadataOnly = "metadata-only" // never touches secret values
	VisibilityProcessOnly  = "process-only"  // values reach a child process, never the model
	VisibilityModelVisible = "model-visible" // values printed only behind --reveal
	VisibilityValueInput   = "value-input"   // values enter only via --stdin
)

// Meta carries per-invocation metadata.
type Meta struct {
	DurationMS int64  `json:"duration_ms"`
	Visibility string `json:"visibility"`
	Cache      string `json:"cache,omitempty"` // hit|miss when a cache was consulted
}

// Envelope is the single success document written to stdout.
type Envelope struct {
	SchemaVersion string      `json:"schema_version"`
	OK            bool        `json:"ok"`
	Command       string      `json:"command"`
	Data          interface{} `json:"data,omitempty"`
	Meta          *Meta       `json:"meta,omitempty"`
}

// ErrorBody is the structured error payload.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// ErrorEnvelope is the single error document written to stderr.
type ErrorEnvelope struct {
	SchemaVersion string    `json:"schema_version"`
	OK            bool      `json:"ok"`
	Command       string    `json:"command"`
	Error         ErrorBody `json:"error"`
}

// WriteResult writes the success envelope as a single JSON line.
func WriteResult(w io.Writer, command string, data interface{}, meta *Meta) error {
	return json.NewEncoder(w).Encode(Envelope{
		SchemaVersion: SchemaVersion, OK: true, Command: command, Data: data, Meta: meta,
	})
}

// WriteError writes the error envelope as a single JSON line.
func WriteError(w io.Writer, command, code, message, hint string) error {
	return json.NewEncoder(w).Encode(ErrorEnvelope{
		SchemaVersion: SchemaVersion, OK: false, Command: command,
		Error: ErrorBody{Code: code, Message: message, Hint: hint},
	})
}

// ExitCodeFor maps error codes to the frozen exit code table.
func ExitCodeFor(code string) int {
	switch code {
	case "usage", "validation":
		return ExitUsage
	case "denied":
		return ExitDenied
	case "expired", "timeout":
		return ExitExpired
	case "network", "server":
		return ExitNetwork
	case "not_found", "not_cached":
		return ExitNotFound
	default:
		return ExitFailure
	}
}
