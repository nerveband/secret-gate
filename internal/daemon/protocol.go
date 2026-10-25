package daemon

import "github.com/johnuopini/secret-gate/internal/passkey"

const (
	CmdGet     = "get"
	CmdStore   = "store"
	CmdList    = "list"
	CmdFlush   = "flush"
	CmdStatus  = "status"
	CmdStop    = "stop"
	CmdWatch   = "watch"
	CmdUnwatch = "unwatch"
	CmdPasskey = "passkey"
)

// Passkey actions handled by CmdPasskey.
const (
	PasskeyArm     = "arm"
	PasskeyLoad    = "load"
	PasskeyCollect = "collect"
	PasskeyRelease = "release"
	PasskeyList    = "list"
)

// PasskeyRequest asks the daemon to hold, read, or release a virtual
// authenticator. Credential carries key material for load only.
type PasskeyRequest struct {
	Action     string              `json:"action"`
	Session    string              `json:"session,omitempty"`
	Endpoint   string              `json:"endpoint,omitempty"`
	PageURL    string              `json:"page_url,omitempty"`
	TargetID   string              `json:"target_id,omitempty"`
	HoldSec    int                 `json:"hold_seconds,omitempty"`
	Item       string              `json:"item,omitempty"`
	Vault      string              `json:"vault,omitempty"`
	Credential *passkey.Credential `json:"credential,omitempty"`
}

type ActivationSpec struct {
	Kind           string   `json:"kind,omitempty"` // "paseo" | "command" | "none"
	PaseoAgentID   string   `json:"paseo_agent_id,omitempty"`
	Argv           []string `json:"argv,omitempty"`
	PromptTemplate string   `json:"prompt_template,omitempty"`
}

type WatchSpec struct {
	Token         string          `json:"token"`
	StatusURL     string          `json:"status_url"`
	SecretURLBase string          `json:"secret_url_base,omitempty"`
	SecretName    string          `json:"secret_name"`
	Vault         string          `json:"vault,omitempty"`
	Fields        []string        `json:"fields,omitempty"`
	IsMutation    bool            `json:"is_mutation,omitempty"`
	CacheTTLSec   int             `json:"cache_ttl_seconds,omitempty"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
	Activation    *ActivationSpec `json:"activation,omitempty"`
	StateDir      string          `json:"state_dir,omitempty"`
}

type WatchInfo struct {
	Token      string `json:"token"`
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
	State      string `json:"state"` // "watching" | "completed" | "failed"
	Since      string `json:"since"`
}

type Request struct {
	Command    string            `json:"command"`
	SecretName string            `json:"secret_name,omitempty"`
	Vault      string            `json:"vault,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	TTLSeconds int               `json:"ttl_seconds,omitempty"`
	Token      string            `json:"token,omitempty"`
	Watch      *WatchSpec        `json:"watch,omitempty"`
	Passkey    *PasskeyRequest   `json:"passkey,omitempty"`
}

type Response struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Entries    []CacheEntryInfo  `json:"entries,omitempty"`
	Watches    []WatchInfo       `json:"watches,omitempty"`
	Status     *DaemonStatus     `json:"status,omitempty"`
	WatchState string            `json:"watch_state,omitempty"` // "registered" | "duplicate"
	Passkeys   []passkey.Info    `json:"passkeys,omitempty"`
	// Credential is returned by collect only, to the requesting client.
	Credential *passkey.Credential `json:"credential,omitempty"`
}

// maxMessageBytes bounds one socket message. Cached attachments travel as
// base64 field values, so this must exceed the 10 MiB attachment limit.
const maxMessageBytes = 32 << 20

type DaemonStatus struct {
	Uptime       string `json:"uptime"`
	EntryCount   int    `json:"entry_count"`
	WatchCount   int    `json:"watch_count,omitempty"`
	PasskeyCount int    `json:"passkey_count,omitempty"`
	SocketPath   string `json:"socket_path"`
	PID          int    `json:"pid"`
}
