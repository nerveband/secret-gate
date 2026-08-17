package daemon

const (
	CmdGet     = "get"
	CmdStore   = "store"
	CmdList    = "list"
	CmdFlush   = "flush"
	CmdStatus  = "status"
	CmdStop    = "stop"
	CmdWatch   = "watch"
	CmdUnwatch = "unwatch"
)

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
}

type Response struct {
	OK         bool              `json:"ok"`
	Error      string            `json:"error,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Entries    []CacheEntryInfo  `json:"entries,omitempty"`
	Watches    []WatchInfo       `json:"watches,omitempty"`
	Status     *DaemonStatus     `json:"status,omitempty"`
	WatchState string            `json:"watch_state,omitempty"` // "registered" | "duplicate"
}

type DaemonStatus struct {
	Uptime     string `json:"uptime"`
	EntryCount int    `json:"entry_count"`
	WatchCount int    `json:"watch_count,omitempty"`
	SocketPath string `json:"socket_path"`
	PID        int    `json:"pid"`
}
