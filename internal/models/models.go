package models

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// RequestStatus represents the approval state of a request
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
)

// SecretRequest represents a single secret in a batch request
type SecretRequest struct {
	SecretName string   `json:"secret_name"`
	Vault      string   `json:"vault,omitempty"`
	Fields     []string `json:"fields,omitempty"` // If empty, return all fields
	// Attachments is filled by the server from the item for every "file:"
	// selector in Fields, so Telegram can show names and sizes.
	Attachments []Attachment `json:"attachments,omitempty"`
	// Summary is filled by the server with a masked description of a card
	// ("Mastercard ending 1100, expires 08/2027"). It never holds a value
	// that needs approval.
	Summary string `json:"summary,omitempty"`
}

// ReservedKeyPrefix starts every key the server adds to released item values
// for metadata. Reserved keys are never field values and never resolve as one.
const ReservedKeyPrefix = "_secret_gate."

// ProcessOnlyKey is a reserved key the server adds to released item values.
// Its value lists, comma-separated, the keys whose values may reach a child
// process or a browser field but never model context (card number, CVV, PIN).
const ProcessOnlyKey = ReservedKeyPrefix + "process_only"

// ExpiresAtKey is a reserved key the server adds to values released under an
// owner window. Its value is an RFC 3339 time: clients must not keep the
// values, in their cache or in ssh-agent, past it. It is the window's end
// plus WindowCacheGrace.
const ExpiresAtKey = ReservedKeyPrefix + "expires_at"

// WindowCacheGrace is how long after its window ends a value read at the
// last minute may stay cached.
const WindowCacheGrace = 5 * time.Minute

// RemainingLife returns how much longer released values may be kept. ok is
// false when the server set no limit. The result is never below one second.
func RemainingLife(values map[string]string, now time.Time) (time.Duration, bool) {
	raw := values[ExpiresAtKey]
	if raw == "" {
		return 0, false
	}
	until, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Second, true // unreadable limit: keep the value as short as possible
	}
	if d := until.Sub(now); d > time.Second {
		return d, true
	}
	return time.Second, true
}

// FieldMetaKey is a reserved key the server adds to released item values.
// Its value is a JSON object mapping each value key to the 1Password field
// metadata behind it (FieldMeta), so clients can tell a login's real
// password field from a saved web-form field with a similar label.
const FieldMetaKey = ReservedKeyPrefix + "fields"

// FieldMeta describes the 1Password field behind one value key. It never
// holds a value. Selector is the key that always addresses the field.
// Alternatives, set by the server on a released key, names other fields
// that match the requested name with a different, non-empty value, so an
// agent whose login fails can request one of them and retry.
type FieldMeta struct {
	ID           string   `json:"id,omitempty"`
	Label        string   `json:"label,omitempty"`
	Selector     string   `json:"selector,omitempty"`
	Type         string   `json:"type,omitempty"`
	Purpose      string   `json:"purpose,omitempty"`
	Alternatives []string `json:"alternatives,omitempty"`
}

// IsReservedKey reports whether a value key is server metadata.
func IsReservedKey(key string) bool {
	return strings.HasPrefix(key, ReservedKeyPrefix)
}

// SensitiveCacheTTL caps how long the local daemon keeps an item that has
// process-only values, so one card approval covers one checkout, not a day.
const SensitiveCacheTTL = 15 * time.Minute

// AttachmentPrefix marks a field selector that names an item attachment
// ("file:<name or id>"). Attachments are released only when named this way.
const AttachmentPrefix = "file:"

// MaxAttachmentBytes caps a single attachment and the attachments of one
// request. It is Secret Gate's own limit, chosen so content can be held in
// server and daemon memory; 1Password allows larger files.
const MaxAttachmentBytes = 10 << 20

// Attachment is a file stored in a 1Password item. Content is never included.
type Attachment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// FileUpload is a file to attach to an item on create or update. Content
// stays in server memory while approval is pending, like field values.
type FileUpload struct {
	Name    string `json:"name"`
	Content []byte `json:"content,omitempty"`
	Size    int64  `json:"size"`
}

// RequestContext describes the agent and task in terms an approver can scan.
type RequestContext struct {
	Runtime      string `json:"runtime,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Model        string `json:"model,omitempty"`
	Think        string `json:"think,omitempty"`
	Project      string `json:"project,omitempty"`
	Task         string `json:"task,omitempty"`
	PaseoAgentID string `json:"paseo_agent_id,omitempty"`
	// Purpose names where a value will be used ("aa.com checkout"). Card
	// reads require it; the approver sees it next to the masked card.
	Purpose string `json:"purpose,omitempty"`
	// Amount is the charge the approver is asked to allow ("$412.30").
	Amount string `json:"amount,omitempty"`
}

// CardLine is the approver-facing line of a card read:
// "Approve $412.30 at aa.com checkout, Visa ending 1111, expires 08/2027",
// or "aa.com checkout, Visa ending 1111, ..." without an amount. It is
// empty for requests that do not read a card.
func (r *ApprovalRequest) CardLine() string {
	if r.IsWrite() {
		return ""
	}
	card := ""
	for _, s := range r.Secrets {
		if s.Summary != "" {
			card = s.Summary
			break
		}
	}
	if card == "" {
		return ""
	}
	line := card
	if r.Context.Purpose != "" {
		line = r.Context.Purpose + ", " + card
	}
	if r.Context.Amount != "" {
		at := r.Context.Purpose
		if at == "" {
			return "Approve " + r.Context.Amount + ", " + card
		}
		return "Approve " + r.Context.Amount + " at " + at + ", " + card
	}
	return line
}

// ItemMutation is an approved write to a 1Password item. Values remain only in
// server memory while approval is pending and are never included in Telegram.
// Item is the target item title; batch requests carry one mutation per item.
type ItemMutation struct {
	Item      string            `json:"item,omitempty"`
	Operation string            `json:"operation"` // create or update
	Category  string            `json:"category,omitempty"`
	Fields    map[string]string `json:"fields"`
	Files     []FileUpload      `json:"files,omitempty"`
	// OwnerFields are labels the approver types on the approval device
	// (the entry page linked from Telegram) instead of the agent sending them.
	OwnerFields []string `json:"owner_fields,omitempty"`
	// TargetCategory is filled by the server: the category of the item that
	// is created, or of the existing item that is updated.
	TargetCategory string `json:"target_category,omitempty"`
}

// Labels returns the mutation's field labels, including owner-entered
// ones, sorted and unique. Values are never included.
func (m ItemMutation) Labels() []string {
	labels := make([]string, 0, len(m.Fields)+len(m.OwnerFields))
	for label := range m.Fields {
		labels = append(labels, label)
	}
	for _, label := range m.OwnerFields {
		if _, ok := m.Fields[label]; !ok {
			labels = append(labels, label)
		}
	}
	sort.Strings(labels)
	return labels
}

// AwaitingOwner reports whether the approver still has to enter values on
// the entry page before this write can be approved.
func (r *ApprovalRequest) AwaitingOwner() bool {
	for _, m := range r.Mutations {
		for _, label := range m.OwnerFields {
			if m.Fields[label] == "" {
				return true
			}
		}
	}
	return false
}

// Approval sources recorded on requests that no human tapped individually.
const (
	AutoApprovedWriteWindow = "write_window"
	AutoApprovedFollowUp    = "follow_up"
	AutoApprovedOwnerWindow = "owner_window"
)

// ApprovalRequest represents a request to access a secret
type ApprovalRequest struct {
	ID                string          `json:"id"`
	Token             string          `json:"token"`
	SecretName        string          `json:"secret_name"`
	Vault             string          `json:"vault"`
	Secrets           []SecretRequest `json:"secrets,omitempty"` // Batch mode
	RequesterMachine  string          `json:"requester_machine"`
	RequesterIP       string          `json:"requester_ip"`
	Reason            string          `json:"reason,omitempty"`
	Action            string          `json:"action,omitempty"`
	Context           RequestContext  `json:"context,omitempty"`
	Mutations         []ItemMutation  `json:"mutations,omitempty"`
	Status            RequestStatus   `json:"status"`
	RequestedAt       time.Time       `json:"requested_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	RespondedAt       *time.Time      `json:"responded_at,omitempty"`
	TelegramMsgID     int             `json:"telegram_msg_id,omitempty"`
	PushWardSlug      string          `json:"pushward_slug,omitempty"`
	Fingerprint       string          `json:"fingerprint,omitempty"`
	MutationState     string          `json:"mutation_state,omitempty"` // executing|completed
	MutationItems     []string        `json:"mutation_items,omitempty"` // written titles by mutation index
	MutationStartedAt *time.Time      `json:"mutation_started_at,omitempty"`
	// MutationItemIDs and MutationFilesDone record, per mutation index, the
	// item already saved and how many of its files are attached, so a retry
	// after a failed attachment neither recreates the item nor re-attaches.
	MutationItemIDs   []string `json:"mutation_item_ids,omitempty"`
	MutationFilesDone []int    `json:"mutation_files_done,omitempty"`
	AutoApproved      string   `json:"auto_approved,omitempty"`   // write_window|follow_up|owner_window
	Approver          string   `json:"approver,omitempty"`        // Telegram user whose tap covers this request
	WriteWindowID     string   `json:"write_window_id,omitempty"` // window that approved or was opened by this request
	// WindowNote tells the approver why an open owner window did not cover
	// this request ("the item is not tagged for windows").
	WindowNote string `json:"window_note,omitempty"`
	// WindowExpiresAt is when the owner window that approved this read ends.
	WindowExpiresAt time.Time  `json:"window_expires_at,omitzero"`
	RemindedAt      *time.Time `json:"reminded_at,omitempty"`
	ExpiryNotified  bool       `json:"expiry_notified,omitempty"`
	// Sensitive marks card reads that release a card number, CVV, or PIN,
	// writes to card or bank account items, and writes with owner fields.
	// They need a tap on this request: read windows, write windows, and
	// follow-ups never cover them.
	Sensitive bool `json:"sensitive,omitempty"`
	// EntryToken opens the owner entry page for OwnerFields; EntryURL is the
	// full link. Both go only to Telegram and the authenticated Approver
	// API, never to the requesting agent.
	EntryToken string `json:"-"`
	EntryURL   string `json:"-"`
}

// IsWrite reports whether the request creates or updates 1Password items.
func (r *ApprovalRequest) IsWrite() bool {
	return len(r.Mutations) > 0
}

// ScrubMutationValues drops pending write values once they can no longer be
// written. It replaces the slice instead of editing shared maps, so copies
// handed out by the store are never mutated.
func (r *ApprovalRequest) ScrubMutationValues() {
	if len(r.Mutations) == 0 {
		return
	}
	scrubbed := make([]ItemMutation, len(r.Mutations))
	for i, m := range r.Mutations {
		fields := make(map[string]string, len(m.Fields))
		for label := range m.Fields {
			fields[label] = ""
		}
		m.Fields = fields
		if len(m.Files) > 0 {
			files := make([]FileUpload, len(m.Files))
			for j, f := range m.Files {
				files[j] = FileUpload{Name: f.Name, Size: f.Size}
			}
			m.Files = files
		}
		scrubbed[i] = m
	}
	r.Mutations = scrubbed
}

// SecretValue holds the retrieved secret data
type SecretValue struct {
	Fields map[string]string `json:"fields"`
}

// NewApprovalRequest creates a new approval request with a unique token
func NewApprovalRequest(secretName, vault, requesterMachine, requesterIP, reason string, ttl time.Duration) (*ApprovalRequest, error) {
	id, err := generateRandomID(16)
	if err != nil {
		return nil, err
	}

	token, err := generateRandomID(32)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &ApprovalRequest{
		ID:               id,
		Token:            token,
		SecretName:       secretName,
		Vault:            vault,
		RequesterMachine: requesterMachine,
		RequesterIP:      requesterIP,
		Reason:           reason,
		Status:           StatusPending,
		RequestedAt:      now,
		ExpiresAt:        now.Add(ttl),
	}, nil
}

// IsExpired checks if the request has expired
func (r *ApprovalRequest) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// CanRetrieveSecret checks if the secret can be retrieved
func (r *ApprovalRequest) CanRetrieveSecret() bool {
	return r.Status == StatusApproved && !r.IsExpired()
}

// Approve marks the request as approved
func (r *ApprovalRequest) Approve() {
	now := time.Now()
	r.Status = StatusApproved
	r.RespondedAt = &now
}

// Deny marks the request as denied
func (r *ApprovalRequest) Deny() {
	now := time.Now()
	r.Status = StatusDenied
	r.RespondedAt = &now
}

// generateRandomID generates a random hex string of the specified byte length
func generateRandomID(byteLen int) (string, error) {
	bytes := make([]byte, byteLen)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
