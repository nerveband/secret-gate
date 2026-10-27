package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/autosession"
	"github.com/johnuopini/secret-gate/internal/config"
	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
	"github.com/johnuopini/secret-gate/internal/store"
	"github.com/johnuopini/secret-gate/internal/writegrant"
)

type telegramClient interface {
	SendApprovalRequest(*models.ApprovalRequest, string, time.Duration) (int, error)
	SendAutoApprovedNotification(*models.ApprovalRequest, string, time.Time) error
	UpdateApprovalRequest(int, *models.ApprovalRequest, time.Duration) error
	AnswerCallbackQuery(string, string) error
	UpdateMessageApproved(int, *models.ApprovalRequest, string) error
	UpdateMessageDenied(int, *models.ApprovalRequest, string) error
	UpdateMessageApprovedWriteWindow(int, *models.ApprovalRequest, string, writegrant.Window) error
	UpdateMessageExpired(int, *models.ApprovalRequest) error
	SendWriteAutoApproved(*models.ApprovalRequest, writegrant.Match) error
	SendReminder(*models.ApprovalRequest) error
	SendWindowRevoked(writegrant.Window, string, int) error
	SendWriteBlocked(*models.ApprovalRequest, string) error
}

// PushWardClient sends approval Live Activities and E2E-encrypted audit notifications.
type PushWardClient interface {
	SendApprovalRequest(req *models.ApprovalRequest, windowTTL time.Duration) (string, error)
	UpdateApprovalRequest(slug string, req *models.ApprovalRequest, windowTTL time.Duration) error
	WatchApproval(req *models.ApprovalRequest, slug string, onAnswer func(data, approver string))
	ResolveActivity(requestID, slug string) error
	SendAutoApprovedNotification(req *models.ApprovalRequest, approver string, expiresAt time.Time) error
	SendWriteAutoApproved(req *models.ApprovalRequest, match writegrant.Match) error
	SendReminder(req *models.ApprovalRequest) error
	SendWindowRevoked(window writegrant.Window, revoker string, dropped int) error
	SendWriteBlocked(req *models.ApprovalRequest, detail string) error
}

// FileAttacher uploads attachments. 1Password Connect cannot upload files,
// so the server uses the 1Password SDK with a service account for this.
type FileAttacher interface {
	CheckVault(ctx context.Context, vaultID string) error
	Attach(ctx context.Context, vaultID, itemID, name string, content []byte) error
}

// Handler holds dependencies for HTTP handlers
type Handler struct {
	store     *store.Store
	opClient  *opconnect.Client
	tgClient  telegramClient
	pwClient  PushWardClient
	config    *config.Config
	sessions  *autosession.Store
	requestMu sync.Mutex
	log       *logger.Logger
	grants    *writegrant.Store
	files     FileAttacher // nil when no service account is configured
	approvals *approvalHub
}

// New creates a new Handler
func New(s *store.Store, op *opconnect.Client, tg telegramClient, cfg *config.Config, sessions *autosession.Store) *Handler {
	return &Handler{
		store:    s,
		opClient: op,
		tgClient: tg,
		config:   cfg,
		sessions: sessions,
		log:      logger.New(),
		grants:   writegrant.NewStore(),
		approvals: newApprovalHub(),
	}
}

// SetFileAttacher enables attaching files on writes.
func (h *Handler) SetFileAttacher(a FileAttacher) {
	h.files = a
}

// SetPushWardClient enables PushWard approval Live Activities and audit notifications.
func (h *Handler) SetPushWardClient(pw PushWardClient) {
	h.pwClient = pw
}

// SearchPayload is the JSON body for secret search
type SearchPayload struct {
	Query string `json:"query"`
	Limit int    `json:"limit,omitempty"`
}

// SearchResponse contains search results
type SearchResponse struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
}

// SearchResultItem is a single search result
type SearchResultItem struct {
	SecretName string  `json:"secret_name"`
	VaultName  string  `json:"vault_name"`
	Score      float64 `json:"score"`
	MatchType  string  `json:"match_type"`
}

// FieldsPayload is the JSON body for fields request
type FieldsPayload struct {
	SecretName string `json:"secret_name"`
	Vault      string `json:"vault,omitempty"`
}

// FieldsResponse contains field and attachment metadata
type FieldsResponse struct {
	SecretName string                `json:"secret_name"`
	VaultName  string                `json:"vault_name"`
	Fields     []opconnect.FieldInfo `json:"fields"`
	Files      []opconnect.FileInfo  `json:"files,omitempty"`
}

// BatchRequestPayload is the JSON body for batch secret requests
type BatchRequestPayload struct {
	// Batch mode
	Secrets []models.SecretRequest `json:"secrets,omitempty"`
	// Legacy single-item mode
	SecretName string `json:"secret_name,omitempty"`
	Vault      string `json:"vault,omitempty"`
	// Common fields
	Machine  string                `json:"machine"`
	Reason   string                `json:"reason,omitempty"`
	Action   string                `json:"action,omitempty"`
	Context  models.RequestContext `json:"context,omitempty"`
	Mutation *models.ItemMutation  `json:"mutation,omitempty"`
	// Batch writes: one approval for several items in one explicit vault.
	Mutations []models.ItemMutation `json:"mutations,omitempty"`
}

// RequestResponse is the response for a new secret request
type RequestResponse struct {
	Token         string `json:"token"`
	StatusURL     string `json:"status_url"`
	ExpiresAt     string `json:"expires_at"`
	Message       string `json:"message"`
	RequestReused bool   `json:"request_reused,omitempty"`
}

// StatusResponse is the response for status checks
type StatusResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type SecretResponse struct {
	Secret map[string]string `json:"secret"`
	Vault  string            `json:"vault,omitempty"`
}

// BatchSecretResponse is the response containing multiple secrets.
type BatchSecretResponse struct {
	Secrets map[string]map[string]string `json:"secrets"`
	Vaults  map[string]string            `json:"vaults,omitempty"`
}

// ErrorResponse is returned on errors
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// MaxBatchWrites caps how many items one write approval may cover, so the
// Telegram message stays reviewable.
const MaxBatchWrites = 10

// HandleRequest handles POST /request
func (h *Handler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}
	h.requestMu.Lock()
	defer h.requestMu.Unlock()

	var payload BatchRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}
	secrets := payload.Secrets
	if len(secrets) == 0 && payload.SecretName != "" {
		secrets = []models.SecretRequest{{SecretName: payload.SecretName, Vault: payload.Vault}}
	}
	secrets, mutations, msg := normalizeWrites(payload, secrets)
	if msg != "" {
		h.writeError(w, http.StatusBadRequest, "invalid_mutation", msg)
		return
	}
	if len(secrets) == 0 {
		h.writeError(w, http.StatusBadRequest, "missing_fields", "secret_name or secrets[] is required")
		return
	}
	if h.config.WebhookBaseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	for i := range secrets {
		secrets[i].Attachments = nil // server-filled only
	}
	if len(mutations) == 0 {
		for i := range secrets {
			meta, err := h.opClient.GetItemFields(secrets[i].Vault, secrets[i].SecretName)
			if err != nil {
				h.writeError(w, http.StatusForbidden, "secret_unavailable", "Secret Gate cannot verify read access to the requested item.")
				return
			}
			secrets[i].Vault = meta.Vault
			secrets[i].SecretName = meta.Title
			attachments, msg := selectAttachments(meta.Files, secrets[i].Fields)
			if msg != "" {
				h.writeError(w, http.StatusUnprocessableEntity, "attachment_unavailable", msg)
				return
			}
			secrets[i].Attachments = attachments
		}
	}

	requesterIP := r.Header.Get("X-Forwarded-For")
	if requesterIP == "" {
		requesterIP = r.RemoteAddr
	}
	ttl := h.config.RequestTTL
	if len(mutations) > 0 && h.config.WriteRequestTTL > 0 {
		ttl = h.config.WriteRequestTTL
	}
	req, err := models.NewApprovalRequest(
		secrets[0].SecretName,
		secrets[0].Vault,
		payload.Machine,
		normalizeRequesterIP(requesterIP),
		payload.Reason,
		ttl,
	)
	if err != nil {
		h.log.Error("Failed to create request", logger.F("error", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create request")
		return
	}
	req.Secrets = secrets
	req.Action = payload.Action
	if req.Action == "" {
		req.Action = "read"
	}
	req.Context = payload.Context
	req.Mutations = mutations

	if req.IsWrite() {
		req.Action = "write"
		if len(req.Mutations) == 1 {
			req.Action = req.Mutations[0].Operation
		}
		capability := h.opClient.CheckWriteCapability(req.Vault)
		if !capability.Allowed {
			h.notifyWriteBlocked(req, capability.Message)
			status := http.StatusServiceUnavailable
			if capability.Code == "vault_write_unavailable" {
				status = http.StatusForbidden
			}
			h.writeError(w, status, capability.Code, capability.Message)
			return
		}
		for _, m := range req.Mutations {
			if precheckErr := h.opClient.PrecheckMutation(req.Vault, m.Item, m.Operation, m.Category, m.Fields); precheckErr != nil {
				var verr *opconnect.ValidationError
				if errors.As(precheckErr, &verr) {
					message := verr.Message
					if len(req.Mutations) > 1 {
						message = fmt.Sprintf("%q: %s", m.Item, verr.Message)
					}
					h.writeError(w, http.StatusUnprocessableEntity, "validation", message)
					return
				}
				h.writeError(w, http.StatusServiceUnavailable, "write_capability_unverified", "Could not verify the item against 1Password Connect before requesting approval.")
				return
			}
		}
		if status, code, msg := h.precheckFiles(req); status != 0 {
			h.writeError(w, status, code, msg)
			return
		}
	}
	req.Fingerprint = fingerprintRequest(req)

	// Reads may ride on the global read window. Writes never do: they need a
	// tap, a write window for this requester and vault, or a follow-up grant.
	if session, ok := h.sessions.Match(); ok && !req.IsWrite() {
		req.Approve()
		if err := h.store.Save(req); err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
			return
		}
		h.notifyAutoApprovedRead(req, session.Approver, session.ExpiresAt)
		h.writeJSON(w, http.StatusAccepted, RequestResponse{
			Token:     req.Token,
			StatusURL: h.config.WebhookBaseURL + "/status/" + req.Token,
			ExpiresAt: req.ExpiresAt.Format(time.RFC3339),
			Message:   "Request auto-approved by active approval session.",
		})
		return
	}
	if req.IsWrite() && h.autoApproveWrite(w, req) {
		return
	}

	stored, reused, err := h.store.SaveOrRenew(req, ttl)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
		return
	}
	req = stored
	if reused {
		if !h.refreshApprovalRequest(w, req) {
			return
		}
	} else {
		if !h.deliverApprovalRequest(w, req) {
			return
		}
	}

	message := "Request submitted. Waiting for human approval via Telegram."
	if reused {
		message = "An equivalent approval request is already pending. Secret Gate reused it without sending another Telegram message."
	}
	h.log.Info("Submitted approval request", logger.F(
		"request_id", req.ID,
		"request_reused", reused,
		"action", req.Action,
		"items", len(req.Secrets),
		"machine", req.RequesterMachine,
		"requester_ip", req.RequesterIP,
		"expires_at", req.ExpiresAt.Format(time.RFC3339),
	))
	h.writeJSON(w, http.StatusAccepted, RequestResponse{
		Token:         req.Token,
		StatusURL:     h.config.WebhookBaseURL + "/status/" + req.Token,
		ExpiresAt:     req.ExpiresAt.Format(time.RFC3339),
		Message:       message,
		RequestReused: reused,
	})
}

// normalizeWrites turns the legacy single mutation or a mutations[] batch
// into one list with item titles set. It returns a message on invalid input.
func normalizeWrites(payload BatchRequestPayload, secrets []models.SecretRequest) ([]models.SecretRequest, []models.ItemMutation, string) {
	var mutations []models.ItemMutation
	switch {
	case payload.Mutation != nil && len(payload.Mutations) > 0:
		return nil, nil, "send mutation or mutations, not both"
	case len(payload.Mutations) > 0:
		if len(secrets) > 0 {
			return nil, nil, "batch writes take their items from mutations[]; omit secret_name and secrets"
		}
		if payload.Vault == "" || payload.Vault == "_auto_" {
			return nil, nil, "writes require an explicit vault"
		}
		if len(payload.Mutations) > MaxBatchWrites {
			return nil, nil, fmt.Sprintf("a batch may write at most %d items", MaxBatchWrites)
		}
		seen := make(map[string]bool, len(payload.Mutations))
		for _, m := range payload.Mutations {
			m.Item = strings.TrimSpace(m.Item)
			if m.Item == "" {
				return nil, nil, "every batch entry needs an item title"
			}
			if seen[m.Item] {
				return nil, nil, fmt.Sprintf("%q appears twice in the batch; merge its fields into one entry", m.Item)
			}
			seen[m.Item] = true
			mutations = append(mutations, m)
			secrets = append(secrets, models.SecretRequest{SecretName: m.Item, Vault: payload.Vault})
		}
	case payload.Mutation != nil:
		if len(secrets) != 1 || secrets[0].Vault == "" || secrets[0].Vault == "_auto_" {
			return nil, nil, "writes require exactly one item and an explicit vault"
		}
		m := *payload.Mutation
		m.Item = secrets[0].SecretName
		mutations = []models.ItemMutation{m}
	default:
		return secrets, nil, ""
	}
	for i := range mutations {
		if len(mutations[i].Fields) == 0 && len(mutations[i].Files) == 0 {
			return nil, nil, "every write needs at least one field or file"
		}
		switch mutations[i].Operation {
		case "create":
			mutations[i].Category = opconnect.NormalizeCategory(mutations[i].Category)
		case "update":
		default:
			return nil, nil, "mutation operation must be create or update"
		}
	}
	return secrets, mutations, ""
}

// selectAttachments resolves every "file:" selector against the item's
// attachments. Content is not read here; the approver sees names and sizes.
func selectAttachments(files []opconnect.FileInfo, fields []string) ([]models.Attachment, string) {
	var out []models.Attachment
	var total int64
	for _, f := range fields {
		selector, ok := strings.CutPrefix(f, models.AttachmentPrefix)
		if !ok {
			continue
		}
		file, err := opconnect.FindFile(files, selector)
		if err != nil {
			return nil, err.Error()
		}
		total += file.Size
		out = append(out, models.Attachment{ID: file.ID, Name: file.Name, Size: file.Size})
	}
	if total > models.MaxAttachmentBytes {
		return nil, fmt.Sprintf("requested attachments total %d bytes; Secret Gate releases at most %d bytes per request", total, models.MaxAttachmentBytes)
	}
	return out, ""
}

func checkFileName(name string) string {
	switch {
	case strings.TrimSpace(name) == "":
		return "attachment name is empty"
	case len(name) > 255:
		return "attachment name is longer than 255 bytes"
	case name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00"):
		return fmt.Sprintf("attachment name %q must be a plain file name", name)
	}
	return ""
}

// precheckFiles validates attachments on a write before approval and sets
// each file's size from its content. A zero status means the request has
// no files or every check passed.
func (h *Handler) precheckFiles(req *models.ApprovalRequest) (int, string, string) {
	var total int64
	for i := range req.Mutations {
		m := &req.Mutations[i]
		prefix := ""
		if len(req.Mutations) > 1 {
			prefix = fmt.Sprintf("%q: ", m.Item)
		}
		seen := make(map[string]bool, len(m.Files))
		for j := range m.Files {
			f := &m.Files[j]
			f.Size = int64(len(f.Content))
			if msg := checkFileName(f.Name); msg != "" {
				return http.StatusUnprocessableEntity, "validation", prefix + msg
			}
			if f.Size == 0 {
				return http.StatusUnprocessableEntity, "validation", prefix + fmt.Sprintf("attachment %q is empty", f.Name)
			}
			if seen[f.Name] {
				return http.StatusUnprocessableEntity, "validation", prefix + fmt.Sprintf("attachment %q appears twice", f.Name)
			}
			seen[f.Name] = true
			total += f.Size
		}
	}
	if total == 0 {
		return 0, "", ""
	}
	if total > models.MaxAttachmentBytes {
		return http.StatusRequestEntityTooLarge, "attachment_too_large",
			fmt.Sprintf("attachments total %d bytes; Secret Gate accepts at most %d bytes per request", total, models.MaxAttachmentBytes)
	}
	if h.files == nil {
		return http.StatusServiceUnavailable, "attachments_unavailable",
			"This server cannot attach files: 1Password Connect has no upload endpoint and no 1Password service account (OP_SERVICE_ACCOUNT_TOKEN) is configured."
	}
	vault, err := h.opClient.ResolveVault(req.Vault)
	if err != nil {
		return http.StatusServiceUnavailable, "write_capability_unverified", "Could not resolve the vault before requesting approval."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := h.files.CheckVault(ctx, vault.ID); err != nil {
		h.log.Error("Attachment precheck failed", logger.F("error", err.Error(), "vault", req.Vault))
		return http.StatusServiceUnavailable, "attachments_unavailable", "The 1Password service account cannot access this vault, so files cannot be attached."
	}
	for _, m := range req.Mutations {
		if m.Operation != "update" || len(m.Files) == 0 {
			continue
		}
		item, err := h.opClient.ResolveItem(req.Vault, m.Item)
		if err != nil {
			return http.StatusServiceUnavailable, "write_capability_unverified", "Could not verify the item against 1Password Connect before requesting approval."
		}
		for _, f := range m.Files {
			for _, existing := range item.Files {
				if existing.Name == f.Name {
					return http.StatusUnprocessableEntity, "validation", fmt.Sprintf("%q already has an attachment named %q", m.Item, f.Name)
				}
			}
		}
	}
	return 0, "", ""
}

// windowTTL is the window the approver may open from req's Telegram message.
func (h *Handler) windowTTL(req *models.ApprovalRequest) time.Duration {
	if req.IsWrite() {
		return h.config.WriteWindowTTL
	}
	return h.config.AutoApproveTTL
}

// autoApproveWrite approves req when a live write window or follow-up grant
// covers every write in it. The Telegram audit message must be delivered
// first: if it fails, the write falls back to a normal approval request.
func (h *Handler) autoApproveWrite(w http.ResponseWriter, req *models.ApprovalRequest) bool {
	match, ok := h.grants.Match(writegrant.ScopeOf(req), req.Mutations)
	if !ok {
		return false
	}
	req.Approve()
	req.Approver = match.Approver
	req.AutoApproved = match.Kind
	req.WriteWindowID = match.WindowID
	if !h.notifyWriteAutoApproved(req, match) {
		h.log.Error("Failed to send write auto-approval audit; asking for a tap instead", logger.F("request_id", req.ID))
		req.Status = models.StatusPending
		req.RespondedAt = nil
		req.Approver, req.AutoApproved, req.WriteWindowID = "", "", ""
		return false
	}
	if err := h.store.Save(req); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
		return true
	}
	h.log.Info("Write auto-approved", logger.F(
		"request_id", req.ID,
		"approved_by", match.Kind,
		"window_id", match.WindowID,
		"source_request_id", match.Source,
		"items", len(req.Mutations),
		"vault", req.Vault,
		"machine", req.RequesterMachine,
		"requester_ip", req.RequesterIP,
	))
	message := "Write auto-approved: it updates an item written under an earlier approval."
	if match.Kind == models.AutoApprovedWriteWindow {
		message = "Write auto-approved by the write window opened in Telegram."
	}
	h.writeJSON(w, http.StatusAccepted, RequestResponse{
		Token:     req.Token,
		StatusURL: h.config.WebhookBaseURL + "/status/" + req.Token,
		ExpiresAt: req.ExpiresAt.Format(time.RFC3339),
		Message:   message,
	})
	return true
}

func fingerprintRequest(req *models.ApprovalRequest) string {
	type fingerprintSecret struct {
		Name   string
		Vault  string
		Fields []string
	}
	type fingerprintMutation struct {
		Item      string
		Operation string
		Category  string
		Labels    []string
		Files     []models.Attachment
	}
	secrets := make([]fingerprintSecret, 0, len(req.Secrets))
	for _, secret := range req.Secrets {
		fields := append([]string(nil), secret.Fields...)
		sort.Strings(fields)
		secrets = append(secrets, fingerprintSecret{Name: secret.SecretName, Vault: secret.Vault, Fields: fields})
	}
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].Vault != secrets[j].Vault {
			return secrets[i].Vault < secrets[j].Vault
		}
		return secrets[i].Name < secrets[j].Name
	})
	var mutations []fingerprintMutation
	for _, m := range req.Mutations {
		var files []models.Attachment
		for _, f := range m.Files {
			files = append(files, models.Attachment{Name: f.Name, Size: f.Size})
		}
		mutations = append(mutations, fingerprintMutation{Item: m.Item, Operation: m.Operation, Category: m.Category, Labels: m.Labels(), Files: files})
	}
	canonical := struct {
		Action    string
		Secrets   []fingerprintSecret
		Context   models.RequestContext
		Reason    string
		Mutations []fingerprintMutation
	}{
		Action: req.Action, Secrets: secrets, Context: req.Context,
		Reason: strings.Join(strings.Fields(req.Reason), " "), Mutations: mutations,
	}
	payload, _ := json.Marshal(canonical)
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func normalizeRequesterIP(requesterIP string) string {
	if requesterIP == "" {
		return ""
	}
	if forwarded := strings.Split(requesterIP, ","); len(forwarded) > 0 {
		requesterIP = strings.TrimSpace(forwarded[0])
	}
	if host, _, err := net.SplitHostPort(requesterIP); err == nil {
		return host
	}
	return requesterIP
}

// HandleStatus handles GET /status/{token}
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/status/")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "Token is required")
		return
	}

	req, err := h.store.GetByToken(token)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}

	baseURL := h.config.WebhookBaseURL
	if baseURL == "" {
		h.writeError(w, http.StatusInternalServerError, "config_error", "WEBHOOK_BASE_URL not configured")
		return
	}

	waitParam := r.URL.Query().Get("wait")
	if waitParam != "" && req.Status == models.StatusPending && !req.IsExpired() {
		if waitSec, err := strconv.Atoi(waitParam); err == nil && waitSec > 0 {
			maxWait := h.config.LongPollMaxWait
			if maxWait <= 0 {
				maxWait = 25 * time.Second
			}
			waitDuration := time.Duration(waitSec) * time.Second
			if waitDuration > maxWait {
				waitDuration = maxWait
			}

			watchCh, cancel := h.store.Watch(token)
			if watchCh != nil {
				defer cancel()
				timer := time.NewTimer(waitDuration)
				defer timer.Stop()

				select {
				case <-r.Context().Done():
					return
				case status, ok := <-watchCh:
					if ok {
						if updatedReq, err := h.store.GetByToken(token); err == nil {
							req = updatedReq
						} else {
							req.Status = status
						}
					}
				case <-timer.C:
					if updatedReq, err := h.store.GetByToken(token); err == nil {
						req = updatedReq
					}
				}
			}
		}
	}

	var resp StatusResponse
	switch req.Status {
	case models.StatusPending:
		resp = StatusResponse{
			Status:  "pending",
			Message: "Waiting for human approval. Continue polling this endpoint.",
		}
	case models.StatusApproved:
		resp = StatusResponse{
			Status:    "approved",
			Message:   "Request approved! Retrieve your secret from secret_url.",
			SecretURL: baseURL + "/secret/" + token,
		}
	case models.StatusDenied:
		resp = StatusResponse{
			Status:  "denied",
			Message: "Request was denied by the approver.",
		}
	case models.StatusExpired:
		resp = StatusResponse{
			Status:  "expired",
			Message: "Request has expired. Please submit a new request.",
		}
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// HandleSecret handles GET /secret/{token}
func (h *Handler) HandleSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/secret/")
	if token == "" {
		h.writeError(w, http.StatusBadRequest, "missing_token", "Token is required")
		return
	}

	req, err := h.store.GetByToken(token)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}

	if !req.CanRetrieveSecret() {
		h.writeError(w, http.StatusForbidden, "not_approved", "Request is not approved or has expired")
		return
	}
	if req.IsWrite() {
		h.executeWrites(w, token)
		return
	}

	// Batch mode: multiple secrets requested or field filtering specified
	if len(req.Secrets) > 1 || (len(req.Secrets) == 1 && len(req.Secrets[0].Fields) > 0) {
		result := make(map[string]map[string]string)
		resolvedVaults := make(map[string]string)
		for _, s := range req.Secrets {
			vault := s.Vault
			if vault == "" {
				vault = "_auto_"
			}

			var allFields map[string]string
			var actualName string

			if vault == "_auto_" {
				var err error
				allFields, vault, actualName, err = h.opClient.FindSecretAcrossVaults(s.SecretName)
				if err != nil {
					h.log.Error("Failed to find secret", logger.F("error", err.Error(), "secret", s.SecretName))
					h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", fmt.Sprintf("Failed to retrieve %s: %s", s.SecretName, err.Error()))
					return
				}
			} else {
				var err error
				allFields, err = h.opClient.GetSecret(vault, s.SecretName)
				if err != nil {
					h.log.Error("Failed to fetch secret", logger.F("error", err.Error(), "secret", s.SecretName, "vault", vault))
					h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", fmt.Sprintf("Failed to retrieve %s: %s", s.SecretName, err.Error()))
					return
				}
				actualName = s.SecretName
			}
			resolvedVaults[actualName] = vault

			// Filter fields if specified
			if len(s.Fields) > 0 {
				filtered := make(map[string]string)
				for _, f := range s.Fields {
					// Attachments are released only when named, base64-encoded
					// under their "file:" selector, never with the whole item.
					if selector, ok := strings.CutPrefix(f, models.AttachmentPrefix); ok {
						file, content, err := h.opClient.ReadFile(vault, actualName, selector, models.MaxAttachmentBytes)
						if err != nil {
							h.log.Error("Failed to download attachment", logger.F("error", err.Error(), "request_id", req.ID, "secret", actualName, "file", selector))
							h.writeError(w, http.StatusInternalServerError, "attachment_fetch_failed", fmt.Sprintf("Failed to download attachment %q", selector))
							return
						}
						filtered[f] = base64.StdEncoding.EncodeToString(content)
						h.log.Info("Attachment released", logger.F("request_id", req.ID, "secret", actualName, "file", file.Name, "size", file.Size))
						continue
					}
					if actual, val, ok := core.ResolveField(allFields, f); ok {
						filtered[actual] = val
					}
				}
				result[actualName] = filtered
			} else {
				result[actualName] = allFields
			}
		}

		h.log.Info("Batch secrets retrieved", logger.F("request_id", req.ID, "count", len(result)))
		h.store.Delete(token)
		h.writeJSON(w, http.StatusOK, BatchSecretResponse{Secrets: result, Vaults: resolvedVaults})
		return
	}

	// Legacy single-item mode
	var secret map[string]string
	var actualVault, actualSecret string

	if req.Vault == "_auto_" {
		secret, actualVault, actualSecret, err = h.opClient.FindSecretAcrossVaults(req.SecretName)
		if err != nil {
			h.log.Error("Failed to find secret across vaults", logger.F("error", err.Error(), "request_id", req.ID, "secret", req.SecretName))
			h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", err.Error())
			return
		}
	} else {
		secret, err = h.opClient.GetSecret(req.Vault, req.SecretName)
		if err != nil {
			h.log.Error("Failed to fetch secret from 1Password", logger.F("error", err.Error(), "request_id", req.ID, "secret", req.SecretName, "vault", req.Vault))
			h.writeError(w, http.StatusInternalServerError, "secret_fetch_failed", "Failed to retrieve secret from 1Password")
			return
		}
		actualVault = req.Vault
		actualSecret = req.SecretName
	}

	h.log.Info("Secret retrieved", logger.F("request_id", req.ID, "secret", actualSecret, "vault", actualVault))
	h.store.Delete(token)
	h.writeJSON(w, http.StatusOK, SecretResponse{Secret: secret, Vault: actualVault})
}

// executeWrites performs an approved write request exactly once. Batch items
// are written in order; each success is recorded so a retry after a partial
// failure resumes at the first unwritten item instead of duplicating items.
func (h *Handler) executeWrites(w http.ResponseWriter, token string) {
	claimed, state, claimErr := h.store.ClaimMutation(token)
	if claimErr != nil {
		h.writeError(w, http.StatusForbidden, "not_approved", "Request is not approved or has expired")
		return
	}
	switch state {
	case "completed":
		h.writeJSON(w, http.StatusOK, mutationResponse(claimed, claimed.MutationItems))
		return
	case "executing":
		h.writeError(w, http.StatusConflict, "mutation_in_progress", "Approved mutation is already being executed")
		return
	case "failed":
		h.writeError(w, http.StatusInternalServerError, "mutation_outcome_unknown", "Approved mutation did not reach a recoverable completion state")
		return
	}
	written := make([]string, len(claimed.Mutations))
	copy(written, claimed.MutationItems)
	for i, m := range claimed.Mutations {
		if written[i] != "" {
			continue
		}
		prefix := ""
		if len(claimed.Mutations) > 1 {
			prefix = fmt.Sprintf("Wrote %d of %d items before %q failed. ", countWritten(written), len(claimed.Mutations), m.Item)
		}
		itemID, filesDone := "", 0
		if i < len(claimed.MutationItemIDs) {
			itemID = claimed.MutationItemIDs[i]
			filesDone = claimed.MutationFilesDone[i]
		}
		title := m.Item
		if itemID == "" {
			var item *opconnect.Item
			var err error
			if m.Operation == "update" && len(m.Fields) == 0 {
				item, err = h.opClient.ResolveItem(claimed.Vault, m.Item)
			} else {
				item, err = h.opClient.PutItem(claimed.Vault, m.Item, m.Operation, m.Category, m.Fields)
			}
			if err != nil {
				_ = h.store.ReleaseMutation(token)
				h.log.Error("Failed to write 1Password item", logger.F("error", err.Error(), "request_id", claimed.ID, "item", m.Item, "vault", claimed.Vault, "index", i))
				var verr *opconnect.ValidationError
				if errors.As(err, &verr) {
					h.writeError(w, http.StatusUnprocessableEntity, "validation", prefix+"1Password rejected the item: "+verr.Message)
					return
				}
				h.writeError(w, http.StatusInternalServerError, "item_write_failed", prefix+"Failed to write item to 1Password")
				return
			}
			itemID, title = item.ID, item.Title
			if len(m.Files) > 0 {
				if err := h.store.RecordMutationProgress(token, i, itemID, 0); err != nil {
					h.log.Error("Failed to record written 1Password item", logger.F("error", err.Error(), "request_id", claimed.ID, "index", i))
					h.writeError(w, http.StatusInternalServerError, "mutation_state_failed", "Item was written but completion state could not be recorded")
					return
				}
			}
		}
		if filesDone < len(m.Files) {
			if !h.attachFiles(w, token, claimed, i, itemID, filesDone, prefix) {
				return
			}
		}
		written[i] = title
		if err := h.store.RecordMutationItem(token, i, title); err != nil {
			h.log.Error("Failed to record written 1Password item", logger.F("error", err.Error(), "request_id", claimed.ID, "index", i))
			h.writeError(w, http.StatusInternalServerError, "mutation_state_failed", "Item was written but completion state could not be recorded")
			return
		}
		h.log.Info("1Password item written", logger.F("request_id", claimed.ID, "item", title, "vault", claimed.Vault, "operation", m.Operation, "files", len(m.Files), "approved_by", firstNonEmpty(claimed.AutoApproved, "tap")))
	}
	if err := h.store.CompleteMutation(token); err != nil {
		h.log.Error("Failed to record completed 1Password write", logger.F("error", err.Error(), "request_id", claimed.ID))
		h.writeError(w, http.StatusInternalServerError, "mutation_state_failed", "Item was written but completion state could not be recorded")
		return
	}
	// Follow-up grants come only from tapped or window-approved writes, so a
	// chain of follow-ups can never extend itself past the original grant.
	if claimed.AutoApproved != models.AutoApprovedFollowUp {
		h.grants.GrantFollowUps(writegrant.ScopeOf(claimed), written, claimed.WriteWindowID, claimed.ID, claimed.Approver, h.config.WriteFollowUpTTL)
	}
	h.writeJSON(w, http.StatusOK, mutationResponse(claimed, written))
}

// attachFiles uploads mutation index's files from filesDone onward, recording
// each success. On failure it releases the claim so a retry resumes with the
// file that failed, and writes the error response. File content is never logged.
func (h *Handler) attachFiles(w http.ResponseWriter, token string, claimed *models.ApprovalRequest, index int, itemID string, filesDone int, prefix string) bool {
	m := claimed.Mutations[index]
	fail := func(status int, code, message string) bool {
		_ = h.store.ReleaseMutation(token)
		h.writeError(w, status, code, prefix+message)
		return false
	}
	if h.files == nil {
		return fail(http.StatusServiceUnavailable, "attachments_unavailable", "No 1Password service account is configured to attach files.")
	}
	vault, err := h.opClient.ResolveVault(claimed.Vault)
	if err != nil {
		return fail(http.StatusInternalServerError, "item_write_failed", "Could not resolve the vault to attach files.")
	}
	for j := filesDone; j < len(m.Files); j++ {
		f := m.Files[j]
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		err := h.files.Attach(ctx, vault.ID, itemID, f.Name, f.Content)
		cancel()
		if err != nil {
			h.log.Error("Failed to attach file", logger.F("error", err.Error(), "request_id", claimed.ID, "item", m.Item, "file", f.Name, "size", f.Size))
			return fail(http.StatusBadGateway, "attachment_failed",
				fmt.Sprintf("%q was saved but attaching %q failed. Retry the same request to resume with that file.", m.Item, f.Name))
		}
		if err := h.store.RecordMutationProgress(token, index, itemID, j+1); err != nil {
			h.writeError(w, http.StatusInternalServerError, "mutation_state_failed", "File was attached but completion state could not be recorded")
			return false
		}
		h.log.Info("File attached", logger.F("request_id", claimed.ID, "item", m.Item, "file", f.Name, "size", f.Size))
	}
	return true
}

func countWritten(items []string) int {
	n := 0
	for _, item := range items {
		if item != "" {
			n++
		}
	}
	return n
}

// mutationResponse keeps the single-write shape older clients expect and
// lists every item for batches. It never includes values.
func mutationResponse(req *models.ApprovalRequest, written []string) map[string]any {
	if len(req.Mutations) == 1 {
		item := ""
		if len(written) > 0 {
			item = written[0]
		}
		return map[string]any{"mutation": map[string]any{
			"status": "completed", "operation": req.Mutations[0].Operation, "item": item, "vault": req.Vault,
		}}
	}
	items := make([]map[string]any, 0, len(req.Mutations))
	for i, m := range req.Mutations {
		item := m.Item
		if i < len(written) && written[i] != "" {
			item = written[i]
		}
		items = append(items, map[string]any{"operation": m.Operation, "item": item})
	}
	return map[string]any{"mutations": items, "status": "completed", "vault": req.Vault}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// HandleTelegramAction applies an inline-button tap. data is the button's
// callback data ("action:id"); approver is the tapping Telegram user.
func (h *Handler) answerCallback(callbackID, text string) {
	if callbackID != "" && h.tgClient != nil {
		_ = h.tgClient.AnswerCallbackQuery(callbackID, text)
	}
}

// HandleTelegramAction applies an inline-button tap from Telegram or PushWard.
// data is the button's callback data ("action:id"); approver is the tapping user.
func (h *Handler) HandleTelegramAction(callbackID, data, approver string) {
	action, id, ok := strings.Cut(data, ":")
	if !ok || id == "" {
		h.answerCallback(callbackID, "Invalid callback data")
		return
	}
	if action == "revoke_window" {
		window, dropped, open := h.grants.Revoke(id)
		if !open {
			h.answerCallback(callbackID, "Write window already closed")
			return
		}
		h.answerCallback(callbackID, "Write window revoked")
		if h.tgClient != nil {
			if err := h.tgClient.SendWindowRevoked(window, approver, dropped); err != nil {
				h.log.Error("Failed to confirm write window revocation", logger.F("error", err.Error(), "window_id", window.ID))
			}
		}
		if h.pwClient != nil {
			if err := h.pwClient.SendWindowRevoked(window, approver, dropped); err != nil {
				h.log.Error("Failed to send PushWard write window revocation", logger.F("error", err.Error(), "window_id", window.ID))
			}
		}
		if h.approvals != nil {
			h.approvals.broadcast(ApprovalEvent{
				Type:     "window.revoked",
				WindowID: window.ID,
				Approver: approver,
			})
		}
		h.log.Info("Write window revoked", logger.F("window_id", window.ID, "revoked_by", approver, "follow_up_grants_removed", dropped))
		return
	}

	req, err := h.store.GetByID(id)
	if err == store.ErrNotFound {
		h.answerCallback(callbackID, "Request not found or expired")
		return
	}
	if err != nil {
		h.log.Error("Error fetching request", logger.F("error", err.Error(), "request_id", id))
		h.answerCallback(callbackID, "Internal error")
		return
	}
	if req.Status == models.StatusExpired || (req.Status == models.StatusPending && req.IsExpired()) {
		// Approving now would show "Approved" for a request the agent can no
		// longer complete. Close it instead.
		h.answerCallback(callbackID, "Request expired. Ask the agent to resubmit.")
		h.closeExpired(time.Now())
		return
	}
	if req.Status != models.StatusPending {
		h.answerCallback(callbackID, "Request already processed")
		return
	}

	fromPushWard := callbackID == "" && approver == "pushward"
	switch action {
	case "approve":
		req.Approve()
		req.Approver = approver
		h.updateRequest(req)
		h.answerCallback(callbackID, "Approved!")
		if h.tgClient != nil && req.TelegramMsgID != 0 {
			_ = h.tgClient.UpdateMessageApproved(req.TelegramMsgID, req, approver)
		}
		if !fromPushWard {
			h.resolvePushWard(req)
		}
		h.emitApprovalEvent("approval.approved", req)
		h.log.Info("Request approved", logger.F("request_id", req.ID, "approver", approver, "action", req.Action))

	case "approve_window":
		if req.IsWrite() {
			h.answerCallback(callbackID, "Read windows do not cover writes")
			return
		}
		req.Approve()
		req.Approver = approver
		session := h.sessions.Create(approver, h.config.AutoApproveTTL)
		h.updateRequest(req)
		h.answerCallback(callbackID, "Approved with window")
		if h.tgClient != nil && req.TelegramMsgID != 0 {
			_ = h.tgClient.UpdateMessageApproved(req.TelegramMsgID, req, approver)
		}
		if !fromPushWard {
			h.resolvePushWard(req)
		}
		h.emitApprovalEvent("approval.approved", req)
		h.log.Info("Request approved with auto-approval window", logger.F(
			"request_id", req.ID,
			"session_id", session.ID,
			"approver", approver,
			"expires_at", session.ExpiresAt.Format(time.RFC3339),
		))

	case "approve_writes":
		if !req.IsWrite() || h.config.WriteWindowTTL <= 0 {
			h.answerCallback(callbackID, "Write windows are not available for this request")
			return
		}
		window := h.grants.OpenWindow(approver, req.ID, writegrant.ScopeOf(req), h.config.WriteWindowTTL)
		req.Approve()
		req.Approver = approver
		req.WriteWindowID = window.ID
		h.updateRequest(req)
		h.answerCallback(callbackID, "Approved with write window")
		if h.tgClient != nil && req.TelegramMsgID != 0 {
			_ = h.tgClient.UpdateMessageApprovedWriteWindow(req.TelegramMsgID, req, approver, window)
		}
		if !fromPushWard {
			h.resolvePushWard(req)
		}
		h.emitApprovalEvent("approval.approved", req)
		h.log.Info("Write approved with write window", logger.F(
			"request_id", req.ID,
			"window_id", window.ID,
			"approver", approver,
			"machine", window.Scope.Machine,
			"requester_ip", window.Scope.IP,
			"paseo_agent_id", window.Scope.AgentID,
			"vault", window.Scope.Vault,
			"expires_at", window.ExpiresAt.Format(time.RFC3339),
		))

	case "deny":
		req.Deny()
		req.ScrubMutationValues()
		h.updateRequest(req)
		h.answerCallback(callbackID, "Denied")
		if h.tgClient != nil && req.TelegramMsgID != 0 {
			_ = h.tgClient.UpdateMessageDenied(req.TelegramMsgID, req, approver)
		}
		if !fromPushWard {
			h.resolvePushWard(req)
		}
		h.emitApprovalEvent("approval.denied", req)
		h.log.Info("Request denied", logger.F("request_id", req.ID, "approver", approver, "action", req.Action))

	default:
		h.answerCallback(callbackID, "Unknown action")
	}
}

func (h *Handler) resolvePushWard(req *models.ApprovalRequest) {
	if h.pwClient == nil || req.PushWardSlug == "" {
		return
	}
	if err := h.pwClient.ResolveActivity(req.ID, req.PushWardSlug); err != nil {
		h.log.Error("Failed to resolve PushWard approval activity", logger.F("error", err.Error(), "request_id", req.ID, "slug", req.PushWardSlug))
	}
}

func (h *Handler) notifyWriteBlocked(req *models.ApprovalRequest, message string) {
	if h.tgClient != nil {
		if err := h.tgClient.SendWriteBlocked(req, message); err != nil {
			h.log.Error("Failed to send blocked-write audit notification", logger.F("error", err.Error()))
		}
	}
	if h.pwClient != nil {
		if err := h.pwClient.SendWriteBlocked(req, message); err != nil {
			h.log.Error("Failed to send PushWard blocked-write audit notification", logger.F("error", err.Error()))
		}
	}
}

func (h *Handler) notifyAutoApprovedRead(req *models.ApprovalRequest, approver string, expiresAt time.Time) {
	if h.tgClient != nil {
		if err := h.tgClient.SendAutoApprovedNotification(req, approver, expiresAt); err != nil {
			h.log.Error("Failed to send auto-approval audit notification", logger.F("error", err.Error(), "request_id", req.ID))
		}
	}
	if h.pwClient != nil {
		if err := h.pwClient.SendAutoApprovedNotification(req, approver, expiresAt); err != nil {
			h.log.Error("Failed to send PushWard auto-approval audit notification", logger.F("error", err.Error(), "request_id", req.ID))
		}
	}
}

func (h *Handler) notifyWriteAutoApproved(req *models.ApprovalRequest, match writegrant.Match) bool {
	sent := false
	if h.tgClient != nil {
		if err := h.tgClient.SendWriteAutoApproved(req, match); err != nil {
			h.log.Error("Failed to send Telegram write auto-approval audit", logger.F("error", err.Error(), "request_id", req.ID))
		} else {
			sent = true
		}
	}
	if h.pwClient != nil {
		if err := h.pwClient.SendWriteAutoApproved(req, match); err != nil {
			h.log.Error("Failed to send PushWard write auto-approval audit", logger.F("error", err.Error(), "request_id", req.ID))
		} else {
			sent = true
		}
	}
	if h.hasApproverAPI() {
		sent = true
	}
	return sent
}

func (h *Handler) deliverApprovalRequest(w http.ResponseWriter, req *models.ApprovalRequest) bool {
	ttl := h.windowTTL(req)
	delivered := false
	if h.tgClient != nil {
		msgID, err := h.tgClient.SendApprovalRequest(req, h.config.WebhookBaseURL, ttl)
		if err != nil {
			h.log.Error("Failed to send Telegram approval request", logger.F("error", err.Error(), "request_id", req.ID))
		} else {
			req.TelegramMsgID = msgID
			delivered = true
		}
	}
	if h.pwClient != nil {
		slug, err := h.pwClient.SendApprovalRequest(req, ttl)
		if err != nil {
			h.log.Error("Failed to send PushWard approval request", logger.F("error", err.Error(), "request_id", req.ID))
		} else {
			req.PushWardSlug = slug
			delivered = true
			reqCopy := *req
			h.pwClient.WatchApproval(&reqCopy, slug, func(data, approver string) {
				h.HandleTelegramAction("", data, approver)
			})
		}
	}
	if h.hasApproverAPI() {
		delivered = true
	}
	if !delivered {
		_ = h.store.Delete(req.Token)
		h.writeError(w, http.StatusBadGateway, "telegram_delivery_failed", "Failed to deliver the approval request.")
		return false
	}
	if err := h.store.Update(req); err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to record the approval request.")
		return false
	}
	h.emitApprovalEvent("approval.created", req)
	return true
}

func (h *Handler) refreshApprovalRequest(w http.ResponseWriter, req *models.ApprovalRequest) bool {
	ttl := h.windowTTL(req)
	refreshed := false
	if h.tgClient != nil && req.TelegramMsgID != 0 {
		if err := h.tgClient.UpdateApprovalRequest(req.TelegramMsgID, req, ttl); err != nil {
			h.log.Error("Failed to refresh Telegram approval request", logger.F("error", err.Error(), "request_id", req.ID, "telegram_message_id", req.TelegramMsgID))
		} else {
			refreshed = true
		}
	}
	if h.pwClient != nil {
		if err := h.pwClient.UpdateApprovalRequest(req.PushWardSlug, req, ttl); err != nil {
			h.log.Error("Failed to refresh PushWard approval request", logger.F("error", err.Error(), "request_id", req.ID, "slug", req.PushWardSlug))
		} else {
			refreshed = true
			reqCopy := *req
			h.pwClient.WatchApproval(&reqCopy, req.PushWardSlug, func(data, approver string) {
				h.HandleTelegramAction("", data, approver)
			})
		}
	}
	if h.hasApproverAPI() {
		refreshed = true
	}
	if refreshed {
		h.emitApprovalEvent("approval.updated", req)
	}
	if !refreshed {
		h.writeError(w, http.StatusBadGateway, "telegram_delivery_failed", "Failed to refresh the existing approval request.")
		return false
	}
	return true
}

func (h *Handler) updateRequest(req *models.ApprovalRequest) {
	if err := h.store.Update(req); err != nil {
		h.log.Error("Error updating request", logger.F("error", err.Error(), "request_id", req.ID))
	}
}

// SweepPending sends write reminders shortly before expiry, closes the
// Telegram messages of expired requests, and drops expired write grants.
func (h *Handler) SweepPending(now time.Time) {
	for _, req := range h.store.DueReminders(now, h.config.WriteReminderBefore) {
		sent := false
		if h.tgClient != nil {
			if err := h.tgClient.SendReminder(req); err != nil {
				h.log.Error("Failed to send write approval reminder", logger.F("error", err.Error(), "request_id", req.ID))
			} else {
				sent = true
			}
		}
		if h.pwClient != nil {
			if err := h.pwClient.SendReminder(req); err != nil {
				h.log.Error("Failed to send PushWard write approval reminder", logger.F("error", err.Error(), "request_id", req.ID))
			} else {
				sent = true
			}
		}
		if sent {
			h.log.Info("Sent write approval reminder", logger.F("request_id", req.ID, "expires_at", req.ExpiresAt.Format(time.RFC3339)))
		}
	}
	h.closeExpired(now)
	h.grants.Cleanup()
}

func (h *Handler) closeExpired(now time.Time) {
	for _, req := range h.store.ExpireOverdue(now) {
		h.log.Info("Request expired", logger.F("request_id", req.ID, "action", req.Action, "items", len(req.Secrets), "machine", req.RequesterMachine))
		if h.tgClient != nil && req.TelegramMsgID != 0 {
			if err := h.tgClient.UpdateMessageExpired(req.TelegramMsgID, req); err != nil {
				h.log.Error("Failed to close expired Telegram request", logger.F("error", err.Error(), "request_id", req.ID))
			}
		}
		h.resolvePushWard(req)
		h.emitApprovalEvent("approval.expired", req)
	}
}

// HandleHealth handles GET /health
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// HandleClientDownload handles GET /client/{os}/{arch} and legacy GET /client/{arch}
func (h *Handler) HandleClientDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/client/")
	parts := strings.Split(path, "/")

	var goos, arch string
	switch len(parts) {
	case 1:
		// Legacy: /client/{arch} — assumes linux
		goos = "linux"
		arch = parts[0]
	case 2:
		// New: /client/{os}/{arch}
		goos = parts[0]
		arch = parts[1]
	default:
		h.writeError(w, http.StatusBadRequest, "invalid_path", "Use /client/{os}/{arch} or /client/{arch}")
		return
	}

	if goos != "linux" && goos != "darwin" {
		h.writeError(w, http.StatusBadRequest, "invalid_os", "Supported operating systems: linux, darwin")
		return
	}
	if arch != "amd64" && arch != "arm64" {
		h.writeError(w, http.StatusBadRequest, "invalid_arch", "Supported architectures: amd64, arm64")
		return
	}

	clientPath := "/app/clients/client-" + goos + "-" + arch

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=secret-gate")

	http.ServeFile(w, r, clientPath)
}

// HandleSearch handles POST /search - fuzzy search for secrets
func (h *Handler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload SearchPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	if payload.Query == "" {
		h.writeError(w, http.StatusBadRequest, "missing_query", "query is required")
		return
	}

	limit := payload.Limit
	if limit <= 0 {
		limit = 10
	}

	results, err := h.opClient.SearchSecrets(payload.Query, limit)
	if err != nil {
		h.log.Error("Search failed", logger.F("error", err.Error(), "query", payload.Query))
		h.writeError(w, http.StatusInternalServerError, "search_failed", "Failed to search secrets")
		return
	}

	var items []SearchResultItem
	for _, r := range results {
		items = append(items, SearchResultItem{
			SecretName: r.Item.Title,
			VaultName:  r.VaultName,
			Score:      r.Score,
			MatchType:  r.MatchType,
		})
	}

	h.writeJSON(w, http.StatusOK, SearchResponse{
		Results: items,
		Query:   payload.Query,
	})
}

// HandleFields handles POST /fields - get field metadata without values
func (h *Handler) HandleFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed")
		return
	}

	var payload FieldsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}

	if payload.SecretName == "" {
		h.writeError(w, http.StatusBadRequest, "missing_fields", "secret_name is required")
		return
	}

	meta, err := h.opClient.GetItemFields(payload.Vault, payload.SecretName)
	if err != nil {
		h.log.Error("Failed to get item fields", logger.F("error", err.Error(), "secret", payload.SecretName))
		h.writeError(w, http.StatusInternalServerError, "fields_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, FieldsResponse{
		SecretName: meta.Title,
		VaultName:  meta.Vault,
		Fields:     meta.Fields,
		Files:      meta.Files,
	})
}

// HandleOpenAPI handles GET /openapi.json - returns OpenAPI spec
func (h *Handler) HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed")
		return
	}

	spec := OpenAPISpec()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(spec))
}

// OpenAPISpec returns the OpenAPI 3.0 specification
func OpenAPISpec() string {
	return `{
  "openapi": "3.0.3",
  "info": {
    "title": "Secret Gate API",
    "description": "Human-in-the-loop gateway for approved reads and writes to 1Password items.",
    "version": "0.5.2"
  },
  "servers": [
    {"url": "/", "description": "Relative to deployment URL"}
  ],
  "paths": {
    "/request": {
      "post": {
        "summary": "Request access to one or more secrets",
        "description": "Submits a request to access secrets. A Telegram notification will be sent for human approval. Supports two formats: legacy single-item (secret_name at top level) and batch (secrets array). Use /search to find secret names and /fields to discover available fields before requesting.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "secrets": {
                    "type": "array",
                    "description": "Batch mode: array of secrets to request. Each item specifies a secret and optionally which fields to retrieve.",
                    "items": {
                      "type": "object",
                      "required": ["secret_name"],
                      "properties": {
                        "secret_name": {
                          "type": "string",
                          "description": "Name of the secret to access"
                        },
                        "vault": {
                          "type": "string",
                          "description": "Optional vault name. If omitted, searches across all vaults."
                        },
                        "fields": {
                          "type": "array",
                          "items": {"type": "string"},
                          "description": "Optional list of field labels to retrieve. If omitted, all fields are returned (attachments never are). Name an attachment as file:<name or id> to release its content, base64-encoded under that key. Use /fields to discover labels and attachments."
                        }
                      }
                    }
                  },
                  "secret_name": {
                    "type": "string",
                    "description": "Legacy mode: name of a single secret to access. Use 'secrets' array for batch requests."
                  },
                  "vault": {
                    "type": "string",
                    "description": "Legacy mode: optional vault name. If omitted, searches across all vaults."
                  },
                  "machine": {
                    "type": "string",
                    "description": "Identifier for the requesting machine/agent"
                  },
                  "reason": {
                    "type": "string",
                    "description": "Reason for requesting access (shown in approval notification)"
                  },
                  "action": {
                    "type": "string",
                    "description": "Requested action. Defaults to read; create and update are set from mutation.operation."
                  },
                  "context": {
                    "type": "object",
                    "description": "Human-readable agent context shown in Telegram.",
                    "properties": {
                      "runtime": {"type": "string"},
                      "provider": {"type": "string"},
                      "model": {"type": "string"},
                      "think": {"type": "string"},
                      "project": {"type": "string"},
                      "task": {"type": "string"}
                    }
                  },
                  "mutation": {
                    "type": "object",
                    "description": "Approval-gated item creation or update. Requires one item and an explicit vault.",
                    "required": ["operation"],
                    "properties": {
                      "operation": {"type": "string", "enum": ["create", "update"]},
                      "category": {"type": "string", "description": "1Password category for a new item. Defaults to SECURE_NOTE."},
                      "fields": {"type": "object", "additionalProperties": {"type": "string"}},
                      "files": {"type": "array", "description": "Files to attach (needs a 1Password service account on the server; at most 10 MiB per request). Telegram shows names and sizes only.", "items": {"type": "object", "required": ["name", "content"], "properties": {"name": {"type": "string"}, "content": {"type": "string", "format": "byte"}}}}
                    }
                  },
                  "mutations": {
                    "type": "array",
                    "maxItems": 10,
                    "description": "Batch write: up to 10 creates or updates in the top-level vault behind one approval. Omit secret_name and secrets. Each item may appear once.",
                    "items": {
                      "type": "object",
                      "required": ["item", "operation"],
                      "properties": {
                        "item": {"type": "string", "description": "Item title"},
                        "operation": {"type": "string", "enum": ["create", "update"]},
                        "category": {"type": "string"},
                        "fields": {"type": "object", "additionalProperties": {"type": "string"}},
                        "files": {"type": "array", "items": {"type": "object", "required": ["name", "content"], "properties": {"name": {"type": "string"}, "content": {"type": "string", "format": "byte"}}}}
                      }
                    }
                  }
                }
              },
              "examples": {
                "batch": {
                  "summary": "Batch request for multiple secrets with field filtering",
                  "value": {
                    "secrets": [
                      {"secret_name": "homelab-ssh-key", "fields": ["private_key"]},
                      {"secret_name": "database-credentials", "vault": "Infrastructure", "fields": ["username", "password"]}
                    ],
                    "machine": "ci-runner-01",
                    "reason": "Deploy to production"
                  }
                },
                "legacy": {
                  "summary": "Legacy single-item request",
                  "value": {
                    "secret_name": "homelab-ssh-key",
                    "machine": "ci-runner-01",
                    "reason": "Deploy to production"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "202": {
            "description": "Request accepted, waiting for approval",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "token": {"type": "string", "description": "Unique token for this request. Use with /status/{token} and /secret/{token}."},
                    "status_url": {"type": "string", "description": "URL to poll for approval status"},
                    "expires_at": {"type": "string", "description": "ISO 8601 timestamp when this request expires"},
                    "message": {"type": "string"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/search": {
      "post": {
        "summary": "Search for secrets",
        "description": "Fuzzy search for secrets across all vaults. Use this to find the correct secret name before requesting.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["query"],
                "properties": {
                  "query": {
                    "type": "string",
                    "description": "Search query (supports fuzzy matching)"
                  },
                  "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of results"
                  }
                }
              },
              "example": {"query": "ssh", "limit": 5}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Search results",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "query": {"type": "string"},
                    "results": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "secret_name": {"type": "string"},
                          "vault_name": {"type": "string"},
                          "score": {"type": "number"},
                          "match_type": {"type": "string", "enum": ["exact", "prefix", "contains", "fuzzy"]}
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/fields": {
      "post": {
        "summary": "Get field metadata for a secret",
        "description": "Returns the field labels and types for a secret item without exposing any values. Use this to discover which fields are available before making a batch request with field filtering.",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["secret_name"],
                "properties": {
                  "secret_name": {
                    "type": "string",
                    "description": "Name of the secret to inspect"
                  },
                  "vault": {
                    "type": "string",
                    "description": "Optional vault name. If omitted, searches across all vaults."
                  }
                }
              },
              "example": {"secret_name": "database-credentials"}
            }
          }
        },
        "responses": {
          "200": {
            "description": "Field metadata for the secret",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "secret_name": {"type": "string", "description": "Resolved name of the secret"},
                    "vault_name": {"type": "string", "description": "Vault containing the secret"},
                    "fields": {
                      "type": "array",
                      "description": "List of fields available on this secret",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": {"type": "string", "description": "Stable field ID"},
                          "label": {"type": "string", "description": "Field label"},
                          "type": {"type": "string", "description": "Field type (for example STRING, CONCEALED, URL, EMAIL, OTP, or PASSKEY)"},
                          "purpose": {"type": "string"},
                          "section": {"type": "string", "description": "Section label; combine with the field label as section.label when labels repeat"},
                          "reference": {"type": "string", "description": "1Password secret reference when supplied by Connect"}
                        }
                      }
                    },
                    "files": {
                      "type": "array",
                      "description": "Attachments on this item: metadata only, never content",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": {"type": "string"},
                          "name": {"type": "string"},
                          "size": {"type": "integer", "description": "Bytes"},
                          "section": {"type": "string"}
                        }
                      }
                    }
                  }
                },
                "example": {
                  "secret_name": "database-credentials",
                  "vault_name": "Infrastructure",
                  "fields": [
                    {"label": "username", "type": "STRING"},
                    {"label": "password", "type": "CONCEALED"},
                    {"label": "hostname", "type": "STRING"},
                    {"label": "port", "type": "STRING"}
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/status/{token}": {
      "get": {
        "summary": "Check request status",
        "description": "Poll this endpoint to check if your request has been approved or denied.",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          },
          {
            "name": "wait",
            "in": "query",
            "required": false,
            "description": "Optional long-polling wait duration in seconds (clamped to server maximum, default 25s)",
            "schema": {"type": "integer"}
          }
        ],
        "responses": {
          "200": {
            "description": "Request status",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": {"type": "string", "enum": ["pending", "approved", "denied", "expired"]},
                    "message": {"type": "string"},
                    "secret_url": {"type": "string"}
                  }
                }
              }
            }
          }
        }
      }
    },
    "/secret/{token}": {
      "get": {
        "summary": "Retrieve approved secret(s)",
        "description": "Retrieve the secret after approval. This is a one-time use endpoint - the token is invalidated after retrieval. Returns batch format (secrets map) for batch requests or legacy format (single secret) for legacy requests.",
        "parameters": [
          {
            "name": "token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {
            "description": "Secret data. Response format depends on how the request was made.",
            "content": {
              "application/json": {
                "schema": {
                  "oneOf": [
                    {
                      "type": "object",
                      "description": "Legacy single-item response",
                      "properties": {
                        "secret": {
                          "type": "object",
                          "additionalProperties": {"type": "string"},
                          "description": "Map of field labels to values for the single requested secret"
                        }
                      }
                    },
                    {
                      "type": "object",
                      "description": "Batch response containing multiple secrets",
                      "properties": {
                        "secrets": {
                          "type": "object",
                          "additionalProperties": {
                            "type": "object",
                            "additionalProperties": {"type": "string"}
                          },
                          "description": "Map of secret names to their field label-value maps"
                        }
                      }
                    }
                  ]
                },
                "examples": {
                  "legacy": {
                    "summary": "Legacy single-item response",
                    "value": {
                      "secret": {
                        "username": "admin",
                        "password": "s3cret"
                      }
                    }
                  },
                  "batch": {
                    "summary": "Batch response with multiple secrets",
                    "value": {
                      "secrets": {
                        "homelab-ssh-key": {
                          "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----..."
                        },
                        "database-credentials": {
                          "username": "admin",
                          "password": "s3cret"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/client/{os}/{arch}": {
      "get": {
        "summary": "Download CLI client",
        "description": "Download the pre-compiled CLI client binary for the specified OS and architecture. Legacy path /client/{arch} is also supported (assumes linux).",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "required": true,
            "schema": {"type": "string", "enum": ["linux", "darwin"]}
          },
          {
            "name": "arch",
            "in": "path",
            "required": true,
            "schema": {"type": "string", "enum": ["amd64", "arm64"]}
          }
        ],
        "responses": {
          "200": {
            "description": "Binary file",
            "content": {"application/octet-stream": {}}
          }
        }
      }
    },
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {"200": {"description": "OK"}}
      }
    },
    "/openapi.json": {
      "get": {
        "summary": "OpenAPI specification",
        "responses": {
          "200": {
            "description": "OpenAPI 3.0 spec",
            "content": {"application/json": {}}
          }
        }
      }
    }
  }
}`
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, errCode, message string) {
	h.writeJSON(w, status, ErrorResponse{Error: errCode, Message: message})
}
