package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/logger"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/store"
)

// ApprovalOption describes a one-tap decision an approver client can render.
type ApprovalOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Style string `json:"style"` // primary | secondary | destructive
}

// ApprovalItemView is the value-free view of one secret or item mutation in an approval request.
type ApprovalItemView struct {
	Item      string              `json:"item"`
	Vault     string              `json:"vault,omitempty"`
	Operation string              `json:"operation,omitempty"` // read | create | update
	Category  string              `json:"category,omitempty"`
	Fields    []string            `json:"fields,omitempty"`
	Files     []models.Attachment `json:"files,omitempty"`
	// Card is the masked card ("Mastercard ending 1100, expires 08/2027").
	Card string `json:"card,omitempty"`
	// OwnerFields are labels the approver types on EntryURL.
	OwnerFields []string `json:"owner_fields,omitempty"`
}

// ApprovalView is the metadata-only wire representation of an approval request
// exposed over the Approver API. Secret values and retrieval tokens are never included.
type ApprovalView struct {
	ID               string                `json:"id"`
	Status           models.RequestStatus  `json:"status"`
	Action           string                `json:"action"` // read | create | update | write
	Title            string                `json:"title"`
	Summary          string                `json:"summary"`
	Vault            string                `json:"vault"`
	Reason           string                `json:"reason,omitempty"`
	RequesterMachine string                `json:"requester_machine"`
	RequesterIP      string                `json:"requester_ip,omitempty"`
	Context          models.RequestContext `json:"context,omitempty"`
	Items            []ApprovalItemView    `json:"items"`
	Options          []ApprovalOption      `json:"options,omitempty"`
	RequestedAt      string                `json:"requested_at"`
	ExpiresAt        string                `json:"expires_at"`
	RespondedAt      string                `json:"responded_at,omitempty"`
	Approver         string                `json:"approver,omitempty"`
	AutoApproved     string                `json:"auto_approved,omitempty"`
	WriteWindowID    string                `json:"write_window_id,omitempty"`
	// Sensitive requests (card reads, card or bank account writes, owner entry) offer no windows.
	Sensitive bool `json:"sensitive,omitempty"`
	// EntryURL is the owner entry page while the approver still has to type
	// OwnerFields; approving happens by submitting that page.
	EntryURL string `json:"entry_url,omitempty"`
}

// ApprovalEvent is broadcast over GET /approvals/events (SSE).
type ApprovalEvent struct {
	Type     string        `json:"type"` // snapshot | approval.created | approval.updated | approval.approved | approval.denied | approval.expired | window.revoked
	TS       string        `json:"ts"`
	Approval *ApprovalView `json:"approval,omitempty"`
	Pending  []ApprovalView `json:"pending,omitempty"`
	WindowID string        `json:"window_id,omitempty"`
	Approver string        `json:"approver,omitempty"`
}

// DecideRequest is the JSON body for POST /approvals/{id}/decide.
type DecideRequest struct {
	Action   string `json:"action"`             // approve | approve_window | approve_writes | deny
	Approver string `json:"approver,omitempty"` // e.g. "voice-workspace"
}

// DecideResponse is returned by POST /approvals/{id}/decide.
type DecideResponse struct {
	OK       bool         `json:"ok"`
	Message  string       `json:"message"`
	Approval ApprovalView `json:"approval"`
}

type approvalHub struct {
	mu      sync.Mutex
	clients map[chan ApprovalEvent]struct{}
}

func newApprovalHub() *approvalHub {
	return &approvalHub{
		clients: make(map[chan ApprovalEvent]struct{}),
	}
}

func (hub *approvalHub) subscribe() (chan ApprovalEvent, func()) {
	ch := make(chan ApprovalEvent, 32)
	hub.mu.Lock()
	hub.clients[ch] = struct{}{}
	hub.mu.Unlock()
	return ch, func() {
		hub.mu.Lock()
		delete(hub.clients, ch)
		hub.mu.Unlock()
	}
}

func (hub *approvalHub) broadcast(ev ApprovalEvent) {
	if hub == nil {
		return
	}
	if ev.TS == "" {
		ev.TS = time.Now().UTC().Format(time.RFC3339)
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for ch := range hub.clients {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (h *Handler) hasApproverAPI() bool {
	return strings.TrimSpace(h.config.ApproverToken) != ""
}

func (h *Handler) checkApproverAuth(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(h.config.ApproverToken)
	if expected == "" {
		h.writeError(w, http.StatusNotFound, "not_enabled", "Approver API is not enabled (set SECRET_GATE_APPROVER_TOKEN)")
		return false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok {
		token = strings.TrimSpace(r.Header.Get("X-Approver-Token"))
	}
	token = strings.TrimSpace(token)
	if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "Valid Bearer SECRET_GATE_APPROVER_TOKEN is required")
		return false
	}
	return true
}

func (h *Handler) toApprovalView(req *models.ApprovalRequest) ApprovalView {
	var items []ApprovalItemView
	if req.IsWrite() {
		for _, m := range req.Mutations {
			var files []models.Attachment
			for _, f := range m.Files {
				files = append(files, models.Attachment{Name: f.Name, Size: f.Size})
			}
			items = append(items, ApprovalItemView{
				Item:        m.Item,
				Vault:       req.Vault,
				Operation:   m.Operation,
				Category:    firstNonEmpty(m.TargetCategory, m.Category),
				Fields:      m.Labels(),
				Files:       files,
				OwnerFields: m.OwnerFields,
			})
		}
	} else {
		for _, s := range req.Secrets {
			var fields []string
			for _, f := range s.Fields {
				if !strings.HasPrefix(f, models.AttachmentPrefix) {
					fields = append(fields, f)
				}
			}
			items = append(items, ApprovalItemView{
				Item:      s.SecretName,
				Vault:     s.Vault,
				Operation: "read",
				Fields:    fields,
				Files:     s.Attachments,
				Card:      s.Summary,
			})
		}
	}

	var options []ApprovalOption
	entryURL := ""
	if req.Status == models.StatusPending && !req.IsExpired() {
		ttl := h.windowTTL(req)
		if req.AwaitingOwner() {
			entryURL = h.entryURL(req)
		} else {
			options = append(options, ApprovalOption{ID: "approve", Label: "Approve", Style: "primary"})
		}
		switch {
		case req.Sensitive || ttl <= 0:
			// Card requests are approved one at a time.
		case !req.IsWrite():
			options = append(options, ApprovalOption{ID: "approve_window", Label: "Approve " + shortDuration(ttl), Style: "secondary"})
		default:
			options = append(options, ApprovalOption{ID: "approve_writes", Label: "Approve + " + shortDuration(ttl), Style: "secondary"})
		}
		options = append(options, ApprovalOption{ID: "deny", Label: "Deny", Style: "destructive"})
	}

	respondedAt := ""
	if req.RespondedAt != nil {
		respondedAt = req.RespondedAt.UTC().Format(time.RFC3339)
	}

	return ApprovalView{
		ID:               req.ID,
		Status:           req.Status,
		Action:           req.Action,
		Title:            approvalCardTitle(req),
		Summary:          approvalCardSummary(req),
		Vault:            req.Vault,
		Reason:           req.Reason,
		RequesterMachine: req.RequesterMachine,
		RequesterIP:      req.RequesterIP,
		Context:          req.Context,
		Items:            items,
		Options:          options,
		RequestedAt:      req.RequestedAt.UTC().Format(time.RFC3339),
		ExpiresAt:        req.ExpiresAt.UTC().Format(time.RFC3339),
		RespondedAt:      respondedAt,
		Approver:         req.Approver,
		AutoApproved:     req.AutoApproved,
		WriteWindowID:    req.WriteWindowID,
		Sensitive:        req.Sensitive,
		EntryURL:         entryURL,
	}
}

func approvalCardTitle(req *models.ApprovalRequest) string {
	if req.IsWrite() {
		if len(req.Mutations) == 1 {
			m := req.Mutations[0]
			verb := "Create"
			if m.Operation == "update" {
				verb = "Update"
			}
			return verb + " " + m.Item
		}
		return fmt.Sprintf("Write %d items", len(req.Mutations))
	}
	name := req.SecretName
	if len(req.Secrets) > 0 && req.Secrets[0].SecretName != "" {
		name = req.Secrets[0].SecretName
	}
	return "Read " + firstNonEmpty(name, "item")
}

func approvalCardSummary(req *models.ApprovalRequest) string {
	s := approvalCardTitle(req) + " in " + req.Vault
	if card := cardSummary(req); card != "" {
		s += " (" + card + ")"
	}
	if reason := firstNonEmpty(req.Context.Purpose, req.Reason, req.Context.Task); reason != "" {
		s += ": " + reason
	}
	return s
}

// cardSummary returns the masked card of a single-card read, if any.
func cardSummary(req *models.ApprovalRequest) string {
	for _, s := range req.Secrets {
		if s.Summary != "" {
			return s.Summary
		}
	}
	return ""
}

func shortDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}

func (h *Handler) pendingApprovalViews() []ApprovalView {
	list := h.store.ListPending()
	sort.Slice(list, func(i, j int) bool {
		return list[i].RequestedAt.Before(list[j].RequestedAt)
	})
	views := make([]ApprovalView, 0, len(list))
	for _, req := range list {
		views = append(views, h.toApprovalView(req))
	}
	return views
}

func (h *Handler) emitApprovalEvent(eventType string, req *models.ApprovalRequest) {
	if h.approvals == nil || req == nil {
		return
	}
	view := h.toApprovalView(req)
	h.approvals.broadcast(ApprovalEvent{
		Type:     eventType,
		Approval: &view,
	})
}

// HandleApprovals routes GET /approvals, GET /approvals/events,
// POST /approvals/{id}/decide, and POST /approvals/windows/{id}/revoke.
func (h *Handler) HandleApprovals(w http.ResponseWriter, r *http.Request) {
	if !h.checkApproverAuth(w, r) {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/approvals")
	path = strings.TrimPrefix(path, "/")

	switch {
	case path == "" && r.Method == http.MethodGet:
		h.writeJSON(w, http.StatusOK, map[string]any{
			"pending": h.pendingApprovalViews(),
		})
	case path == "events" && r.Method == http.MethodGet:
		h.handleApprovalEvents(w, r)
	case strings.HasPrefix(path, "windows/") && strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
		windowID := strings.TrimSuffix(strings.TrimPrefix(path, "windows/"), "/revoke")
		h.handleWindowRevoke(w, r, windowID)
	case strings.HasSuffix(path, "/decide") && r.Method == http.MethodPost:
		id := strings.TrimSuffix(path, "/decide")
		h.handleApprovalDecide(w, r, id)
	case !strings.Contains(path, "/") && path != "" && r.Method == http.MethodGet:
		req, err := h.store.GetByID(path)
		if err == store.ErrNotFound {
			h.writeError(w, http.StatusNotFound, "not_found", "Approval request not found")
			return
		}
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to load approval request")
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"approval": h.toApprovalView(req)})
	default:
		h.writeError(w, http.StatusNotFound, "not_found", "Unknown approvals endpoint")
	}
}

func (h *Handler) handleApprovalEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "streaming_unsupported", "Streaming is not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	ch, unsub := h.approvals.subscribe()
	defer unsub()

	snapshot := ApprovalEvent{
		Type:    "snapshot",
		TS:      time.Now().UTC().Format(time.RFC3339),
		Pending: h.pendingApprovalViews(),
	}
	if data, err := json.Marshal(snapshot); err == nil {
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			_, _ = fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case ev := <-ch:
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *Handler) handleApprovalDecide(w http.ResponseWriter, r *http.Request, id string) {
	var body DecideRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON payload")
		return
	}
	action := strings.TrimSpace(body.Action)
	switch action {
	case "approve", "approve_window", "approve_writes", "deny":
	default:
		h.writeError(w, http.StatusBadRequest, "unknown_option", "action must be approve, approve_window, approve_writes, or deny")
		return
	}
	approver := firstNonEmpty(strings.TrimSpace(body.Approver), "approver-api")

	req, err := h.store.GetByID(id)
	if err == store.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "not_found", "Request not found or expired")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve request")
		return
	}
	if req.Status == models.StatusExpired || (req.Status == models.StatusPending && req.IsExpired()) {
		h.closeExpired(time.Now())
		h.writeError(w, http.StatusGone, "alert_moved_on", "Request expired. Ask the agent to resubmit.")
		return
	}
	if req.Status != models.StatusPending {
		h.writeError(w, http.StatusConflict, "already_processed", "Request was already processed")
		return
	}
	if action == "approve_window" && req.IsWrite() {
		h.writeError(w, http.StatusBadRequest, "unknown_option", "Read windows do not cover writes")
		return
	}
	if action == "approve_writes" && (!req.IsWrite() || h.config.WriteWindowTTL <= 0) {
		h.writeError(w, http.StatusBadRequest, "unknown_option", "Write windows are not available for this request")
		return
	}

	h.HandleTelegramAction("", action+":"+id, approver)
	updated, err := h.store.GetByID(id)
	if err != nil {
		updated = req
	}
	msg := "Approved"
	if action == "deny" {
		msg = "Denied"
	}
	h.writeJSON(w, http.StatusOK, DecideResponse{
		OK:       true,
		Message:  msg,
		Approval: h.toApprovalView(updated),
	})
}

func (h *Handler) handleWindowRevoke(w http.ResponseWriter, r *http.Request, windowID string) {
	var body struct {
		Approver string `json:"approver,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	approver := firstNonEmpty(strings.TrimSpace(body.Approver), "approver-api")

	window, dropped, open := h.grants.Revoke(windowID)
	if !open {
		h.writeError(w, http.StatusConflict, "already_closed", "Write window already closed")
		return
	}
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
	h.writeJSON(w, http.StatusOK, map[string]any{
		"ok":                        true,
		"window_id":                 window.ID,
		"follow_up_grants_removed": dropped,
	})
}
