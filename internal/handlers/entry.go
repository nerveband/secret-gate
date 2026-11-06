package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/nerveband/secret-gate/internal/logger"
	"github.com/nerveband/secret-gate/internal/models"
	"github.com/nerveband/secret-gate/internal/opconnect"
)

// EntryApprover is recorded as the approver of writes completed on the
// owner entry page.
const EntryApprover = "owner entry page"

// maxEntryBody bounds the entry form body.
const maxEntryBody = 64 << 10

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// entryURL is the owner entry page of req, linked from Telegram and the
// authenticated Approver API only.
func (h *Handler) entryURL(req *models.ApprovalRequest) string {
	return req.EntryURL
}

// pendingByEntryToken finds the pending request whose entry token matches.
func (h *Handler) pendingByEntryToken(token string) *models.ApprovalRequest {
	if len(token) != 64 {
		return nil
	}
	for _, req := range h.store.ListPending() {
		if req.EntryToken != "" && subtle.ConstantTimeCompare([]byte(req.EntryToken), []byte(token)) == 1 {
			return req
		}
	}
	return nil
}

type entryInput struct {
	Name, Label, Type, Mode, Placeholder string
}

type entryItem struct {
	Title, Operation, Category string
	Inputs                     []entryInput
}

type entryPage struct {
	Requester, Reason, Vault, Error, Expires string
	Items                                    []entryItem
	Done                                     bool
}

var entryTemplate = template.Must(template.New("entry").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Secret Gate: enter values</title>
<style>
body{font:16px -apple-system,system-ui,sans-serif;margin:0;padding:24px;max-width:520px;margin:auto;color:#111}
h1{font-size:20px} .meta{color:#555;font-size:14px} .err{background:#fde8e8;color:#8a1111;padding:10px;border-radius:8px}
fieldset{border:1px solid #ddd;border-radius:10px;margin:16px 0;padding:12px}
label{display:block;margin:10px 0 4px;font-weight:600} input{font:inherit;width:100%;box-sizing:border-box;padding:10px;border:1px solid #bbb;border-radius:8px}
button{font:inherit;margin-top:16px;padding:12px 18px;border:0;border-radius:10px;background:#1a7f37;color:#fff;width:100%}
</style></head><body>
{{if .Done}}<h1>Saved</h1><p>The values were handed to Secret Gate, which writes them to 1Password now. You can close this page.</p>
{{else}}<h1>Enter values for Secret Gate</h1>
<p class="meta">Requested by {{.Requester}} for the "{{.Vault}}" vault. Expires {{.Expires}}.</p>
<p><b>{{.Reason}}</b></p>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" autocomplete="off">
{{range .Items}}<fieldset><legend>{{.Operation}} {{.Title}} ({{.Category}})</legend>
{{range .Inputs}}<label for="{{.Name}}">{{.Label}}</label>
<input id="{{.Name}}" name="{{.Name}}" type="{{.Type}}" inputmode="{{.Mode}}" placeholder="{{.Placeholder}}" autocomplete="off" autocapitalize="off" spellcheck="false" required>
{{end}}</fieldset>{{end}}
<button type="submit">Save to 1Password</button>
</form>
<p class="meta">Submitting approves this write. To refuse it, tap Deny in Telegram.</p>
{{end}}</body></html>`))

func entryInputFor(category, label, name string) entryInput {
	in := entryInput{Name: name, Label: label, Type: "text", Mode: "text"}
	switch opconnect.FieldType(category, label) {
	case "CREDIT_CARD_NUMBER":
		in.Type, in.Mode, in.Placeholder = "password", "numeric", "card number"
	case "CONCEALED":
		in.Type = "password"
		if n := strings.ToLower(label); strings.Contains(n, "cvv") || strings.Contains(n, "cvc") || n == "pin" || strings.Contains(n, "verification") || strings.Contains(n, "security code") {
			in.Mode = "numeric"
		}
	case "MONTH_YEAR":
		in.Mode, in.Placeholder = "numeric", "MM/YY"
	case "DATE":
		in.Type = "date"
	}
	return in
}

// entryPageFor describes req's owner fields. Values are never rendered.
func entryPageFor(req *models.ApprovalRequest, message string) entryPage {
	page := entryPage{
		Requester: firstNonEmpty(req.Context.Provider, req.Context.Runtime, req.RequesterMachine, "an agent"),
		Reason:    firstNonEmpty(req.Reason, req.Context.Task),
		Vault:     req.Vault,
		Error:     message,
		Expires:   req.ExpiresAt.Format("15:04 MST"),
	}
	for i, m := range req.Mutations {
		if len(m.OwnerFields) == 0 {
			continue
		}
		category := firstNonEmpty(m.TargetCategory, opconnect.NormalizeCategory(m.Category))
		item := entryItem{Title: m.Item, Operation: operationTitle(m.Operation), Category: category}
		for j, label := range m.OwnerFields {
			item.Inputs = append(item.Inputs, entryInputFor(category, label, fmt.Sprintf("f_%d_%d", i, j)))
		}
		page.Items = append(page.Items, item)
	}
	return page
}

func operationTitle(op string) string {
	if op == "update" {
		return "Update"
	}
	return "Create"
}

func (h *Handler) renderEntry(w http.ResponseWriter, status int, page entryPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_ = entryTemplate.Execute(w, page)
}

// HandleEntry serves GET/POST /entry/{token}: the approver types the owner
// fields of a pending write on their own device, which approves the write.
// Values are never logged, echoed back, or sent to Telegram.
func (h *Handler) HandleEntry(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/entry/")
	notFound := func() {
		h.renderEntry(w, http.StatusNotFound, entryPage{Error: "This link has expired or was already used.", Done: false})
	}
	switch r.Method {
	case http.MethodGet:
		req := h.pendingByEntryToken(token)
		if req == nil || !req.AwaitingOwner() {
			notFound()
			return
		}
		h.renderEntry(w, http.StatusOK, entryPageFor(req, ""))
	case http.MethodPost:
		h.requestMu.Lock()
		defer h.requestMu.Unlock()
		req := h.pendingByEntryToken(token)
		if req == nil || !req.AwaitingOwner() {
			notFound()
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxEntryBody)
		if err := r.ParseForm(); err != nil {
			h.renderEntry(w, http.StatusBadRequest, entryPageFor(req, "The form could not be read. Try again."))
			return
		}
		mutations, message := fillOwnerFields(req.Mutations, r.PostForm)
		if message != "" {
			h.renderEntry(w, http.StatusUnprocessableEntity, entryPageFor(req, message))
			return
		}
		req.Mutations = mutations
		req.Approve()
		req.Approver = EntryApprover
		h.updateRequest(req)
		if h.tgClient != nil && req.TelegramMsgID != 0 {
			if err := h.tgClient.UpdateMessageApproved(req.TelegramMsgID, req, EntryApprover); err != nil {
				h.log.Error("Failed to update Telegram after owner entry", logger.F("error", err.Error(), "request_id", req.ID))
			}
		}
		h.resolvePushWard(req)
		h.emitApprovalEvent("approval.approved", req)
		h.log.Info("Write approved on the owner entry page", logger.F("request_id", req.ID, "items", len(req.Mutations), "vault", req.Vault))
		h.renderEntry(w, http.StatusOK, entryPage{Done: true, Expires: time.Now().Format("15:04 MST")})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// fillOwnerFields returns copies of mutations with the owner-entered values
// set, or a message naming the first problem. Messages never include values.
func fillOwnerFields(mutations []models.ItemMutation, form map[string][]string) ([]models.ItemMutation, string) {
	out := make([]models.ItemMutation, len(mutations))
	for i, m := range mutations {
		fields := make(map[string]string, len(m.Fields)+len(m.OwnerFields))
		for k, v := range m.Fields {
			fields[k] = v
		}
		for j, label := range m.OwnerFields {
			values := form[fmt.Sprintf("f_%d_%d", i, j)]
			value := ""
			if len(values) > 0 {
				value = strings.TrimSpace(values[0])
			}
			if value == "" {
				return nil, fmt.Sprintf("%q needs a value.", label)
			}
			fields[label] = value
		}
		category := firstNonEmpty(m.TargetCategory, opconnect.NormalizeCategory(m.Category))
		if err := opconnect.ValidateTypedFields(category, fields); err != nil {
			var verr *opconnect.ValidationError
			if errors.As(err, &verr) {
				return nil, fmt.Sprintf("%s: %s", m.Item, verr.Message)
			}
			return nil, "The values could not be checked."
		}
		m.Fields = fields
		out[i] = m
	}
	return out, ""
}
