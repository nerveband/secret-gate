package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nerveband/secret-gate/internal/audit"
	"github.com/nerveband/secret-gate/internal/config"
	"github.com/nerveband/secret-gate/internal/logger"
	"github.com/nerveband/secret-gate/internal/models"
	"github.com/nerveband/secret-gate/internal/opconnect"
	"github.com/nerveband/secret-gate/internal/ownerwindow"
	"github.com/nerveband/secret-gate/internal/settings"
	"github.com/nerveband/secret-gate/internal/telegram"
	"github.com/nerveband/secret-gate/internal/tz"
)

// ControlTelegram is the owner's command surface in Telegram: plain
// messages with buttons, and edits of those messages.
type ControlTelegram interface {
	Send(text string, keyboard *telegram.InlineKeyboardMarkup) (int, error)
	Edit(messageID int, text string, keyboard *telegram.InlineKeyboardMarkup) error
}

const (
	confirmTTL         = 2 * time.Minute
	maxPendingConfirms = 3
	maxCommandAge      = 2 * time.Minute
	counterEditEvery   = 10 * time.Second
	opensPerHour       = 6
	minWindow          = 5 * time.Minute
	rejectLogEvery     = time.Minute
)

// Window sources recorded in audit lines.
const (
	sourcePanel   = "telegram-panel"
	sourceCommand = "telegram-command"
	sourceAPI     = "api"
)

var (
	errOwnerDisabled = errors.New("phone windows are off")
	errNoVault       = errors.New("no vault is configured for owner windows")
	errUnknownVault  = errors.New("that vault is not configured for owner windows")
	errAuditDown     = errors.New("the window audit message could not be delivered")
	errBadMinutes    = errors.New("minutes out of range")
)

// openConfirm is a window waiting for the owner's second tap.
type openConfirm struct {
	minutes   int
	vault     string
	source    string
	userID    int64
	messageID int
	expires   time.Time
}

// SetControl enables the Telegram command surface.
func (h *Handler) SetControl(c ControlTelegram) { h.ctl = c }

// SetSettings replaces the runtime settings store.
func (h *Handler) SetSettings(s *settings.Store) { h.settings = s }

// SetAudit sets where owner window and settings events are written.
func (h *Handler) SetAudit(a *audit.Log) { h.audit = a }

// OwnerWindows exposes the window store to the server's sweeper and tests.
func (h *Handler) OwnerWindows() *ownerwindow.Store { return h.owner }

func (h *Handler) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}

func settingsDefaults(cfg *config.Config) settings.Defaults {
	mode := cfg.TelegramNotifications
	if mode == "" {
		mode = settings.NotifyOn
	}
	return settings.Defaults{TelegramNotifications: mode, OwnerWindows: cfg.OwnerWindowEnabled, TapWindows: true, Timezone: cfg.Timezone}
}

func (h *Handler) settingsValues() settings.Values { return h.settings.Get() }

// telegramMode is the alert mode in effect. "Off" only holds while PushWard
// can deliver alerts; with no other channel it acts as "silent", so a
// request is never left without a message.
func (h *Handler) telegramMode() string {
	mode := h.settingsValues().TelegramNotifications
	if mode == settings.NotifyOff && h.pwClient == nil {
		return settings.NotifySilent
	}
	return mode
}

// TelegramSilent reports whether Telegram messages should arrive without a push.
func (h *Handler) TelegramSilent() bool { return h.telegramMode() != settings.NotifyOn }

// tg returns the Telegram client for unprompted alerts, or nil when alerts
// are off. Replies to the owner's own taps and commands never use it.
func (h *Handler) tg() telegramClient {
	if h.tgClient == nil || h.telegramMode() == settings.NotifyOff {
		return nil
	}
	return h.tgClient
}

func (h *Handler) tapWindowsEnabled() bool { return h.settingsValues().TapWindows }

func (h *Handler) ownerWindowsEnabled() bool {
	return h.settingsValues().OwnerWindows && len(h.config.OwnerWindowVaults) > 0
}

func (h *Handler) ownerTTL() time.Duration {
	if h.config.OwnerWindowTTL > 0 {
		return h.config.OwnerWindowTTL
	}
	return config.DefaultOwnerWindowTTL
}

func (h *Handler) ownerMax() time.Duration {
	max := h.config.OwnerWindowMax
	if max <= 0 {
		max = config.DefaultOwnerWindowMax
	}
	if max > config.OwnerWindowCeiling {
		max = config.OwnerWindowCeiling
	}
	return max
}

func (h *Handler) ownerLimits() ownerwindow.Limits {
	daily := h.config.OwnerWindowDailyMax
	if daily <= 0 {
		daily = config.DefaultOwnerWindowDailyMax
	}
	return ownerwindow.Limits{Ceiling: h.ownerMax(), OpensPerHour: opensPerHour, DailyMax: daily}
}

func (h *Handler) ownerBudget() (requests, items int) {
	requests, items = h.config.OwnerWindowMaxRequests, h.config.OwnerWindowMaxItems
	if requests <= 0 {
		requests = config.DefaultOwnerWindowMaxRequests
	}
	if items <= 0 {
		items = config.DefaultOwnerWindowMaxItems
	}
	return requests, items
}

// fieldLabels lists every field label and ID on an item.
func fieldLabels(meta *opconnect.ItemMeta) []string {
	var out []string
	for _, f := range meta.Fields {
		if f.Label != "" {
			out = append(out, f.Label)
		}
		if f.ID != "" {
			out = append(out, f.ID)
		}
	}
	return out
}

func (h *Handler) ownerTag() string { return h.policy.Tag }

func windowView(w ownerwindow.Window) telegram.WindowView {
	return telegram.WindowView{
		ID: w.ID, Vault: w.Vault, Tag: w.Tag, Source: w.Source, Opener: w.Opener,
		OpenedAt: w.OpenedAt, ExpiresAt: w.ExpiresAt, ClosedAt: w.ClosedAt,
		Requests: w.Requests, MaxRequests: w.MaxRequests, Items: w.Items, MaxItems: w.MaxItems,
	}
}

func windowViews(ws []ownerwindow.Window) []telegram.WindowView {
	out := make([]telegram.WindowView, 0, len(ws))
	for _, w := range ws {
		out = append(out, windowView(w))
	}
	return out
}

// ---------------------------------------------------------------------------
// Coverage of reads

// legacyCovers reports whether the older tap-opened window may approve a
// read. It still covers everything except Secret Gate's own credentials,
// passkeys, and attachments.
func (h *Handler) legacyCovers(req *models.ApprovalRequest, items []ownerwindow.Item) bool {
	for _, it := range items {
		if ok, reason := h.policy.CheckLegacy(it); !ok {
			req.WindowNote = ownerwindow.ReasonText(reason)
			h.audit.Event(audit.WindowNotCovered, map[string]any{"window": "tap", "request_id": req.ID, "item": it.Title, "reason": reason})
			return false
		}
	}
	return true
}

// tryOwnerWindow approves a read that an open owner window covers. It
// reports true when it answered the HTTP request.
func (h *Handler) tryOwnerWindow(w http.ResponseWriter, req *models.ApprovalRequest, items []ownerwindow.Item) bool {
	if !h.ownerWindowsEnabled() {
		return false
	}
	res := h.owner.Take(ownerwindow.TakeRequest{
		Items: items, Machine: req.RequesterMachine, AgentID: req.Context.PaseoAgentID, Policy: h.policy,
	})
	if res.Closed != nil {
		h.announceClosed(*res.Closed, "")
	}
	if !res.Covered {
		if res.Reason != ownerwindow.ReasonNoWindow {
			req.WindowNote = ownerwindow.ReasonText(res.Reason)
			h.audit.Event(audit.WindowNotCovered, map[string]any{
				"window": res.Window.ID, "request_id": req.ID, "items": titles(items), "reason": res.Reason,
				"machine": req.RequesterMachine, "agent_id": req.Context.PaseoAgentID,
			})
		}
		return false
	}
	if len(res.NewItems) > 0 && !h.announceUse(res, req) {
		h.owner.Release(res)
		req.WindowNote = ownerwindow.ReasonText(ownerwindow.ReasonAudit)
		h.audit.Event(audit.WindowNotCovered, map[string]any{
			"window": res.Window.ID, "request_id": req.ID, "items": titles(items), "reason": ownerwindow.ReasonAudit,
		})
		return false
	}
	req.Approve()
	req.Approver = res.Window.Opener
	req.AutoApproved = models.AutoApprovedOwnerWindow
	req.WriteWindowID = res.Window.ID
	req.WindowExpiresAt = res.Window.ExpiresAt
	if err := h.store.Save(req); err != nil {
		h.owner.Release(res)
		h.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to save request")
		return true
	}
	h.audit.Event(audit.WindowUsed, map[string]any{
		"window": res.Window.ID, "request_id": req.ID, "items": titles(items), "vault": res.Window.Vault,
		"fields": requestedFieldNames(req), "machine": req.RequesterMachine, "requester_ip": req.RequesterIP,
		"agent_id": req.Context.PaseoAgentID, "project": req.Context.Project,
		"requests": res.Window.Requests, "distinct_items": len(res.Window.Items),
	})
	h.emitWindowEvent("window.used", res.Window, "")
	h.writeJSON(w, http.StatusAccepted, RequestResponse{
		Token:     req.Token,
		StatusURL: h.config.WebhookBaseURL + "/status/" + req.Token,
		ExpiresAt: req.ExpiresAt.Format(time.RFC3339),
		Message:   "Request auto-approved by the read window the owner opened.",
	})
	return true
}

func titles(items []ownerwindow.Item) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Title)
	}
	return out
}

func requestedFieldNames(req *models.ApprovalRequest) []string {
	var out []string
	for _, s := range req.Secrets {
		for _, f := range s.Fields {
			if !strings.HasPrefix(f, models.AttachmentPrefix) {
				out = append(out, f)
			}
		}
	}
	return out
}

func agentLine(req *models.ApprovalRequest) string {
	var parts []string
	for _, p := range []string{firstNonEmpty(req.Context.Provider, req.Context.Runtime), req.Context.Project, req.RequesterMachine} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

// announceUse sends the first-use audit for newly covered items. It reports
// whether at least one channel delivered it.
func (h *Handler) announceUse(res ownerwindow.TakeResult, req *models.ApprovalRequest) bool {
	use := telegram.WindowUse{
		Window: windowView(res.Window), Items: res.NewItems, Fields: requestedFieldNames(req),
		Agent: agentLine(req), Reason: firstNonEmpty(req.Reason, req.Context.Task), Request: req.ID,
	}
	delivered := false
	if h.ctl != nil && h.telegramMode() != settings.NotifyOff {
		text, kb := telegram.WindowUsedMessage(use)
		if _, err := h.ctl.Send(text, kb); err != nil {
			h.log.Error("Failed to send window use audit to Telegram", logger.F("error", err.Error(), "window", res.Window.ID))
		} else {
			delivered = true
		}
	}
	if h.pwClient != nil {
		title := "📖 Read via window: " + strings.Join(res.NewItems, ", ")
		body := fmt.Sprintf("%s in %q, %d of %d reads.\nBy: %s", fieldSummary(use.Fields), res.Window.Vault, res.Window.Requests, res.Window.MaxRequests, use.Agent)
		if err := h.pwClient.SendAudit(title, res.Window.Vault, body, "active"); err != nil {
			h.log.Error("Failed to send window use audit to PushWard", logger.F("error", err.Error(), "window", res.Window.ID))
		} else {
			delivered = true
		}
	}
	return delivered
}

func fieldSummary(fields []string) string {
	if len(fields) == 0 {
		return "All fields"
	}
	return "Fields: " + strings.Join(fields, ", ")
}

// markWindowRelease prepares values released under an owner window. Every
// value becomes process-only, so clients refuse to show it to the model and
// cap its cache at 15 minutes, and the release carries the time after which
// it must not be kept (the window's end plus a short grace).
func markWindowRelease(req *models.ApprovalRequest, values map[string]string) {
	markProcessOnly(values)
	if !req.WindowExpiresAt.IsZero() {
		values[models.ExpiresAtKey] = req.WindowExpiresAt.Add(models.WindowCacheGrace).UTC().Format(time.RFC3339)
	}
}

// markProcessOnly is the part of markWindowRelease that lists every value as
// process-only. Keys the marker format cannot carry are dropped rather than
// left unprotected.
func markProcessOnly(values map[string]string) {
	set := map[string]bool{}
	for _, k := range strings.Split(values[models.ProcessOnlyKey], ",") {
		if k = strings.TrimSpace(k); k != "" {
			set[k] = true
		}
	}
	for k := range values {
		if models.IsReservedKey(k) {
			continue
		}
		if strings.Contains(k, ",") {
			delete(values, k)
			continue
		}
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	values[models.ProcessOnlyKey] = strings.Join(keys, ",")
}

// ---------------------------------------------------------------------------
// Opening, closing, announcing

// openRequest asks to open a window.
type openRequest struct {
	Minutes int
	Vault   string
	Source  string
	Opener  string
	Machine string
	AgentID string
	// ConfirmMessage is the Telegram confirm card to turn into the window
	// card; zero when the window was not opened from Telegram.
	ConfirmMessage int
}

// resolveVault picks the configured vault named by the owner, or the first.
func (h *Handler) resolveVault(name string) (string, error) {
	vaults := h.config.OwnerWindowVaults
	if len(vaults) == 0 {
		return "", errNoVault
	}
	if strings.TrimSpace(name) == "" {
		return vaults[0], nil
	}
	for _, v := range vaults {
		if strings.EqualFold(v, strings.TrimSpace(name)) {
			return v, nil
		}
	}
	return "", errUnknownVault
}

// resolveMinutes returns the window length for a request of m minutes
// (0 means the default) or errBadMinutes.
func (h *Handler) resolveMinutes(m int) (time.Duration, error) {
	if m == 0 {
		return h.ownerTTL(), nil
	}
	d := time.Duration(m) * time.Minute
	if d < minWindow || d > h.ownerMax() {
		return 0, errBadMinutes
	}
	return d, nil
}

// openOwnerWindow opens a window and delivers its audit message. When no
// channel can deliver it, the window is closed again and nothing stays open.
func (h *Handler) openOwnerWindow(r openRequest) (ownerwindow.Window, error) {
	if !h.ownerWindowsEnabled() {
		return ownerwindow.Window{}, errOwnerDisabled
	}
	vault, err := h.resolveVault(r.Vault)
	if err != nil {
		return ownerwindow.Window{}, err
	}
	ttl, err := h.resolveMinutes(r.Minutes)
	if err != nil {
		return ownerwindow.Window{}, err
	}
	requests, items := h.ownerBudget()
	win, err := h.owner.Open(ownerwindow.OpenParams{
		Vault: vault, Tag: h.ownerTag(), Source: r.Source, Opener: r.Opener, TTL: ttl,
		MaxRequests: requests, MaxItems: items, Machine: r.Machine, AgentID: r.AgentID,
	}, h.ownerLimits())
	if err != nil {
		return win, err
	}
	if !h.announceOpened(win, r.ConfirmMessage) {
		h.owner.Revoke(win.ID, ownerwindow.ReasonAudit)
		h.audit.Event(audit.WindowRejected, map[string]any{"reason": ownerwindow.ReasonAudit, "source": r.Source, "opener": r.Opener})
		return ownerwindow.Window{}, errAuditDown
	}
	h.audit.Event(audit.WindowOpened, map[string]any{
		"window": win.ID, "source": r.Source, "opener": r.Opener, "vault": win.Vault, "tag": win.Tag,
		"expires_at": win.ExpiresAt.Format(time.RFC3339), "max_requests": win.MaxRequests, "max_items": win.MaxItems,
		"machine_pin": win.Machine, "agent_pin": win.AgentID,
	})
	h.emitWindowEvent("window.opened", win, "")
	return win, nil
}

// announceOpened shows the window card and alerts every channel. It reports
// whether at least one delivered.
func (h *Handler) announceOpened(win ownerwindow.Window, confirmMessage int) bool {
	delivered := false
	text, kb := telegram.WindowOpenedMessage(windowView(win))
	if h.ctl != nil {
		if confirmMessage != 0 {
			// Opened from Telegram: the confirm card becomes the window card.
			if err := h.ctl.Edit(confirmMessage, text, kb); err != nil {
				h.log.Error("Failed to show the window card", logger.F("error", err.Error(), "window", win.ID))
			} else {
				h.owner.SetMessage(win.ID, confirmMessage)
				delivered = true
			}
		} else if h.telegramMode() != settings.NotifyOff {
			if id, err := h.ctl.Send(text, kb); err != nil {
				h.log.Error("Failed to send the window alert to Telegram", logger.F("error", err.Error(), "window", win.ID))
			} else {
				h.owner.SetMessage(win.ID, id)
				delivered = true
			}
		}
	}
	if h.pwClient != nil {
		title := "🟢 Reads window open until " + tz.Clock(win.ExpiresAt)
		scope := "every item in it except Secret Gate credentials, cards, passkeys, and files"
		if win.Tag != "" {
			scope = fmt.Sprintf("items tagged %q only", win.Tag)
		}
		body := fmt.Sprintf("Vault %q: %s. Opened by %s (%s). Max %d reads, %d items.", win.Vault, scope, win.Opener, win.Source, win.MaxRequests, win.MaxItems)
		if err := h.pwClient.SendAudit(title, win.Vault, body, "time-sensitive"); err != nil {
			h.log.Error("Failed to send the window alert to PushWard", logger.F("error", err.Error(), "window", win.ID))
		} else {
			delivered = true
		}
	}
	return delivered
}

// announceClosed shows a closed window everywhere. by names who closed it.
func (h *Handler) announceClosed(w ownerwindow.Window, by string) {
	view := windowView(w)
	view.CloseReason = ownerwindow.ReasonText(w.CloseReason)
	if by != "" {
		view.CloseReason += " (by " + by + ")"
	}
	if h.ctl != nil && w.MessageID != 0 {
		if err := h.ctl.Edit(w.MessageID, telegram.WindowClosedMessage(view), nil); err != nil {
			h.log.Error("Failed to update the closed window card", logger.F("error", err.Error(), "window", w.ID))
		}
	}
	if h.pwClient != nil {
		title := "⌛ Reads window closed: " + view.CloseReason
		body := fmt.Sprintf("Vault %q, %d of %d reads, %d items.", w.Vault, w.Requests, w.MaxRequests, len(w.Items))
		if err := h.pwClient.SendAudit(title, w.Vault, body, "passive"); err != nil {
			h.log.Error("Failed to send the window close alert to PushWard", logger.F("error", err.Error(), "window", w.ID))
		}
	}
	h.audit.Event(audit.WindowClosed, map[string]any{
		"window": w.ID, "reason": w.CloseReason, "by": by, "requests": w.Requests, "distinct_items": len(w.Items),
	})
	h.emitWindowEvent("window.closed", w, w.CloseReason)
}

// closeOwnerWindow closes one window; it reports false if it was not open.
func (h *Handler) closeOwnerWindow(id, by string) bool {
	w, ok := h.owner.Revoke(id, ownerwindow.ReasonRevoked)
	if !ok {
		return false
	}
	h.announceClosed(w, by)
	return true
}

func (h *Handler) closeAllOwnerWindows(reason, by string) int {
	ws := h.owner.RevokeAll(reason)
	for _, w := range ws {
		h.announceClosed(w, by)
	}
	return len(ws)
}

// sweepOwnerWindows closes windows that ran out of time and edits the
// running counters of the others.
func (h *Handler) sweepOwnerWindows() {
	for _, w := range h.owner.Expire() {
		h.announceClosed(w, "")
	}
	if h.ctl == nil {
		return
	}
	for _, w := range h.owner.DueCounters(counterEditEvery) {
		if w.MessageID == 0 {
			continue
		}
		text, kb := telegram.WindowCounterMessage(windowView(w))
		if err := h.ctl.Edit(w.MessageID, text, kb); err != nil {
			h.log.Warn("Failed to update the window counter", logger.F("error", err.Error(), "window", w.ID))
		}
	}
}

// AnnounceStartup tells the owner that a restart ended every window. It is
// silent for deployments that do not use owner windows.
func (h *Handler) AnnounceStartup() {
	if len(h.config.OwnerWindowVaults) == 0 {
		return
	}
	text := "🔐 Secret Gate started. No read window is open."
	if h.ctl != nil && h.telegramMode() != settings.NotifyOff {
		if _, err := h.ctl.Send(text, nil); err != nil {
			h.log.Error("Failed to send the startup notice", logger.F("error", err.Error()))
		}
	}
	if h.pwClient != nil {
		_ = h.pwClient.SendAudit("🔐 Secret Gate started", "", "No read window is open.", "passive")
	}
}

// ---------------------------------------------------------------------------
// Telegram entry points

// authorizedTelegram accepts only the approver, in the configured chat.
func (h *Handler) authorizedTelegram(userID int64, chatID int64, hasChat bool) bool {
	approver := h.config.ApproverUserID()
	return approver != 0 && userID == approver && hasChat && chatID == h.config.TelegramChatID
}

// rejectTelegram records a refused update, at most once a minute per user,
// and never answers it.
func (h *Handler) rejectTelegram(userID int64, kind, reason string) {
	now := h.clock()
	h.ownerMu.Lock()
	last := h.rejectedAt[userID]
	log := now.Sub(last) >= rejectLogEvery
	if log {
		h.rejectedAt[userID] = now
	}
	h.ownerMu.Unlock()
	if log {
		h.audit.Event(audit.TelegramRejected, map[string]any{"kind": kind, "reason": reason, "user_id": userID})
	}
}

func displayName(u telegram.User) string {
	return firstNonEmpty(u.Username, u.FirstName, strconv.FormatInt(u.ID, 10))
}

// HandleTelegramCallback applies a button tap from the poller. Only the
// approver's taps, in the configured chat, are accepted.
func (h *Handler) HandleTelegramCallback(cb *telegram.CallbackQuery) {
	if cb == nil {
		return
	}
	chatID, chatType, hasChat := int64(0), "", false
	if cb.Message != nil {
		chatID, chatType, hasChat = cb.Message.Chat.ID, cb.Message.Chat.Type, true
	}
	if !h.authorizedTelegram(cb.From.ID, chatID, hasChat) {
		h.rejectTelegram(cb.From.ID, "callback", "sender_mismatch")
		return
	}
	approver := displayName(cb.From)
	action, arg, _ := strings.Cut(cb.Data, ":")
	switch action {
	case telegram.CBOpen, telegram.CBConfirm, telegram.CBCancel, telegram.CBClose, telegram.CBCloseAll,
		telegram.CBWindows, telegram.CBSet, telegram.CBSettings, telegram.CBPending, telegram.CBPanelRedraw:
		if chatType != "private" {
			h.answerCallback(cb.ID, "Controls only work in a private chat")
			return
		}
		h.handleControl(cb, action, arg, approver)
	default:
		h.HandleTelegramAction(cb.ID, cb.Data, approver)
	}
}

// HandleTelegramMessage applies a text command from the poller. Only the
// approver's direct messages are accepted; forwarded, edited-in, and stale
// messages are ignored.
func (h *Handler) HandleTelegramMessage(m *telegram.Message) {
	if m == nil || m.Text == "" {
		return
	}
	var userID int64
	if m.From != nil {
		userID = m.From.ID
	}
	if !h.authorizedTelegram(userID, m.Chat.ID, true) || m.Chat.Type != "private" {
		h.rejectTelegram(userID, "message", "sender_mismatch")
		return
	}
	if len(m.ForwardOrigin) > 0 || m.ViaBot != nil {
		h.rejectTelegram(userID, "message", "forwarded")
		return
	}
	if age := h.clock().Sub(time.Unix(m.Date, 0)); age > maxCommandAge {
		h.rejectTelegram(userID, "message", "stale")
		return
	}
	text := strings.TrimSpace(m.Text)
	if !strings.HasPrefix(text, "/") {
		return
	}
	fields := strings.Fields(text)
	command := strings.ToLower(strings.TrimPrefix(fields[0], "/"))
	if at := strings.Index(command, "@"); at >= 0 {
		command = command[:at]
	}
	args := fields[1:]
	by := displayName(*m.From)
	switch command {
	case "start", "help":
		h.reply(telegram.HelpMessage(), nil)
	case "panel":
		h.sendPanel()
	case "open":
		h.commandOpen(args, by, userID)
	case "close":
		n := h.closeAllOwnerWindows(ownerwindow.ReasonRevoked, by)
		h.reply(fmt.Sprintf("🛑 Closed %d window(s).", n), nil)
	case "windows":
		text, kb := telegram.WindowListMessage(windowViews(h.owner.List()))
		h.reply(text, kb)
	case "pending":
		h.sendPending()
	case "settings":
		h.sendSettings()
	case "set":
		h.commandSet(args, by)
	default:
		h.reply("Unknown command. /help lists them.", nil)
	}
}

func (h *Handler) reply(text string, kb *telegram.InlineKeyboardMarkup) {
	if h.ctl == nil {
		return
	}
	if _, err := h.ctl.Send(text, kb); err != nil {
		h.log.Error("Failed to send a Telegram reply", logger.F("error", err.Error()))
	}
}

func (h *Handler) edit(messageID int, text string, kb *telegram.InlineKeyboardMarkup) {
	if h.ctl == nil || messageID == 0 {
		return
	}
	if err := h.ctl.Edit(messageID, text, kb); err != nil && !strings.Contains(err.Error(), "message is not modified") {
		h.log.Error("Failed to edit a Telegram message", logger.F("error", err.Error()))
	}
}

// parseMinutes reads "30", "30m", or "1h" as minutes.
func parseMinutes(s string) (int, bool) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, n >= 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d%time.Minute != 0 {
		return 0, false
	}
	return int(d / time.Minute), true
}

func (h *Handler) commandOpen(args []string, by string, userID int64) {
	minutes, vault := 0, ""
	for _, a := range args {
		if n, ok := parseMinutes(a); ok {
			minutes = n
			continue
		}
		vault = strings.TrimSpace(vault + " " + a)
	}
	h.beginOpen(openRequest{Minutes: minutes, Vault: vault, Source: sourceCommand, Opener: by}, userID)
}

// beginOpen validates a request and posts the confirm card. Nothing opens
// until the owner taps it.
func (h *Handler) beginOpen(r openRequest, userID int64) (string, bool) {
	fail := func(msg string) (string, bool) {
		h.audit.Event(audit.WindowRejected, map[string]any{"reason": msg, "source": r.Source, "opener": r.Opener})
		h.reply("🚫 "+msg, nil)
		return msg, false
	}
	if !h.ownerWindowsEnabled() {
		if len(h.config.OwnerWindowVaults) == 0 {
			return fail("Phone windows have no vault configured (OWNER_WINDOW_VAULTS).")
		}
		return fail("Phone windows are off. Turn them on in /settings.")
	}
	vault, err := h.resolveVault(r.Vault)
	if err != nil {
		return fail("That vault is not configured for phone windows.")
	}
	ttl, err := h.resolveMinutes(r.Minutes)
	if err != nil {
		return fail(fmt.Sprintf("Minutes must be between %d and %d.", int(minWindow/time.Minute), int(h.ownerMax()/time.Minute)))
	}
	now := h.clock()
	nonce, err := newNonce()
	if err != nil {
		return fail("Could not create a confirm card.")
	}
	h.ownerMu.Lock()
	for n, c := range h.confirms {
		if !now.Before(c.expires) {
			delete(h.confirms, n)
		}
	}
	if len(h.confirms) >= maxPendingConfirms {
		h.ownerMu.Unlock()
		return fail("Too many confirm cards are waiting. Answer or wait two minutes.")
	}
	h.ownerMu.Unlock()
	requests, items := h.ownerBudget()
	text, kb := telegram.WindowConfirmMessage(telegram.WindowConfirm{
		Vault: vault, Tag: h.ownerTag(), Minutes: int(ttl / time.Minute), Until: now.Add(ttl),
		MaxRequests: requests, MaxItems: items, Nonce: nonce,
	})
	if h.ctl == nil {
		return "", false
	}
	id, err := h.ctl.Send(text, kb)
	if err != nil {
		h.log.Error("Failed to send the window confirm card", logger.F("error", err.Error()))
		return "", false
	}
	h.ownerMu.Lock()
	h.confirms[nonce] = &openConfirm{
		minutes: int(ttl / time.Minute), vault: vault, source: r.Source, userID: userID, messageID: id, expires: now.Add(confirmTTL),
	}
	h.ownerMu.Unlock()
	h.audit.Event(audit.WindowOpenRequested, map[string]any{
		"source": r.Source, "opener": r.Opener, "minutes": int(ttl / time.Minute), "vault": vault,
	})
	return "Confirm card sent", true
}

func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (h *Handler) handleControl(cb *telegram.CallbackQuery, action, arg, by string) {
	messageID := cb.Message.MessageID
	switch action {
	case telegram.CBOpen:
		minutes, _ := parseMinutes(arg)
		if msg, ok := h.beginOpen(openRequest{Minutes: minutes, Source: sourcePanel, Opener: by}, cb.From.ID); ok {
			h.answerCallback(cb.ID, "Check the confirm card")
		} else {
			h.answerCallback(cb.ID, firstNonEmpty(msg, "Not opened"))
		}
	case telegram.CBConfirm:
		h.confirmOpen(cb, arg, by)
	case telegram.CBCancel:
		h.ownerMu.Lock()
		c, ok := h.confirms[arg]
		if ok && c.messageID == messageID && c.userID == cb.From.ID {
			delete(h.confirms, arg)
		} else {
			ok = false
		}
		h.ownerMu.Unlock()
		if ok {
			h.edit(messageID, telegram.WindowConfirmGoneMessage("cancelled"), nil)
		}
		h.answerCallback(cb.ID, "Cancelled")
	case telegram.CBClose:
		if h.closeOwnerWindow(arg, by) {
			h.answerCallback(cb.ID, "Window closed")
		} else {
			h.answerCallback(cb.ID, "Window already closed")
		}
	case telegram.CBCloseAll:
		n := h.closeAllOwnerWindows(ownerwindow.ReasonRevoked, by)
		h.answerCallback(cb.ID, fmt.Sprintf("Closed %d window(s)", n))
		h.sendPanelEdit(messageID)
	case telegram.CBWindows:
		text, kb := telegram.WindowListMessage(windowViews(h.owner.List()))
		h.reply(text, kb)
		h.answerCallback(cb.ID, "")
	case telegram.CBSettings:
		text, kb := telegram.SettingsMessage(h.settingsView())
		h.edit(messageID, text, kb)
		h.answerCallback(cb.ID, "")
	case telegram.CBPanelRedraw:
		h.sendPanelEdit(messageID)
		h.answerCallback(cb.ID, "")
	case telegram.CBPending:
		n := h.sendPending()
		h.answerCallback(cb.ID, fmt.Sprintf("%d pending", n))
	case telegram.CBSet:
		name, value, _ := strings.Cut(arg, "=")
		result, err := h.applySetting(name, value, by)
		if err != nil {
			h.answerCallback(cb.ID, err.Error())
			return
		}
		text, kb := telegram.SettingsMessage(h.settingsView())
		h.edit(messageID, text, kb)
		h.answerCallback(cb.ID, result)
	}
}

// confirmOpen is the second tap: it checks the one-time card and opens.
func (h *Handler) confirmOpen(cb *telegram.CallbackQuery, nonce, by string) {
	now := h.clock()
	h.ownerMu.Lock()
	c, ok := h.confirms[nonce]
	if ok {
		delete(h.confirms, nonce) // single use, whatever happens next
	}
	h.ownerMu.Unlock()
	messageID := cb.Message.MessageID
	switch {
	case !ok:
		h.edit(messageID, telegram.WindowConfirmGoneMessage("this card expired or was already used"), nil)
		h.answerCallback(cb.ID, "Card expired")
		return
	case !now.Before(c.expires):
		h.edit(messageID, telegram.WindowConfirmGoneMessage("the card expired after two minutes"), nil)
		h.answerCallback(cb.ID, "Card expired")
		return
	case c.userID != cb.From.ID || c.messageID != messageID:
		h.answerCallback(cb.ID, "Not your card")
		return
	}
	win, err := h.openOwnerWindow(openRequest{
		Minutes: c.minutes, Vault: c.vault, Source: c.source, Opener: by, ConfirmMessage: messageID,
	})
	switch {
	case err == nil:
		h.answerCallback(cb.ID, "Window open")
	case errors.Is(err, ownerwindow.ErrAlreadyOpen):
		text, kb := telegram.WindowOpenedMessage(windowView(win))
		h.edit(messageID, text, kb)
		h.answerCallback(cb.ID, "Already open; not extended")
	default:
		h.edit(messageID, telegram.WindowConfirmGoneMessage(openErrorText(err)), nil)
		h.answerCallback(cb.ID, "Not opened")
	}
}

func openErrorText(err error) string {
	switch {
	case errors.Is(err, ownerwindow.ErrRateLimited):
		return "too many windows opened in the last hour"
	case errors.Is(err, ownerwindow.ErrDailyCap):
		return "the daily window time is used up"
	case errors.Is(err, errAuditDown):
		return "no alert channel could confirm it, so nothing was opened"
	case errors.Is(err, errOwnerDisabled):
		return "phone windows are off"
	}
	return err.Error()
}

func (h *Handler) sendPanel() {
	text, kb := telegram.PanelMessage(windowViews(h.owner.List()), int(h.ownerTTL()/time.Minute), h.ownerWindowsEnabled())
	h.reply(text, kb)
}

func (h *Handler) sendPanelEdit(messageID int) {
	text, kb := telegram.PanelMessage(windowViews(h.owner.List()), int(h.ownerTTL()/time.Minute), h.ownerWindowsEnabled())
	h.edit(messageID, text, kb)
}

func (h *Handler) settingsView() telegram.SettingsView {
	v := h.settingsValues()
	return telegram.SettingsView{
		Notifications: v.TelegramNotifications, NotificationsEffective: h.telegramMode(),
		OwnerWindows: v.OwnerWindows, OwnerWindowsAvailable: len(h.config.OwnerWindowVaults) > 0,
		TapWindows: v.TapWindows, Timezone: v.Timezone, Saved: h.settings.Persistent(),
	}
}

func (h *Handler) sendSettings() {
	text, kb := telegram.SettingsMessage(h.settingsView())
	h.reply(text, kb)
}

func (h *Handler) commandSet(args []string, by string) {
	if len(args) != 2 {
		h.reply("Usage: /set &lt;name&gt; &lt;value&gt;\nNames: notifications (on, silent, off), windows (on, off), tap_windows (on, off), timezone (pst, mst, cst, est, utc, or a name like Europe/London). Use the value <code>default</code> to clear a change.", nil)
		return
	}
	result, err := h.applySetting(args[0], args[1], by)
	if err != nil {
		h.reply("🚫 "+escapeText(err.Error()), nil)
		return
	}
	h.reply("⚙️ "+escapeText(result), nil)
}

func escapeText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func describe(v settings.Values, name string) string {
	switch name {
	case settings.TelegramNotifications:
		return v.TelegramNotifications
	case settings.OwnerWindows:
		return onOffText(v.OwnerWindows)
	case settings.TapWindows:
		return onOffText(v.TapWindows)
	case settings.Timezone:
		return v.Timezone
	}
	return ""
}

func onOffText(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// applySetting changes one switch, applies its side effects, alerts the other
// channels, and returns a short result for the owner.
func (h *Handler) applySetting(name, value, by string) (string, error) {
	canonical, ok := settings.Canonical(name)
	if !ok {
		return "", fmt.Errorf("unknown setting %q", name)
	}
	if canonical == settings.OwnerWindows && len(h.config.OwnerWindowVaults) == 0 && !strings.EqualFold(strings.TrimSpace(value), "off") {
		return "", errors.New("phone windows have no vault configured (OWNER_WINDOW_VAULTS)")
	}
	before, after, err := h.settings.Set(canonical, value)
	notSaved := errors.Is(err, settings.ErrNotSaved)
	if err != nil && !notSaved {
		return "", err
	}
	from, to := describe(before, canonical), describe(after, canonical)
	if canonical == settings.Timezone {
		if err := tz.Set(after.Timezone); err != nil {
			return "", err
		}
	}
	result := fmt.Sprintf("%s: %s", canonical, to)
	if notSaved {
		result += " (not saved: lasts until restart)"
	}
	if from == to {
		return result + " (unchanged)", nil
	}
	if canonical == settings.OwnerWindows && !after.OwnerWindows {
		h.closeAllOwnerWindows(ownerwindow.ReasonRevoked, by)
	}
	if canonical == settings.TapWindows && !after.TapWindows {
		h.sessions.Clear()
	}
	h.audit.Event(audit.SettingsChanged, map[string]any{"setting": canonical, "from": from, "to": to, "by": by, "saved": !notSaved})
	if h.pwClient != nil {
		body := fmt.Sprintf("%s changed from %s to %s by %s.", canonical, from, to, by)
		if err := h.pwClient.SendAudit("⚙️ Secret Gate setting changed", "", body, "active"); err != nil {
			h.log.Error("Failed to send the settings alert to PushWard", logger.F("error", err.Error()))
		}
	}
	return result, nil
}

// sendPending puts every request that is waiting for a decision into the
// chat, without a push if alerts are silent or off. It returns how many were
// pending. Requests whose card is already in the chat are left alone.
func (h *Handler) sendPending() int {
	pending := h.store.ListPending()
	sort.Slice(pending, func(i, j int) bool { return pending[i].RequestedAt.Before(pending[j].RequestedAt) })
	waiting, sent := 0, 0
	for _, req := range pending {
		if req.IsExpired() {
			continue
		}
		waiting++
		if req.TelegramMsgID != 0 || h.tgClient == nil {
			continue
		}
		id, err := h.tgClient.SendApprovalRequest(req, h.config.WebhookBaseURL, h.windowTTL(req))
		if err != nil {
			h.log.Error("Failed to send a pending approval to Telegram", logger.F("error", err.Error(), "request_id", req.ID))
			continue
		}
		req.TelegramMsgID = id
		h.updateRequest(req)
		sent++
	}
	switch {
	case waiting == 0:
		h.reply("No request is waiting for a decision.", nil)
	case sent == 0:
		h.reply(fmt.Sprintf("📋 %d request(s) waiting. Their cards are already in this chat.", waiting), nil)
	default:
		h.reply(fmt.Sprintf("📋 %d request(s) waiting, %d sent above.", waiting, sent), nil)
	}
	return waiting
}
