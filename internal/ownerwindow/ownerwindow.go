// Package ownerwindow implements read windows that the owner opens before any
// request exists ("allow reads for 30 minutes").
//
// A window covers one vault. By default it covers every item in it, except
// Secret Gate's own credentials, cards, bank or identity items, passkeys, and
// attachments; an optional 1Password tag narrows it to items the owner
// marked. It has a fixed length, a request budget, and an item budget.
// Windows live in memory, so a restart closes them. Everything that decides
// coverage comes from 1Password Connect (vault, title, category, tags), not
// from the requesting client.
package ownerwindow

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Why a request is not covered, or why a window closed.
const (
	ReasonNoWindow       = "no_window"
	ReasonVault          = "vault"
	ReasonUntagged       = "untagged"
	ReasonControlPlane   = "control_plane"
	ReasonCategory       = "category"
	ReasonPasskey        = "passkey"
	ReasonAttachment     = "attachment"
	ReasonPin            = "pin"
	ReasonBudgetRequests = "budget_requests"
	ReasonBudgetItems    = "budget_items"
	ReasonAudit          = "audit_unavailable"
	ReasonExpired        = "expired"
	ReasonRevoked        = "revoked"
	ReasonRestart        = "restart"
)

// ReasonText describes a reason for the owner in one short phrase.
func ReasonText(reason string) string {
	switch reason {
	case ReasonNoWindow:
		return "no window is open"
	case ReasonVault:
		return "the item is in a vault the window does not cover"
	case ReasonUntagged:
		return "the item is not tagged for windows"
	case ReasonControlPlane:
		return "Secret Gate credentials are never covered"
	case ReasonCategory:
		return "this item type is never covered"
	case ReasonPasskey:
		return "passkeys are never covered"
	case ReasonAttachment:
		return "attachments are never covered"
	case ReasonPin:
		return "the window is pinned to another requester"
	case ReasonBudgetRequests:
		return "the window used up its requests"
	case ReasonBudgetItems:
		return "the window used up its distinct items"
	case ReasonAudit:
		return "the audit message could not be delivered"
	case ReasonExpired:
		return "it ran out of time"
	case ReasonRevoked:
		return "it was closed"
	case ReasonRestart:
		return "the server restarted"
	}
	return reason
}

// defaultDeny matches titles of Secret Gate's own credentials (the approver
// and opener tokens, the Connect token and credentials file, the service
// account token) and the PushWard key. They would let an agent approve its
// own requests, so no window ever covers them. It is deliberately narrow: an
// unrelated item that merely mentions Telegram or a service account stays
// readable. An owner-configured pattern adds to it.
const defaultDeny = `secret[ _-]?gate|pushward`

// deniedCategories are item types a window never covers, even when tagged.
var deniedCategories = map[string]bool{
	"CREDIT_CARD": true, "BANK_ACCOUNT": true, "IDENTITY": true, "PASSPORT": true,
	"DRIVER_LICENSE": true, "SOCIAL_SECURITY_NUMBER": true, "MEDICAL_RECORD": true,
}

// Item is what Connect says about one requested item.
type Item struct {
	Vault    string
	Title    string
	Category string
	Tags     []string
	// Fields are the requested selectors; empty means every field.
	Fields []string
	// FieldLabels lists every field label and ID on the item, used to see
	// what an empty selection would release.
	FieldLabels []string
	// Attachments is true when the request names a file: selector.
	Attachments bool
}

// Policy decides which items a window may cover.
type Policy struct {
	Tag  string
	deny *regexp.Regexp
}

// NewPolicy compiles the deny rule: the built-in pattern plus an optional
// extra one. An empty tag means every item in the window's vault is eligible.
func NewPolicy(tag, extraDeny string) (Policy, error) {
	tag = strings.TrimSpace(tag)
	pattern := defaultDeny
	if extra := strings.TrimSpace(extraDeny); extra != "" {
		pattern += "|" + extra
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return Policy{}, fmt.Errorf("owner window deny pattern: %w", err)
	}
	return Policy{Tag: tag, deny: re}, nil
}

// controlPlane reports whether a title names a Secret Gate credential.
func (p Policy) controlPlane(title string) bool {
	if p.deny == nil {
		p, _ = NewPolicy("", "")
	}
	return p.deny.MatchString(title)
}

func isPasskey(label string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(label)), "passkey")
}

// passkeyReleased reports whether the request would release a passkey field.
func passkeyReleased(it Item) bool {
	labels := it.Fields
	if len(labels) == 0 {
		labels = it.FieldLabels
	}
	for _, l := range labels {
		if isPasskey(l) {
			return true
		}
	}
	return false
}

// CheckLegacy applies the exclusions that hold for every read window,
// including the older tap-opened one: Secret Gate credentials, passkeys, and
// attachments. It returns the reason when an item is excluded.
func (p Policy) CheckLegacy(it Item) (bool, string) {
	switch {
	case p.controlPlane(it.Title):
		return false, ReasonControlPlane
	case passkeyReleased(it):
		return false, ReasonPasskey
	case it.Attachments:
		return false, ReasonAttachment
	}
	return true, ""
}

// Check decides whether an owner window over vaults may cover the item.
func (p Policy) Check(it Item, vaults []string) (bool, string) {
	if ok, reason := p.CheckLegacy(it); !ok {
		return false, reason
	}
	if deniedCategories[strings.ToUpper(it.Category)] {
		return false, ReasonCategory
	}
	inVault := false
	for _, v := range vaults {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(it.Vault)) {
			inVault = true
			break
		}
	}
	if !inVault {
		return false, ReasonVault
	}
	if p.Tag == "" {
		return true, ""
	}
	for _, tag := range it.Tags {
		if strings.EqualFold(strings.TrimSpace(tag), p.Tag) {
			return true, ""
		}
	}
	return false, ReasonUntagged
}

// Window is one open (or just closed) owner window.
type Window struct {
	ID          string
	Vault       string
	Tag         string
	Source      string // telegram-panel, telegram-command, api
	Opener      string // who opened it: a Telegram name or an API label
	Machine     string // optional pin, self-reported by clients
	AgentID     string // optional pin, self-reported by clients
	OpenedAt    time.Time
	ExpiresAt   time.Time
	ClosedAt    time.Time
	CloseReason string
	MaxRequests int
	MaxItems    int
	Requests    int
	Items       []string
	// MessageID is the Telegram message that shows this window.
	MessageID int

	seen       map[string]struct{}
	dirty      bool
	lastCounts time.Time
}

// Limits bound how often and how long windows may be open.
type Limits struct {
	Ceiling      time.Duration // longest single window
	OpensPerHour int
	DailyMax     time.Duration // total open time over a rolling 24 hours
}

// Open parameters.
type OpenParams struct {
	Vault       string
	Tag         string
	Source      string
	Opener      string
	TTL         time.Duration
	MaxRequests int
	MaxItems    int
	Machine     string
	AgentID     string
}

// Errors returned by Open.
var (
	ErrAlreadyOpen = errors.New("a window is already open for this vault")
	ErrRateLimited = errors.New("too many windows opened in the last hour")
	ErrDailyCap    = errors.New("the daily window time is used up")
	ErrBadLength   = errors.New("window length is out of range")
)

type span struct{ from, to time.Time }

// Store keeps windows in memory.
type Store struct {
	mu      sync.Mutex
	now     func() time.Time
	live    map[string]*Window
	history []*span // every window opened in the last 24 hours; to is zero while open
	byID    map[string]*span
	closed  map[string]closure // window id -> how it ended, kept 24 hours
	expired []Window           // windows that ran out of time, waiting to be announced
}

// NewStore returns an empty store.
func NewStore() *Store { return newStore(time.Now) }

// NewStoreWithClock returns an empty store that reads time from now. Tests
// use it to move a window through its lifetime.
func NewStoreWithClock(now func() time.Time) *Store { return newStore(now) }

func newStore(now func() time.Time) *Store {
	return &Store{now: now, live: map[string]*Window{}, byID: map[string]*span{}, closed: map[string]closure{}}
}

// Open starts a window. When one is already open for the vault it returns
// that window with ErrAlreadyOpen and never extends it.
func (s *Store) Open(p OpenParams, lim Limits) (Window, error) {
	if p.TTL <= 0 || (lim.Ceiling > 0 && p.TTL > lim.Ceiling) {
		return Window{}, ErrBadLength
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	for _, w := range s.live {
		if strings.EqualFold(w.Vault, p.Vault) {
			return w.snapshot(), ErrAlreadyOpen
		}
	}
	s.pruneLocked(now)
	if lim.OpensPerHour > 0 {
		recent := 0
		for _, sp := range s.history {
			if now.Sub(sp.from) < time.Hour {
				recent++
			}
		}
		if recent >= lim.OpensPerHour {
			return Window{}, ErrRateLimited
		}
	}
	if lim.DailyMax > 0 {
		used := time.Duration(0)
		for _, sp := range s.history {
			end := sp.to
			if end.IsZero() || end.After(now) {
				end = now
			}
			used += end.Sub(sp.from)
		}
		if used+p.TTL > lim.DailyMax {
			return Window{}, ErrDailyCap
		}
	}
	w := &Window{
		ID: randomID(), Vault: p.Vault, Tag: p.Tag, Source: p.Source, Opener: p.Opener,
		Machine: p.Machine, AgentID: p.AgentID,
		OpenedAt: now, ExpiresAt: now.Add(p.TTL),
		MaxRequests: p.MaxRequests, MaxItems: p.MaxItems,
		seen: map[string]struct{}{},
	}
	s.live[w.ID] = w
	sp := &span{from: now}
	s.history = append(s.history, sp)
	s.byID[w.ID] = sp
	return w.snapshot(), nil
}

func (w *Window) snapshot() Window {
	c := *w
	c.seen = nil
	c.Items = make([]string, 0, len(w.seen))
	for item := range w.seen {
		c.Items = append(c.Items, item)
	}
	sort.Strings(c.Items)
	return c
}

// TakeRequest is one read to evaluate.
type TakeRequest struct {
	Items   []Item
	Machine string
	AgentID string
	Policy  Policy
}

// TakeResult is the outcome of Take.
type TakeResult struct {
	Covered bool
	// Reason is why the request is not covered; empty when covered.
	Reason string
	// Window is the window that covers the request, or, when not covered,
	// the open window that was looked at (zero if none).
	Window Window
	// NewItems are items this window had not covered before, so their first
	// use needs an audit message.
	NewItems []string
	// Closed is set when this request closed the window (budget).
	Closed *Window
	// touched lists the windows whose counters this request changed, so a
	// failed audit can give them back.
	touched map[string][]string
}

// Take decides whether open windows cover every item and, if so, counts the
// request against them. A request is covered only if each item passes the
// policy and has an open window for its vault. A request that would exceed a
// budget is refused and closes that window.
func (s *Store) Take(r TakeRequest) TakeResult {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	if len(r.Items) == 0 {
		return TakeResult{Reason: ReasonNoWindow}
	}
	if len(s.live) == 0 {
		return TakeResult{Reason: ReasonNoWindow}
	}
	byVault := map[string]*Window{}
	var seenWindow *Window
	for _, w := range s.live {
		byVault[strings.ToLower(w.Vault)] = w
		seenWindow = w
	}
	type pending struct {
		w     *Window
		items []string
	}
	plan := map[string]*pending{}
	for _, it := range r.Items {
		w := byVault[strings.ToLower(strings.TrimSpace(it.Vault))]
		if w == nil {
			return TakeResult{Reason: ReasonVault, Window: seenWindow.snapshot()}
		}
		if ok, reason := r.Policy.Check(it, []string{w.Vault}); !ok {
			return TakeResult{Reason: reason, Window: w.snapshot()}
		}
		if w.Machine != "" && !strings.EqualFold(w.Machine, r.Machine) {
			return TakeResult{Reason: ReasonPin, Window: w.snapshot()}
		}
		if w.AgentID != "" && w.AgentID != r.AgentID {
			return TakeResult{Reason: ReasonPin, Window: w.snapshot()}
		}
		p := plan[w.ID]
		if p == nil {
			p = &pending{w: w}
			plan[w.ID] = p
		}
		if _, known := w.seen[it.Title]; !known {
			dup := false
			for _, t := range p.items {
				if t == it.Title {
					dup = true
				}
			}
			if !dup {
				p.items = append(p.items, it.Title)
			}
		}
	}
	for _, p := range plan {
		w := p.w
		if w.MaxRequests > 0 && w.Requests+1 > w.MaxRequests {
			return s.closeLocked(w, ReasonBudgetRequests, now, TakeResult{Reason: ReasonBudgetRequests})
		}
		if w.MaxItems > 0 && len(w.seen)+len(p.items) > w.MaxItems {
			return s.closeLocked(w, ReasonBudgetItems, now, TakeResult{Reason: ReasonBudgetItems})
		}
	}
	res := TakeResult{Covered: true, touched: map[string][]string{}}
	for id, p := range plan {
		p.w.Requests++
		for _, t := range p.items {
			p.w.seen[t] = struct{}{}
		}
		p.w.dirty = true
		res.touched[id] = p.items
		res.NewItems = append(res.NewItems, p.items...)
		res.Window = p.w.snapshot()
	}
	sort.Strings(res.NewItems)
	return res
}

func (s *Store) closeLocked(w *Window, reason string, now time.Time, res TakeResult) TakeResult {
	w.ClosedAt = now
	w.CloseReason = reason
	s.closed[w.ID] = closure{reason: reason, at: now}
	snap := w.snapshot()
	delete(s.live, w.ID)
	s.endSpanLocked(w.ID, now)
	res.Window = snap
	res.Closed = &snap
	return res
}

// Release gives back the counters a covered Take used, after the audit for
// it could not be delivered.
func (s *Store) Release(res TakeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, items := range res.touched {
		w := s.live[id]
		if w == nil {
			continue
		}
		if w.Requests > 0 {
			w.Requests--
		}
		for _, t := range items {
			delete(w.seen, t)
		}
	}
}

// Revoke closes a window and reports whether it was open.
func (s *Store) Revoke(id, reason string) (Window, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.live[id]
	if w == nil || !now.Before(w.ExpiresAt) {
		return Window{}, false
	}
	res := s.closeLocked(w, reason, now, TakeResult{})
	return *res.Closed, true
}

// RevokeAll closes every open window.
func (s *Store) RevokeAll(reason string) []Window {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Window
	for _, w := range s.live {
		if !now.Before(w.ExpiresAt) {
			continue
		}
		out = append(out, *s.closeLocked(w, reason, now, TakeResult{}).Closed)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt.Before(out[j].OpenedAt) })
	return out
}

// List returns the open windows, oldest first.
func (s *Store) List() []Window {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	out := make([]Window, 0, len(s.live))
	for _, w := range s.live {
		out = append(out, w.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt.Before(out[j].OpenedAt) })
	return out
}

// Get returns one open window.
func (s *Store) Get(id string) (Window, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	w := s.live[id]
	if w == nil {
		return Window{}, false
	}
	return w.snapshot(), true
}

// SetMessage records the Telegram message that shows a window.
func (s *Store) SetMessage(id string, messageID int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w := s.live[id]; w != nil {
		w.MessageID = messageID
	}
}

// Expire closes windows that ran out of time and returns every one that ran
// out since the last call, each once. Reads, opens, and listings expire
// windows too; their closures are queued here so the owner is always told.
func (s *Store) Expire() []Window {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	out := s.expired
	s.expired = nil
	sort.Slice(out, func(i, j int) bool { return out[i].OpenedAt.Before(out[j].OpenedAt) })
	return out
}

func (s *Store) expireLocked(now time.Time) {
	for _, w := range s.live {
		if now.Before(w.ExpiresAt) {
			continue
		}
		w.ClosedAt = w.ExpiresAt
		w.CloseReason = ReasonExpired
		s.expired = append(s.expired, w.snapshot())
		delete(s.live, w.ID)
		s.endSpanLocked(w.ID, w.ExpiresAt)
	}
}

// DueCounters returns windows whose use counters changed since the last
// call at least minInterval ago, so one message can be edited instead of one
// message per read.
func (s *Store) DueCounters(minInterval time.Duration) []Window {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Window
	for _, w := range s.live {
		if w.dirty && now.Sub(w.lastCounts) >= minInterval {
			w.dirty = false
			w.lastCounts = now
			out = append(out, w.snapshot())
		}
	}
	return out
}

func (s *Store) endSpanLocked(id string, at time.Time) {
	if sp := s.byID[id]; sp != nil {
		sp.to = at
		delete(s.byID, id)
	}
}

// pruneLocked drops history older than 24 hours.
func (s *Store) pruneLocked(now time.Time) {
	kept := s.history[:0]
	for _, sp := range s.history {
		if !sp.to.IsZero() && now.Sub(sp.to) > 24*time.Hour {
			continue
		}
		kept = append(kept, sp)
	}
	s.history = kept
	for id, c := range s.closed {
		if now.Sub(c.at) > 24*time.Hour {
			delete(s.closed, id)
		}
	}
}

type closure struct {
	reason string
	at     time.Time
}

// ClosedEarly reports whether a window was closed before it ran out of time
// (revoked, or out of budget). A read approved under such a window must not
// be released.
func (s *Store) ClosedEarly(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.closed[id]
	return ok && c.reason != ReasonExpired
}

func randomID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))[:16]
	}
	return hex.EncodeToString(b)
}
