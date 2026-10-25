// Package writegrant holds the short-lived, in-memory grants that let a write
// ride on an earlier human approval: write windows opened from Telegram and
// follow-up grants for items an approved write just touched.
//
// Grants never outlive a server restart, never cover reads, and are always
// scoped to one requester (machine, IP, Paseo agent ID) and one vault.
package writegrant

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

// Scope identifies who may use a grant and where.
type Scope struct {
	Machine string
	IP      string
	AgentID string
	Vault   string
}

// ScopeOf returns the grant scope of a request.
func ScopeOf(req *models.ApprovalRequest) Scope {
	return Scope{Machine: req.RequesterMachine, IP: req.RequesterIP, AgentID: req.Context.PaseoAgentID, Vault: req.Vault}
}

// Window lets one requester create new items in one vault without a tap
// until it expires or is revoked.
type Window struct {
	ID              string
	Approver        string
	SourceRequestID string
	Scope           Scope
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type followUp struct {
	scope    Scope
	item     string
	windowID string
	source   string
	approver string
	expires  time.Time
}

// Match explains why a write may proceed without a tap.
type Match struct {
	Kind      string // models.AutoApprovedWriteWindow or models.AutoApprovedFollowUp
	WindowID  string
	Approver  string
	Source    string // request ID whose approval is reused
	ExpiresAt time.Time
}

// Store keeps windows and follow-up grants in memory.
type Store struct {
	mu        sync.Mutex
	now       func() time.Time
	windows   map[string]*Window
	followUps []followUp
}

// NewStore returns an empty grant store.
func NewStore() *Store {
	return &Store{now: time.Now, windows: make(map[string]*Window)}
}

// OpenWindow starts a write window for scope.
func (s *Store) OpenWindow(approver, sourceRequestID string, scope Scope, ttl time.Duration) Window {
	now := s.now()
	w := &Window{ID: randomID(), Approver: approver, SourceRequestID: sourceRequestID, Scope: scope, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windows[w.ID] = w
	return *w
}

// Revoke closes a window and every follow-up grant it produced. It reports
// whether the window was still open and how many follow-up grants were dropped.
func (s *Store) Revoke(id string) (Window, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[id]
	if !ok || !s.now().Before(w.ExpiresAt) {
		delete(s.windows, id)
		return Window{}, 0, false
	}
	delete(s.windows, id)
	kept := s.followUps[:0]
	dropped := 0
	for _, f := range s.followUps {
		if f.windowID == id {
			dropped++
			continue
		}
		kept = append(kept, f)
	}
	s.followUps = kept
	return *w, dropped, true
}

// GrantFollowUps lets scope update items for ttl after an approved write.
// windowID ties the grants to a window so revoking it removes them too.
func (s *Store) GrantFollowUps(scope Scope, items []string, windowID, source, approver string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	expires := s.now().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range items {
		if item == "" {
			continue
		}
		s.followUps = append(s.followUps, followUp{scope: scope, item: item, windowID: windowID, source: source, approver: approver, expires: expires})
	}
}

// Match reports whether every write in mutations is covered by a live grant
// for scope. Creates need an open window. Updates need a follow-up grant for
// that exact item; a window alone never covers updates to existing items.
func (s *Store) Match(scope Scope, mutations []models.ItemMutation) (Match, bool) {
	if len(mutations) == 0 {
		return Match{}, false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	window := s.liveWindowLocked(scope, now)
	var result Match
	for _, m := range mutations {
		switch m.Operation {
		case "create":
			if window == nil {
				return Match{}, false
			}
			result = Match{Kind: models.AutoApprovedWriteWindow, WindowID: window.ID, Approver: window.Approver, Source: window.SourceRequestID, ExpiresAt: window.ExpiresAt}
		case "update":
			grant := s.followUpLocked(scope, m.Item, now)
			if grant == nil {
				return Match{}, false
			}
			if result.Kind == "" {
				result = Match{Kind: models.AutoApprovedFollowUp, WindowID: grant.windowID, Approver: grant.approver, Source: grant.source, ExpiresAt: grant.expires}
			}
		default:
			return Match{}, false
		}
	}
	return result, true
}

func (s *Store) liveWindowLocked(scope Scope, now time.Time) *Window {
	var best *Window
	for _, w := range s.windows {
		if w.Scope != scope || !now.Before(w.ExpiresAt) {
			continue
		}
		if best == nil || w.ExpiresAt.After(best.ExpiresAt) {
			best = w
		}
	}
	return best
}

func (s *Store) followUpLocked(scope Scope, item string, now time.Time) *followUp {
	var best *followUp
	for i := range s.followUps {
		f := &s.followUps[i]
		if f.scope != scope || f.item != item || !now.Before(f.expires) {
			continue
		}
		if best == nil || f.expires.After(best.expires) {
			best = f
		}
	}
	return best
}

// Cleanup drops expired windows and grants and returns how many were removed.
func (s *Store) Cleanup() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, w := range s.windows {
		if !now.Before(w.ExpiresAt) {
			delete(s.windows, id)
			removed++
		}
	}
	kept := s.followUps[:0]
	for _, f := range s.followUps {
		if now.Before(f.expires) {
			kept = append(kept, f)
			continue
		}
		removed++
	}
	s.followUps = kept
	return removed
}

func randomID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))[:16]
	}
	return hex.EncodeToString(bytes)
}
