package autosession

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Session is a temporary, global in-memory approval window created from Telegram.
type Session struct {
	ID        string
	Approver  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store keeps temporary approval sessions in memory.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewStore creates an empty auto-approval session store.
func NewStore() *Store {
	return &Store{sessions: make(map[string]*Session)}
}

// Create adds a global approval window. All requests match until it expires.
func (s *Store) Create(approver string, ttl time.Duration) *Session {
	now := time.Now()
	session := &Session{
		ID:        randomID(),
		Approver:  approver,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return session
}

// Match returns any live global approval window.
func (s *Store) Match() (*Session, bool) {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
			continue
		}
		return session, true
	}
	return nil, false
}

// Cleanup removes expired sessions and returns how many were removed.
func (s *Store) Cleanup() int {
	now := time.Now()
	removed := 0

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed
}

// Clear ends every window at once, used when tap windows are switched off.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*Session)
}

func randomID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(bytes)
}
