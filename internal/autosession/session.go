package autosession

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

// Session is a temporary, in-memory approval rule created from a Telegram approval.
type Session struct {
	ID          string
	Approver    string
	Machine     string
	RequesterIP string
	SecretsKey  string
	CreatedAt   time.Time
	ExpiresAt   time.Time
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

// Create adds a session scoped to the request's requester and exact secret set.
func (s *Store) Create(req *models.ApprovalRequest, approver string, ttl time.Duration) *Session {
	now := time.Now()
	session := &Session{
		ID:          randomID(),
		Approver:    approver,
		Machine:     req.RequesterMachine,
		RequesterIP: req.RequesterIP,
		SecretsKey:  secretsKey(req.Secrets),
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return session
}

// Match returns a live session that covers the exact request.
func (s *Store) Match(req *models.ApprovalRequest) (*Session, bool) {
	now := time.Now()
	key := secretsKey(req.Secrets)

	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
			continue
		}
		if session.Machine == req.RequesterMachine &&
			session.RequesterIP == req.RequesterIP &&
			session.SecretsKey == key {
			return session, true
		}
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

func secretsKey(secrets []models.SecretRequest) string {
	parts := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		fields := append([]string(nil), secret.Fields...)
		sort.Strings(fields)
		parts = append(parts, secret.SecretName+"\x00"+secret.Vault+"\x00"+strings.Join(fields, "\x00"))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x01")
}

func randomID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(bytes)
}
