package store

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

var (
	ErrNotFound      = errors.New("request not found")
	ErrAlreadyExists = errors.New("request already exists")
)

const (
	MaxWatchersPerToken = 16
	MaxTotalWatchers    = 1024
)

// Store provides thread-safe storage for approval requests
type Store struct {
	mu            sync.RWMutex
	requests      map[string]*models.ApprovalRequest // keyed by token
	byID          map[string]*models.ApprovalRequest // keyed by ID for Telegram callbacks
	byFingerprint map[string]*models.ApprovalRequest
	watchers      map[string][]chan models.RequestStatus
}

// New creates a new Store
func New() *Store {
	return &Store{
		requests:      make(map[string]*models.ApprovalRequest),
		byID:          make(map[string]*models.ApprovalRequest),
		byFingerprint: make(map[string]*models.ApprovalRequest),
		watchers:      make(map[string][]chan models.RequestStatus),
	}
}

// Save stores an approval request
func (s *Store) Save(req *models.ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[req.Token]; exists {
		return ErrAlreadyExists
	}

	copy := *req
	s.requests[req.Token] = &copy
	s.byID[req.ID] = &copy
	if req.Fingerprint != "" {
		s.byFingerprint[req.Fingerprint] = &copy
	}
	return nil
}

// SaveOrRenew atomically stores a new request or renews an equivalent pending request.
func (s *Store) SaveOrRenew(req *models.ApprovalRequest, ttl time.Duration) (*models.ApprovalRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.byFingerprint[req.Fingerprint]; existing != nil {
		if existing.Status == models.StatusPending && !existing.IsExpired() && mutationsEqual(existing.Mutation, req.Mutation) {
			now := time.Now()
			existing.ExpiresAt = now.Add(ttl)
			existing.LastRemindedAt = &now
			existing.ReminderCount++
			copy := *existing
			return &copy, true, nil
		}
	}
	if _, exists := s.requests[req.Token]; exists {
		return nil, false, ErrAlreadyExists
	}
	copy := *req
	s.requests[req.Token] = &copy
	s.byID[req.ID] = &copy
	if req.Fingerprint != "" {
		s.byFingerprint[req.Fingerprint] = &copy
	}
	return &copy, false, nil
}

func mutationsEqual(left, right *models.ItemMutation) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Operation == right.Operation && left.Category == right.Category && reflect.DeepEqual(left.Fields, right.Fields)
}

// GetByToken retrieves a request by its polling token
func (s *Store) GetByToken(token string) (*models.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[token]
	if !ok {
		return nil, ErrNotFound
	}

	// Check and update expiration status
	if req.Status == models.StatusPending && req.IsExpired() {
		req.Status = models.StatusExpired
		s.notifyWatchersLocked(token, models.StatusExpired)
	}

	copy := *req
	return &copy, nil
}

// GetByID retrieves a request by its ID (used for Telegram callbacks)
func (s *Store) GetByID(id string) (*models.ApprovalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}

	copy := *req
	return &copy, nil
}

// Update updates an existing request
func (s *Store) Update(req *models.ApprovalRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.requests[req.Token]; !exists {
		return ErrNotFound
	}

	copy := *req
	s.requests[req.Token] = &copy
	s.byID[req.ID] = &copy
	if req.Status != models.StatusPending {
		s.notifyWatchersLocked(req.Token, req.Status)
	}
	return nil
}

// Delete removes a request from the store
func (s *Store) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, exists := s.requests[token]
	if !exists {
		return ErrNotFound
	}
	delete(s.requests, token)
	delete(s.byID, req.ID)
	if current := s.byFingerprint[req.Fingerprint]; current == req {
		delete(s.byFingerprint, req.Fingerprint)
	}
	delete(s.watchers, token)
	return nil
}

// ClaimMutation atomically grants one caller permission to execute an approved
// mutation. Completed mutations return their stored result; executing
// mutations remain owned by the original caller.
func (s *Store) ClaimMutation(token string) (*models.ApprovalRequest, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[token]
	if !ok {
		return nil, "", ErrNotFound
	}
	if req.Mutation == nil || req.Status != models.StatusApproved || req.IsExpired() {
		return nil, "", ErrNotFound
	}
	switch req.MutationState {
	case "completed":
		copy := *req
		return &copy, "completed", nil
	case "failed":
		copy := *req
		return &copy, "failed", nil
	case "executing":
		if req.MutationStartedAt != nil && time.Since(*req.MutationStartedAt) >= 30*time.Second {
			req.MutationState = "failed"
			copy := *req
			return &copy, "failed", nil
		}
		return nil, "executing", nil
	default:
		now := time.Now()
		req.MutationState = "executing"
		req.MutationStartedAt = &now
		copy := *req
		return &copy, "claimed", nil
	}
}

func (s *Store) CompleteMutation(token, item string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[token]
	if !ok {
		return ErrNotFound
	}
	if req.MutationState != "executing" {
		return fmt.Errorf("mutation %q is not executing", token)
	}
	req.MutationStartedAt = nil
	req.MutationState = "completed"
	req.MutationItem = item
	return nil
}

func (s *Store) ReleaseMutation(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, ok := s.requests[token]
	if !ok {
		return ErrNotFound
	}
	if req.MutationState == "executing" {
		req.MutationStartedAt = nil
		req.MutationState = ""
	}
	return nil
}

// Cleanup removes expired requests and returns the number removed
func (s *Store) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	now := time.Now()

	for token, req := range s.requests {
		// Remove requests that expired more than 1 hour ago
		if now.After(req.ExpiresAt.Add(time.Hour)) {
			delete(s.requests, token)
			delete(s.byID, req.ID)
			if current := s.byFingerprint[req.Fingerprint]; current == req {
				delete(s.byFingerprint, req.Fingerprint)
			}
			s.notifyWatchersLocked(token, models.StatusExpired)
			removed++
		}
	}

	return removed
}

// Count returns the number of requests in the store
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.requests)
}

// ListPending returns all pending requests
func (s *Store) ListPending() []*models.ApprovalRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var pending []*models.ApprovalRequest
	for _, req := range s.requests {
		if req.Status == models.StatusPending && !req.IsExpired() {
			copy := *req
			pending = append(pending, &copy)
		}
	}
	return pending
}

// Watch registers a listener for status updates on a request token.
// Returns a buffered channel that receives the terminal status, or nil if over capacity or request missing.
// The returned cancel function must be called when the caller is done watching.
func (s *Store) Watch(token string) (<-chan models.RequestStatus, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, exists := s.requests[token]
	if !exists {
		return nil, func() {}
	}

	// If already terminal or expired, return immediately with a pre-filled buffered channel
	if req.Status != models.StatusPending || req.IsExpired() {
		status := req.Status
		if req.Status == models.StatusPending && req.IsExpired() {
			req.Status = models.StatusExpired
			status = models.StatusExpired
			s.notifyWatchersLocked(token, models.StatusExpired)
		}
		ch := make(chan models.RequestStatus, 1)
		ch <- status
		return ch, func() {}
	}

	// Enforce watcher capacity bounds
	if len(s.watchers[token]) >= MaxWatchersPerToken || s.totalWatchersLocked() >= MaxTotalWatchers {
		return nil, func() {}
	}

	ch := make(chan models.RequestStatus, 1)
	s.watchers[token] = append(s.watchers[token], ch)

	cancel := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		list := s.watchers[token]
		for i, w := range list {
			if w == ch {
				s.watchers[token] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(s.watchers[token]) == 0 {
			delete(s.watchers, token)
		}
	}

	return ch, cancel
}

func (s *Store) totalWatchersLocked() int {
	total := 0
	for _, list := range s.watchers {
		total += len(list)
	}
	return total
}

func (s *Store) notifyWatchersLocked(token string, status models.RequestStatus) {
	list, exists := s.watchers[token]
	if !exists {
		return
	}
	delete(s.watchers, token)
	for _, ch := range list {
		select {
		case ch <- status:
		default:
		}
	}
}
