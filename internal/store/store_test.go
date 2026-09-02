package store_test

import (
	"sync"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/store"
)

func newTestRequest(token, id string, status models.RequestStatus, ttl time.Duration) *models.ApprovalRequest {
	return &models.ApprovalRequest{
		ID:               id,
		Token:            token,
		SecretName:       "test-secret",
		Vault:            "test-vault",
		RequesterMachine: "devbox",
		RequesterIP:      "127.0.0.1",
		Status:           status,
		RequestedAt:      time.Now(),
		ExpiresAt:        time.Now().Add(ttl),
	}
}

func TestStoreWatchThenApprove(t *testing.T) {
	s := store.New()
	req := newTestRequest("tok-1", "req-1", models.StatusPending, 10*time.Minute)
	if err := s.Save(req); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	ch, cancel := s.Watch("tok-1")
	if ch == nil {
		t.Fatal("Watch returned nil channel")
	}
	defer cancel()

	// Update to approved
	req.Approve()
	if err := s.Update(req); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	select {
	case status := <-ch:
		if status != models.StatusApproved {
			t.Fatalf("expected status approved, got %v", status)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for watch notification")
	}
}

func TestStoreApproveThenWatch(t *testing.T) {
	s := store.New()
	req := newTestRequest("tok-2", "req-2", models.StatusApproved, 10*time.Minute)
	if err := s.Save(req); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	ch, cancel := s.Watch("tok-2")
	if ch == nil {
		t.Fatal("Watch returned nil channel")
	}
	defer cancel()

	select {
	case status := <-ch:
		if status != models.StatusApproved {
			t.Fatalf("expected status approved, got %v", status)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for immediate watch notification on approved request")
	}
}

func TestStoreWatchThenDeny(t *testing.T) {
	s := store.New()
	req := newTestRequest("tok-3", "req-3", models.StatusPending, 10*time.Minute)
	if err := s.Save(req); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	ch, cancel := s.Watch("tok-3")
	if ch == nil {
		t.Fatal("Watch returned nil channel")
	}
	defer cancel()

	req.Deny()
	if err := s.Update(req); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	select {
	case status := <-ch:
		if status != models.StatusDenied {
			t.Fatalf("expected status denied, got %v", status)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for watch notification")
	}
}

func TestStoreWatchCancellation(t *testing.T) {
	s := store.New()
	req := newTestRequest("tok-4", "req-4", models.StatusPending, 10*time.Minute)
	if err := s.Save(req); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	ch, cancel := s.Watch("tok-4")
	if ch == nil {
		t.Fatal("Watch returned nil channel")
	}
	// Cancel immediately
	cancel()

	req.Approve()
	if err := s.Update(req); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	select {
	case status := <-ch:
		t.Fatalf("unexpected notification after cancel: %v", status)
	case <-time.After(50 * time.Millisecond):
		// Expected: no notification received
	}
}

func TestStoreWatchCapacityBounds(t *testing.T) {
	s := store.New()
	req := newTestRequest("tok-cap", "req-cap", models.StatusPending, 10*time.Minute)
	if err := s.Save(req); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	var cancels []func()
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()

	for i := range store.MaxWatchersPerToken {
		ch, cancel := s.Watch("tok-cap")
		if ch == nil {
			t.Fatalf("expected watch channel %d to succeed", i)
		}
		cancels = append(cancels, cancel)
	}

	// Exceeding per-token capacity should return nil channel
	chOver, cancelOver := s.Watch("tok-cap")
	if chOver != nil {
		cancelOver()
		t.Fatal("expected nil channel when exceeding MaxWatchersPerToken")
	}
}

func TestStoreConcurrentWatchAndUpdate(t *testing.T) {
	s := store.New()
	const numReqs = 20
	const numWatchersPerReq = 5

	for i := range numReqs {
		token := "tok-conc-" + string(rune('a'+i))
		id := "req-conc-" + string(rune('a'+i))
		req := newTestRequest(token, id, models.StatusPending, 10*time.Minute)
		if err := s.Save(req); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	var wg sync.WaitGroup

	// Spawn watchers
	for i := range numReqs {
		token := "tok-conc-" + string(rune('a'+i))
		for range numWatchersPerReq {
			wg.Add(1)
			go func(tok string) {
				defer wg.Done()
				ch, cancel := s.Watch(tok)
				if ch != nil {
					defer cancel()
					select {
					case <-ch:
					case <-time.After(2 * time.Second):
					}
				}
			}(token)
		}
	}

	// Spawn updaters
	for i := range numReqs {
		token := "tok-conc-" + string(rune('a'+i))
		id := "req-conc-" + string(rune('a'+i))
		wg.Add(1)
		go func(tok, reqID string) {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			req, err := s.GetByToken(tok)
			if err == nil {
				req.Approve()
				_ = s.Update(req)
			}
		}(token, id)
	}

	wg.Wait()
}

func TestClaimMutationAllowsOneConcurrentExecutor(t *testing.T) {
	s := store.New()
	req := newTestRequest("tok-mutation", "req-mutation", models.StatusApproved, time.Minute)
	req.Mutation = &models.ItemMutation{Operation: "create", Fields: map[string]string{"notes": "value"}}
	if err := s.Save(req); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	states := make(chan string, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, state, err := s.ClaimMutation(req.Token)
			if err != nil {
				states <- "error"
				return
			}
			states <- state
		}()
	}
	wg.Wait()
	close(states)
	claimed := 0
	for state := range states {
		if state == "claimed" {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("claimed executors = %d, want 1", claimed)
	}
}

func TestSaveOrRenewEquivalentPendingRequest(t *testing.T) {
	requests := store.New()
	firstExpiry := time.Now().Add(time.Minute)
	first := &models.ApprovalRequest{
		ID: "first", Token: "token-first", Fingerprint: "same",
		Status: models.StatusPending, ExpiresAt: firstExpiry,
		Mutation: &models.ItemMutation{Operation: "update", Fields: map[string]string{"notes": "same-value"}},
	}
	if _, reused, err := requests.SaveOrRenew(first, time.Minute); err != nil || reused {
		t.Fatalf("first save: reused=%v err=%v", reused, err)
	}
	second := &models.ApprovalRequest{
		ID: "second", Token: "token-second", Fingerprint: "same",
		Status: models.StatusPending, ExpiresAt: time.Now().Add(time.Minute),
		Mutation: &models.ItemMutation{Operation: "update", Fields: map[string]string{"notes": "same-value"}},
	}
	got, reused, err := requests.SaveOrRenew(second, 2*time.Minute)
	if err != nil || !reused {
		t.Fatalf("renew: reused=%v err=%v", reused, err)
	}
	if got.Token != first.Token || !got.ExpiresAt.After(firstExpiry) || requests.Count() != 1 {
		t.Fatalf("renewed request = %#v, count=%d", got, requests.Count())
	}
}
func TestSaveOrRenewDoesNotMergeDifferentMutationValues(t *testing.T) {
	requests := store.New()
	first := &models.ApprovalRequest{
		ID: "first", Token: "token-first", Fingerprint: "same",
		Status: models.StatusPending, ExpiresAt: time.Now().Add(time.Minute),
		Mutation: &models.ItemMutation{Operation: "update", Fields: map[string]string{"notes": "first"}},
	}
	_, _, _ = requests.SaveOrRenew(first, time.Minute)
	second := &models.ApprovalRequest{
		ID: "second", Token: "token-second", Fingerprint: "same",
		Status: models.StatusPending, ExpiresAt: time.Now().Add(time.Minute),
		Mutation: &models.ItemMutation{Operation: "update", Fields: map[string]string{"notes": "second"}},
	}
	got, reused, err := requests.SaveOrRenew(second, time.Minute)
	if err != nil || reused || got.Token != second.Token || requests.Count() != 2 {
		t.Fatalf("second request = %#v, reused=%v err=%v count=%d", got, reused, err, requests.Count())
	}
}
