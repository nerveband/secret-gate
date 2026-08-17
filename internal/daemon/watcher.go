package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type watchTask struct {
	spec      WatchSpec
	startedAt time.Time
	cancel    context.CancelFunc
}

type Watcher struct {
	mu         sync.Mutex
	watches    map[string]*watchTask
	cache      *Cache
	defaultTTL time.Duration
	httpClient *http.Client
}

func NewWatcher(cache *Cache, defaultTTL time.Duration) *Watcher {
	return &Watcher{
		watches:    make(map[string]*watchTask),
		cache:      cache,
		defaultTTL: defaultTTL,
		httpClient: &http.Client{Timeout: 0},
	}
}

// Register adds a watch task. Returns true if newly registered, false if already watching.
func (w *Watcher) Register(spec WatchSpec) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.watches[spec.Token]; exists {
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())
	task := &watchTask{
		spec:      spec,
		startedAt: time.Now(),
		cancel:    cancel,
	}
	w.watches[spec.Token] = task

	go w.runWatch(ctx, spec)
	return true
}

// Unwatch cancels and removes an active watch by token.
func (w *Watcher) Unwatch(token string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	task, exists := w.watches[token]
	if !exists {
		return false
	}
	task.cancel()
	delete(w.watches, token)
	return true
}

// List returns a snapshot of active watches.
func (w *Watcher) List() []WatchInfo {
	w.mu.Lock()
	defer w.mu.Unlock()

	infos := make([]WatchInfo, 0, len(w.watches))
	for token, task := range w.watches {
		infos = append(infos, WatchInfo{
			Token:      token,
			SecretName: task.spec.SecretName,
			Vault:      task.spec.Vault,
			State:      "watching",
			Since:      task.startedAt.Format(time.RFC3339),
		})
	}
	return infos
}

// Count returns the number of active watches.
func (w *Watcher) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watches)
}

// Stop cancels all active watches.
func (w *Watcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, task := range w.watches {
		task.cancel()
	}
	w.watches = make(map[string]*watchTask)
}

func (w *Watcher) runWatch(ctx context.Context, spec WatchSpec) {
	defer func() {
		w.mu.Lock()
		delete(w.watches, spec.Token)
		w.mu.Unlock()
	}()

	var deadline time.Time
	if spec.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, spec.ExpiresAt); err == nil {
			deadline = t
		}
	}
	if deadline.IsZero() {
		deadline = time.Now().Add(15 * time.Minute)
	}

	backoff := 1 * time.Second
	maxBackoff := 5 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if time.Now().After(deadline) {
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "expired", "")
			return
		}

		// Long-poll status endpoint with wait=25
		targetURL := spec.StatusURL
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		targetURL = fmt.Sprintf("%s%swait=25", targetURL, sep)

		reqCtx, reqCancel := context.WithTimeout(ctx, 35*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
		if err != nil {
			reqCancel()
			return
		}

		resp, err := w.httpClient.Do(req)
		if err != nil {
			reqCancel()
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		reqCancel()

		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			// If not found, check if already retrieved into cache
			if entry, ok := w.cache.Get(spec.SecretName, spec.Vault); ok && entry.Fields != nil {
				_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "approved", "")
			} else {
				_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "expired", "")
			}
			return
		}

		if resp.StatusCode != http.StatusOK {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}

		backoff = 1 * time.Second

		var status statusWireResponse
		if err := json.Unmarshal(respBody, &status); err != nil {
			continue
		}

		switch status.Status {
		case "pending":
			continue

		case "approved":
			if status.SecretURL != "" {
				w.retrieveAndCache(ctx, spec, status.SecretURL)
			}
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "approved", "")
			return

		case "denied":
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "denied", "")
			return

		case "expired":
			_ = FireActivation(spec.Activation, spec.Token, spec.SecretName, "expired", "")
			return

		default:
			return
		}
	}
}

func (w *Watcher) retrieveAndCache(ctx context.Context, spec WatchSpec, secretURL string) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, secretURL, nil)
	if err != nil {
		return
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	if spec.IsMutation {
		// Mutation write committed on GET /secret/{token}
		return
	}

	var secretResp secretWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return
	}

	fields := secretResp.Secret
	if fields == nil && len(secretResp.Secrets) > 0 {
		fields = secretResp.Secrets[spec.SecretName]
		if fields == nil && len(secretResp.Secrets) == 1 {
			for _, f := range secretResp.Secrets {
				fields = f
			}
		}
	}

	if fields != nil {
		ttl := w.defaultTTL
		if spec.CacheTTLSec > 0 {
			ttl = time.Duration(spec.CacheTTLSec) * time.Second
		}
		w.cache.Store(spec.SecretName, spec.Vault, fields, ttl)
	}
}

type statusWireResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	SecretURL string `json:"secret_url,omitempty"`
}

type secretWireResponse struct {
	Secret  map[string]string            `json:"secret"`
	Secrets map[string]map[string]string `json:"secrets"`
}
