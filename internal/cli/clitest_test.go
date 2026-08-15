package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/core"
	"github.com/johnuopini/secret-gate/internal/daemon"
)

// --- fake daemon (implements core.AdminDaemonClient) ---

type fakeDaemon struct {
	running bool
	data    map[string]map[string]string
	flushed bool
	stopped bool
}

func newFakeDaemon() *fakeDaemon {
	return &fakeDaemon{running: true, data: map[string]map[string]string{}}
}

func (f *fakeDaemon) IsRunning() bool { return f.running }
func (f *fakeDaemon) StatusInfo() (*core.DaemonStatusResult, error) {
	return &core.DaemonStatusResult{Running: f.running, Uptime: "1m", EntryCount: len(f.data), PID: 4242}, nil
}
func (f *fakeDaemon) Get(name, vault string) (map[string]string, error) {
	if fields, ok := f.data[name]; ok {
		return fields, nil
	}
	return nil, core.E(core.ErrNotFound, "not cached", "")
}
func (f *fakeDaemon) Store(name, vault string, fields map[string]string, ttl int) error {
	f.data[name] = fields
	return nil
}
func (f *fakeDaemon) EnsureRunning() error { f.running = true; return nil }
func (f *fakeDaemon) List() ([]daemon.CacheEntryInfo, error) {
	var out []daemon.CacheEntryInfo
	for name := range f.data {
		out = append(out, daemon.CacheEntryInfo{SecretName: name})
	}
	return out, nil
}
func (f *fakeDaemon) Flush() error      { f.flushed = true; f.data = map[string]map[string]string{}; return nil }
func (f *fakeDaemon) StopDaemon() error { f.stopped = true; f.running = false; return nil }

// --- fake proxy (implements core.ProxyClient + core.AsyncProxyClient) ---

type fakeProxy struct {
	searchResults []core.SearchResultItem
	fieldsResult  *core.FieldsResult
	fieldsErr     error
	writeResult   *core.RequestResult
	writeCalls    int

	pending   *core.PendingRequest
	statuses  []core.StatusResult // consumed one per Status() call; last repeats
	retrieved *core.RequestResult
	statusIdx int
}

func (p *fakeProxy) Search(query string, limit int) ([]core.SearchResultItem, error) {
	return p.searchResults, nil
}
func (p *fakeProxy) GetFields(name, vault string) (*core.FieldsResult, error) {
	if p.fieldsErr != nil {
		return nil, p.fieldsErr
	}
	return p.fieldsResult, nil
}
func (p *fakeProxy) Request(ctx context.Context, name, vault, reason string, fields []string, rc core.RequestContext) (*core.RequestResult, error) {
	return &core.RequestResult{Status: "approved", SecretName: name, Cached: true}, nil
}
func (p *fakeProxy) Write(ctx context.Context, name, vault, reason, op, cat string, fields map[string]string, rc core.RequestContext) (*core.RequestResult, error) {
	p.writeCalls++
	if p.writeResult != nil {
		return p.writeResult, nil
	}
	return &core.RequestResult{Status: "completed", SecretName: name}, nil
}
func (p *fakeProxy) Submit(ctx context.Context, name, vault, reason string, fields []string, rc core.RequestContext) (*core.PendingRequest, error) {
	if p.pending != nil {
		return p.pending, nil
	}
	return &core.PendingRequest{Token: "tok123", StatusURL: "http://gate/status/tok123", ExpiresAt: "2026-08-15T13:00:00Z"}, nil
}
func (p *fakeProxy) Status(ctx context.Context, statusURL string) (*core.StatusResult, error) {
	if len(p.statuses) == 0 {
		return &core.StatusResult{Status: "pending"}, nil
	}
	st := p.statuses[p.statusIdx]
	if p.statusIdx < len(p.statuses)-1 {
		p.statusIdx++
	}
	return &st, nil
}
func (p *fakeProxy) Retrieve(ctx context.Context, secretURL, name, vault string) (*core.RequestResult, error) {
	if p.retrieved != nil {
		return p.retrieved, nil
	}
	return &core.RequestResult{Status: "approved", SecretName: name, Cached: true}, nil
}

// --- test harness ---

type testApp struct {
	app    *App
	daemon *fakeDaemon
	proxy  *fakeProxy
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	fd := newFakeDaemon()
	fp := &fakeProxy{}
	svc := core.NewService(core.Config{ServerURL: "http://gate", CacheTTLSec: 3600}, fd, fp)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	return &testApp{
		app: &App{
			Version: "0.4.0", ServerURL: "http://gate",
			Service: svc, Async: fp, Admin: fd,
			StateDir: t.TempDir(),
			Stdout: stdout, Stderr: stderr, Stdin: &bytes.Buffer{},
			Now: func() time.Time { return time.Unix(59, 0) },
		},
		daemon: fd, proxy: fp, stdout: stdout, stderr: stderr,
	}
}

// okEnvelope decodes stdout as a success envelope.
func (ta *testApp) okEnvelope(t *testing.T) map[string]interface{} {
	t.Helper()
	var env map[string]interface{}
	if err := json.Unmarshal(ta.stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not a JSON envelope: %v\nstdout=%q", err, ta.stdout.String())
	}
	return env
}

// errEnvelope decodes stderr as an error envelope.
func (ta *testApp) errEnvelope(t *testing.T) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	data := ta.stderr.Bytes()
	if idx := bytes.IndexByte(data, '{'); idx >= 0 {
		data = data[idx:]
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("stderr is not a JSON error envelope: %v\nstderr=%q", err, ta.stderr.String())
	}
	return env
}
