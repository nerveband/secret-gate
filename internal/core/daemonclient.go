package core

import (
	"os"
	"sync"

	"github.com/johnuopini/secret-gate/internal/daemon"
)

// RealDaemonClient wraps daemon.Client to implement AdminDaemonClient.
type RealDaemonClient struct {
	mu          sync.Mutex
	client      *daemon.Client
	selfBin     string
	cacheTTLSec int
}

var _ AdminDaemonClient = (*RealDaemonClient)(nil)

// NewRealDaemonClient creates a daemon client with the default 1h TTL.
func NewRealDaemonClient() *RealDaemonClient {
	return NewRealDaemonClientWithConfig(3600)
}

// NewRealDaemonClientWithConfig creates a daemon client with the given TTL.
func NewRealDaemonClientWithConfig(cacheTTLSec int) *RealDaemonClient {
	selfBin, _ := os.Executable()
	return &RealDaemonClient{
		client:      daemon.NewClient(daemon.SocketPath()),
		selfBin:     selfBin,
		cacheTTLSec: cacheTTLSec,
	}
}

func (r *RealDaemonClient) IsRunning() bool { return r.client.IsRunning() }

func (r *RealDaemonClient) StatusInfo() (*DaemonStatusResult, error) {
	status, err := r.client.Status()
	if err != nil {
		return nil, err
	}
	return &DaemonStatusResult{
		Running:    true,
		Uptime:     status.Uptime,
		EntryCount: status.EntryCount,
		SocketPath: status.SocketPath,
		PID:        status.PID,
	}, nil
}

func (r *RealDaemonClient) Get(secretName, vault string) (map[string]string, error) {
	return r.client.Get(secretName, vault)
}

func (r *RealDaemonClient) Store(secretName, vault string, fields map[string]string, ttl int) error {
	return r.client.Store(secretName, vault, fields, ttl)
}

func (r *RealDaemonClient) List() ([]daemon.CacheEntryInfo, error) { return r.client.List() }
func (r *RealDaemonClient) Flush() error                           { return r.client.Flush() }
func (r *RealDaemonClient) StopDaemon() error                      { return r.client.StopDaemon() }

func (r *RealDaemonClient) EnsureRunning() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client.IsRunning() {
		return nil
	}
	client, err := daemon.EnsureDaemon(r.selfBin, r.cacheTTLSec)
	if err != nil {
		return err
	}
	r.client = client
	return nil
}
