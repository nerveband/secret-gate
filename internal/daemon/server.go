package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/nerveband/secret-gate/internal/passkey"
)

type Server struct {
	socketPath string
	cache      *Cache
	cacheTTL   time.Duration
	startedAt  time.Time
	watcher    *Watcher
	passkeys   *passkey.Manager
	runMu      sync.Mutex
	listenerMu sync.Mutex
	listener   net.Listener
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

func NewServer(socketPath string, cacheTTL time.Duration) *Server {
	c := NewCache()
	return &Server{
		socketPath: socketPath,
		cache:      c,
		cacheTTL:   cacheTTL,
		startedAt:  time.Now(),
		watcher:    NewWatcher(c, cacheTTL, socketPath+".watches.json"),
		passkeys:   passkey.NewManager(),
		stopCh:     make(chan struct{}),
	}
}

func (s *Server) Run() error {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.watcher.restoreErr != nil {
		return s.watcher.restoreErr
	}
	os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.listenerMu.Lock()
	s.listener = ln
	select {
	case <-s.stopCh:
		s.listener = nil
		s.listenerMu.Unlock()
		ln.Close()
		return nil
	default:
		s.listenerMu.Unlock()
	}

	if err := os.Chmod(s.socketPath, 0600); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	s.wg.Add(1)
	go s.cleanupLoop()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return nil
			default:
				continue
			}
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.watcher != nil {
			s.watcher.Stop()
		}
		s.passkeys.CloseAll()
		s.listenerMu.Lock()
		if s.listener != nil {
			s.listener.Close()
			s.listener = nil
		}
		s.listenerMu.Unlock()
		os.Remove(s.socketPath)
	})
	s.runMu.Lock()
	s.runMu.Unlock()
	s.wg.Wait()
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	if !scanner.Scan() {
		return
	}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		s.writeResponse(conn, Response{Error: "invalid request"})
		return
	}

	resp := s.handleRequest(req)
	s.writeResponse(conn, resp)
}

func (s *Server) handleRequest(req Request) Response {
	switch req.Command {
	case CmdGet:
		return s.handleGet(req)
	case CmdStore:
		return s.handleStore(req)
	case CmdList:
		return s.handleList()
	case CmdFlush:
		return s.handleFlush()
	case CmdStatus:
		return s.handleStatus()
	case CmdWatch:
		return s.handleWatch(req)
	case CmdUnwatch:
		return s.handleUnwatch(req)
	case CmdPasskey:
		return s.handlePasskey(req)
	case CmdStop:
		go func() {
			time.Sleep(100 * time.Millisecond)
			s.Stop()
		}()
		return Response{OK: true}
	default:
		return Response{Error: fmt.Sprintf("unknown command: %s", req.Command)}
	}
}
func (s *Server) handleGet(req Request) Response {
	entry, ok := s.cache.Get(req.SecretName, req.Vault)
	if !ok {
		return Response{OK: false, Error: "cache miss"}
	}
	return Response{OK: true, Fields: entry.Fields}
}

func (s *Server) handleStore(req Request) Response {
	ttl := s.cacheTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	s.cache.Store(req.SecretName, req.Vault, req.Fields, ttl)
	return Response{OK: true}
}

func (s *Server) handleList() Response {
	return Response{
		OK:      true,
		Entries: s.cache.List(),
		Watches: s.watcher.List(),
	}
}

func (s *Server) handleFlush() Response {
	s.cache.Flush()
	return Response{OK: true}
}

func (s *Server) handleStatus() Response {
	return Response{
		OK: true,
		Status: &DaemonStatus{
			Uptime:       time.Since(s.startedAt).Truncate(time.Second).String(),
			EntryCount:   s.cache.Count(),
			WatchCount:   s.watcher.Count(),
			PasskeyCount: len(s.passkeys.List()),
			SocketPath:   s.socketPath,
			PID:          os.Getpid(),
		},
	}
}

func (s *Server) handleWatch(req Request) Response {
	if req.Watch == nil || req.Watch.Token == "" || req.Watch.StatusURL == "" {
		return Response{OK: false, Error: "invalid watch specification: token and status_url required"}
	}
	if req.Watch.CacheTTLSec <= 0 {
		req.Watch.CacheTTLSec = int(s.cacheTTL.Seconds())
	}
	newlyRegistered, err := s.watcher.Register(*req.Watch)
	if err != nil {
		return Response{OK: false, Error: "persist watch: " + err.Error()}
	}
	state := "registered"
	if !newlyRegistered {
		state = "duplicate"
	}
	return Response{OK: true, WatchState: state}
}

func (s *Server) handleUnwatch(req Request) Response {
	if req.Token == "" {
		return Response{OK: false, Error: "token is required for unwatch"}
	}
	removed, err := s.watcher.Unwatch(req.Token)
	if err != nil {
		return Response{OK: false, Error: "persist unwatch: " + err.Error()}
	}
	state := "not_found"
	if removed {
		state = "removed"
	}
	return Response{OK: true, WatchState: state}
}

// handlePasskey runs a passkey action. Only collect returns key material, and
// only to the client on the 0600 socket; nothing here is logged.
func (s *Server) handlePasskey(req Request) Response {
	p := req.Passkey
	if p == nil {
		return Response{Error: "passkey request is missing"}
	}
	ctx := context.Background()
	target := passkey.Target{Endpoint: p.Endpoint, PageURL: p.PageURL, TargetID: p.TargetID, Hold: time.Duration(p.HoldSec) * time.Second}
	var info passkey.Info
	var err error
	switch p.Action {
	case PasskeyArm:
		info, err = s.passkeys.Arm(ctx, target)
	case PasskeyLoad:
		if p.Credential == nil {
			return Response{Error: "load needs a credential"}
		}
		info, err = s.passkeys.Load(ctx, target, *p.Credential, p.Item, p.Vault)
	case PasskeyCollect:
		var cred passkey.Credential
		cred, info, err = s.passkeys.Collect(ctx, p.Session, p.Item, p.Vault)
		if err == nil {
			return Response{OK: true, Passkeys: []passkey.Info{info}, Credential: &cred}
		}
	case PasskeyRelease:
		info, err = s.passkeys.Release(ctx, p.Session)
	case PasskeyList:
		return Response{OK: true, Passkeys: s.passkeys.List()}
	default:
		return Response{Error: fmt.Sprintf("unknown passkey action %q", p.Action)}
	}
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Passkeys: []passkey.Info{info}}
}

func (s *Server) writeResponse(conn net.Conn, resp Response) {
	data, _ := json.Marshal(resp)
	data = append(data, '\n')
	conn.Write(data)
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cache.Cleanup()
		}
	}
}
