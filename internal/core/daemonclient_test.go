package core

import "testing"

func TestRealDaemonClientImplementsAdmin(t *testing.T) {
	var _ AdminDaemonClient = NewRealDaemonClientWithConfig(60)
}

func TestRealDaemonClientNotRunningOnEmptyRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir()) // isolated socket path — nothing listening
	dc := NewRealDaemonClientWithConfig(60)
	if dc.IsRunning() {
		t.Fatal("IsRunning() = true with no daemon socket")
	}
}
