package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchStoreRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watches.json")
	store := newWatchStore(path)
	spec := WatchSpec{Token: "tok", StatusURL: "http://127.0.0.1/status/tok", SecretName: "item", Vault: "Infra", IsMutation: true, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}
	if err := store.save([]WatchSpec{spec}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	got, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Token != "tok" || !got[0].IsMutation {
		t.Fatalf("loaded watches = %+v", got)
	}
}

func TestWatchStoreDropsExpiredWatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watches.json")
	store := newWatchStore(path)
	if err := store.save([]WatchSpec{{Token: "expired", ExpiresAt: time.Now().Add(-time.Minute).Format(time.RFC3339)}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("loaded expired watches = %+v", got)
	}
}

func TestWatcherStopPreservesPendingWatchesForRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watches.json")
	watcher := NewWatcher(NewCache(), time.Hour, path)
	spec := WatchSpec{
		Token: "pending", StatusURL: "http://127.0.0.1:1/status/pending",
		SecretName: "item", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
	}
	registered, err := watcher.Register(spec)
	if err != nil || !registered {
		t.Fatalf("register: registered=%v err=%v", registered, err)
	}
	watcher.Stop()
	time.Sleep(25 * time.Millisecond)
	got, err := newWatchStore(path).load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Token != "pending" {
		t.Fatalf("persisted watches after stop = %+v", got)
	}
}

func TestWatcherSurfacesCorruptPersistentState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watches.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	watcher := NewWatcher(NewCache(), time.Hour, path)
	if watcher.restoreErr == nil {
		t.Fatal("corrupt watch state was silently ignored")
	}
}
