package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEventsAreAppendedAsPrivateJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "audit.jsonl")
	l := New(path)
	l.Event(WindowOpened, map[string]any{"window": "w1", "vault": "AI Agents"})
	l.Event(WindowClosed, map[string]any{"window": "w1", "reason": "revoked"})

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("audit file: %v, %v", info, err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	var events []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("line is not JSON: %q", scanner.Text())
		}
		if entry["ts"] == nil || entry["window"] != "w1" {
			t.Fatalf("entry = %v", entry)
		}
		events = append(events, entry["event"].(string))
	}
	if len(events) != 2 || events[0] != WindowOpened || events[1] != WindowClosed {
		t.Fatalf("events = %v", events)
	}
}

func TestNilLogAndEmptyPathAreSafe(t *testing.T) {
	var nilLog *Log
	nilLog.Event(WindowOpened, nil)
	New("").Event(WindowOpened, map[string]any{"k": "v"})
}
