package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestWriteResultEnvelope(t *testing.T) {
	var buf bytes.Buffer
	err := WriteResult(&buf, "item search", map[string]int{"count": 0}, &Meta{Visibility: VisibilityMetadataOnly})
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if env["schema_version"] != "1.0" || env["ok"] != true || env["command"] != "item search" {
		t.Fatalf("envelope = %v", env)
	}
	meta := env["meta"].(map[string]interface{})
	if meta["visibility"] != "metadata-only" {
		t.Fatalf("meta = %v", meta)
	}
}

func TestWriteErrorEnvelope(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteError(&buf, "item read", "not_found", "nope", "try request submit"); err != nil {
		t.Fatal(err)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Command       string `json:"command"`
		Error         struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
		} `json:"error"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error.Code != "not_found" || env.Error.Hint == "" {
		t.Fatalf("env = %+v", env)
	}
}

func TestExitCodeFor(t *testing.T) {
	cases := map[string]int{
		"usage": 2, "validation": 2,
		"denied": 3,
		"expired": 4, "timeout": 4,
		"network": 5, "server": 5,
		"not_found": 6, "not_cached": 6,
		"internal": 1, "anything-else": 1,
	}
	for code, want := range cases {
		if got := ExitCodeFor(code); got != want {
			t.Errorf("ExitCodeFor(%q) = %d, want %d", code, got, want)
		}
	}
}
