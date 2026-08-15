package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/johnuopini/secret-gate/internal/core"
)

func writeStdin(ta *testApp, s string) {
	ta.app.Stdin = bytes.NewBufferString(s)
}

func TestWriteRequiresStdinFlag(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"write", "create", "--item", "ci-token", "--vault", "Infra", "--reason", "store token"})
	if code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(ta.errEnvelope(t).Error.Hint, "--stdin") {
		t.Fatal("hint should explain the --stdin contract")
	}
	if ta.proxy.writeCalls != 0 {
		t.Fatal("proxy called despite validation failure")
	}
}

func TestWriteCreateHappyPath(t *testing.T) {
	ta := newTestApp(t)
	writeStdin(ta, `{"category":"API_CREDENTIAL","fields":{"credential":"fake-api-key-123456"}}`)
	code := ta.app.Run([]string{"write", "create", "--item", "ci-token", "--vault", "Infra",
		"--reason", "store the new CI token", "--stdin"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	if ta.proxy.writeCalls != 1 {
		t.Fatalf("writeCalls = %d", ta.proxy.writeCalls)
	}
	if strings.Contains(ta.stdout.String(), "fake-api-key-123456") {
		t.Fatal("value leaked into envelope")
	}
	env := ta.okEnvelope(t)
	if env["meta"].(map[string]interface{})["visibility"] != "value-input" {
		t.Fatal("write must be value-input")
	}
}

func TestWriteDryRunShowsLabelsOnly(t *testing.T) {
	ta := newTestApp(t)
	writeStdin(ta, `{"fields":{"credential":"fake-api-key-123456","url":"https://api.example.com"}}`)
	code := ta.app.Run([]string{"write", "update", "--item", "ci-token", "--vault", "Infra",
		"--reason", "rotate token", "--stdin", "--dry-run"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	if ta.proxy.writeCalls != 0 {
		t.Fatal("--dry-run called the proxy")
	}
	out := ta.stdout.String()
	if strings.Contains(out, "fake-api-key-123456") {
		t.Fatal("dry-run leaked a value")
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	labels := data["field_labels"].([]interface{})
	if data["dry_run"] != true || len(labels) != 2 {
		t.Fatalf("data = %v", data)
	}
}

func TestWriteDeniedExitThree(t *testing.T) {
	ta := newTestApp(t)
	ta.proxy.writeResult = &core.RequestResult{Status: "denied", SecretName: "ci-token", Message: "Request was denied by the approver."}
	writeStdin(ta, `{"fields":{"credential":"fake-api-key-123456"}}`)
	code := ta.app.Run([]string{"write", "create", "--item", "ci-token", "--vault", "Infra",
		"--reason", "store token", "--stdin"})
	if code != ExitDenied {
		t.Fatalf("exit = %d, want 3", code)
	}
	if ta.errEnvelope(t).Error.Code != "denied" {
		t.Fatal("error code should be denied")
	}
}

func TestWriteInvalidOperation(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"write", "delete", "--item", "x"})
	if code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(ta.errEnvelope(t).Error.Message, "create") {
		t.Fatal("error should enumerate valid operations")
	}
}
