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

const batchStdin = `{"items":[
	{"item":"Play service account","operation":"create","category":"API_CREDENTIAL","fields":{"credential":"fake-play-json-123"}},
	{"item":"Expo token","operation":"create","fields":{"token":"fake-expo-token-456"}}]}`

func TestWriteBatchSubmitsOneRequestWithoutEchoingValues(t *testing.T) {
	ta := newTestApp(t)
	writeStdin(ta, batchStdin)
	code := ta.app.Run([]string{"write", "batch", "--vault", "AI Agents", "--reason", "store release credentials", "--stdin"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	if len(ta.proxy.batchItems) != 1 || len(ta.proxy.batchItems[0]) != 2 || ta.proxy.writeCalls != 0 {
		t.Fatalf("batch calls = %v, single writes = %d", ta.proxy.batchItems, ta.proxy.writeCalls)
	}
	for _, value := range []string{"fake-play-json-123", "fake-expo-token-456"} {
		if strings.Contains(ta.stdout.String()+ta.stderr.String(), value) {
			t.Fatalf("value %s leaked into output", value)
		}
	}
}

func TestWriteBatchDryRunListsItemsAndLabelsOnly(t *testing.T) {
	ta := newTestApp(t)
	writeStdin(ta, batchStdin)
	code := ta.app.Run([]string{"write", "batch", "--vault", "AI Agents", "--reason", "store", "--stdin", "--dry-run"})
	if code != ExitOK || len(ta.proxy.batchItems) != 0 {
		t.Fatalf("exit = %d, proxy calls = %d", code, len(ta.proxy.batchItems))
	}
	out := ta.stdout.String()
	if strings.Contains(out, "fake-play-json-123") || !strings.Contains(out, "Expo token") || !strings.Contains(out, `"token"`) {
		t.Fatalf("dry-run output = %s", out)
	}
}

func TestWriteBatchRejectsDuplicateItemsBeforeSubmitting(t *testing.T) {
	ta := newTestApp(t)
	writeStdin(ta, `{"items":[{"item":"A","operation":"create","fields":{"k":"v"}},{"item":"A","operation":"update","fields":{"j":"v"}}]}`)
	code := ta.app.Run([]string{"write", "batch", "--vault", "AI Agents", "--reason", "store", "--stdin"})
	if code != ExitUsage || len(ta.proxy.batchItems) != 0 {
		t.Fatalf("exit = %d, proxy calls = %d", code, len(ta.proxy.batchItems))
	}
}

func TestWriteNoWaitHandsCompletionToDaemon(t *testing.T) {
	ta := newTestApp(t)
	writeStdin(ta, `{"fields":{"otp":"fake-seed-789"}}`)
	code := ta.app.Run([]string{"write", "create", "--item", "WordPress.org 2FA", "--vault", "AI Agents",
		"--reason", "store 2FA seed", "--stdin", "--no-wait"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	if ta.proxy.submitWrites != 1 || ta.proxy.writeCalls != 0 {
		t.Fatalf("submitWrites=%d blocking writes=%d", ta.proxy.submitWrites, ta.proxy.writeCalls)
	}
	if len(ta.daemon.watches) != 1 || !ta.daemon.watches[0].IsMutation || ta.daemon.watches[0].Token != "tok-write" {
		t.Fatalf("daemon watches = %#v", ta.daemon.watches)
	}
	entry, err := ta.app.ledgerEntry("tok-write")
	if err != nil || entry == nil || entry.Operation != "write" || entry.State != "pending" {
		t.Fatalf("ledger entry = %#v err=%v", entry, err)
	}
	out := ta.stdout.String()
	if strings.Contains(out, "fake-seed-789") || !strings.Contains(out, "request wait tok-write") {
		t.Fatalf("output = %s", out)
	}
}
