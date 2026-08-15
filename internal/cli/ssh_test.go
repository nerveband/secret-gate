package cli

import (
	"strings"
	"testing"
)

const fakeSSHKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakefakefake\n-----END OPENSSH PRIVATE KEY-----"

func TestSSHDryRunPreview(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["deploy-key"] = map[string]string{"private key": fakeSSHKey}
	code := ta.app.Run([]string{"ssh", "--item", "deploy-key", "--host", "deploy@web1.example.com",
		"--command", "uptime", "--dry-run"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	if data["dry_run"] != true || data["secret_used"] != "deploy-key/private key" {
		t.Fatalf("data = %v", data)
	}
	argv := data["argv"].([]interface{})
	if argv[0] != "ssh" || argv[len(argv)-1] != "uptime" {
		t.Fatalf("argv = %v", argv)
	}
	if strings.Contains(ta.stdout.String(), "BEGIN OPENSSH") {
		t.Fatal("dry-run leaked key material")
	}
}

func TestSSHMissingHost(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"ssh", "--item", "deploy-key"}); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestSSHNoKeyFieldExitSix(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["not-a-key"] = map[string]string{"password": "fake-pass-9999"}
	code := ta.app.Run([]string{"ssh", "--item", "not-a-key", "--host", "a@b", "--dry-run"})
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
}

func TestSSHNotCachedExitSix(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"ssh", "--item", "ghost", "--host", "a@b", "--dry-run"})
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
}
