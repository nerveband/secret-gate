package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecArgvInjectsWithoutShell(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["prod-api"] = map[string]string{"credential": "fake-api-key-123456"}
	code := ta.app.Run([]string{"exec", "--item", "prod-api", "--field", "credential",
		"--env", "API_KEY", "--", "sh", "-c", "test -n \"$API_KEY\""})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	env := ta.okEnvelope(t)
	meta := env["meta"].(map[string]interface{})
	if meta["visibility"] != "process-only" {
		t.Fatalf("visibility = %v", meta["visibility"])
	}
}

func TestExecOutputRedacted(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["prod-api"] = map[string]string{"credential": "fake-api-key-123456"}
	code := ta.app.Run([]string{"exec", "--item", "prod-api", "--field", "credential",
		"--env", "API_KEY", "--shell", "echo leaked=$API_KEY"})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	out := ta.stdout.String()
	if strings.Contains(out, "fake-api-key-123456") {
		t.Fatalf("secret leaked to stdout: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:prod-api/credential]") {
		t.Fatalf("missing redaction marker: %q", out)
	}
}

func TestExecShellAndArgvMutuallyExclusive(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"exec", "--item", "x", "--field", "f", "--env", "V",
		"--shell", "echo hi", "--", "echo", "hi"})
	if code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestExecNotCachedExitSix(t *testing.T) {
	ta := newTestApp(t)
	code := ta.app.Run([]string{"exec", "--item", "ghost", "--field", "f", "--env", "V", "--", "true"})
	if code != ExitNotFound {
		t.Fatalf("exit = %d, want 6", code)
	}
}

func TestExecDryRunDoesNotExecute(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["prod-api"] = map[string]string{"credential": "fake-api-key-123456"}
	marker := filepath.Join(t.TempDir(), "executed")
	code := ta.app.Run([]string{"exec", "--item", "prod-api", "--field", "credential",
		"--env", "API_KEY", "--dry-run", "--", "touch", marker})
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, ta.stderr.String())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("--dry-run executed the command")
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	if data["dry_run"] != true || data["secret_used"] != "prod-api/credential" {
		t.Fatalf("data = %v", data)
	}
	if strings.Contains(ta.stdout.String(), "fake-api-key-123456") {
		t.Fatal("dry-run leaked the value")
	}
}

func TestExecChildFailureExitOne(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["prod-api"] = map[string]string{"credential": "fake-api-key-123456"}
	code := ta.app.Run([]string{"exec", "--item", "prod-api", "--field", "credential",
		"--env", "API_KEY", "--", "sh", "-c", "exit 7"})
	if code != ExitFailure {
		t.Fatalf("exit = %d, want 1", code)
	}
	env := ta.okEnvelope(t)
	if env["data"].(map[string]interface{})["exit_code"].(float64) != 7 {
		t.Fatalf("data = %v", env["data"])
	}
}
