package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "secret-gate-cli-int")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "secret-gate")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		panic("build failed: " + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type runResult struct {
	stdout string
	stderr string
	exit   int
}

// run executes the built binary in a fully isolated environment:
// no daemon socket, no ledger, unroutable server, empty HOME.
func run(t *testing.T, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(),
		"XDG_RUNTIME_DIR="+t.TempDir(),
		"SECRET_GATE_STATE_DIR="+t.TempDir(),
		"SECRET_GATE_URL=http://127.0.0.1:9",
		"HOME="+t.TempDir(),
	)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exit := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return runResult{stdout.String(), stderr.String(), exit}
}

func decode(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %v\ninput=%q", err, s)
	}
	return m
}

func TestBinaryVersionEnvelope(t *testing.T) {
	res := run(t, "version")
	if res.exit != 0 {
		t.Fatalf("exit = %d, stderr = %s", res.exit, res.stderr)
	}
	env := decode(t, res.stdout)
	if env["ok"] != true || env["command"] != "version" {
		t.Fatalf("env = %v", env)
	}
}

func TestBinaryUnknownCommandExitTwo(t *testing.T) {
	res := run(t, "frobnicate")
	if res.exit != 2 {
		t.Fatalf("exit = %d, want 2", res.exit)
	}
	if res.stdout != "" {
		t.Fatalf("stdout not empty: %q", res.stdout)
	}
	env := decode(t, res.stderr)
	if env["ok"] != false {
		t.Fatalf("stderr env = %v", env)
	}
}

// TestBinaryLegacyLeakClosed is the regression test for the pre-0.4.0
// stdout secret leak: flag-style invocation must never reach the
// request path and must never print values.
func TestBinaryLegacyLeakClosed(t *testing.T) {
	for _, args := range [][]string{
		{"--server", "http://127.0.0.1:9", "--secret", "deploy-key"},
		{"--secret", "deploy-key"},
		{"--search", "deploy"},
	} {
		res := run(t, args...)
		if res.exit != 2 {
			t.Errorf("args %v: exit = %d, want 2", args, res.exit)
		}
		if res.stdout != "" {
			t.Errorf("args %v: stdout not empty: %q", args, res.stdout)
		}
		env := decode(t, res.stderr)
		errBody := env["error"].(map[string]interface{})
		if !strings.Contains(errBody["hint"].(string), "item read") {
			t.Errorf("args %v: hint %v lacks migration guidance", args, errBody["hint"])
		}
	}
}

func TestBinaryItemReadRequiresReveal(t *testing.T) {
	res := run(t, "item", "read", "--item", "prod-api")
	if res.exit != 2 {
		t.Fatalf("exit = %d, want 2", res.exit)
	}
}

func TestBinaryExecNotCachedExitSix(t *testing.T) {
	res := run(t, "exec", "--item", "ghost", "--field", "f", "--env", "V", "--", "true")
	if res.exit != 6 {
		t.Fatalf("exit = %d, want 6\nstderr=%s", res.exit, res.stderr)
	}
}

func TestBinarySearchNetworkExitFive(t *testing.T) {
	res := run(t, "item", "search", "--query", "deploy")
	if res.exit != 5 {
		t.Fatalf("exit = %d, want 5\nstderr=%s", res.exit, res.stderr)
	}
	env := decode(t, res.stderr)
	if env["error"].(map[string]interface{})["code"] != "network" {
		t.Fatalf("error = %v", env["error"])
	}
}

func TestBinarySchemaAndAgentContext(t *testing.T) {
	res := run(t, "schema")
	if res.exit != 0 {
		t.Fatalf("schema exit = %d", res.exit)
	}
	data := decode(t, res.stdout)["data"].(map[string]interface{})
	if len(data["commands"].([]interface{})) < 19 {
		t.Fatal("schema manifest too small")
	}

	res = run(t, "agent-context", "--json")
	if res.exit != 0 {
		t.Fatalf("agent-context exit = %d", res.exit)
	}
	data = decode(t, res.stdout)["data"].(map[string]interface{})
	if data["exit_codes"] == nil || data["visibility_classes"] == nil {
		t.Fatal("agent-context incomplete")
	}
}

func TestBinaryDaemonVerbsIdempotentWithoutDaemon(t *testing.T) {
	for _, args := range [][]string{
		{"daemon", "status"},
		{"daemon", "flush", "--commit"},
		{"daemon", "stop"},
	} {
		res := run(t, args...)
		if res.exit != 0 {
			t.Errorf("args %v: exit = %d, want 0 (idempotent no-op)\nstderr=%s", args, res.exit, res.stderr)
		}
		if decode(t, res.stdout)["ok"] != true {
			t.Errorf("args %v: not an ok envelope", args)
		}
	}
}
