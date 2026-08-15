package cli

import (
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"version"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	env := ta.okEnvelope(t)
	data := env["data"].(map[string]interface{})
	if data["version"] != "0.4.0" || env["command"] != "version" {
		t.Fatalf("env = %v", env)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"frobnicate"}); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
	if ta.stdout.Len() != 0 {
		t.Fatalf("stdout not empty: %q", ta.stdout.String())
	}
	env := ta.errEnvelope(t)
	if env.Error.Code != "usage" || !strings.Contains(env.Error.Hint, "--help") {
		t.Fatalf("error = %+v", env.Error)
	}
}

func TestRunNoArgsIsUsageError(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run(nil); code != ExitUsage {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestGlobalFlagsStripped(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"--json", "--quiet", "version"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !ta.app.Quiet {
		t.Fatal("--quiet did not set Quiet")
	}
}

func TestRootHelpListsSubcommands(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"--help"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	help := ta.stdout.String()
	for _, want := range []string{"item", "exec", "ssh", "otp", "write", "request", "daemon", "agent-context", "schema", "version", "Exit codes"} {
		if !strings.Contains(help, want) {
			t.Errorf("root help missing %q", want)
		}
	}
}
