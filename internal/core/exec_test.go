package core

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecArgvNoShellInterpolation(t *testing.T) {
	// $INJECTED and ; must NOT be interpreted: argv goes straight to execve.
	res, err := ExecCommand(context.Background(), ExecSpec{
		Argv: []string{"echo", "$INJECTED;", "id"},
		Env:  map[string]string{"INJECTED": "boom"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "$INJECTED; id" {
		t.Fatalf("stdout = %q — shell interpolation happened", got)
	}
}

func TestExecShellOptIn(t *testing.T) {
	res, err := ExecCommand(context.Background(), ExecSpec{
		ShellCommand: "echo $SECRET_VALUE_X | tr a-z A-Z",
		Env:          map[string]string{"SECRET_VALUE_X": "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "HELLO" {
		t.Fatalf("stdout = %q, want HELLO", got)
	}
}

func TestExecRejectsBothOrNeither(t *testing.T) {
	_, err := ExecCommand(context.Background(), ExecSpec{})
	if CodeOf(err) != ErrValidation {
		t.Fatalf("neither: CodeOf = %v, want validation", CodeOf(err))
	}
	_, err = ExecCommand(context.Background(), ExecSpec{Argv: []string{"echo"}, ShellCommand: "echo"})
	if CodeOf(err) != ErrValidation {
		t.Fatalf("both: CodeOf = %v, want validation", CodeOf(err))
	}
}

func TestExecRedactsOutputStreams(t *testing.T) {
	r := NewRedactor()
	r.Add("fake-api-key-123456", "prod-api/credential")
	res, err := ExecCommand(context.Background(), ExecSpec{
		ShellCommand: "echo $K; echo $K >&2",
		Env:          map[string]string{"K": "fake-api-key-123456"},
		Redactor:     r,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout, "fake-api-key-123456") || strings.Contains(res.Stderr, "fake-api-key-123456") {
		t.Fatalf("secret leaked: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "[REDACTED:prod-api/credential]") {
		t.Fatalf("stdout missing redaction marker: %q", res.Stdout)
	}
	if !strings.Contains(res.Stderr, "[REDACTED:prod-api/credential]") {
		t.Fatalf("stderr missing redaction marker: %q", res.Stderr)
	}
}

func TestExecExitCodeAndTimeout(t *testing.T) {
	res, err := ExecCommand(context.Background(), ExecSpec{Argv: []string{"sh", "-c", "exit 7"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", res.ExitCode)
	}

	res, err = ExecCommand(context.Background(), ExecSpec{
		Argv:    []string{"sleep", "5"},
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != -1 || !strings.Contains(res.Stderr, "timed out") {
		t.Fatalf("timeout: ExitCode=%d Stderr=%q", res.ExitCode, res.Stderr)
	}
}

func TestExecWorkingDir(t *testing.T) {
	dir := t.TempDir()
	res, err := ExecCommand(context.Background(), ExecSpec{Argv: []string{"pwd"}, WorkingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.TrimSpace(res.Stdout), dir) {
		t.Fatalf("pwd = %q, want %q", res.Stdout, dir)
	}
}
