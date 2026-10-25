package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	// DefaultExecTimeout bounds child processes that do not set a timeout.
	DefaultExecTimeout = 30 * time.Second
	maxOutputSize      = 1 << 20 // 1MB per stream
)

// ExecSpec describes a child process to run with secret material injected
// via environment variables. Exactly one of Argv or ShellCommand must be
// set. Argv is passed directly to the OS with no shell interpretation;
// ShellCommand is the explicit opt-in that runs via "sh -c".
type ExecSpec struct {
	Argv         []string
	ShellCommand string
	Env          map[string]string
	Stdin        []byte // optional child stdin
	WorkingDir   string
	Timeout      time.Duration
	Redactor     *Redactor
}

// truncateOutput caps output at maxOutputSize and appends a notice.
func truncateOutput(s string) string {
	if len(s) <= maxOutputSize {
		return s
	}
	return s[:maxOutputSize] + "\n[output truncated at 1MB]"
}

// ExecCommand runs the child described by spec. Captured stdout/stderr
// are truncated and passed through spec.Redactor before being returned,
// so exact occurrences of registered secrets never leave this function.
func ExecCommand(ctx context.Context, spec ExecSpec) (*ExecResult, error) {
	hasArgv := len(spec.Argv) > 0
	hasShell := spec.ShellCommand != ""
	if hasArgv == hasShell {
		return nil, E(ErrValidation,
			"exactly one of argv or shell command must be provided",
			"pass the command after -- for direct exec, or use --shell for shell interpretation")
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if hasShell {
		cmd = exec.CommandContext(ctx, "sh", "-c", spec.ShellCommand)
	} else {
		cmd = exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	}

	// Inherit current environment, then layer secret env vars on top.
	cmd.Env = os.Environ()
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	if spec.WorkingDir != "" {
		cmd.Dir = spec.WorkingDir
	}
	if spec.Stdin != nil {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	redact := func(s string) string {
		if spec.Redactor != nil {
			return spec.Redactor.Redact(s)
		}
		return s
	}
	result := &ExecResult{
		Stdout: redact(truncateOutput(stdout.String())),
		Stderr: redact(truncateOutput(stderr.String())),
	}

	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr = result.Stderr + "\ncommand timed out after " + timeout.String()
			return result, nil
		} else if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, E(ErrInternal, "failed to run command: "+runErr.Error(), "")
		}
	}
	return result, nil
}
