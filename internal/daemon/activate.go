package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// FireActivation executes the requested activation action (Paseo prompt injection or command).
// It redacts sensitive secrets by construction: message contains only token, secret name, status, and approver.
func FireActivation(spec *ActivationSpec, token, secretName, status, approver string) error {
	if spec == nil || spec.Kind == "none" {
		return nil
	}

	kind := spec.Kind
	if kind == "" && spec.PaseoAgentID != "" {
		kind = "paseo"
	}

	switch kind {
	case "paseo":
		return activatePaseo(spec, token, secretName, status, approver)
	case "command":
		return activateCommand(spec, token, secretName, status, approver)
	default:
		return nil
	}
}

func activatePaseo(spec *ActivationSpec, token, secretName, status, approver string) error {
	if spec.PaseoAgentID == "" {
		return fmt.Errorf("paseo_agent_id is required for paseo activation")
	}

	message := spec.PromptTemplate
	if message == "" {
		switch status {
		case "approved":
			message = fmt.Sprintf("Secret Gate: request %s for item %q was approved. Access is cached in the local daemon. Resume the task with exec_with_secret, ssh_with_secret, or read_item_fields.", token, secretName)
		case "denied":
			message = fmt.Sprintf("Secret Gate: request %s for item %q was denied by the approver.", token, secretName)
		case "expired":
			message = fmt.Sprintf("Secret Gate: request %s for item %q expired before approval.", token, secretName)
		default:
			message = fmt.Sprintf("Secret Gate: request %s for item %q status: %s.", token, secretName, status)
		}
	}

	paseoBin, err := FindPaseoBinary()
	if err != nil {
		return fmt.Errorf("locating paseo binary: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, paseoBin, "send", spec.PaseoAgentID, message)
	cmd.Env = os.Environ()
	return cmd.Run()
}

func activateCommand(spec *ActivationSpec, token, secretName, status, approver string) error {
	if len(spec.Argv) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, spec.Argv[0], spec.Argv[1:]...)
	cmd.Env = append(os.Environ(),
		"SECRET_GATE_TOKEN="+token,
		"SECRET_GATE_SECRET_NAME="+secretName,
		"SECRET_GATE_STATUS="+status,
		"SECRET_GATE_APPROVER="+approver,
	)
	return cmd.Run()
}

// FindPaseoBinary searches PATH and standard installation paths for the paseo CLI.
func FindPaseoBinary() (string, error) {
	if path, err := exec.LookPath("paseo"); err == nil {
		return path, nil
	}

	candidates := []string{
		"/usr/local/bin/paseo",
		"/usr/bin/paseo",
		os.ExpandEnv("$HOME/.local/bin/paseo"),
		os.ExpandEnv("$HOME/.cargo/bin/paseo"),
		"/Applications/Paseo.app/Contents/Resources/bin/paseo",
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && (fi.Mode()&0111 != 0) {
			return c, nil
		}
	}

	// Fallback to "paseo" in case PATH will resolve at execution time
	return "paseo", nil
}

// SniffActivationSpec infers the activation spec from environment variables.
func SniffActivationSpec() *ActivationSpec {
	// 1. Explicit override
	if val := os.Getenv("SECRET_GATE_ACTIVATE"); val != "" {
		if strings.EqualFold(val, "none") {
			return &ActivationSpec{Kind: "none"}
		}
		if strings.HasPrefix(val, "paseo:") {
			return &ActivationSpec{Kind: "paseo", PaseoAgentID: strings.TrimPrefix(val, "paseo:")}
		}
		if strings.HasPrefix(val, "cmd:") {
			parts := strings.Fields(strings.TrimPrefix(val, "cmd:"))
			return &ActivationSpec{Kind: "command", Argv: parts}
		}
	}

	// 2. Paseo agent environment
	for _, envVar := range []string{"PASEO_AGENT_ID", "SECRET_GATE_PASEO_AGENT_ID"} {
		if id := os.Getenv(envVar); id != "" {
			return &ActivationSpec{Kind: "paseo", PaseoAgentID: id}
		}
	}

	return nil
}
