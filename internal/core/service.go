package core

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/johnuopini/secret-gate/internal/daemon"
	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/otp"
)

const (
	defaultSearchLimit = 10
	defaultSSHPort     = 22
	defaultSSHTimeout  = 120 * time.Second
	defaultSSHAgentTTL = 1 * time.Hour
)

// Config carries settings shared by every face of the binary.
type Config struct {
	ServerURL   string
	CacheTTLSec int
	SSHAgent    bool
}

// Service is the single domain layer behind the CLI and the MCP adapter.
type Service struct {
	Daemon FullDaemonClient
	Proxy  ProxyClient
	Config Config
	Now    func() time.Time
}

// NewService wires a Service with the real clock.
func NewService(cfg Config, dc FullDaemonClient, pc ProxyClient) *Service {
	return &Service{Daemon: dc, Proxy: pc, Config: cfg, Now: time.Now}
}

// SearchOutput is the search result set.
type SearchOutput struct {
	Results []SearchResultItem `json:"results"`
	Query   string             `json:"query"`
	Count   int                `json:"count"`
}

// OTPResult is a generated one-time code.
type OTPResult struct {
	Code       string `json:"code"`
	ExpiresAt  string `json:"expires_at"`
	SecretUsed string `json:"secret_used"`
}

// ExecRequest describes running a child process with one secret field
// injected as an environment variable.
type ExecRequest struct {
	SecretName   string
	Vault        string
	Field        string
	EnvVar       string
	Argv         []string
	ShellCommand string
	WorkingDir   string
	Timeout      time.Duration
}

// SSHRequest describes an SSH invocation using a cached key item.
type SSHRequest struct {
	SecretName string
	Vault      string
	Host       string
	Command    string
	Port       int
	Timeout    time.Duration
}

// ExecOutcome is the redacted result of a process-only operation.
// Alternatives names other fields of the item that match the requested
// field with a different value; if a login fails, request one and retry.
type ExecOutcome struct {
	ExitCode     int      `json:"exit_code"`
	Stdout       string   `json:"stdout"`
	Stderr       string   `json:"stderr"`
	SecretUsed   string   `json:"secret_used"`
	Alternatives []string `json:"alternatives,omitempty"`
}

func requestHint(secretName string) string {
	return fmt.Sprintf("run: secret-gate request submit --item %q --reason <why>", secretName)
}

func (s *Service) Search(query string, limit int) (*SearchOutput, error) {
	if query == "" {
		return nil, E(ErrValidation, "query is required", `pass a search term, e.g. item search --query "deploy"`)
	}
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	results, err := s.Proxy.Search(query, limit)
	if err != nil {
		return nil, err
	}
	return &SearchOutput{Results: results, Query: query, Count: len(results)}, nil
}

func (s *Service) InspectFields(secretName, vault string) (*FieldsResult, error) {
	if secretName == "" {
		return nil, E(ErrValidation, "item name is required", "pass --item <name>")
	}
	return s.Proxy.GetFields(secretName, vault)
}

// CachedFields returns every approved field of an item from the daemon
// cache, or a not_found error when the item is not approved and cached.
func (s *Service) CachedFields(secretName, vault string) (map[string]string, error) {
	if secretName == "" {
		return nil, E(ErrValidation, "item name is required", "pass --item <name>")
	}
	if !s.Daemon.IsRunning() {
		return nil, E(ErrNotFound, "daemon is not running so no items are cached", requestHint(secretName))
	}
	fields, err := s.Daemon.Get(secretName, vault)
	if err != nil {
		return nil, E(ErrNotFound, fmt.Sprintf("item %q is not approved and cached", secretName), requestHint(secretName))
	}
	return fields, nil
}

// ReadFields returns approved field values for model context. Attachments
// are never returned here; they reach commands only through AttachmentExec.
// Process-only values (card number, CVV, PIN) are withheld from a full read
// and refused when named; they reach commands through exec or browser fill.
func (s *Service) ReadFields(secretName, vault string, want []string) (map[string]string, error) {
	values, err := s.CachedFields(secretName, vault)
	if err != nil {
		return nil, err
	}
	protected := ProcessOnlyKeys(values)
	if len(want) == 0 {
		out := make(map[string]string, len(values))
		for name, value := range values {
			if !strings.HasPrefix(name, AttachmentPrefix) && !models.IsReservedKey(name) && !protected[name] {
				out[name] = value
			}
		}
		return out, nil
	}
	out := make(map[string]string, len(want))
	for _, name := range want {
		if file, ok := strings.CutPrefix(name, AttachmentPrefix); ok {
			return nil, E(ErrValidation, "attachment content is never returned to model context",
				fmt.Sprintf("run: secret-gate attachment exec --item %q --file %q --env FILE_PATH -- <command>", secretName, file))
		}
		actual, value, ok := ResolveField(values, name)
		if !ok {
			if err := FieldAmbiguity(values, name); err != nil {
				return nil, err
			}
			return nil, E(ErrNotFound, fmt.Sprintf("field %q is not available", name),
				"available fields: "+strings.Join(FieldNames(values), ", "))
		}
		if protected[actual] {
			return nil, E(ErrValidation, fmt.Sprintf("%q is process-only (card number, CVV, or PIN) and never enters model context", actual),
				fmt.Sprintf("use: secret-gate browser fill --item %q --field '%s=<css selector>' ... or secret-gate exec --item %q --field %q --env VAR -- <command>", secretName, actual, secretName, actual))
		}
		out[actual] = value
	}
	return out, nil
}

func (s *Service) GetOTP(secretName, vault, field string) (*OTPResult, error) {
	values, err := s.CachedFields(secretName, vault)
	if err != nil {
		return nil, err
	}
	wanted := field
	if wanted == "" {
		wanted = "otp"
	}
	actual, seed, ok := ResolveField(values, wanted)
	if !ok {
		if err := FieldAmbiguity(values, wanted); err != nil {
			return nil, err
		}
		return nil, E(ErrNotFound, "no OTP/MFA/TOTP/2FA field is available in this item",
			fmt.Sprintf("run: secret-gate item fields --item %q", secretName))
	}
	code, expires, err := otp.Generate(seed, s.Now())
	if err != nil {
		return nil, E(ErrInternal, "could not generate OTP: "+err.Error(), "")
	}
	return &OTPResult{
		Code:       code,
		ExpiresAt:  expires.UTC().Format(time.RFC3339),
		SecretUsed: secretName + "/" + actual,
	}, nil
}


// itemRedactor registers every field value of an item so no exact value
// can survive into captured child output.
func itemRedactor(secretName string, values map[string]string) *Redactor {
	r := NewRedactor()
	protected := ProcessOnlyKeys(values)
	for name, v := range values {
		if models.IsReservedKey(name) {
			continue
		}
		r.Add(v, secretName+"/"+name)
		if protected[name] {
			// Card numbers are often printed in groups of four.
			for _, sep := range []string{" ", "-"} {
				if grouped := groupDigits(v, sep); grouped != v {
					r.Add(grouped, secretName+"/"+name)
				}
			}
		}
	}
	return r
}

// groupDigits writes a long digit string in groups of four ("4111 1111 ...").
func groupDigits(v, sep string) string {
	if len(v) < 12 || strings.Trim(v, "0123456789") != "" {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i += 4 {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(v[i:min(i+4, len(v))])
	}
	return b.String()
}

func (s *Service) Exec(ctx context.Context, req ExecRequest) (*ExecOutcome, error) {
	if req.Field == "" {
		return nil, E(ErrValidation, "field is required", "pass --field <label>")
	}
	if file, ok := strings.CutPrefix(req.Field, AttachmentPrefix); ok {
		return nil, E(ErrValidation, "attachments run through attachment exec, not exec",
			fmt.Sprintf("run: secret-gate attachment exec --item %q --file %q --env FILE_PATH -- <command>", req.SecretName, file))
	}
	if req.EnvVar == "" {
		return nil, E(ErrValidation, "env var name is required", "pass --env <NAME>")
	}
	values, err := s.CachedFields(req.SecretName, req.Vault)
	if err != nil {
		return nil, err
	}
	actual, value, ok := ResolveField(values, req.Field)
	if !ok {
		if err := FieldAmbiguity(values, req.Field); err != nil {
			return nil, err
		}
		return nil, E(ErrNotFound,
			fmt.Sprintf("field %q not found in item %q", req.Field, req.SecretName),
			"available fields: "+strings.Join(FieldNames(values), ", "))
	}
	result, err := ExecCommand(ctx, ExecSpec{
		Argv:         req.Argv,
		ShellCommand: req.ShellCommand,
		Env:          map[string]string{req.EnvVar: value},
		WorkingDir:   req.WorkingDir,
		Timeout:      req.Timeout,
		Redactor:     itemRedactor(req.SecretName, values),
	})
	if err != nil {
		return nil, err
	}
	return &ExecOutcome{
		ExitCode:     result.ExitCode,
		Stdout:       result.Stdout,
		Stderr:       result.Stderr,
		SecretUsed:   req.SecretName + "/" + actual,
		Alternatives: FieldAlternatives(values, req.Field, actual),
	}, nil
}

// BuildSSHArgs returns the ssh argv (without identity-file flags) used
// both for execution and for --dry-run previews.
func BuildSSHArgs(host string, port int, command string) []string {
	if port <= 0 {
		port = defaultSSHPort
	}
	args := []string{"ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-p", fmt.Sprintf("%d", port), host}
	if command != "" {
		args = append(args, command)
	}
	return args
}

func (s *Service) SSH(ctx context.Context, req SSHRequest) (*ExecOutcome, error) {
	if req.Host == "" {
		return nil, E(ErrValidation, "host is required", "pass --host user@host")
	}
	values, err := s.CachedFields(req.SecretName, req.Vault)
	if err != nil {
		return nil, err
	}
	fieldName, keyValue, found := daemon.FindSSHKeyField(values)
	if !found {
		return nil, E(ErrNotFound,
			fmt.Sprintf("no SSH private key found in item %q", req.SecretName),
			"available fields: "+strings.Join(FieldNames(values), ", "))
	}

	identityPath := ""
	if s.Config.SSHAgent {
		ttl := time.Duration(s.Config.CacheTTLSec) * time.Second
		if ttl <= 0 {
			ttl = defaultSSHAgentTTL
		}
		if err := daemon.AddToSSHAgent(keyValue, ttl); err != nil {
			identityPath, err = daemon.CreateTempSSHKey(keyValue)
			if err != nil {
				return nil, E(ErrInternal, fmt.Sprintf("failed to prepare SSH key (%s): %v", fieldName, err), "")
			}
		}
	} else {
		var err error
		identityPath, err = daemon.CreateTempSSHKey(keyValue)
		if err != nil {
			return nil, E(ErrInternal, fmt.Sprintf("failed to prepare SSH key (%s): %v", fieldName, err), "")
		}
	}
	if identityPath != "" {
		defer os.Remove(identityPath)
	}

	port := req.Port
	if port <= 0 {
		port = defaultSSHPort
	}
	argv := []string{"ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-p", fmt.Sprintf("%d", port)}
	if identityPath != "" {
		argv = append(argv, "-o", "IdentitiesOnly=yes", "-i", identityPath)
	}
	argv = append(argv, req.Host)
	if req.Command != "" {
		argv = append(argv, req.Command)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultSSHTimeout
	}
	result, err := ExecCommand(ctx, ExecSpec{
		Argv:     argv,
		Timeout:  timeout,
		Redactor: itemRedactor(req.SecretName, values),
	})
	if err != nil {
		return nil, err
	}
	return &ExecOutcome{
		ExitCode:   result.ExitCode,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		SecretUsed: req.SecretName + "/" + fieldName,
	}, nil
}

func (s *Service) Request(ctx context.Context, secretName, vault, reason string, fields []string, rc RequestContext) (*RequestResult, error) {
	if secretName == "" {
		return nil, E(ErrValidation, "item name is required", "pass --item <name>")
	}
	if reason == "" {
		return nil, E(ErrValidation, "reason is required",
			"explain why you need this item so the approver can make an informed decision")
	}
	if s.Daemon.IsRunning() {
		cached, err := s.Daemon.Get(secretName, vault)
		available := err == nil && cached != nil
		for _, f := range fields {
			if _, _, ok := ResolveField(cached, f); !ok {
				available = false
				break
			}
		}
		if available {
			return &RequestResult{
				Status: "approved", SecretName: secretName, Cached: true,
				FieldsAvailable: FieldNames(cached),
				Message:         "Item is already cached and available.",
			}, nil
		}
	}
	return s.Proxy.Request(ctx, secretName, vault, reason, fields, rc)
}

func (s *Service) Write(ctx context.Context, secretName, vault, reason, operation, category string, fields map[string]string, rc RequestContext) (*RequestResult, error) {
	if secretName == "" || vault == "" || len(fields) == 0 || reason == "" {
		return nil, E(ErrValidation, "item name, vault, fields, and reason are required", "")
	}
	if operation != "create" && operation != "update" {
		return nil, E(ErrValidation, fmt.Sprintf("operation must be create or update, got %q", operation), "")
	}
	return s.Proxy.Write(ctx, secretName, vault, reason, operation, category, fields, rc)
}

// MaxWriteItems mirrors the server's per-approval batch limit.
const MaxWriteItems = 10

// WriteItems creates or updates several items in one vault behind a single
// Telegram approval.
func (s *Service) WriteItems(ctx context.Context, vault, reason string, items []ItemWrite, rc RequestContext) (*RequestResult, error) {
	wc, err := s.writeClient(vault, reason, items)
	if err != nil {
		return nil, err
	}
	return wc.WriteItems(ctx, vault, reason, items, rc)
}

// SubmitWrite submits the approval and returns at once. The server holds the
// values while approval is pending, so the caller can drop them now.
func (s *Service) SubmitWrite(ctx context.Context, vault, reason string, items []ItemWrite, rc RequestContext) (*PendingRequest, error) {
	wc, err := s.writeClient(vault, reason, items)
	if err != nil {
		return nil, err
	}
	return wc.SubmitWrite(ctx, vault, reason, items, rc)
}

func (s *Service) writeClient(vault, reason string, items []ItemWrite) (WriteClient, error) {
	if vault == "" || reason == "" {
		return nil, E(ErrValidation, "vault and reason are required", "pass --vault <vault> --reason <why>")
	}
	if len(items) == 0 || len(items) > MaxWriteItems {
		return nil, E(ErrValidation, fmt.Sprintf("a write needs 1 to %d items, got %d", MaxWriteItems, len(items)), "")
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		if item.Item == "" || (len(item.Fields) == 0 && len(item.Files) == 0 && len(item.OwnerFields) == 0) {
			return nil, E(ErrValidation, "every item needs a title and at least one field, file, or owner field", "")
		}
		if item.Operation != "create" && item.Operation != "update" {
			return nil, E(ErrValidation, fmt.Sprintf("operation must be create or update, got %q", item.Operation), "")
		}
		if seen[item.Item] {
			return nil, E(ErrValidation, fmt.Sprintf("%q appears twice; merge its fields into one entry", item.Item), "")
		}
		seen[item.Item] = true
	}
	if err := loadFiles(items); err != nil {
		return nil, err
	}
	wc, ok := s.Proxy.(WriteClient)
	if !ok {
		return nil, E(ErrInternal, "this proxy client cannot submit batch or background writes", "")
	}
	return wc, nil
}

func (s *Service) DaemonStatus() (*DaemonStatusResult, error) {
	if !s.Daemon.IsRunning() {
		return &DaemonStatusResult{Running: false}, nil
	}
	status, err := s.Daemon.StatusInfo()
	if err != nil {
		return nil, E(ErrInternal, "failed to get daemon status: "+err.Error(), "")
	}
	return status, nil
}
