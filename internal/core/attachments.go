package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// AttachmentPrefix marks an attachment selector in request fields and the
// cache key an approved attachment is stored under ("file:<name or id>").
const AttachmentPrefix = "file:"

// MaxAttachmentBytes mirrors the server's per-request attachment limit.
const MaxAttachmentBytes = 10 << 20

// AttachmentExecRequest runs a command with one cached attachment, either as
// a mode-0600 temporary file whose path is in PathEnv, or on stdin.
type AttachmentExecRequest struct {
	SecretName   string
	Vault        string
	File         string // attachment name or ID, as requested
	PathEnv      string
	Stdin        bool
	Argv         []string
	ShellCommand string
	WorkingDir   string
	Timeout      time.Duration
}

func attachmentHint(secretName, file string) string {
	return fmt.Sprintf("run: secret-gate request submit --item %q --fields %q --reason <why>", secretName, AttachmentPrefix+file)
}

// AttachmentExec hands an approved attachment to a child process. The
// content never enters model context: a temporary file is created in a
// private directory and removed when the command exits, and exact copies of
// text content are redacted from captured output.
func (s *Service) AttachmentExec(ctx context.Context, req AttachmentExecRequest) (*ExecOutcome, error) {
	if req.File == "" {
		return nil, E(ErrValidation, "attachment is required", "pass --file <name>")
	}
	if (req.PathEnv == "") == !req.Stdin {
		return nil, E(ErrValidation, "pass exactly one of --env <VAR> (temporary file path) or --stdin", "")
	}
	values, err := s.CachedFields(req.SecretName, req.Vault)
	if err != nil {
		return nil, err
	}
	key := AttachmentPrefix + req.File
	encoded, ok := values[key]
	if !ok {
		return nil, E(ErrNotFound, fmt.Sprintf("attachment %q of %q is not approved and cached", req.File, req.SecretName), attachmentHint(req.SecretName, req.File))
	}
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, E(ErrInternal, "cached attachment is not valid base64", attachmentHint(req.SecretName, req.File))
	}
	redactor := itemRedactor(req.SecretName, values)
	if utf8.Valid(content) {
		redactor.Add(string(content), req.SecretName+"/"+key)
		redactor.Add(strings.TrimSpace(string(content)), req.SecretName+"/"+key)
	}
	spec := ExecSpec{
		Argv:         req.Argv,
		ShellCommand: req.ShellCommand,
		WorkingDir:   req.WorkingDir,
		Timeout:      req.Timeout,
		Redactor:     redactor,
	}
	if req.Stdin {
		spec.Stdin = content
	} else {
		dir, err := os.MkdirTemp("", "secret-gate-file-")
		if err != nil {
			return nil, E(ErrInternal, "creating a private temporary directory: "+err.Error(), "")
		}
		defer os.RemoveAll(dir)
		name := filepath.Base(req.File)
		if name == "." || name == string(filepath.Separator) {
			name = "attachment"
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return nil, E(ErrInternal, "writing the temporary attachment file: "+err.Error(), "")
		}
		spec.Env = map[string]string{req.PathEnv: path}
	}
	result, err := ExecCommand(ctx, spec)
	if err != nil {
		return nil, err
	}
	return &ExecOutcome{
		ExitCode:   result.ExitCode,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		SecretUsed: req.SecretName + "/" + key,
	}, nil
}

// loadFiles reads each file to attach from its local path and checks names
// and the per-request size limit before anything is sent for approval.
func loadFiles(items []ItemWrite) error {
	var total int64
	for i := range items {
		for j := range items[i].Files {
			f := &items[i].Files[j]
			if f.Path == "" {
				return E(ErrValidation, "every file needs a local path", "")
			}
			info, err := os.Stat(f.Path)
			if err != nil {
				return E(ErrValidation, fmt.Sprintf("cannot read file %q: %v", f.Path, err), "")
			}
			if !info.Mode().IsRegular() {
				return E(ErrValidation, fmt.Sprintf("%q is not a regular file", f.Path), "")
			}
			total += info.Size()
			if total > MaxAttachmentBytes {
				return E(ErrValidation, fmt.Sprintf("attachments exceed %d bytes per request", MaxAttachmentBytes), "attach large files in separate requests")
			}
			content, err := os.ReadFile(f.Path)
			if err != nil {
				return E(ErrValidation, fmt.Sprintf("cannot read file %q: %v", f.Path, err), "")
			}
			f.Content = content
			if f.Name == "" {
				f.Name = filepath.Base(f.Path)
			}
		}
	}
	return nil
}
