package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func attachmentService(t *testing.T, content string) *Service {
	t.Helper()
	svc, _ := newTestService(map[string]map[string]string{"Release keys": {
		"password":      "pw-value-123",
		"file:cert.pem": base64.StdEncoding.EncodeToString([]byte(content)),
	}})
	return svc
}

func TestReadFieldsNeverReturnsAttachments(t *testing.T) {
	svc := attachmentService(t, "-----BEGIN CERT-----")
	all, err := svc.ReadFields("Release keys", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := all["file:cert.pem"]; leaked || all["password"] == "" {
		t.Fatalf("whole-item read = %v", FieldNames(all))
	}
	_, err = svc.ReadFields("Release keys", "", []string{"file:cert.pem"})
	if CodeOf(err) != ErrValidation || !strings.Contains(HintOf(err), "attachment exec") {
		t.Fatalf("explicit attachment read: code=%v hint=%q", CodeOf(err), HintOf(err))
	}
	_, err = svc.Exec(context.Background(), ExecRequest{SecretName: "Release keys", Field: "file:cert.pem", EnvVar: "X", ShellCommand: "true"})
	if CodeOf(err) != ErrValidation {
		t.Fatalf("exec with an attachment field: code=%v", CodeOf(err))
	}
}

func TestAttachmentExecTempFileIsPrivateAndRemoved(t *testing.T) {
	svc := attachmentService(t, "certificate body text")
	out, err := svc.AttachmentExec(context.Background(), AttachmentExecRequest{
		SecretName: "Release keys", File: "cert.pem", PathEnv: "CERT",
		ShellCommand: `stat -c %a "$CERT" 2>/dev/null || stat -f %Lp "$CERT"; basename "$CERT"; echo "$CERT"; cat "$CERT"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.Stdout), "\n")
	if len(lines) != 4 || lines[0] != "600" || lines[1] != "cert.pem" {
		t.Fatalf("stdout = %q", out.Stdout)
	}
	if strings.Contains(out.Stdout, "certificate body text") {
		t.Fatal("attachment content reached captured output unredacted")
	}
	if _, err := os.Stat(lines[2]); !os.IsNotExist(err) {
		t.Fatalf("temporary file %s still exists after the command: %v", lines[2], err)
	}
	if out.SecretUsed != "Release keys/file:cert.pem" {
		t.Fatalf("secret_used = %q", out.SecretUsed)
	}
}

func TestAttachmentExecStdin(t *testing.T) {
	svc := attachmentService(t, "abc")
	out, err := svc.AttachmentExec(context.Background(), AttachmentExecRequest{
		SecretName: "Release keys", File: "cert.pem", Stdin: true, Argv: []string{"wc", "-c"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.Stdout) != "3" {
		t.Fatalf("stdout = %q", out.Stdout)
	}
	_, err = svc.AttachmentExec(context.Background(), AttachmentExecRequest{SecretName: "Release keys", File: "other.bin", Stdin: true, Argv: []string{"true"}})
	if CodeOf(err) != ErrNotFound || !strings.Contains(HintOf(err), "file:other.bin") {
		t.Fatalf("unapproved attachment: code=%v hint=%q", CodeOf(err), HintOf(err))
	}
}

// Files are read on the client and travel as content, never as a path the
// server would have to read.
func TestWriteItemsSendsFileContentNotPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release.jks")
	if err := os.WriteFile(path, []byte("keystore"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "tok", "status_url": "http://gate/status/tok"})
	}))
	t.Cleanup(srv.Close)
	svc := NewService(Config{ServerURL: srv.URL}, newMemDaemon(), NewHTTPProxyClient(srv.URL, newMemDaemon(), 3600))
	_, err := svc.SubmitWrite(context.Background(), "AI Agents", "store keystore", []ItemWrite{{
		Item: "Keystore", Operation: "create", Files: []FileWrite{{Path: path}},
	}}, RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	files := got["mutation"].(map[string]any)["files"].([]any)
	file := files[0].(map[string]any)
	if file["name"] != "release.jks" || file["content"] != base64.StdEncoding.EncodeToString([]byte("keystore")) || file["path"] != nil {
		t.Fatalf("wire file = %#v", file)
	}

	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, MaxAttachmentBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = svc.SubmitWrite(context.Background(), "AI Agents", "r", []ItemWrite{{Item: "Big", Operation: "create", Files: []FileWrite{{Path: big}}}}, RequestContext{})
	if CodeOf(err) != ErrValidation {
		t.Fatalf("oversized file: code=%v err=%v", CodeOf(err), err)
	}
}

// Attachment refusals must not look like network errors, which agents retry.
func TestAttachmentRefusalsAreNotNetworkErrors(t *testing.T) {
	for _, code := range []string{"attachments_unavailable", "attachment_unavailable", "attachment_too_large"} {
		err := httpError(http.StatusServiceUnavailable, []byte(`{"error":"`+code+`","message":"no"}`))
		if CodeOf(err) != ErrValidation {
			t.Errorf("%s mapped to %s", code, CodeOf(err))
		}
	}
}
