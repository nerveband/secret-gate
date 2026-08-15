package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/otp"
)

type scriptedProxy struct {
	searchResults []SearchResultItem
	requested     bool
}

func (p *scriptedProxy) Search(query string, limit int) ([]SearchResultItem, error) {
	return p.searchResults, nil
}
func (p *scriptedProxy) GetFields(name, vault string) (*FieldsResult, error) {
	return &FieldsResult{SecretName: name, VaultName: vault}, nil
}
func (p *scriptedProxy) Request(ctx context.Context, name, vault, reason string, fields []string, rc RequestContext) (*RequestResult, error) {
	p.requested = true
	return &RequestResult{Status: "approved", SecretName: name, Cached: true}, nil
}
func (p *scriptedProxy) Write(ctx context.Context, name, vault, reason, op, cat string, fields map[string]string, rc RequestContext) (*RequestResult, error) {
	return &RequestResult{Status: "completed", SecretName: name}, nil
}

func newTestService(daemonData map[string]map[string]string) (*Service, *scriptedProxy) {
	dc := newMemDaemon()
	for k, v := range daemonData {
		dc.data[k] = v
	}
	pc := &scriptedProxy{}
	svc := NewService(Config{ServerURL: "http://gate", CacheTTLSec: 3600, SSHAgent: false}, dc, pc)
	return svc, pc
}

func TestServiceSearchValidation(t *testing.T) {
	svc, _ := newTestService(nil)
	if _, err := svc.Search("", 10); CodeOf(err) != ErrValidation {
		t.Fatalf("CodeOf = %v, want validation", CodeOf(err))
	}
	out, err := svc.Search("deploy", 0)
	if err != nil {
		t.Fatal(err)
	}
	if out.Query != "deploy" || out.Count != 0 {
		t.Fatalf("out = %+v", out)
	}
}

func TestServiceReadFieldsNotCached(t *testing.T) {
	svc, _ := newTestService(nil)
	_, err := svc.ReadFields("ghost", "", nil)
	if CodeOf(err) != ErrNotFound {
		t.Fatalf("CodeOf = %v, want not_found", CodeOf(err))
	}
	if !strings.Contains(HintOf(err), "request submit") {
		t.Fatalf("hint %q does not point to request submit", HintOf(err))
	}
}

func TestServiceReadFieldsResolvesAliases(t *testing.T) {
	svc, _ := newTestService(map[string]map[string]string{
		"vpn": {"notesPlain": "connect notes", "password": "fake-pass-9999"},
	})
	out, err := svc.ReadFields("vpn", "", []string{"note"})
	if err != nil {
		t.Fatal(err)
	}
	if out["notesPlain"] != "connect notes" || len(out) != 1 {
		t.Fatalf("out = %v", out)
	}
}

func TestServiceGetOTP(t *testing.T) {
	seed := "GEZDGNBVGEZDGNBVGEZDGNBVGEZDGNBV" // RFC 6238 demo seed
	svc, _ := newTestService(map[string]map[string]string{
		"github": {"one-time password": seed},
	})
	fixed := time.Unix(59, 0)
	svc.Now = func() time.Time { return fixed }

	got, err := svc.GetOTP("github", "", "")
	if err != nil {
		t.Fatal(err)
	}
	wantCode, _, _ := otp.Generate(seed, fixed)
	if got.Code != wantCode {
		t.Fatalf("Code = %q, want %q", got.Code, wantCode)
	}
	if got.SecretUsed != "github/one-time password" {
		t.Fatalf("SecretUsed = %q", got.SecretUsed)
	}
}

func TestServiceExecInjectsAndRedacts(t *testing.T) {
	svc, _ := newTestService(map[string]map[string]string{
		"prod-api": {"credential": "fake-api-key-123456", "url": "https://api.example.com"},
	})
	out, err := svc.Exec(context.Background(), ExecRequest{
		SecretName: "prod-api", Field: "credential", EnvVar: "API_KEY",
		ShellCommand: "echo key=$API_KEY url=$OTHER",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.Stdout, "fake-api-key-123456") {
		t.Fatalf("secret leaked in stdout: %q", out.Stdout)
	}
	if !strings.Contains(out.Stdout, "[REDACTED:prod-api/credential]") {
		t.Fatalf("stdout = %q, missing redaction", out.Stdout)
	}
	if out.SecretUsed != "prod-api/credential" {
		t.Fatalf("SecretUsed = %q", out.SecretUsed)
	}
}

func TestServiceExecArgvMode(t *testing.T) {
	svc, _ := newTestService(map[string]map[string]string{
		"prod-api": {"credential": "fake-api-key-123456"},
	})
	out, err := svc.Exec(context.Background(), ExecRequest{
		SecretName: "prod-api", Field: "credential", EnvVar: "API_KEY",
		Argv: []string{"echo", "$API_KEY"}, // must NOT expand
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.Stdout) != "$API_KEY" {
		t.Fatalf("stdout = %q — argv was shell-interpreted", out.Stdout)
	}
}

func TestServiceExecUnknownFieldHintListsFields(t *testing.T) {
	svc, _ := newTestService(map[string]map[string]string{
		"prod-api": {"credential": "fake-api-key-123456"},
	})
	_, err := svc.Exec(context.Background(), ExecRequest{
		SecretName: "prod-api", Field: "nope", EnvVar: "X", Argv: []string{"true"},
	})
	if CodeOf(err) != ErrNotFound || !strings.Contains(HintOf(err), "credential") {
		t.Fatalf("err = %v hint = %q", err, HintOf(err))
	}
}

func TestServiceRequestShortCircuitsOnCache(t *testing.T) {
	svc, pc := newTestService(map[string]map[string]string{
		"deploy-key": {"private key": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfake\n-----END OPENSSH PRIVATE KEY-----"},
	})
	res, err := svc.Request(context.Background(), "deploy-key", "", "deploy", nil, RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Cached || pc.requested {
		t.Fatalf("res=%+v proxied=%v — cache short-circuit failed", res, pc.requested)
	}
}

func TestServiceWriteValidation(t *testing.T) {
	svc, _ := newTestService(nil)
	_, err := svc.Write(context.Background(), "item", "Vault", "reason", "delete", "", map[string]string{"a": "b"}, RequestContext{})
	if CodeOf(err) != ErrValidation || !strings.Contains(MessageOf(err), "create or update") {
		t.Fatalf("err = %v", err)
	}
}

func TestBuildSSHArgs(t *testing.T) {
	got := BuildSSHArgs("deploy@web1.example.com", 0, "uptime")
	want := []string{"ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
		"-p", "22", "deploy@web1.example.com", "uptime"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("BuildSSHArgs = %v", got)
	}
}
