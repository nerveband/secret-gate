package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/johnuopini/secret-gate/internal/models"
	"github.com/johnuopini/secret-gate/internal/opconnect"
)

// fakeAttacher records uploads; failOnce makes the call with that file name
// fail the first time it is attempted.
type fakeAttacher struct {
	mu       sync.Mutex
	attached []string // itemID/name
	failOnce string
	failed   bool
	vaultErr error
}

func (f *fakeAttacher) CheckVault(context.Context, string) error { return f.vaultErr }

func (f *fakeAttacher) Attach(_ context.Context, vaultID, itemID, name string, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name == f.failOnce && !f.failed {
		f.failed = true
		return errors.New("1password unavailable")
	}
	f.attached = append(f.attached, fmt.Sprintf("%s/%s/%s=%s", vaultID, itemID, name, content))
	return nil
}

func filesBody(item, op, files string) string {
	return fmt.Sprintf(`{"secret_name":%q,"vault":"AI Agents","machine":"mac-server","reason":"store keys","mutation":{"operation":%q,"fields":{},"files":%s}}`, item, op, files)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestAttachmentReadReleasesOnlyNamedFileAfterApproval(t *testing.T) {
	wh := newWriteHarness(t)
	wh.connect.items["item-0"] = opconnect.Item{ID: "item-0", Title: "Release keys", Vault: opconnect.Vault{ID: "vid"},
		Fields: []opconnect.Field{{ID: "password", Label: "password", Type: "CONCEALED", Value: "pw"}},
		Files:  []opconnect.File{{ID: "f1", Name: "notes.txt", Size: 11}, {ID: "f2", Name: "other.bin", Size: 4}}}
	wh.connect.content["f1"] = []byte("hello world")
	wh.connect.content["f2"] = []byte("nope")

	body := `{"secret_name":"Release keys","vault":"AI Agents","machine":"m","reason":"sign release","secrets":[{"secret_name":"Release keys","vault":"AI Agents","fields":["file:notes.txt"]}]}`
	code, resp, raw := wh.submit(body, agentAddr)
	if code != http.StatusAccepted {
		t.Fatalf("code=%d body=%s", code, raw)
	}
	pending, _ := wh.store.GetByToken(resp.Token)
	got := pending.Secrets[0].Attachments
	if len(got) != 1 || got[0].Name != "notes.txt" || got[0].Size != 11 {
		t.Fatalf("attachments shown to the approver = %#v", got)
	}
	if code, _ := wh.complete(resp.Token); code != http.StatusForbidden {
		t.Fatalf("content released before approval: code=%d", code)
	}
	wh.tap("approve", resp.Token)
	code, out := wh.complete(resp.Token)
	if code != http.StatusOK {
		t.Fatalf("release code=%d body=%s", code, out)
	}
	var secrets BatchSecretResponse
	if err := json.Unmarshal([]byte(out), &secrets); err != nil {
		t.Fatal(err)
	}
	fields := secrets.Secrets["Release keys"]
	if len(fields) != 1 || fields["file:notes.txt"] != b64("hello world") {
		t.Fatalf("released fields = %#v; want only the named attachment", fields)
	}
}

func TestUnknownOrAmbiguousAttachmentIsRejectedBeforeTelegram(t *testing.T) {
	wh := newWriteHarness(t)
	wh.connect.items["item-0"] = opconnect.Item{ID: "item-0", Title: "Release keys", Vault: opconnect.Vault{ID: "vid"},
		Files: []opconnect.File{{ID: "f1", Name: "dup.txt", Size: 1}, {ID: "f2", Name: "dup.txt", Size: 1}}}
	for selector, want := range map[string]string{"file:missing.txt": "no attachment", "file:dup.txt": "f1, f2"} {
		body := fmt.Sprintf(`{"secret_name":"Release keys","vault":"AI Agents","machine":"m","reason":"r","secrets":[{"secret_name":"Release keys","vault":"AI Agents","fields":[%q]}]}`, selector)
		code, _, raw := wh.submit(body, agentAddr)
		if code != http.StatusUnprocessableEntity || !strings.Contains(raw, want) {
			t.Errorf("%s: code=%d body=%s", selector, code, raw)
		}
	}
	if wh.tg.sends != 0 {
		t.Fatalf("approval messages sent for unusable attachment requests: %d", wh.tg.sends)
	}
}

func TestWriteWithFilesNeedsServiceAccount(t *testing.T) {
	wh := newWriteHarness(t)
	code, _, raw := wh.submit(filesBody("Keystore", "create", fmt.Sprintf(`[{"name":"release.jks","content":%q}]`, b64("key"))), agentAddr)
	if code != http.StatusServiceUnavailable || !strings.Contains(raw, "attachments_unavailable") {
		t.Fatalf("code=%d body=%s", code, raw)
	}
	if wh.tg.sends != 0 {
		t.Fatal("approval requested for a write that cannot attach files")
	}
}

func TestAttachmentWriteValidationBeforeApproval(t *testing.T) {
	wh := newWriteHarness(t, "Keystore")
	wh.connect.items["item-0"] = opconnect.Item{ID: "item-0", Title: "Keystore", Vault: opconnect.Vault{ID: "vid"},
		Files: []opconnect.File{{ID: "f1", Name: "release.jks", Size: 3}}}
	wh.h.SetFileAttacher(&fakeAttacher{})
	big := base64.StdEncoding.EncodeToString(make([]byte, models.MaxAttachmentBytes+1))
	cases := map[string]struct {
		body string
		code int
		want string
	}{
		"path in name":         {filesBody("New", "create", fmt.Sprintf(`[{"name":"../x","content":%q}]`, b64("k"))), http.StatusUnprocessableEntity, "plain file name"},
		"empty file":           {filesBody("New", "create", `[{"name":"a.txt","content":""}]`), http.StatusUnprocessableEntity, "is empty"},
		"over the size limit":  {filesBody("New", "create", fmt.Sprintf(`[{"name":"big.bin","content":%q}]`, big)), http.StatusRequestEntityTooLarge, "attachment_too_large"},
		"name already on item": {filesBody("Keystore", "update", fmt.Sprintf(`[{"name":"release.jks","content":%q}]`, b64("k"))), http.StatusUnprocessableEntity, "already has an attachment"},
	}
	for name, tc := range cases {
		code, _, raw := wh.submit(tc.body, agentAddr)
		if code != tc.code || !strings.Contains(raw, tc.want) {
			t.Errorf("%s: code=%d body=%s", name, code, raw)
		}
	}
	if wh.tg.sends != 0 {
		t.Fatalf("approval messages for invalid attachment writes: %d", wh.tg.sends)
	}
}

// A failed upload after the item was created must not create the item again
// on retry, and must resume with the file that failed.
func TestAttachmentWriteResumesWithoutRecreatingItem(t *testing.T) {
	wh := newWriteHarness(t)
	attacher := &fakeAttacher{failOnce: "b.txt"}
	wh.h.SetFileAttacher(attacher)
	files := fmt.Sprintf(`[{"name":"a.txt","content":%q},{"name":"b.txt","content":%q}]`, b64("A"), b64("B"))
	body := fmt.Sprintf(`{"secret_name":"Keystore","vault":"AI Agents","machine":"mac-server","reason":"store keys","mutation":{"operation":"create","fields":{"note":"release"},"files":%s}}`, files)
	code, resp, raw := wh.submit(body, agentAddr)
	if code != http.StatusAccepted {
		t.Fatalf("code=%d body=%s", code, raw)
	}
	wh.tap("approve", resp.Token)
	if code, out := wh.complete(resp.Token); code != http.StatusBadGateway || !strings.Contains(out, "b.txt") {
		t.Fatalf("first attempt code=%d body=%s", code, out)
	}
	if code, out := wh.complete(resp.Token); code != http.StatusOK {
		t.Fatalf("retry code=%d body=%s", code, out)
	}
	if got := wh.connect.writeLog(); len(got) != 1 || got[0] != "create:Keystore" {
		t.Fatalf("Connect writes = %v; the item must be created once", got)
	}
	want := "vid/item-0/a.txt=A|vid/item-0/b.txt=B"
	if got := strings.Join(attacher.attached, "|"); got != want {
		t.Fatalf("attached = %s, want %s", got, want)
	}
	done, _ := wh.store.GetByToken(resp.Token)
	if f := done.Mutations[0].Files; len(f) != 2 || f[0].Content != nil || f[1].Size != 1 {
		t.Fatalf("file content kept after completion: %#v", f)
	}
}
