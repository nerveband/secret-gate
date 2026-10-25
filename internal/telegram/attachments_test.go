package telegram

import (
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestApprovalMessagesShowAttachmentNamesAndSizesOnly(t *testing.T) {
	write := &models.ApprovalRequest{ID: "w", Vault: "AI Agents", ExpiresAt: time.Now().Add(time.Hour),
		Mutations: []models.ItemMutation{{Item: "Keystore", Operation: "create",
			Fields: map[string]string{"note": "release"},
			Files:  []models.FileUpload{{Name: "release.jks", Content: []byte("KEYSTORE-BYTES"), Size: 2048}}}}}
	text := approvalMessage(write)
	if !strings.Contains(text, "release.jks (2.0 KB)") || strings.Contains(text, "KEYSTORE-BYTES") {
		t.Fatalf("write message = %s", text)
	}

	batch := &models.ApprovalRequest{ID: "b", Vault: "AI Agents", ExpiresAt: time.Now().Add(time.Hour),
		Mutations: []models.ItemMutation{
			{Item: "A", Operation: "create", Fields: map[string]string{"token": "t"}},
			{Item: "B", Operation: "update", Files: []models.FileUpload{{Name: "cert.p12", Size: 3 << 20}}}}}
	if text := approvalMessage(batch); !strings.Contains(text, `Update "B" (files: cert.p12 (3.0 MB))`) || !strings.Contains(text, `Create "A" (fields: token)`) {
		t.Fatalf("batch message = %s", text)
	}

	read := &models.ApprovalRequest{ID: "r", Vault: "AI Agents", SecretName: "Keys", ExpiresAt: time.Now().Add(time.Hour),
		Secrets: []models.SecretRequest{{SecretName: "Keys", Vault: "AI Agents", Fields: []string{"file:notes.txt"},
			Attachments: []models.Attachment{{ID: "f1", Name: "notes.txt", Size: 11}}}}}
	if text := approvalMessage(read); !strings.Contains(text, "📎 notes.txt (11 B)") {
		t.Fatalf("read message = %s", text)
	}
}
