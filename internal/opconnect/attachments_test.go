package opconnect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func attachmentConnect(t *testing.T, item Item, content map[string]string, onPut func(Item)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/vaults":
			_ = json.NewEncoder(w).Encode([]Vault{{ID: "vid", Name: "Agents"}})
		case r.URL.Path == "/v1/vaults/vid/items":
			_ = json.NewEncoder(w).Encode([]Item{{ID: item.ID, Title: item.Title}})
		case strings.HasSuffix(r.URL.Path, "/content"):
			parts := strings.Split(r.URL.Path, "/")
			_, _ = w.Write([]byte(content[parts[len(parts)-2]]))
		case r.URL.Path == "/v1/vaults/vid/items/"+item.ID && r.Method == http.MethodPut:
			var saved Item
			_ = json.NewDecoder(r.Body).Decode(&saved)
			onPut(saved)
			_ = json.NewEncoder(w).Encode(saved)
		case r.URL.Path == "/v1/vaults/vid/items/"+item.ID:
			_ = json.NewEncoder(w).Encode(item)
		default:
			t.Errorf("unexpected Connect call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return New(server.URL, "token")
}

func TestReadFileSelectsByNameOrIDAndEnforcesLimit(t *testing.T) {
	item := Item{ID: "iid", Title: "Keys", Vault: Vault{ID: "vid"}, Files: []File{
		{ID: "f1", Name: "a.txt", Size: 5}, {ID: "f2", Name: "big.bin", Size: 100},
	}}
	client := attachmentConnect(t, item, map[string]string{"f1": "hello", "f2": strings.Repeat("x", 100)}, nil)

	info, content, err := client.ReadFile("Agents", "Keys", "a.txt", 10)
	if err != nil || string(content) != "hello" || info.ID != "f1" {
		t.Fatalf("by name: info=%#v content=%q err=%v", info, content, err)
	}
	if _, content, err = client.ReadFile("Agents", "Keys", "f1", 10); err != nil || string(content) != "hello" {
		t.Fatalf("by ID: content=%q err=%v", content, err)
	}
	if _, _, err = client.ReadFile("Agents", "Keys", "big.bin", 10); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized attachment err = %v", err)
	}
}

// Connect replaces the whole item on PUT; an update that dropped the files
// array could lose attachments, so updates send it back unchanged.
func TestPutItemUpdateSendsAttachmentsBack(t *testing.T) {
	item := Item{ID: "iid", Title: "Keys", Vault: Vault{ID: "vid"}, Category: "SECURE_NOTE",
		Fields: []Field{{ID: "token", Label: "token", Type: "CONCEALED", Value: "old"}},
		Files:  []File{{ID: "f1", Name: "a.txt", Size: 5, ContentPath: "v1/vaults/vid/items/iid/files/f1/content"}}}
	var saved Item
	client := attachmentConnect(t, item, nil, func(it Item) { saved = it })
	if _, err := client.PutItem("Agents", "Keys", "update", "", map[string]string{"token": "new"}); err != nil {
		t.Fatal(err)
	}
	if len(saved.Files) != 1 || saved.Files[0].ID != "f1" || saved.Fields[0].Value != "new" {
		t.Fatalf("PUT body files=%#v fields=%#v", saved.Files, saved.Fields)
	}
}
