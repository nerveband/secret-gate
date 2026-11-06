package opconnect

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/johnuopini/secret-gate/internal/models"
)

// Client wraps the 1Password Connect API
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// Item represents a 1Password item. Files are kept so an update sends back
// the item's attachments unchanged.
type Item struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Vault    Vault     `json:"vault"`
	Fields   []Field   `json:"fields"`
	Files    []File    `json:"files,omitempty"`
	Version  int       `json:"version"`
	Category string    `json:"category,omitempty"`
	Sections []Section `json:"sections,omitempty"`
}

// File is an attachment as Connect lists it (Item: File object). Content is
// never requested inline; it is downloaded from the file content endpoint.
type File struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Size        int64    `json:"size"`
	ContentPath string   `json:"content_path,omitempty"`
	Section     *Section `json:"section,omitempty"`
}

type Section struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// Vault represents a 1Password vault reference
type Vault struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Field represents a field in a 1Password item
type Field struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Purpose   string   `json:"purpose,omitempty"`
	Label     string   `json:"label"`
	Value     string   `json:"value"`
	Section   *Section `json:"section,omitempty"`
	Reference string   `json:"reference,omitempty"`
}

// New creates a new 1Password Connect client
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetVaults returns all accessible vaults
func (c *Client) GetVaults() ([]Vault, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/v1/vaults", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var vaults []Vault
	if err := json.NewDecoder(resp.Body).Decode(&vaults); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return vaults, nil
}

// CapabilityResult describes whether Connect can perform an operation.
type CapabilityResult struct {
	Allowed bool
	Code    string
	Message string
}

// ResolveVault resolves a vault name or ID within the token's visible scope.
func (c *Client) ResolveVault(name string) (Vault, error) {
	vaults, err := c.GetVaults()
	if err != nil {
		return Vault{}, err
	}
	for _, vault := range vaults {
		if vault.Name == name || vault.ID == name {
			return vault, nil
		}
	}
	return Vault{}, fmt.Errorf("vault not found: %s", name)
}

// CheckWriteCapability verifies write authorization without creating an item.
// Connect checks vault authorization before rejecting the intentionally invalid
// empty item document. A 400 response therefore proves the write authorization
// check passed; every ambiguous response fails closed.
func (c *Client) CheckWriteCapability(vaultName string) CapabilityResult {
	vault, err := c.ResolveVault(vaultName)
	if err != nil {
		return CapabilityResult{Code: "write_capability_unverified", Message: "Could not verify access to the target vault."}
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/v1/vaults/%s/items", c.baseURL, vault.ID), bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return CapabilityResult{Code: "write_capability_unverified", Message: "Could not build the Connect capability check."}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return CapabilityResult{Code: "write_capability_unverified", Message: "1Password Connect could not be reached to verify write access."}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return CapabilityResult{Allowed: true}
	case http.StatusUnauthorized, http.StatusForbidden:
		return CapabilityResult{Code: "vault_write_unavailable", Message: "The configured 1Password Connect token has read-only access."}
	default:
		return CapabilityResult{Code: "write_capability_unverified", Message: fmt.Sprintf("1Password Connect returned status %d while checking write access.", resp.StatusCode)}
	}
}

// findByTitle returns the summary of every item in a vault with exactly this title.
func (c *Client) findByTitle(vaultID, itemTitle string) ([]Item, error) {
	filter := url.QueryEscape(fmt.Sprintf(`title eq "%s"`, itemTitle))
	url := fmt.Sprintf("%s/v1/vaults/%s/items?filter=%s", c.baseURL, vaultID, filter)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var items []Item
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return items, nil
}

// GetItemByTitle fetches an item by vault ID and item title
func (c *Client) GetItemByTitle(vaultID, itemTitle string) (*Item, error) {
	items, err := c.findByTitle(vaultID, itemTitle)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("item not found: %s", itemTitle)
	}

	// Get the full item with all fields
	return c.GetItem(vaultID, items[0].ID)
}

// GetItem fetches a full item by vault ID and item ID
func (c *Client) GetItem(vaultID, itemID string) (*Item, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/items/%s", c.baseURL, vaultID, itemID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var item Item
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &item, nil
}

// GetSecret retrieves a secret item and returns it as a map of field labels to values
func (c *Client) GetSecret(vaultName, itemTitle string) (map[string]string, error) {
	// First, find the vault ID by name
	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	var vaultID string
	for _, v := range vaults {
		if v.Name == vaultName || v.ID == vaultName {
			vaultID = v.ID
			break
		}
	}

	if vaultID == "" {
		return nil, fmt.Errorf("vault not found: %s", vaultName)
	}

	// Get the item
	item, err := c.GetItemByTitle(vaultID, itemTitle)
	if err != nil {
		return nil, fmt.Errorf("getting item: %w", err)
	}

	return itemFieldValues(item), nil
}

// HealthCheck verifies connectivity to 1Password Connect
func (c *Client) HealthCheck() error {
	req, err := http.NewRequest("GET", c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy status: %d", resp.StatusCode)
	}

	return nil
}

// SearchResult represents a fuzzy search match
type SearchResult struct {
	Item      Item    `json:"item"`
	VaultName string  `json:"vault_name"`
	VaultID   string  `json:"vault_id"`
	Score     float64 `json:"score"`
	MatchType string  `json:"match_type"` // "exact", "prefix", "contains", "fuzzy"
}

// FieldInfo holds metadata about a field without its value. ProcessOnly
// fields (card number, CVV, PIN) reach commands and browser fields only.
type FieldInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	Purpose     string `json:"purpose,omitempty"`
	Section     string `json:"section,omitempty"`
	Reference   string `json:"reference,omitempty"`
	ProcessOnly bool   `json:"process_only,omitempty"`
}

// FileInfo is attachment metadata: name, size, and ID, never content.
type FileInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Section string `json:"section,omitempty"`
}

// ItemMeta describes an item without any values. Card is the masked view
// of a CREDIT_CARD item (type, last four digits, expiry).
type ItemMeta struct {
	Vault    string
	Title    string
	Category string
	Fields   []FieldInfo
	Files    []FileInfo
	Card     *CardSummary
}

// GetItemFields returns field and attachment metadata for an item without values
func (c *Client) GetItemFields(vaultName, itemTitle string) (*ItemMeta, error) {
	var item *Item
	var actualVault, actualTitle string

	if vaultName == "" || vaultName == "_auto_" {
		// Cross-vault search
		results, err := c.SearchSecrets(itemTitle, 5)
		if err != nil {
			return nil, fmt.Errorf("searching secrets: %w", err)
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("item not found: %s", itemTitle)
		}
		best := results[0]
		if best.MatchType != "exact" && best.MatchType != "prefix" && best.Score < 0.8 {
			var suggestions []string
			for _, r := range results {
				suggestions = append(suggestions, r.Item.Title)
			}
			return nil, fmt.Errorf("no exact match for '%s'. Did you mean: %s", itemTitle, strings.Join(suggestions, ", "))
		}
		item, err = c.GetItem(best.VaultID, best.Item.ID)
		if err != nil {
			return nil, fmt.Errorf("getting item: %w", err)
		}
		actualVault = best.VaultName
		actualTitle = best.Item.Title
	} else {
		// Direct vault lookup
		vaults, err := c.GetVaults()
		if err != nil {
			return nil, fmt.Errorf("listing vaults: %w", err)
		}
		var vaultID string
		for _, v := range vaults {
			if v.Name == vaultName || v.ID == vaultName {
				vaultID = v.ID
				actualVault = v.Name
				break
			}
		}
		if vaultID == "" {
			return nil, fmt.Errorf("vault not found: %s", vaultName)
		}
		item, err = c.GetItemByTitle(vaultID, itemTitle)
		if err != nil {
			return nil, fmt.Errorf("getting item: %w", err)
		}
		actualTitle = item.Title
	}

	var fields []FieldInfo
	for _, f := range item.Fields {
		if f.Label != "" || f.ID != "" {
			section := ""
			if f.Section != nil {
				section = f.Section.Label
			}
			fields = append(fields, FieldInfo{
				ID:          f.ID,
				Label:       f.Label,
				Type:        f.Type,
				Purpose:     f.Purpose,
				Section:     section,
				Reference:   f.Reference,
				ProcessOnly: isProcessOnly(item.Category, f),
			})
		}
	}

	sectionLabels := make(map[string]string, len(item.Sections))
	for _, s := range item.Sections {
		sectionLabels[s.ID] = s.Label
	}
	var files []FileInfo
	for _, f := range item.Files {
		section := ""
		if f.Section != nil {
			section = sectionLabels[f.Section.ID]
		}
		files = append(files, FileInfo{ID: f.ID, Name: f.Name, Size: f.Size, Section: section})
	}

	return &ItemMeta{Vault: actualVault, Title: actualTitle, Category: item.Category, Fields: fields, Files: files, Card: summarizeCard(item)}, nil
}

// PutItem creates or replaces an item through 1Password Connect. For updates,
// the existing item is fetched and modified so unknown fields and sections are
// preserved.
func (c *Client) PutItem(vaultName, itemTitle, operation, category string, values map[string]string) (*Item, error) {
	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}
	var vaultID string
	for _, v := range vaults {
		if v.Name == vaultName || v.ID == vaultName {
			vaultID = v.ID
			break
		}
	}
	if vaultID == "" {
		return nil, fmt.Errorf("vault not found: %s", vaultName)
	}

	var item Item
	method := http.MethodPost
	endpoint := fmt.Sprintf("%s/v1/vaults/%s/items", c.baseURL, vaultID)
	if operation == "update" {
		existing, getErr := c.GetItemByTitle(vaultID, itemTitle)
		if getErr != nil {
			return nil, getErr
		}
		item = *existing
		method = http.MethodPut
		endpoint += "/" + existing.ID
	} else if operation == "create" {
		category = NormalizeCategory(category)
		item = Item{Title: itemTitle, Vault: Vault{ID: vaultID}, Category: category}
	} else {
		return nil, fmt.Errorf("unsupported mutation operation %q", operation)
	}

	for _, label := range sortedKeys(values) {
		value := values[label]
		matchID := ""
		if f, ok := templateFieldFor(item.Category, label); ok {
			matchID = f.ID
		}
		found := false
		for i := range item.Fields {
			if item.Fields[i].Label == label || item.Fields[i].ID == label || (matchID != "" && item.Fields[i].ID == matchID) {
				if typed, ok, err := typedField(item.Category, label, value); err != nil {
					return nil, err
				} else if ok {
					value = typed.Value
				}
				item.Fields[i].Value = value
				found = true
				break
			}
		}
		if !found {
			field, err := newField(item.Category, label, value)
			if err != nil {
				return nil, err
			}
			item.Fields = append(item.Fields, field)
		}
	}
	if operation == "create" {
		fillCardType(&item)
	}
	ensureSections(&item)
	body, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("encoding item: %w", err)
	}
	req, err := http.NewRequest(method, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusBadRequest {
			return nil, &ValidationError{Message: string(b)}
		}
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(b))
	}
	var saved Item
	if err := json.NewDecoder(resp.Body).Decode(&saved); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &saved, nil
}

// ResolveItem returns the full item with this exact title in a vault.
func (c *Client) ResolveItem(vaultName, title string) (*Item, error) {
	vault, err := c.ResolveVault(vaultName)
	if err != nil {
		return nil, err
	}
	return c.GetItemByTitle(vault.ID, title)
}

// FindFile selects one attachment by exact name, then by file ID. Several
// attachments sharing the name must be addressed by ID.
func FindFile(files []FileInfo, selector string) (FileInfo, error) {
	var named []FileInfo
	for _, f := range files {
		if f.Name == selector {
			named = append(named, f)
		}
	}
	switch len(named) {
	case 1:
		return named[0], nil
	case 0:
	default:
		ids := make([]string, 0, len(named))
		for _, f := range named {
			ids = append(ids, f.ID)
		}
		return FileInfo{}, fmt.Errorf("%d attachments are named %q; use one of the file IDs: %s", len(named), selector, strings.Join(ids, ", "))
	}
	for _, f := range files {
		if f.ID == selector {
			return f, nil
		}
	}
	return FileInfo{}, fmt.Errorf("no attachment named %q", selector)
}

// ReadFile downloads one attachment through the Connect file content
// endpoint. Files larger than limit are refused before and while reading.
func (c *Client) ReadFile(vaultName, itemTitle, selector string, limit int64) (FileInfo, []byte, error) {
	vault, err := c.ResolveVault(vaultName)
	if err != nil {
		return FileInfo{}, nil, err
	}
	item, err := c.GetItemByTitle(vault.ID, itemTitle)
	if err != nil {
		return FileInfo{}, nil, err
	}
	infos := make([]FileInfo, 0, len(item.Files))
	for _, f := range item.Files {
		infos = append(infos, FileInfo{ID: f.ID, Name: f.Name, Size: f.Size})
	}
	file, err := FindFile(infos, selector)
	if err != nil {
		return FileInfo{}, nil, err
	}
	if file.Size > limit {
		return file, nil, fmt.Errorf("attachment %q is %d bytes, over the %d byte limit", file.Name, file.Size, limit)
	}
	endpoint := fmt.Sprintf("%s/v1/vaults/%s/items/%s/files/%s/content", c.baseURL, vault.ID, item.ID, url.PathEscape(file.ID))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return file, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return file, nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return file, nil, fmt.Errorf("unexpected status %d downloading attachment", resp.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return file, nil, fmt.Errorf("reading attachment: %w", err)
	}
	if int64(len(content)) > limit {
		return file, nil, fmt.Errorf("attachment %q is over the %d byte limit", file.Name, limit)
	}
	file.Size = int64(len(content))
	return file, content, nil
}

// ValidationError is a 1Password Connect 400 rejecting an item as invalid.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string {
	return "item rejected: " + e.Message
}

// purposeCategories lists the categories whose Connect templates require
// (LOGIN) or validate (PASSWORD) fields by purpose. Other templates, such as
// SERVER or DATABASE, already define username/password fields and reject a
// second field carrying the same purpose.
func purposeCategory(category string) string {
	switch category {
	case "LOGIN", "PASSWORD":
		return category
	}
	return ""
}

func newField(category, label, value string) (Field, error) {
	if field, ok, err := typedField(category, label, value); ok || err != nil {
		return field, err
	}
	normalized := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(label))
	field := Field{ID: label, Label: label, Type: "STRING", Value: value}
	switch normalized {
	case "otp", "totp", "mfa", "2fa", "onetimepassword":
		field.Type = "OTP"
	case "note", "notes", "notesplain", "securenote":
		field.ID = "notesPlain"
		field.Label = "notesPlain"
		field.Purpose = "NOTES"
	case "password":
		field.ID = "password"
		field.Label = "password"
		field.Type = "CONCEALED"
		if purposeCategory(category) != "" {
			field.Purpose = "PASSWORD"
		}
	case "username":
		field.ID = "username"
		field.Label = "username"
		if category == "LOGIN" {
			field.Purpose = "USERNAME"
		}
	case "passphrase", "secret", "token", "apikey", "privatekey", "credential", "clientsecret", "secretkey", "accesstoken", "refreshtoken", "authtoken", "bearertoken", "passkeyprivatekey":
		field.Type = "CONCEALED"
	case "url", "website", "loginurl":
		field.Type = "URL"
	case "email", "emailaddress":
		field.Type = "EMAIL"
	}
	return field, nil
}

// ListItemsInVault returns all items in a vault (titles only, no fields)
func (c *Client) ListItemsInVault(vaultID string) ([]Item, error) {
	url := fmt.Sprintf("%s/v1/vaults/%s/items", c.baseURL, vaultID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var items []Item
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return items, nil
}

// SearchSecrets searches for secrets across all vaults using fuzzy matching
func (c *Client) SearchSecrets(query string, limit int) ([]SearchResult, error) {
	if limit <= 0 {
		limit = 10
	}

	vaults, err := c.GetVaults()
	if err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	var results []SearchResult
	queryLower := strings.ToLower(query)

	for _, vault := range vaults {
		items, err := c.ListItemsInVault(vault.ID)
		if err != nil {
			// Skip vaults we can't access
			continue
		}

		for _, item := range items {
			titleLower := strings.ToLower(item.Title)
			score, matchType := fuzzyScore(queryLower, titleLower)

			if score > 0 {
				results = append(results, SearchResult{
					Item:      item,
					VaultName: vault.Name,
					VaultID:   vault.ID,
					Score:     score,
					MatchType: matchType,
				})
			}
		}
	}

	// Sort by score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	// Limit results
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

// FindSecretAcrossVaults finds a secret by name across all vaults
// Returns the best match or an error if not found
func (c *Client) FindSecretAcrossVaults(secretName string) (map[string]string, string, string, error) {
	results, err := c.SearchSecrets(secretName, 5)
	if err != nil {
		return nil, "", "", fmt.Errorf("searching secrets: %w", err)
	}

	if len(results) == 0 {
		return nil, "", "", fmt.Errorf("secret not found: %s", secretName)
	}

	// Use the best match
	best := results[0]

	// Only accept exact or very close matches for actual retrieval
	if best.MatchType != "exact" && best.MatchType != "prefix" && best.Score < 0.8 {
		// Return suggestions instead
		var suggestions []string
		for _, r := range results {
			suggestions = append(suggestions, r.Item.Title)
		}
		return nil, "", "", fmt.Errorf("no exact match for '%s'. Did you mean: %s", secretName, strings.Join(suggestions, ", "))
	}

	// Get the full item
	item, err := c.GetItem(best.VaultID, best.Item.ID)
	if err != nil {
		return nil, "", "", fmt.Errorf("getting item: %w", err)
	}

	return itemFieldValues(item), best.VaultName, best.Item.Title, nil
}

// itemFieldValues provides convenient labels while retaining stable selectors.
// Duplicate labels remain reachable by field ID and section.label. A field
// ID keeps its key even when another field's label matches it. Card
// numbers, CVVs, and PINs are listed under models.ProcessOnlyKey so clients
// keep them out of model context, and every key's field ID, type, and
// purpose under models.FieldMetaKey. Dates read as YYYY-MM-DD and month-year
// fields as MM/YYYY, as the 1Password app shows them.
func itemFieldValues(item *Item) map[string]string {
	fields := make(map[string]string)
	keys := make(map[string][]string)
	meta := make(map[string]models.FieldMeta)
	labelCounts := make(map[string]int)
	for _, f := range item.Fields {
		if f.Label != "" {
			labelCounts[f.Label]++
		}
	}
	set := func(f Field, key string) {
		if _, taken := fields[key]; taken {
			return
		}
		fields[key] = normalizeFieldValue(f)
		keys[f.ID] = append(keys[f.ID], key)
		meta[key] = models.FieldMeta{ID: f.ID, Type: f.Type, Purpose: f.Purpose}
	}
	for _, f := range item.Fields {
		if f.ID != "" {
			set(f, f.ID)
			// OTP-type fields stay reachable by OTP alias whatever their label.
			if strings.EqualFold(f.Type, "OTP") && !strings.HasPrefix(f.ID, "TOTP_") {
				set(f, "TOTP_"+f.ID)
			}
		}
	}
	for _, f := range item.Fields {
		if f.Label == "" {
			continue
		}
		if labelCounts[f.Label] == 1 {
			set(f, f.Label)
		}
		if f.Section != nil && f.Section.Label != "" {
			set(f, f.Section.Label+"."+f.Label)
		}
	}
	if marker := processOnlyMarker(item, keys); marker != "" {
		fields[models.ProcessOnlyKey] = marker
	}
	if len(meta) > 0 {
		if raw, err := json.Marshal(meta); err == nil {
			fields[models.FieldMetaKey] = string(raw)
		}
	}
	return fields
}

func normalizeFieldValue(f Field) string {
	switch strings.ToUpper(f.Type) {
	case "SSHKEY":
		return normalizeSSHKeyValue(f.Value)
	case "DATE":
		return presentDate(f.Value)
	case "MONTH_YEAR":
		return presentMonthYear(f.Value)
	}
	return f.Value
}

func normalizeSSHKeyValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return ensureTrailingNewline(trimmed)
	}

	block, _ := pem.Decode([]byte(trimmed))
	if block == nil || block.Type != "PRIVATE KEY" {
		return value
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return value
	}

	openSSHBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return value
	}

	return string(pem.EncodeToMemory(openSSHBlock))
}

func ensureTrailingNewline(value string) string {
	if strings.HasSuffix(value, "\n") {
		return value
	}
	return value + "\n"
}

// fuzzyScore calculates a match score between query and target
// Returns score (0-1) and match type
func fuzzyScore(query, target string) (float64, string) {
	// Exact match
	if query == target {
		return 1.0, "exact"
	}

	// Prefix match
	if strings.HasPrefix(target, query) {
		return 0.9, "prefix"
	}

	// Contains match
	if strings.Contains(target, query) {
		// Score based on position and length ratio
		idx := strings.Index(target, query)
		posScore := 1.0 - float64(idx)/float64(len(target))
		lenScore := float64(len(query)) / float64(len(target))
		return 0.7 * (posScore*0.5 + lenScore*0.5), "contains"
	}

	// Fuzzy match using Levenshtein-like scoring
	// Check if all query chars appear in order in target
	qi := 0
	matches := 0
	for ti := 0; ti < len(target) && qi < len(query); ti++ {
		if target[ti] == query[qi] {
			matches++
			qi++
		}
	}

	if qi == len(query) {
		// All query characters found in order
		score := float64(matches) / float64(max(len(query), len(target)))
		return score * 0.5, "fuzzy"
	}

	// Check word-based matching (e.g., "ssh" matches "homelab-ssh-key")
	queryWords := strings.FieldsFunc(query, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})
	targetWords := strings.FieldsFunc(target, func(r rune) bool {
		return r == '-' || r == '_' || r == ' '
	})

	wordMatches := 0
	for _, qw := range queryWords {
		for _, tw := range targetWords {
			if strings.Contains(tw, qw) || strings.Contains(qw, tw) {
				wordMatches++
				break
			}
		}
	}

	if wordMatches > 0 {
		score := float64(wordMatches) / float64(len(queryWords))
		return score * 0.4, "fuzzy"
	}

	return 0, ""
}

// NormalizeCategory upper-cases and trims a category, defaulting to
// SECURE_NOTE. Friendly names (card, api, note, login, bank, ...) map to
// the native 1Password category.
func NormalizeCategory(category string) string {
	if native, ok := categoryAliases[normalizeLabel(category)]; ok {
		return native
	}
	category = strings.ToUpper(strings.TrimSpace(category))
	if category == "" {
		return "SECURE_NOTE"
	}
	return strings.ReplaceAll(category, " ", "_")
}

// MaxOwnerFields caps how many values one entry page asks the approver for.
const MaxOwnerFields = 10

// PrecheckMutation rejects writes that Connect would refuse after the human
// has already approved, so approvals are never spent on doomed requests.
// ownerFields are labels the approver will type on the entry page; their
// values are checked once entered. It returns the category of the item that
// is created or updated. Values are never included in returned messages.
func (c *Client) PrecheckMutation(vaultName, title, operation, category string, values map[string]string, ownerFields []string) (string, error) {
	bad := func(format string, a ...any) error {
		return &ValidationError{Message: fmt.Sprintf(format, a...)}
	}
	if strings.TrimSpace(title) == "" {
		return "", bad("item title is empty")
	}
	if strings.Contains(title, `"`) {
		return "", bad("item titles containing a double quote cannot be looked up through Connect")
	}
	for label, value := range values {
		if strings.TrimSpace(label) == "" {
			return "", bad("field labels must not be empty")
		}
		if value == "" {
			return "", bad("field %q has an empty value", label)
		}
	}
	if len(ownerFields) > MaxOwnerFields {
		return "", bad("ask the approver for at most %d fields", MaxOwnerFields)
	}
	all := make(map[string]string, len(values)+len(ownerFields))
	for label, value := range values {
		all[label] = value
	}
	for _, label := range ownerFields {
		if strings.TrimSpace(label) == "" {
			return "", bad("owner field labels must not be empty")
		}
		if _, dup := all[label]; dup {
			return "", bad("field %q is both sent and asked of the approver", label)
		}
		all[label] = ""
	}
	vault, err := c.ResolveVault(vaultName)
	if err != nil {
		return "", err
	}
	existing, err := c.findByTitle(vault.ID, title)
	if err != nil {
		return "", err
	}
	switch operation {
	case "create":
		category = NormalizeCategory(category)
		if category == "DOCUMENT" || category == "CUSTOM" {
			return "", bad("1Password Connect cannot create %s items", category)
		}
		if len(existing) > 0 {
			return "", bad("an item titled %q already exists in this vault; use update", title)
		}
		if category == "PASSWORD" {
			found := false
			for label := range all {
				if f, _ := newField(category, label, "x"); f.Purpose == "PASSWORD" {
					found = true
				}
			}
			if !found {
				return "", bad("PASSWORD items require a non-empty \"password\" field")
			}
		}
		if category == "CREDIT_CARD" {
			found := false
			for label := range all {
				if f, ok := templateFieldFor(category, label); ok && f.ID == "ccnum" {
					found = true
				}
			}
			if !found {
				return "", bad("CREDIT_CARD items need a card \"number\" field (send it, or ask the approver with owner fields)")
			}
		}
	case "update":
		switch len(existing) {
		case 0:
			return "", bad("no item titled %q exists in this vault; use create", title)
		case 1:
			category = existing[0].Category
		default:
			return "", bad("%d items are titled %q; rename duplicates before updating", len(existing), title)
		}
	}
	if err := ValidateTypedFields(category, all); err != nil {
		return "", err
	}
	return category, nil
}
