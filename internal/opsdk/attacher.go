// Package opsdk attaches files to 1Password items through the 1Password Go
// SDK. 1Password Connect can list and download attachments but has no upload
// endpoint, so uploads need a service account token. Only the server binary
// imports this package.
package opsdk

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// sectionID is the item section that holds files attached by Secret Gate.
// Attach saves the section with Items().Put first when the item does not have it yet.
const sectionID = "attachments"

// Attacher uploads files with a service account. The SDK client is created
// on first use, so the server starts even when 1Password.com is unreachable.
type Attacher struct {
	token   string
	version string

	mu     sync.Mutex
	client *onepassword.Client
}

// New returns an Attacher for a service account token.
func New(token, version string) *Attacher {
	return &Attacher{token: token, version: version}
}

func (a *Attacher) sdk(ctx context.Context) (*onepassword.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return a.client, nil
	}
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(a.token),
		onepassword.WithIntegrationInfo("Secret Gate", a.version),
	)
	if err != nil {
		return nil, fmt.Errorf("starting 1Password SDK client: %w", err)
	}
	a.client = client
	return client, nil
}

// CheckVault reports whether the service account can see the vault.
func (a *Attacher) CheckVault(ctx context.Context, vaultID string) error {
	client, err := a.sdk(ctx)
	if err != nil {
		return err
	}
	if _, err := client.Vaults().GetOverview(ctx, vaultID); err != nil {
		return fmt.Errorf("service account cannot access the vault: %w", err)
	}
	return nil
}

// Attach saves content as a file field named name in the item.
func (a *Attacher) Attach(ctx context.Context, vaultID, itemID, name string, content []byte) error {
	client, err := a.sdk(ctx)
	if err != nil {
		return err
	}
	item, err := client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return fmt.Errorf("loading item: %w", err)
	}
	hasSection := false
	for _, s := range item.Sections {
		if s.ID == sectionID {
			hasSection = true
			break
		}
	}
	if !hasSection {
		item.Sections = append(item.Sections, onepassword.ItemSection{ID: sectionID, Title: "Attachments"})
		item, err = client.Items().Put(ctx, item)
		if err != nil {
			return fmt.Errorf("creating attachments section: %w", err)
		}
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generating field ID: %w", err)
	}
	_, err = client.Items().Files().Attach(ctx, item, onepassword.FileCreateParams{
		Name:      name,
		Content:   content,
		SectionID: sectionID,
		FieldID:   "file_" + hex.EncodeToString(suffix),
	})
	if err != nil {
		return fmt.Errorf("attaching file: %w", err)
	}
	return nil
}
