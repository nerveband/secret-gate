package core

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorTaxonomy(t *testing.T) {
	err := E(ErrNotFound, "item \"x\" is not approved and cached", "run: secret-gate request submit --item \"x\" --reason <why>")

	if got := err.Error(); got != "not_found: item \"x\" is not approved and cached" {
		t.Fatalf("Error() = %q", got)
	}
	wrapped := fmt.Errorf("outer: %w", err)
	if CodeOf(wrapped) != ErrNotFound {
		t.Fatalf("CodeOf(wrapped) = %q, want not_found", CodeOf(wrapped))
	}
	if MessageOf(wrapped) != "item \"x\" is not approved and cached" {
		t.Fatalf("MessageOf(wrapped) = %q", MessageOf(wrapped))
	}
	if HintOf(wrapped) == "" {
		t.Fatal("HintOf(wrapped) is empty")
	}
}

func TestCodeOfPlainError(t *testing.T) {
	plain := errors.New("boom")
	if CodeOf(plain) != ErrInternal {
		t.Fatalf("CodeOf(plain) = %q, want internal", CodeOf(plain))
	}
	if MessageOf(plain) != "boom" {
		t.Fatalf("MessageOf(plain) = %q, want boom", MessageOf(plain))
	}
	if HintOf(plain) != "" {
		t.Fatalf("HintOf(plain) = %q, want empty", HintOf(plain))
	}
}
