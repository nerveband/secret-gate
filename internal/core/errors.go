// Package core is the shared domain layer behind every face of the
// secret-gate binary: the noun-verb CLI, the MCP adapter, and the daemon
// control commands. It contains no flag parsing and no output formatting.
package core

import (
	"errors"
	"fmt"
)

// ErrCode classifies domain failures. The CLI maps codes to exit codes;
// the MCP adapter maps them to tool errors.
type ErrCode string

const (
	ErrValidation             ErrCode = "validation"
	ErrDenied                 ErrCode = "denied"
	ErrExpired                ErrCode = "expired"
	ErrTimeout                ErrCode = "timeout"
	ErrNetwork                ErrCode = "network"
	ErrNotFound               ErrCode = "not_found"
	ErrInternal               ErrCode = "internal"
	ErrVaultWriteUnavailable  ErrCode = "vault_write_unavailable"
	ErrWriteCapabilityUnknown ErrCode = "write_capability_unverified"
)

// Error is a coded domain error with an agent-actionable hint.
type Error struct {
	Code    ErrCode
	Message string
	Hint    string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// E builds a coded error.
func E(code ErrCode, message, hint string) *Error {
	return &Error{Code: code, Message: message, Hint: hint}
}

// CodeOf extracts the ErrCode from err, defaulting to ErrInternal.
func CodeOf(err error) ErrCode {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ErrInternal
}

// MessageOf extracts the bare message (without the code prefix).
func MessageOf(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Message
	}
	return err.Error()
}

// HintOf extracts the recovery hint, if any.
func HintOf(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Hint
	}
	return ""
}
