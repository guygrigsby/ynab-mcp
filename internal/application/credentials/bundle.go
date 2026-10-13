// Package credentials owns the opaque OAuth credential boundary. Bundles are
// never domain values, MCP results, financial snapshots or metadata records.
package credentials

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

const (
	ReadOnlyScope     = "read-only"
	MaxTokenBytes     = 8192
	MaxPlaintextBytes = 40 << 10
	redacted          = "[redacted YNAB credentials]"
)

var (
	ErrInvalidBundle = errors.New("invalid complete credential bundle")
	ErrNotFound      = errors.New("protected credential not found")
	ErrConflict      = errors.New("immutable credential conflict")
	ErrUnavailable   = errors.New("protected credential store unavailable")
	ErrIntegrity     = errors.New("protected credential integrity failure")
)

// CompleteBundle is an immutable complete access/refresh pair and its validated
// read-only scope and expiry. Its zero value is invalid. Generic serialization
// and formatting redact secrets; only the narrowly named integration methods
// below export plaintext. Go cannot guarantee erasure of copied strings.
type CompleteBundle struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	scope        string
}

// Bundle is a concise alias for Store implementations.
type Bundle = CompleteBundle

// Store persists immutable complete bundles. PutImmutable succeeds only after
// an exact authenticated readback. Repeating the identical bundle is idempotent;
// a different pair, expiry or scope at the same reference must be rejected.
// Read must authenticate the entire expected reference, including its version.
// No method may include provider errors, secrets or plaintext in returned errors.
type Store interface {
	Read(context.Context, connection.CredentialRef) (CompleteBundle, error)
	PutImmutable(context.Context, connection.CredentialRef, CompleteBundle) error
}

// OAuth is the explicit one-attempt adapter boundary. Lifecycle coordination,
// callback validation and protected persistence remain the caller's obligations.
type OAuth interface {
	Exchange(context.Context, string, string) (*CompleteBundle, error)
	Refresh(context.Context, *CompleteBundle) (*CompleteBundle, error)
}

// NewOAuthBundle is called only by validated OAuth responses or protected-store
// decoding. Omitted scope may be resolved to ReadOnlyScope only by a flow that
// independently proves the original authorization requested read-only access.
func NewOAuthBundle(accessToken, refreshToken string, expiresAt time.Time, scope string) (CompleteBundle, error) {
	b := CompleteBundle{accessToken: accessToken, refreshToken: refreshToken, expiresAt: expiresAt.UTC().Round(0), scope: scope}
	if b.Validate() != nil {
		return CompleteBundle{}, ErrInvalidBundle
	}
	return b, nil
}

func (b CompleteBundle) Validate() error {
	if !validToken(b.accessToken) || !validToken(b.refreshToken) || b.scope != ReadOnlyScope || !b.expiresAt.After(time.Unix(0, 0)) || b.expiresAt.Year() > 9999 {
		return ErrInvalidBundle
	}
	return nil
}
func validToken(s string) bool {
	if s == "" || len(s) > MaxTokenBytes {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func (CompleteBundle) String() string               { return redacted }
func (CompleteBundle) GoString() string             { return redacted }
func (CompleteBundle) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte(redacted)) }
func (CompleteBundle) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (CompleteBundle) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// UnmarshalJSON rejects generic credential injection; decoding a store record
// must use the schema-checked, bounded protected-store function below.
func (*CompleteBundle) UnmarshalJSON([]byte) error { return ErrInvalidBundle }
func (b CompleteBundle) ExpiresAt() time.Time      { return b.expiresAt }
func (b CompleteBundle) ReadOnly() bool            { return b.scope == ReadOnlyScope }

// Equal verifies the entire valid bundle, including both tokens. Never compare
// only expiry, access token or a metadata proof when checking persistence.
func (b CompleteBundle) Equal(other CompleteBundle) bool {
	if b.Validate() != nil || other.Validate() != nil {
		return false
	}
	access := subtle.ConstantTimeCompare([]byte(b.accessToken), []byte(other.accessToken))
	refresh := subtle.ConstantTimeCompare([]byte(b.refreshToken), []byte(other.refreshToken))
	return access&refresh == 1 && b.expiresAt.Equal(other.expiresAt) && b.scope == other.scope
}

// ExportAccessTokenForYNABRead is a plaintext boundary for the fixed-host read
// adapter. The caller must first revalidate the active owner/connection binding,
// policy and exact generation. Never log or serialize its returned string.
func (b CompleteBundle) ExportAccessTokenForYNABRead() string { return b.accessToken }

// ExportRefreshTokenForOAuth is a plaintext boundary for one durably fenced
// OAuth attempt. Never log it or reuse it after an ambiguous exchange outcome.
func (b CompleteBundle) ExportRefreshTokenForOAuth() string { return b.refreshToken }

type protectedWire struct {
	Version int    `json:"version"`
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expiry  string `json:"expires_at"`
	Scope   string `json:"scope"`
}

// MarshalForProtectedStore exports complete plaintext solely for immediate AEAD
// encryption by a protected-store adapter. The caller must not persist this
// result without encryption, or put it in logs/errors, metadata or tool output.
func (b CompleteBundle) MarshalForProtectedStore() ([]byte, error) {
	if b.Validate() != nil {
		return nil, ErrInvalidBundle
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(protectedWire{1, b.accessToken, b.refreshToken, b.expiresAt.Format(time.RFC3339Nano), b.scope}) != nil {
		return nil, ErrInvalidBundle
	}
	encoded := bytes.TrimSuffix(out.Bytes(), []byte{'\n'})
	if len(encoded) > MaxPlaintextBytes {
		return nil, ErrInvalidBundle
	}
	return encoded, nil
}

// UnmarshalFromProtectedStore accepts only the bounded canonical schema emitted
// by MarshalForProtectedStore, after successful AEAD verification. Exact
// canonical re-encoding rejects duplicate keys, unknown fields and alternative
// spellings, eliminating parser ambiguity. Errors never contain input data.
func UnmarshalFromProtectedStore(plaintext []byte) (CompleteBundle, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextBytes {
		return CompleteBundle{}, ErrInvalidBundle
	}
	var wire protectedWire
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.Version != 1 {
		return CompleteBundle{}, ErrInvalidBundle
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return CompleteBundle{}, ErrInvalidBundle
	}
	expiry, err := time.Parse(time.RFC3339Nano, wire.Expiry)
	if err != nil {
		return CompleteBundle{}, ErrInvalidBundle
	}
	bundle, err := NewOAuthBundle(wire.Access, wire.Refresh, expiry, wire.Scope)
	if err != nil {
		return CompleteBundle{}, ErrInvalidBundle
	}
	canonical, err := bundle.MarshalForProtectedStore()
	if err != nil {
		return CompleteBundle{}, ErrInvalidBundle
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, plaintext) {
		return CompleteBundle{}, ErrInvalidBundle
	}
	return bundle, nil
}
