// Package secrets provides a candidate AEAD-encrypted credential adapter. It
// does not select a production vault, key authority or persistent blob backend.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"unicode"
	"unicode/utf8"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	MaxCiphertextBytes = 64 << 10
	envelopeHeader     = "YNAB-CREDENTIAL-AEAD-v1\x00"
	storeRedacted      = "[redacted protected credential store]"
)

var ErrInvalidConfiguration = errors.New("invalid protected credential store configuration")

// BlobStore stores ciphertext only. PutIfAbsent must atomically create a durable
// immutable version, never overwrite, and return credentials.ErrConflict if a
// version already exists. Read returns credentials.ErrNotFound for missing
// versions, copies caller-owned bytes, and must bound reads to MaxCiphertextBytes
// before allocation. Production durability, independent rollback resistance,
// access control and backup policy require separate approval and testing.
type BlobStore interface {
	Read(context.Context, connection.CredentialRef) ([]byte, error)
	PutIfAbsent(context.Context, connection.CredentialRef, []byte) error
}

type EncryptedStore struct {
	blobs BlobStore
	aead  tink.AEADWithContext
}

var _ credentials.Store = (*EncryptedStore)(nil)

// NewEncryptedStore injects an existing LOCAL Tink AEAD. It is unsuitable for
// AEADs that can fail due to remote KMS/RPC outages; use the context-aware
// constructor below for those. Local decryption failures are authenticated-
// ciphertext failures. No key is created, serialized, stored, logged or selected
// here. Tests generate their own ephemeral Tink keys.
func NewEncryptedStore(blobs BlobStore, primitive tink.AEAD) (*EncryptedStore, error) {
	if nilValue(primitive) {
		return nil, ErrInvalidConfiguration
	}
	return NewEncryptedStoreWithContext(blobs, localAEAD{primitive})
}

// NewEncryptedStoreWithContext also supports injected key-service AEADs whose
// RPCs honor cancellation. The injected service must return credentials.ErrIntegrity
// only for a proven authentication failure, never an outage or denied key access.
// Unclassified failures become ErrUnavailable; cancellation is preserved. Key
// authority must remain outside metadata backups.
func NewEncryptedStoreWithContext(blobs BlobStore, primitive tink.AEADWithContext) (*EncryptedStore, error) {
	if nilValue(blobs) || nilValue(primitive) {
		return nil, ErrInvalidConfiguration
	}
	return &EncryptedStore{blobs: blobs, aead: primitive}, nil
}
func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}
func (EncryptedStore) String() string               { return storeRedacted }
func (EncryptedStore) GoString() string             { return storeRedacted }
func (EncryptedStore) Format(s fmt.State, _ rune)   { _, _ = s.Write([]byte(storeRedacted)) }
func (EncryptedStore) LogValue() slog.Value         { return slog.StringValue(storeRedacted) }
func (EncryptedStore) MarshalJSON() ([]byte, error) { return json.Marshal(storeRedacted) }

type localAEAD struct{ tink.AEAD }

func (a localAEAD) EncryptWithContext(ctx context.Context, p, ad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.Encrypt(p, ad)
}
func (a localAEAD) DecryptWithContext(ctx context.Context, c, ad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	plaintext, err := a.Decrypt(c, ad)
	if err != nil {
		clear(plaintext)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, credentials.ErrIntegrity
	}
	return plaintext, nil
}

func (s *EncryptedStore) Read(ctx context.Context, ref connection.CredentialRef) (credentials.CompleteBundle, error) {
	if err := s.check(ctx, ref); err != nil {
		return credentials.CompleteBundle{}, err
	}
	blob, err := s.blobs.Read(ctx, ref)
	if err != nil {
		return credentials.CompleteBundle{}, safeReadError(err)
	}
	if len(blob) <= len(envelopeHeader) || len(blob) > MaxCiphertextBytes || !bytes.HasPrefix(blob, []byte(envelopeHeader)) {
		return credentials.CompleteBundle{}, credentials.ErrIntegrity
	}
	plaintext, err := s.aead.DecryptWithContext(ctx, blob[len(envelopeHeader):], associatedData(ref))
	defer clear(plaintext)
	if err != nil {
		if ctx.Err() != nil {
			return credentials.CompleteBundle{}, ctx.Err()
		}
		return credentials.CompleteBundle{}, safeDecryptError(err)
	}
	if len(plaintext) > credentials.MaxPlaintextBytes {
		return credentials.CompleteBundle{}, credentials.ErrIntegrity
	}
	bundle, err := credentials.UnmarshalFromProtectedStore(plaintext)
	if err != nil {
		return credentials.CompleteBundle{}, credentials.ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return credentials.CompleteBundle{}, err
	}
	return bundle, nil
}

// PutImmutable does not expose overwrite/delete operations. Existing exact
// bundles are idempotent, including a racing/lost-acknowledgment put. Every
// success follows authenticated readback of both tokens, expiry and scope.
func (s *EncryptedStore) PutImmutable(ctx context.Context, ref connection.CredentialRef, bundle credentials.CompleteBundle) error {
	if err := s.check(ctx, ref); err != nil {
		return err
	}
	if bundle.Validate() != nil {
		return credentials.ErrInvalidBundle
	}
	prior, err := s.Read(ctx, ref)
	if err == nil {
		return compare(prior, bundle)
	}
	if !errors.Is(err, credentials.ErrNotFound) {
		return err
	}
	plaintext, err := bundle.MarshalForProtectedStore()
	if err != nil {
		return credentials.ErrInvalidBundle
	}
	defer clear(plaintext)
	ciphertext, err := s.aead.EncryptWithContext(ctx, plaintext, associatedData(ref))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return safeReadError(err)
	}
	if len(ciphertext) == 0 || len(ciphertext) > MaxCiphertextBytes-len(envelopeHeader) {
		return credentials.ErrUnavailable
	}
	blob := make([]byte, 0, len(envelopeHeader)+len(ciphertext))
	blob = append(blob, envelopeHeader...)
	blob = append(blob, ciphertext...)
	if err := ctx.Err(); err != nil {
		return err
	}
	err = s.blobs.PutIfAbsent(ctx, ref, blob)
	if err != nil && !errors.Is(err, credentials.ErrConflict) {
		return safeReadError(err)
	}
	readback, err := s.Read(ctx, ref)
	if err != nil {
		return err
	}
	return compare(readback, bundle)
}
func compare(got, want credentials.CompleteBundle) error {
	if !got.Equal(want) {
		return credentials.ErrConflict
	}
	return nil
}
func (s *EncryptedStore) check(ctx context.Context, ref connection.CredentialRef) error {
	if s == nil || nilValue(s.blobs) || nilValue(s.aead) {
		return ErrInvalidConfiguration
	}
	if ctx == nil {
		return credentials.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validRef(ref) {
		return credentials.ErrInvalidBundle
	}
	return nil
}
func validRef(ref connection.CredentialRef) bool {
	if ref.Validate() != nil {
		return false
	}
	for _, v := range []string{ref.Provider, ref.Location, ref.ImmutableVersion} {
		if !utf8.ValidString(v) {
			return false
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	return true
}
func associatedData(ref connection.CredentialRef) []byte {
	// A fixed domain separator, schema version and an unambiguous tuple bind the
	// complete exact reference. JSON escaping prevents delimiter collisions.
	data, _ := json.Marshal([5]string{"ynab-mcp/protected-credentials", "1", ref.Provider, ref.Location, ref.ImmutableVersion})
	return data
}
func safeReadError(err error) error {
	for _, safe := range []error{credentials.ErrNotFound, credentials.ErrConflict, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return credentials.ErrUnavailable
}

func safeDecryptError(err error) error {
	for _, safe := range []error{credentials.ErrIntegrity, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return credentials.ErrUnavailable
}
