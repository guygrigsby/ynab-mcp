package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

// MemoryBlobStore is a synthetic ciphertext backend for tests and examples only.
// It is NOT durable, rollback-resistant or an approved production vault. Reusing
// this object across EncryptedStore instances tests adapter reconstruction, not
// persistence across operating-system process restarts.
type MemoryBlobStore struct {
	mu    sync.RWMutex
	blobs map[connection.CredentialRef][]byte
}

func NewMemoryBlobStoreForTesting() *MemoryBlobStore {
	return &MemoryBlobStore{blobs: make(map[connection.CredentialRef][]byte)}
}
func (*MemoryBlobStore) String() string   { return "[synthetic ciphertext backend]" }
func (*MemoryBlobStore) GoString() string { return "[synthetic ciphertext backend]" }
func (*MemoryBlobStore) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[synthetic ciphertext backend]"))
}
func (*MemoryBlobStore) MarshalJSON() ([]byte, error) {
	return json.Marshal("[synthetic ciphertext backend]")
}
func (*MemoryBlobStore) LogValue() slog.Value {
	return slog.StringValue("[synthetic ciphertext backend]")
}
func (m *MemoryBlobStore) Read(ctx context.Context, ref connection.CredentialRef) ([]byte, error) {
	if m == nil || ctx == nil {
		return nil, credentials.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validRef(ref) {
		return nil, credentials.ErrInvalidBundle
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	blob, ok := m.blobs[ref]
	if !ok {
		return nil, credentials.ErrNotFound
	}
	if len(blob) > MaxCiphertextBytes {
		return nil, credentials.ErrIntegrity
	}
	return bytes.Clone(blob), nil
}
func (m *MemoryBlobStore) PutIfAbsent(ctx context.Context, ref connection.CredentialRef, blob []byte) error {
	if m == nil || ctx == nil {
		return credentials.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validRef(ref) || len(blob) <= len(envelopeHeader) || len(blob) > MaxCiphertextBytes || !bytes.HasPrefix(blob, []byte(envelopeHeader)) {
		return credentials.ErrInvalidBundle
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.blobs[ref]; ok {
		return credentials.ErrConflict
	}
	if m.blobs == nil {
		m.blobs = make(map[connection.CredentialRef][]byte)
	}
	m.blobs[ref] = bytes.Clone(blob)
	return nil
}
