package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

var testRef = connection.CredentialRef{Provider: "synthetic-vault", Location: "connection/lineage/candidate", ImmutableVersion: "synthetic-version-1"}

const accessMarker = "synthetic-secret-access-marker"
const refreshMarker = "synthetic-secret-refresh-marker"

func testPrimitive(t *testing.T) tink.AEAD {
	t.Helper()
	handle, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	primitive, err := aead.New(handle)
	if err != nil {
		t.Fatal(err)
	}
	return primitive
}
func testBundle(t *testing.T) credentials.CompleteBundle {
	t.Helper()
	b, err := credentials.NewOAuthBundle(accessMarker, refreshMarker, time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC), credentials.ReadOnlyScope)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testStore(t *testing.T) (*EncryptedStore, *MemoryBlobStore, tink.AEAD) {
	t.Helper()
	backend := NewMemoryBlobStoreForTesting()
	primitive := testPrimitive(t)
	store, err := NewEncryptedStore(backend, primitive)
	if err != nil {
		t.Fatal(err)
	}
	return store, backend, primitive
}
func noSecrets(t *testing.T, s string) {
	t.Helper()
	for _, secret := range []string{accessMarker, refreshMarker} {
		if strings.Contains(s, secret) {
			t.Fatal("secret marker leaked")
		}
	}
}
func TestCompletePairPersistsEncryptedAcrossAdapterReconstruction(t *testing.T) {
	ctx := context.Background()
	store, backend, primitive := testStore(t)
	bundle := testBundle(t)
	if err := store.PutImmutable(ctx, testRef, bundle); err != nil {
		t.Fatal(err)
	}
	blob, err := backend.Read(ctx, testRef)
	if err != nil {
		t.Fatal(err)
	}
	noSecrets(t, string(blob))
	// Only ciphertext and an independently retained AEAD are reused. This tests
	// reconstructed adapters, not production durability or process persistence.
	restarted, err := NewEncryptedStore(backend, primitive)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Read(ctx, testRef)
	if err != nil || !got.Equal(bundle) {
		t.Fatal("reconstructed store did not read complete pair")
	}
	if err := restarted.PutImmutable(ctx, testRef, bundle); err != nil {
		t.Fatal("exact put was not idempotent")
	}
	after, _ := backend.Read(ctx, testRef)
	if !bytes.Equal(blob, after) {
		t.Fatal("idempotent put replaced ciphertext")
	}
	for _, different := range []struct {
		access, refresh string
		delta           time.Duration
	}{{accessMarker + "x", refreshMarker, 0}, {accessMarker, refreshMarker + "x", 0}, {accessMarker, refreshMarker, time.Second}} {
		b, _ := credentials.NewOAuthBundle(different.access, different.refresh, bundle.ExpiresAt().Add(different.delta), credentials.ReadOnlyScope)
		if err := store.PutImmutable(ctx, testRef, b); !errors.Is(err, credentials.ErrConflict) {
			t.Fatal("different complete pair overwrote immutable version")
		}
	}
	after, _ = backend.Read(ctx, testRef)
	if !bytes.Equal(blob, after) {
		t.Fatal("rejected put changed ciphertext")
	}
}
func TestAEADBindsProviderLocationAndImmutableVersion(t *testing.T) {
	ctx := context.Background()
	store, backend, _ := testStore(t)
	if err := store.PutImmutable(ctx, testRef, testBundle(t)); err != nil {
		t.Fatal(err)
	}
	blob, _ := backend.Read(ctx, testRef)
	for _, ref := range []connection.CredentialRef{
		{Provider: "other", Location: testRef.Location, ImmutableVersion: testRef.ImmutableVersion},
		{Provider: testRef.Provider, Location: "other", ImmutableVersion: testRef.ImmutableVersion},
		{Provider: testRef.Provider, Location: testRef.Location, ImmutableVersion: "other"},
	} {
		if err := backend.PutIfAbsent(ctx, ref, blob); err != nil {
			t.Fatal(err)
		}
		if got, err := store.Read(ctx, ref); !errors.Is(err, credentials.ErrIntegrity) || got.Validate() == nil {
			t.Fatal("ciphertext reference substitution accepted")
		}
	}
}
func TestCiphertextTamperingTruncationWrongKeyAndCorruptSchemaFailClosed(t *testing.T) {
	ctx := context.Background()
	store, backend, primitive := testStore(t)
	if err := store.PutImmutable(ctx, testRef, testBundle(t)); err != nil {
		t.Fatal(err)
	}
	original, _ := backend.Read(ctx, testRef)
	changed := bytes.Clone(original)
	changed[len(changed)-1] ^= 1
	version := bytes.Clone(original)
	version[0] ^= 1
	for _, blob := range [][]byte{nil, original[:len(envelopeHeader)], original[:len(original)-1], changed, version, bytes.Repeat([]byte{'x'}, MaxCiphertextBytes+1)} {
		backend.mu.Lock()
		backend.blobs[testRef] = blob
		backend.mu.Unlock()
		if got, err := store.Read(ctx, testRef); err == nil || got.Validate() == nil {
			t.Fatal("corrupt ciphertext accepted")
		}
		noSecrets(t, fmt.Sprint(blobReadError(store, ctx)))
	}
	backend.mu.Lock()
	backend.blobs[testRef] = original
	backend.mu.Unlock()
	wrong, _ := NewEncryptedStore(backend, testPrimitive(t))
	if _, err := wrong.Read(ctx, testRef); !errors.Is(err, credentials.ErrIntegrity) {
		t.Fatal("wrong key accepted")
	}
	for _, plaintext := range [][]byte{[]byte(`{"version":1,"access_token":"` + accessMarker + `"}`), bytes.Repeat([]byte{'x'}, credentials.MaxPlaintextBytes+1)} {
		encrypted, err := primitive.Encrypt(plaintext, associatedData(testRef))
		if err != nil {
			t.Fatal(err)
		}
		backend.mu.Lock()
		backend.blobs[testRef] = append([]byte(envelopeHeader), encrypted...)
		backend.mu.Unlock()
		if _, err := store.Read(ctx, testRef); !errors.Is(err, credentials.ErrIntegrity) {
			t.Fatal("authenticated incomplete/oversized plaintext accepted")
		}
	}
}
func blobReadError(store *EncryptedStore, ctx context.Context) error {
	_, err := store.Read(ctx, testRef)
	return err
}
func TestAllStoreErrorsAndFormattingAreSanitized(t *testing.T) {
	ctx := context.Background()
	store, backend, primitive := testStore(t)
	for _, v := range []any{store, *store, backend, []any{store, backend}, map[string]any{"store": store}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			noSecrets(t, fmt.Sprintf(format, v))
		}
		data, _ := json.Marshal(v)
		noSecrets(t, string(data))
		var out bytes.Buffer
		slog.New(slog.NewJSONHandler(&out, nil)).Info("synthetic", "value", v)
		noSecrets(t, out.String())
	}
	hostile := errors.New(accessMarker + refreshMarker)
	fault := &faultBackend{readErr: hostile}
	broken, _ := NewEncryptedStore(fault, primitive)
	if _, err := broken.Read(ctx, testRef); !errors.Is(err, credentials.ErrUnavailable) {
		t.Fatal("unexpected safe error")
	} else {
		noSecrets(t, fmt.Sprint(err))
	}
	fault.readErr = credentials.ErrNotFound
	fault.putErr = hostile
	if err := broken.PutImmutable(ctx, testRef, testBundle(t)); !errors.Is(err, credentials.ErrUnavailable) {
		t.Fatal("unexpected safe put error")
	} else {
		noSecrets(t, fmt.Sprint(err))
	}
	broken, _ = NewEncryptedStore(backend, faultAEAD{err: hostile})
	if err := broken.PutImmutable(ctx, testRef, testBundle(t)); !errors.Is(err, credentials.ErrUnavailable) {
		t.Fatal("unsafe encryption error")
	} else {
		noSecrets(t, fmt.Sprint(err))
	}
}

type faultBackend struct {
	readErr, putErr error
	blob            []byte
}

func (b *faultBackend) Read(context.Context, connection.CredentialRef) ([]byte, error) {
	return bytes.Clone(b.blob), b.readErr
}
func (b *faultBackend) PutIfAbsent(context.Context, connection.CredentialRef, []byte) error {
	return b.putErr
}

type faultAEAD struct {
	err       error
	encrypted []byte
}

func (a faultAEAD) Encrypt([]byte, []byte) ([]byte, error) { return a.encrypted, a.err }
func (a faultAEAD) Decrypt([]byte, []byte) ([]byte, error) { return nil, a.err }
func TestInvalidContextsReferencesAndZeroValuesDoNotWrite(t *testing.T) {
	store, backend, primitive := testStore(t)
	ctx := context.Background()
	if _, err := NewEncryptedStore(nil, primitive); err == nil {
		t.Fatal("nil backend accepted")
	}
	if _, err := NewEncryptedStore(backend, nil); err == nil {
		t.Fatal("nil AEAD accepted")
	}
	var typedNil *MemoryBlobStore
	if _, err := NewEncryptedStore(typedNil, primitive); err == nil {
		t.Fatal("typed nil backend accepted")
	}
	for _, ref := range []connection.CredentialRef{{}, {Provider: "p", Location: "l", ImmutableVersion: ""}, {Provider: "p\t", Location: "l", ImmutableVersion: "v"}, {Provider: "p", Location: "\xff", ImmutableVersion: "v"}} {
		if err := store.PutImmutable(ctx, ref, testBundle(t)); !errors.Is(err, credentials.ErrInvalidBundle) {
			t.Fatal("invalid ref accepted")
		}
	}
	if err := store.PutImmutable(ctx, testRef, credentials.CompleteBundle{}); !errors.Is(err, credentials.ErrInvalidBundle) {
		t.Fatal("zero bundle stored")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.PutImmutable(canceled, testRef, testBundle(t)); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled write accepted")
	}
	if err := store.PutImmutable(nil, testRef, testBundle(t)); err == nil {
		t.Fatal("nil context accepted")
	}
	var zero EncryptedStore
	if err := zero.PutImmutable(ctx, testRef, testBundle(t)); err == nil {
		t.Fatal("zero store accepted")
	}
	if len(backend.blobs) != 0 {
		t.Fatal("invalid input caused a write")
	}
}
func TestReadbackIsRequiredAndVerifiesBothTokens(t *testing.T) {
	ctx := context.Background()
	primitive := testPrimitive(t)
	want := testBundle(t)
	altered, _ := credentials.NewOAuthBundle(accessMarker, refreshMarker+"-different", want.ExpiresAt(), credentials.ReadOnlyScope)
	raw, _ := altered.MarshalForProtectedStore()
	ciphertext, _ := primitive.Encrypt(raw, associatedData(testRef))
	backend := &readbackBackend{blob: append([]byte(envelopeHeader), ciphertext...)}
	store, _ := NewEncryptedStore(backend, primitive)
	if err := store.PutImmutable(ctx, testRef, want); !errors.Is(err, credentials.ErrConflict) {
		t.Fatal("wrong refresh token passed readback")
	}
	backend = &readbackBackend{missing: true}
	store, _ = NewEncryptedStore(backend, primitive)
	if err := store.PutImmutable(ctx, testRef, want); !errors.Is(err, credentials.ErrNotFound) {
		t.Fatal("missing readback reported success")
	}
}

type readbackBackend struct {
	reads   int
	blob    []byte
	missing bool
}

func (b *readbackBackend) Read(context.Context, connection.CredentialRef) ([]byte, error) {
	b.reads++
	if b.reads == 1 || b.missing {
		return nil, credentials.ErrNotFound
	}
	return bytes.Clone(b.blob), nil
}
func (*readbackBackend) PutIfAbsent(context.Context, connection.CredentialRef, []byte) error {
	return nil
}
func TestConcurrentIdempotentWritesAndConflicts(t *testing.T) {
	ctx := context.Background()
	store, backend, _ := testStore(t)
	bundle := testBundle(t)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Go(func() { errs <- store.PutImmutable(ctx, testRef, bundle) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(backend.blobs) != 1 {
		t.Fatal("more than one immutable blob")
	}
	got, err := store.Read(ctx, testRef)
	if err != nil || !got.Equal(bundle) {
		t.Fatal("racing writers damaged complete pair")
	}
}
func TestBackendCopiesCiphertextAndNeverOverwrites(t *testing.T) {
	ctx := context.Background()
	_, backend, primitive := testStore(t)
	raw, _ := testBundle(t).MarshalForProtectedStore()
	encrypted, _ := primitive.Encrypt(raw, associatedData(testRef))
	blob := append([]byte(envelopeHeader), encrypted...)
	if err := backend.PutIfAbsent(ctx, testRef, blob); err != nil {
		t.Fatal(err)
	}
	copyBefore := bytes.Clone(blob)
	clear(blob)
	read, _ := backend.Read(ctx, testRef)
	if !bytes.Equal(read, copyBefore) {
		t.Fatal("backend retained caller-owned input")
	}
	clear(read)
	read, _ = backend.Read(ctx, testRef)
	if !bytes.Equal(read, copyBefore) {
		t.Fatal("backend exposed mutable internal bytes")
	}
	if err := backend.PutIfAbsent(ctx, testRef, copyBefore); !errors.Is(err, credentials.ErrConflict) {
		t.Fatal("backend overwrote existing version")
	}
}
func TestOversizedAEADOutputNeverReachesBackend(t *testing.T) {
	backend := NewMemoryBlobStoreForTesting()
	store, _ := NewEncryptedStore(backend, faultAEAD{encrypted: make([]byte, MaxCiphertextBytes+1)})
	if err := store.PutImmutable(context.Background(), testRef, testBundle(t)); !errors.Is(err, credentials.ErrUnavailable) {
		t.Fatal("unbounded ciphertext accepted")
	}
	if len(backend.blobs) != 0 {
		t.Fatal("oversized ciphertext reached backend")
	}
}

func TestLostPutAcknowledgmentIsReconciledWithoutOverwrite(t *testing.T) {
	ctx := context.Background()
	backend := &lostAckBackend{MemoryBlobStore: NewMemoryBlobStoreForTesting()}
	primitive := testPrimitive(t)
	store, _ := NewEncryptedStore(backend, primitive)
	bundle := testBundle(t)
	if err := store.PutImmutable(ctx, testRef, bundle); !errors.Is(err, credentials.ErrUnavailable) {
		t.Fatal("lost put acknowledgment falsely reported success")
	}
	got, err := store.Read(ctx, testRef)
	if err != nil || !got.Equal(bundle) {
		t.Fatal("exact candidate could not be reconciled")
	}
	if err := store.PutImmutable(ctx, testRef, bundle); err != nil {
		t.Fatal("existing exact candidate was not idempotent")
	}
	if backend.puts != 1 {
		t.Fatal("reconciliation repeated immutable backend write")
	}
}

type lostAckBackend struct {
	*MemoryBlobStore
	puts int
}

func (b *lostAckBackend) PutIfAbsent(ctx context.Context, ref connection.CredentialRef, blob []byte) error {
	b.puts++
	if err := b.MemoryBlobStore.PutIfAbsent(ctx, ref, blob); err != nil {
		return err
	}
	return errors.New(accessMarker)
}
func TestConcurrentDifferentPairsPublishOnlyOneCompleteGeneration(t *testing.T) {
	ctx := context.Background()
	store, backend, _ := testStore(t)
	first := testBundle(t)
	second, _ := credentials.NewOAuthBundle(accessMarker+"-two", refreshMarker+"-two", first.ExpiresAt(), credentials.ReadOnlyScope)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, b := range []credentials.CompleteBundle{first, second} {
		wg.Go(func() { errs <- store.PutImmutable(ctx, testRef, b) })
	}
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, credentials.ErrConflict):
			conflicts++
		default:
			t.Fatal("unexpected race error")
		}
	}
	if successes != 1 || conflicts != 1 || len(backend.blobs) != 1 {
		t.Fatal("conflicting race did not have exactly one immutable winner")
	}
	got, err := store.Read(ctx, testRef)
	if err != nil || !got.Equal(first) && !got.Equal(second) {
		t.Fatal("race mixed credential generations")
	}
}
func TestContextKeyServiceReceivesAuthenticatedReference(t *testing.T) {
	ctx := context.Background()
	backend := NewMemoryBlobStoreForTesting()
	service := &testKeyService{primitive: testPrimitive(t)}
	store, err := NewEncryptedStoreWithContext(backend, service)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutImmutable(ctx, testRef, testBundle(t)); err != nil {
		t.Fatal(err)
	}
	if service.encrypts != 1 || service.decrypts != 1 || !bytes.Equal(service.lastAD, associatedData(testRef)) {
		t.Fatal("key service did not receive exact associated reference")
	}
	// Formatting never follows into the injected key service or errors it holds.
	service.secret = accessMarker + refreshMarker
	for _, format := range []string{"%v", "%#v", "%+v", "%x"} {
		noSecrets(t, fmt.Sprintf(format, store))
	}
}

type testKeyService struct {
	primitive          tink.AEAD
	encrypts, decrypts int
	lastAD             []byte
	secret             string
}

func (s *testKeyService) EncryptWithContext(ctx context.Context, p, ad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.encrypts++
	s.lastAD = bytes.Clone(ad)
	return s.primitive.Encrypt(p, ad)
}
func (s *testKeyService) DecryptWithContext(ctx context.Context, c, ad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.decrypts++
	s.lastAD = bytes.Clone(ad)
	return s.primitive.Decrypt(c, ad)
}

func TestTemporaryKeyFailureIsUnavailableAndDoesNotClaimCorruption(t *testing.T) {
	ctx := context.Background()
	store, backend, _ := testStore(t)
	bundle := testBundle(t)
	if err := store.PutImmutable(ctx, testRef, bundle); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		failure, want error
	}{
		{"unknown remote failure", errors.New(accessMarker + " temporary RPC outage"), credentials.ErrUnavailable},
		{"key unavailable", credentials.ErrUnavailable, credentials.ErrUnavailable},
		{"denied key access", errors.New("synthetic permission denied"), credentials.ErrUnavailable},
		{"canceled key RPC", context.Canceled, context.Canceled},
		{"deadline exceeded", context.DeadlineExceeded, context.DeadlineExceeded},
		{"proven authentication failure", fmt.Errorf("%s: %w", accessMarker, credentials.ErrIntegrity), credentials.ErrIntegrity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unavailable, err := NewEncryptedStoreWithContext(backend, failingKeyService{tc.failure})
			if err != nil {
				t.Fatal(err)
			}
			got, err := unavailable.Read(ctx, testRef)
			if !errors.Is(err, tc.want) || got.Validate() == nil {
				t.Fatal("key-service failure misclassified")
			}
			noSecrets(t, fmt.Sprint(err))
			if tc.want != credentials.ErrIntegrity && errors.Is(err, credentials.ErrIntegrity) {
				t.Fatal("outage was classified as corrupted ciphertext")
			}
			if err := unavailable.PutImmutable(ctx, testRef, bundle); !errors.Is(err, tc.want) {
				t.Fatal("put ignored existing unreadable ciphertext")
			}
		})
	}
	// Recovery needs no blob or bundle replacement after a transient key outage.
	recovered, err := store.Read(ctx, testRef)
	if err != nil || !recovered.Equal(bundle) {
		t.Fatal("key outage changed stored complete credentials")
	}
}

type failingKeyService struct{ err error }

func (s failingKeyService) EncryptWithContext(context.Context, []byte, []byte) ([]byte, error) {
	return nil, s.err
}
func (s failingKeyService) DecryptWithContext(context.Context, []byte, []byte) ([]byte, error) {
	return nil, s.err
}
