# Candidate encrypted credential boundary

This package is a **candidate adapter, not an approved production vault**. It
implements `credentials.Store` using an injected Tink `AEAD` / `AEADWithContext`
and an injected immutable ciphertext `BlobStore`. It does not choose a cloud
provider, key service, key storage mechanism or deployment. No live keys or
resources are needed by its tests.

## What the boundary enforces

- The application owns an opaque complete bundle: access token, refresh token,
  exact `read-only` scope and UTC access expiry. Missing, malformed or oversized
  components fail closed. Generic JSON, formatting and structured logging redact
  the entire bundle.
- Only explicitly named store, fixed-host read and OAuth integration methods
  export plaintext. Generic JSON decoding cannot construct credentials. These
  narrow methods are a code-review boundary, not a sandbox against trusted code.
- Store serialization is bounded, versioned, canonical JSON. Parsing rejects
  missing/unknown/duplicate fields, altered scope, trailing input and alternate
  encodings. It is never written unencrypted.
- The AEAD authenticates a versioned domain separator and the exact tuple of
  provider, location and immutable version as associated data. Copying ciphertext
  between references, modifying a version or altering ciphertext fails closed.
- The blob backend exposes create-if-absent only. Exact repeated writes are
  idempotent; changed access token, refresh token or expiry cannot overwrite the
  same reference. Every successful put includes authenticated readback and exact
  comparison of the complete pair and metadata. A put with an uncertain backend
  acknowledgment may return failure even if the immutable blob exists; callers
  reconcile by reading that exact candidate, never by replaying OAuth.
- Local Tink authentication failures are classified as integrity failures. For
  remote/context-aware key services, only an explicitly identified
  `credentials.ErrIntegrity` means proven ciphertext authentication failure;
  unclassified RPC/key-service failures become unavailable, and cancellation is
  preserved. A temporary key-service outage must not force reauthorization.
- Reference strings, plaintext and ciphertext are bounded. The production backend
  must enforce `MaxCiphertextBytes` before allocating a remote read. Provider,
  parser and cryptographic errors are replaced with safe fixed errors.
- Temporary plaintext byte buffers are cleared after use. Go strings, library
  buffers and garbage collection mean this is not a secure-erasure guarantee.

## Production decisions deliberately left open

A production backend must provide tested durable immutable writes, authorization,
rollback/freshness controls, bounded I/O, availability, retention and recovery.
The production key authority must live **outside metadata backups**; keys must
never be stored as plaintext local files or alongside metadata. Use `NewEncryptedStore` only for local Tink primitives, and the context-aware
constructor for any primitive that can call a remote service. Key rotation,
key recovery, KMS/envelope policy, limits, audit retention and provider contracts
remain approval gates. Injected AEADs and blob backends are trusted components.

Content authentication does not establish that a valid blob is the current
credential generation, prevent rollback of an entire metadata backup, or prove
that another worker has not completed a token exchange. The lifecycle layer must
reconcile the owner/connection/lineage, exact expected reference, generation,
expiry and protected freshness state before activating or serving a restored
connection. Restored metadata must remain quarantined until that reconciliation
succeeds. Encryption alone cannot make the old refresh token safe to replay.

`MemoryBlobStore` / `NewMemoryBlobStoreForTesting` holds **ciphertext only** and is
synthetic test infrastructure. Re-instantiating `EncryptedStore` with the same
backend and independently retained test AEAD proves complete-bundle decoding and
reference integrity. It does not prove disk durability, cross-process persistence,
rollback resistance or a production vault. Tink-generated AES-256-GCM keysets in
tests are ephemeral and are never serialized or exported.

Tink dependency: https://github.com/tink-crypto/tink-go/releases/tag/v2.8.0
