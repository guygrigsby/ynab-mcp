# Recovery and deployment boundaries

This is guidance for reviewing a future deployment. It does not create or approve
one. No production keys, account credentials, issuer, host or storage service are
configured by the repository.

## Offline check

With Go 1.27.2 or newer:

```sh
go run ./cmd/budget-mcp --help
go run ./cmd/budget-mcp check-state /path/to/existing-private-metadata.db
```

The command opens existing candidate SQLite metadata read-only. It never creates
an owner/database, runs migrations, loads credentials, exchanges OAuth tokens,
opens a listener or starts a public callback. Success establishes structural
metadata validity only, not authorization, freshness or safe production startup.

## Authoritative state versus a restored copy

- Use the normal SQLite `Open` API only for the authoritative current private
  metadata file. Keep its directory private and trusted; path checks are not a
  substitute for OS isolation against a local attacker controlling its directory.
- Use `OpenRestored` for copied/restored or otherwise potentially stale metadata.
  It requires reconnect for potentially stale generations, preserves disabled
  state, and applies a full rolling-window quota cooldown. Never choose normal
  open merely to avoid that recovery gate.
- The metadata database cannot detect a previously valid copy by itself. An
  external durable secret authority, backup provenance, rollback controls and an
  approved restoration procedure are required before production use.
- Metadata includes owner identity, allowlists and secret references. Protect its
  backups even though it contains neither financial payloads nor bearer tokens.
  Keep the decryption authority outside this database and its backups.

## Refresh recovery

Recovery is a trusted administrative/startup operation, never an MCP tool.

1. Establish the authoritative metadata and protected store. Quiesce the previous
   instance and independently verify stopped-worker evidence. A lease expiration
   cannot cancel a token request already in flight.
2. Inspect the connection/attempt through repository APIs. An active committed
   pointer is checked against the complete protected bundle before any read.
3. For `prepared`, require exact stopped-worker evidence and the bounded lease
   condition before abandoning the attempt. No exchange was admitted yet.
4. For `request_started` or `secret_saved`, an existing valid candidate may finish
   its policy-fenced generation commit. Never send another exchange for that
   attempt. If the candidate is missing after verified worker loss, mark the
   outcome ambiguous and require fresh owner consent.
5. If the protected store/key service is temporarily unavailable, preserve the
   recovery state and return unavailable. Do not replace it with a personal token
   or classify an untyped remote key-service error as corrupted credentials.
6. Disable, reconnect or owner-policy changes beat stale work. Cleanup of encrypted
   orphan/obsolete generations requires a selected retention policy and separate
   implementation; no automatic deletion is included.

## Consent callback integration

The application authorization service implements the state/PKCE/activation
boundary, but does not provide an internet callback route. A selected adapter
must obtain the exact owner principal from the approved issuer, use an
independently authenticated server session, supply the verified HTTPS callback
origin plus escaped path, reject duplicate query parameters, and keep codes,
state, verifiers and session identifiers out of access logs. An MCP session ID or
client-provided identity is not this authenticated owner session.

Pending flows are bounded, expiring and consumed once. A restart or uncertain
exchange requires a new consent flow. No state/code is replayed from the metadata
backup. A failed callback may have stored an encrypted orphan or committed before
an acknowledgment was lost; do not infer that failure authorizes reuse of its code.

## Things this repository does not choose

- Production SQLite volume versus another approved durable adapter
- Cloud vault/blob provider, external KMS/key authority, identity/access grants
- Issuer, OAuth client registration and compatible token profile
- HTTPS ingress, callback host, network exposure, tunnel or deployment
- Backup/retention and orphan retirement policy
- Live financial account or budget disclosure allowlist

The candidate composition helpers take explicit dependencies and do not supply
permissive defaults for these decisions. Follow the remaining gates in
[implementation status](IMPLEMENTATION.md) before any real account access.
