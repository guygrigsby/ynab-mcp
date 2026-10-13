# SQLite metadata candidate

This adapter is implemented and tested with synthetic temporary files. It is not
a production backend selection, deployment, or credential-store implementation.
No server automatically opens a database or initializes an owner.

## API and ownership

- `Open(path)` opens a private regular file and applies schema v1 only to an empty
  SQLite database. Unknown application IDs, unknown schema versions, unrelated
  databases, symlinks, memory databases, and raw SQLite URI configuration fail.
- `Initialize(ctx, grant, connection)` atomically creates the single owner,
  connection, grant and explicit allowlist. It requires explicit administrative
  authorization. The initial policy version is 1; no identity is auto-enrolled.
- `ReadAccessState` and `ReadAuthorizationState` use one joined SQL statement, so
  connection, policy version and allowlist always come from one read snapshot.
- `ReplaceGrant` replaces the allowlist and policy in one transaction, requires
  exactly `expected + 1`, and cannot create or transfer connection ownership.
- `Connections()` supplies plain administrative CAS and policy-scoped lifecycle
  CAS. `CompareAndSwapAuthorized` additionally fences consent activation against
  the exact owner principal, policy, connection version and prior status.
- `Quotas()` uses the immutable connection ID as `QuotaKey`. Tokens, token hashes,
  credential generations and authorization lineages never determine that key.
- `OpenReadOnly(path)` inspects existing schema without migrations or file writes.
  Mutations fail with `ErrReadOnly`.

The file contains owner/principal policy, budget identifiers, protected-store
references, connection/refresh metadata, and bounded quota reservations only.
There are no token, authorization-code, PKCE, financial-payload or snapshot
columns. API types cannot accept a financial result or credential bundle.

## Consistency and durability

Foreign keys and strict table constraints enforce one configured owner, one
owned connection and one ledger per connection. Indexed version/ownership
columns are checked against canonical, size-bounded metadata. Grants are
normalized into owner, grant and allowlist tables. Connection and quota roots
use canonical JSON to retain all validated domain metadata; unknown, omitted,
duplicated or inconsistent fields fail closed. Unlike the illustrative design
schema's millisecond timestamps, JSON retains UTC-instant nanosecond precision
to avoid shortening a rolling-window boundary after reopening. The fixed quota
policy is 180 attempts/hour with a one-second safety margin and at most 180
stored reservations. The owner allowlist is bounded to 1,024 concrete IDs.

Writes start with `BEGIN IMMEDIATE`, before loading state, including across
independent processes. SQL is parameterized, CAS checks affected-row counts,
and transactions contain only metadata operations. Each database connection
uses foreign keys, `synchronous=FULL`, disabled trusted schema, and a five-second
SQLite busy timeout. SQLite lock acquisition retries are bounded by that timeout
and caller cancellation; the adapter does not replay transaction callbacks or
ambiguous commits. One pooled connection per Store avoids unconfigured recycled
connections. The candidate uses SQLite's default rollback journal. No WAL mode
or network filesystem is enabled or implied.

New database files are mode 0600; SQLite rollback journals inherit the database's
private permissions. Existing group/world-accessible files and final-path
symlinks are rejected without changing permissions. The caller must supply a
trusted private directory and approved durable local storage. Filesystem safety,
host encryption, backups and storage guarantees remain deployment gates. Generic
database failures are sanitized; returned errors never include raw SQL, paths,
principal metadata, references or driver error strings.

## Quota and crash behavior

A missing ledger on `Reserve` is durably replaced with a full-hour-plus-safety
cooldown and that attempt is rejected. It never becomes an empty usable ledger.
A malformed ledger is rejected without being overwritten. Successful admission
is committed before returning its reservation; a subsequent process crash
therefore overcounts safely. Every HTTP retry needs a fresh attempt identifier.
Failed requests never refund reservations. Rotation and reconnect retain the
same quota key and count.

`RecordCooldown` preserves the longer deadline and performs a bounded detached
write so cancelling the failed HTTP request cannot discard an authoritative 429.
Clock rollback rejects admission and cooldown edits; it never prunes reservations
or grants extra capacity. The application must surface persistence failures.

## Restore is different from ordinary restart

`Open` is only for a current authoritative database, including normal crash
recovery. A file cannot prove it has not been replaced by an older backup.
Opening a restored database with `Open` is therefore unsafe and unsupported.

Use `OpenRestored(path, now)` for a backup or stale copy. In one transaction it
marks active/refreshing connections `reconnect_required`, retains disabled
connections and owner-grant settings, and imposes a full new quota cooldown
after the later of the supplied clock and stored clock. A longer existing
cooldown is retained. No old credential reference becomes readable, no refresh
is replayed, and no secret-store operation occurs. Corrupt metadata fails closed
instead of being guessed or repaired. The owner must complete explicitly
authorized reconnect with a new credential reference and authorization lineage.

An already unconnected database remains unconnected. A normal crash with an
unresolved refresh is handled by the application lifecycle service using its
fenced journal and protected-store checks; this adapter does not decide that
an absent candidate means it is safe to retry an OAuth exchange.

## Synthetic acceptance coverage

Tests cover single-owner initialization rollback; exact grant/version/ownership
CAS; atomic policy-fenced activation and refresh; immutable returned metadata;
concurrent readers/writers and independent-process CAS/quota saturation;
reservation persistence after abrupt process exit before send; interrupted
transaction rollback; corruption, unsupported versions, private files, read-only
inspection, clock rollback, conservative time boundaries, cooldown persistence
after cancellation, and explicit backup restore blocking old credentials.

All helper processes operate on test-created temporary databases. No account,
network listener, real token, secret-manager service or financial payload is used.
