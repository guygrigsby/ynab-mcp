# Implementation status and release gates

This is an undeployed, single-owner development implementation. The
[design](DESIGN.md) remains the target architecture; its historical
“documentation only” status describes the earlier design delivery.

## Implemented boundaries

Dependencies point inward: adapters → application → domain. No application
service depends on SQLite, the MCP SDK, HTTP DTOs or a selected cloud vault.

| Area | Implemented and synthetically tested | Still required before live use |
| --- | --- | --- |
| Access policy | Exact issuer/subject/tenant; one owned connection; versioned explicit budget grants; pre-read and pre-disclosure checks | Approved owner, budget and field configuration |
| Financial inquiry | Eight read-only tools, exact money, dates/IDs, distinct scheduled/recorded models, split preservation, strict schemas, bounded queue/coalescing | Actual account/host contract acceptance and operational load measurements |
| Snapshots | Memory-only immutable pages, opaque scope/query/version-bound cursors, replay, absolute ≤5-minute TTL, byte/count caps, expiry/eviction | Operational cleanup cadence; correctness never depends on cleanup timing |
| Inbound OAuth/MCP | Official SDK, stateless Streamable HTTP, JOSE verification, bounded pinned JWKS, resource metadata/challenges, owner checks on all MCP requests | Approved compatible issuer/client registration and actual host authorization flow |
| HTTP | Exact host/origin allowlists, request limits/deadlines, no trusted forwarding headers, content-free health route | Approved TLS ingress, listener and network architecture |
| SQLite candidate | Single-owner initialization, atomic grant replacement, structurally validated connection transitions, version CAS, atomic policy-fenced activation/refresh, durable quota ledger, read-only inspection and explicit restored-backup handling | Production backend selection, approved durable volume, private directory, backup policy and operational validation |
| Protected credentials | Complete opaque bundle, redacted generic serialization/logging, Tink AEAD boundary, immutable ciphertext records, exact authenticated readback, reference/version binding, clear remote-outage classification | Approved durable secret backend and independently controlled key authority, access policy, rotation and rollback protection |
| Refresh lifecycle | One coalesced exchange, persisted/fenced phases before effects, full-pair readback before generation commit, lost-ack reconciliation, no uncertain replay, policy/disable/reconnect race checks | Trusted startup/dead-worker orchestration and provider-specific operational acceptance |
| Owner consent callback | Random single-use expiring owner/session-bound state, S256 PKCE, exact callback, bounded attempts, immutable persistence and atomic policy-fenced activation | A separately reviewed HTTP/session adapter using an independently authenticated server session; no public callback route exists yet |
| Upstream admission | Durable rolling reservations, 180/hour headroom, missing-ledger full-window cooldown, rollback protection, stable key across token rotation, 429 persistence even after downstream cancellation | Durable volume/recovery acceptance and visibility into externally consumed upstream quota |
| YNAB adapters | Fixed GET-only financial routes, DTO projection, mandatory currency metadata, bounds, separate fixed-host single-attempt OAuth transport | Approved live OAuth application, protected client-secret loading and named budget consent |
| Composition | Candidate read-handler wiring plus an offline read-only metadata-check executable | Production serving command and trustworthy startup recovery/key/vault configuration |

## Important implementation choices

### Control metadata

SQLite is implemented as a **candidate**, not silently selected for deployment.
Its schema stores explicit owner/grant/allowlist relationships and versioned,
canonical bounded JSON for connection and quota aggregates. The aggregate JSON
contains references and control state only, never tokens or financial payloads.
This refines the design's proposed relational layout while preserving ownership,
CAS and transaction boundaries. Only the current refresh attempt is retained;
there is no general audit/event history or automatic secret-retirement job.

`Open` is for authoritative current state. `OpenReadOnly` performs no migration or
initialization. `OpenRestored` explicitly blocks potentially stale credentials
and imposes conservative quota backoff while preserving disabled state. No local
SQLite file can prove that it is not an old copy; backup provenance and external
key/vault rollback authority remain operational requirements. See
[recovery and deployment boundaries](OPERATIONS.md).

### Protected credentials

`credentials.CompleteBundle` carries the complete validated read-only pair.
Generic JSON, formatting and structured logs redact it. Narrow export methods
exist only for immediate encryption, a fenced OAuth refresh and the fixed YNAB
read adapter. Go cannot guarantee erasure of copied strings.

The encryption adapter takes an injected Tink primitive and immutable ciphertext
backend. Production keys are neither created nor stored by this implementation.
The local constructor is for local Tink AEAD only. Remote key services use the
context-aware constructor and explicitly distinguish proven integrity failure
from temporary unavailability; a KMS outage does not silently force reconnect.

The exported memory ciphertext backend is conspicuously named for testing and is
not durable. Integration tests additionally use a test-only fsynced ciphertext
backend in a temporary directory, with keys kept exclusively in memory. Neither
constitutes an approved production vault or key-management design.

### Refresh and consent

Every refresh metadata transition uses a repository operation that checks current
owner policy and connection state **in one transaction**. External OAuth and
secret-store work never runs inside retried SQL transactions. An unresolved
`request_started` exchange is never stolen or replayed. Recovery may adopt an
already persisted candidate; classifying a missing candidate requires exact
stopped-worker evidence, and known live local workers cannot be claimed stopped.

A callback consumes state before exchange and publishes only after complete
protected persistence/readback and an atomic policy/connection comparison. State,
verifiers, codes and authenticated session identifiers are not persisted in
metadata. Pending flows are lost on restart and must begin again. Late or failed
flows may leave unreferenced encrypted generations; no unapproved cleanup deletes
them. The future session/HTTP adapter must enforce trusted principal/session
binding and exact callback origin/path, not accept these from arbitrary clients.

## Verification scope

`make check` runs formatting, vet, all tests, the race detector and package builds.
`make fuzz` exercises MCP arguments, protected bundle decoding, OAuth responses,
JWT parsing and exact money. `make vuln` uses pinned govulncheck. These are
point-in-time engineering checks, not a security certification.

The test suite includes:

- The official SDK client and Streamable HTTP server with signed synthetic access
  tokens, the real read service and memory snapshots
- Fixed YNAB HTTP-route/projection/response-bound tests with mock transports
- SQLite ownership, transaction, CAS, corruption, reopen, quota and restored-state
  contract tests; no external OAuth or secret call inside a SQL transaction
- Concurrent refresh callers, all lifecycle checkpoint failures, lost commit/store
  acknowledgments, disable/reconnect/policy races and stopped-worker recovery
- Real SQLite plus encrypted synthetic ciphertext files for consent, rotation,
  service/store reconstruction, and recovery from persisted refresh phases
- Callback replay, owner/session/path mismatch, expiry, bounds and policy races
- Credential confidentiality, substitution/tampering and key-service outage tests

Persisted-state checkpoint tests model process loss at named boundaries. They do
not claim hardware power-loss guarantees, a real cloud vault/key-service restart,
a live issuer/YNAB connection, or actual OpenAI client interoperability. No CI
workflow is created or enabled. No live credentials or account grants are used.

## Conservative behavior retained

- Single owner only; no billing, multi-user hosting, financial mutations, arbitrary
  URL/method tool, bulk export or MCP administration endpoint.
- Fresh full bounded fetches only; no automatic GET retry, refresh-on-401 retry,
  stale cache mode or delta sync. Proactive expiry-based refresh is implemented;
  an upstream 401 returns reconnect guidance without replaying a financial GET.
- Explicit inclusive transaction date bounds, at most 366 days; pending recorded
  transactions excluded; scheduled results describe the next upstream occurrence.
- Inbound verifier accepts signed `at+jwt` / `application/at+jwt` profiles only.
  Generic ID-token `JWT` profiles and opaque tokens fail closed.
- SDK loopback Host heuristics are replaced only inside a constructor enforcing
  explicit host/origin admission. No forwarding header is trusted.
- Financial content is memory-only. A permitted client can still retain or share
  returned data; read-only is not a confidentiality guarantee.

## Remaining release gates

1. Review the candidate backend, choose the repository license, issuer/client
   registration, host, durable volume, protected secret backend and external key
   authority. Approve their security/backup/retention/cost boundaries.
2. Implement the selected provider/session/key/backend adapters and the production
   startup/restore/recovery composition. Verify the actual authenticated callback
   flow before exposing a listener; independently establish worker termination.
3. Separately approve account setup, credentials and deployment. Start with
   synthetic host results, then consent to explicitly named budgets.
4. Complete operational acceptance: live discovery/PKCE, wrong-identity denial,
   quota behavior, redacted operations, revocation/reconnect, restore and retention.

There is intentionally no production serving command that guesses these choices.
