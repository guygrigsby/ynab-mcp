# Initial implementation and release gates

This document describes the implementation branch, not a deployed connector. The
[design](DESIGN.md) is the target architecture. The historical design document's
“documentation only” status refers to that earlier delivery; it has not been
rewritten to imply operational acceptance.

## Delivered boundary

The dependency direction is adapters → application → domain. `internal/bootstrap`
composes an HTTP handler from supplied ports. There is deliberately no production
`main`, permissive demo server, sample bearer token, in-memory production quota
fallback, secret-store selection or live account bootstrap script.

| Area | Implemented | Remaining before live use |
| --- | --- | --- |
| Access policy | Exact issuer/subject/tenant tuple, one owned connection, explicit concrete budget IDs, immutable versioned grants, authorization before reads and after upstream/snapshot work | Durable administrative transactions and approved owner/budget configuration |
| Financial values | Typed IDs, integer milliunits and exact decimal/string JSON, checked arithmetic, calendar dates, split/transfer references, distinct scheduled/recorded models, null/absent/redacted text | Contract review against approved account settings and any additional target fields |
| Inquiry | Eight typed query families, strict tool argument keys/types, bounded queue/concurrency, identical in-flight read coalescing, filtered budget list | Operational load measurements; no stale-data mode or persistent response cache |
| Snapshots | Memory-only immutable pages, exact scope/query/limit binding, hashed cursor lookup, deterministic replay, absolute ≤5-minute TTL, byte/count bounds, eviction/restart invalidation | Optional periodic expired-object cleanup; correctness never depends on cleanup timing |
| MCP | Official SDK, stateless Streamable HTTP, eight read-only tools, bounded structured results, generic sanitized errors | Actual target-host protocol/auth interoperability acceptance |
| Inbound auth | JOSE access-token signatures, pinned algorithms/issuer/audience, expiry/nbf/scope, explicit access-token type, static keys or bounded pinned HTTPS JWKS, resource metadata/challenges | Approved mature issuer and client registration; no authorization server or dynamic registration implementation |
| HTTP | Exact host/origin allowlists, body/deadline/server limits, no trust in forwarded headers, owner check on every MCP method, content-free health route | Approved TLS ingress/listener and network architecture |
| YNAB reads | Fixed `/v1/plans` GET-only destination, DTO allowlist, currency metadata required, separate settings observations disclosed, no redirects, response/decompression limits, cancellation, 429 cooldown port | Durable token and quota adapters, live schema/account acceptance |
| YNAB OAuth | Separate fixed-host exchange adapter using maintained OAuth library; S256, read-only scope, one-attempt exchanges, bounded response validation, opaque/redacted in-memory credentials | Owner-bound expiring single-use state/callback service, protected complete-bundle persistence/readback/reload, durable refresh coordinator |
| Connection lifecycle | Pure version/fence transitions for prepared, request-started, secret-saved, committed and ambiguous recovery; disables/reconnects invalidate stale candidates | Repository implementation and crash-injection tests at real storage/network boundaries |
| Upstream admission | Pure rolling-window model, 180/hour headroom, persisted-reservation contract, cooldown, rollback protection and full-window missing-ledger backoff | Selected durable repository and atomic concurrency/restart tests |

## Important deliberate limitations

- Single owner only. No subscriptions, tenant database, multi-user hosting, billing,
  write tools, deployment, tunnel enrollment, provider configuration or live grants.
- SQLite and Firestore remain choices, not implemented adapters. Passing a
  process-local test repository to the composition API is **not** permission to
  use it for production quota or credentials.
- No fully wired live OAuth flow. The OAuth package intentionally does not export
  refresh-token serialization or restore a complete persisted bundle. An approved
  secret-store integration must be designed before that boundary is opened.
- The caller of OAuth exchange must consume owner-bound single-use state and the
  correct PKCE verifier. The caller of refresh must persist/fence the unresolved
  attempt first. An ambiguous outcome requires reconnect; do not replay an old
  credential object. Returned credentials do not themselves prove durable commit.
- No automatic YNAB GET retry, 401 refresh, full response reuse or delta sync. Each
  requested fresh read does a full bounded fetch; settings and financial data may
  require two separately reserved GETs. This conservative foundation favors an
  explicit error over replay or fabricated completeness.
- Transaction dates are explicit inclusive bounds, limited to 366 days. Recorded
  transaction results exclude pending items. Scheduled results describe the
  upstream next occurrence, not every future recurrence.
- All financial content remains in memory. A public response is still sensitive:
  read-only controls do not prevent a permitted client from retaining/disclosing it.
- Unknown issuer token profiles fail closed. The initial verifier accepts signed
  `at+jwt` / `application/at+jwt` access tokens only; it rejects generic ID-token
  `JWT` profiles and opaque tokens. Provider interoperability is a release gate.
- SDK loopback-only Host heuristics are replaced only inside a constructor that
  requires explicit host/origin admission. This supports a separately approved
  reverse proxy without allowing arbitrary Host headers or trusting forwarding
  headers. The raw `NewServer` protocol object is not a secure HTTP composition.

## Verification scope

Every automated test uses synthetic data and generated keys. Unit/contract tests
cover domain money/date/identity invariants, unknown arguments/write dispatch,
zero-upstream denial, revoked in-flight reads, cursor isolation and bounds,
fixed GET routes/projections, OAuth failure behavior, signed-token denial cases,
JWKS rotation/outage, HTTP admission and quota/refresh pure transitions.

The integration test uses the real official SDK client and Streamable HTTP server,
real signed synthetic access tokens, the real application service and memory
snapshot store, and a synthetic inquiry gateway. YNAB HTTP mapping is tested
separately with a mock transport; no test here claims a real issuer/YNAB account or
OpenAI client connection worked.

Run `make check`, `make fuzz`, and `make vuln`. Vulnerability findings are a point-in-
time result, not a security guarantee. Dependencies are pinned in `go.mod`/`go.sum`.
No CI workflow is created or enabled in this branch. No durable-backend contract,
real storage crash/recovery, production load or live end-to-end acceptance is
claimed by a green unit/integration suite.

## Next implementation gates

1. Review this draft, select license, and choose the durable metadata/secret-store
   boundary and an issuer with a compatible access-token profile.
2. Implement one durable backend and its repository contracts. Wire complete
   credential persistence/readback and coordinated refresh; inject crashes around
   every request-started/secret-saved/commit boundary. Test quota accounting across
   retries, crashes, token rotation, restore and concurrent callers.
3. Implement the owner authorization callback/state service and explicit production
   composition root, keeping all administrative/credential routes off MCP.
4. Separately approve account setup, credentials and deployment. Verify actual host
   discovery/PKCE/client registration first with synthetic results, then named
   budget consent, redacted operations, revoke/reconnect and restart acceptance.

These gates are intentionally visible so that a passing development suite is not
mistaken for a safe-to-deploy financial connector.
