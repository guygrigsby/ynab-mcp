# Budget MCP for YNAB design

Status: proposed design, not implemented or deployed. Reviewed against official documentation on 13 October 2026.

## Recommendation

Build an original, small Go MCP resource server for one owner. Expose a deliberately limited read-only interface, protect every financial-data request with OAuth access-token validation and an exact owner allowlist, and separately obtain a read-only YNAB authorization. Start with a public authenticated HTTPS endpoint only after deployment approval, or a secure MCP tunnel whose availability and identity behavior have been verified. Keep tsnet as an optional transport adapter.

The source repository is `ynab-mcp`; use **Budget MCP for YNAB** as the application display name. Public application and domain branding must be checked against YNAB requirements before release. This document does not determine how those requirements apply to a repository slug.

This delivery is repository documentation only. Implementation, live account connections, credentials, infrastructure changes, CI activation, and deployment are separate work. No third-party connector code is copied.

## Current upstream facts that affect the design

YNAB now documents `/plans` as its primary API path. Its March 2026 change retained `/budgets` compatibility, including the old response keys. Transaction lists default to one year of history unless `since_date` is supplied; `until_date` is available. OAuth authorization-code flow supports refresh tokens, S256 PKCE, and `read-only` scope. Personal tokens are simpler but do not expire automatically. The quota is 200 requests per rolling hour per token. Amounts include integer milliunits, with 1,000 per currency unit. Delta-capable collections return `server_knowledge` and accept `last_knowledge_of_server`. Public application/domain naming has specific branding restrictions. [YNAB documentation and changelog](https://api.ynab.com/)

The current OpenAPI description has date and delta filters for transactions but no page-number or upstream cursor parameter. Account, category, month, transaction and scheduled-transaction GET routes are available. Transaction listings exclude pending transactions. [Official endpoint specification](https://api.ynab.com/papi/open_api_spec.yaml)

All remaining limits and architecture choices below are proposed project policy, not claimed upstream guarantees.

## Scope and non-goals

The first useful version answers: which allowed budgets exist, account balances, category balances and targets, a monthly budget summary, matching transactions, and scheduled transactions. It does not move money, change categories, approve transactions, import bank transactions, edit budgets, or provide generic API access. There is no tool that accepts a URL, HTTP method, SQL, shell command, or arbitrary headers.

Multiple budgets belonging to the same approved owner are supported through an explicit ID allowlist. Multi-user hosting, shared budgets across identities, background financial analysis, webhook delivery, dashboards, write tools, and bulk export are out of scope.

## Components and trust boundaries

1. The OpenAI host connects over Streamable HTTP to `/mcp`.
2. Authentication middleware verifies the MCP access token and derives an immutable principal from issuer and subject, with tenant validation where applicable.
3. Policy middleware resolves that principal to one configured YNAB connection and a set of allowed budget IDs.
4. Typed MCP handlers validate inputs and invoke a narrow read service.
5. The read service handles bounded caching, filtering, paging and freshness.
6. A YNAB adapter makes fixed-destination GET requests with a different access token. A separate credential component owns upstream OAuth exchanges and refresh.

Use the [official Go MCP SDK](https://github.com/modelcontextprotocol/go-sdk) for protocol framing, schemas and Streamable HTTP. Its published packages include OAuth primitives and protected-resource metadata support; these do not eliminate the need for token validation or an issuer. Pin reviewed stable dependencies at implementation time and test the protocol versions actually negotiated by the target OpenAI client.

Suggested layout, to create only in the implementation phase:

```text
cmd/budget-mcp/          process wiring and configuration
internal/mcpserver/     tools, typed schemas and dispatch
internal/auth/          resource-server token validation and principal
internal/policy/        owner, tenant and budget authorization
internal/ynab/          GET-only resource client and upstream credentials
internal/cache/         snapshots, delta merge and cursor store
internal/transport/     ordinary HTTPS listener; optional tsnet adapter
internal/observability/ metadata-only logging and metrics
test/integration/      mock issuer, mock YNAB and real MCP client tests
testdata/               synthetic fixtures only
docs/                  design, threat model and eventual runbooks
```

## Two independent authorization systems

### OpenAI host to MCP server

Use a mature authorization server, preferably an existing approved issuer or a managed provider with documented MCP support. Do not implement an authorization server in this repository. Provider choice is a release-blocking interoperability decision, not an assumption that any OIDC product automatically works.

Required compatibility: protected-resource metadata and 401 discovery challenge; issuer metadata; authorization code with S256 PKCE; exact redirect registration; resource indicators tied to access-token audience; a supported client registration mechanism; and scope enforcement. Copy the actual callback shown by the target connection UI. Current OpenAI guidance also describes RFC 9207 issuer identification and supports CIMD, DCR or predefined clients. [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth)

For this single-user service, prefer a predefined client where the target UI supports it. Otherwise use the issuer's supported CIMD/DCR implementation with restrictive registration and consent policies. Never enable unrestricted registration merely to make a demo connect. Verify discovery and token exchange with the real host before proceeding beyond synthetic data.

The MCP resource identifier is one configured canonical HTTPS URL. Never derive issuer, resource, callback, or JWKS URLs from an untrusted Host header, tool input, or token claim. Require an access token minted for that resource and scope `budget:read`. Validate algorithm, signature, issuer, audience, expiry and not-before, then owner and tenant membership. An ID token is not an API access token. Reject opaque tokens unless the chosen provider supplies a supported, authenticated introspection path that is explicitly implemented.

Use the provider's maintained Go access-token verifier when available; otherwise a reviewed JOSE implementation such as [go-jose](https://github.com/go-jose/go-jose), with bounded JWKS caching and explicit application policy. Never implement cryptographic verification manually. Pin algorithms, reject unknown keys after one bounded refresh, and fail closed when no usable trusted key exists. Do not choose `go-oidc`'s ID-token verifier merely because the access token resembles a JWT.

Authenticate every MCP HTTP request, including initialization and tool discovery. A protocol session ID is not authorization. Prefer stateless request handling for v1; if sessions are required, bind them to the validated principal and expire them. Return standard invalid-token challenges for authentication failures and insufficient-scope responses where applicable. Do not reveal whether another user's budget exists.

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) is the protocol baseline. Actual target-client interoperability remains an acceptance test.

### MCP server to YNAB

Preferred production choice: a separately registered YNAB OAuth application with read-only consent. Use a maintained OAuth client library such as [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2), plus tested provider-specific configuration and durable credential handling. The owner completes the authorization flow outside MCP tools. Store client secret and refresh/access tokens in a secret store; never in git, tool arguments, chat, logs, or test fixtures.

Require random, expiring, single-use state bound to the initiating owner session, exact callback checks and PKCE. Validate token response shape and expiry, request only the read-only scope, and reject an unexpected broader scope if the provider returns one. Do not use a live mutation attempt to probe scope. Refresh under a per-connection lock, save replacement credentials atomically, and never let concurrent requests race old refresh tokens. A failed or revoked refresh disables upstream access and asks the owner to reconnect; it never silently changes auth mode.

This has more setup than a personal token: application registration, callback configuration, a secret store and refresh persistence are required. A personal token may be an explicitly approved development fallback, but upstream write prevention would then depend more heavily on this application's controls. It is not the recommended production security posture.

MCP access tokens are never sent to YNAB, and YNAB tokens are never sent to the OpenAI host. The mapping between owner principal and upstream connection is configured administratively, not supplied by the model. This avoids token passthrough and limits confused-deputy exposure. [MCP security guidance](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

## Small tool interface

Use stable user-facing `budget_id` terminology while mapping it to upstream `plan_id`. Do not duplicate every tool under both names. All tools require `budget:read`; set read-only and non-destructive annotations, but enforce policy in code.

| Tool | Inputs | Result |
| --- | --- | --- |
| `list_budgets` | none | Allowed budget IDs, names and currency metadata only |
| `get_budget` | budget ID | Small summary and settings, not an unbounded nested dump |
| `list_accounts` | budget ID, optional account ID, include-closed flag | Account balances and types |
| `list_categories` | budget ID, optional category ID and month | Category groups, balances and targets |
| `get_month` | budget ID, explicit month | Monthly summary and bounded category data |
| `list_transactions` | budget ID, explicit date bounds, optional account/category ID and status, cursor, limit | Bounded transaction page |
| `get_transaction` | budget ID, transaction ID | One transaction with requested split details |
| `list_scheduled_transactions` | budget ID, optional date/account filters, cursor, limit | Bounded scheduled-item page |

Common list inputs include bounded `limit` and an opaque `cursor` where results can exceed one page; note-bearing tools accept `include_notes`, defaulting to false. Enforce strict schemas and reject unknown arguments. Every child ID is interpreted within the allowed budget. Disallow `default` and `last-used` aliases at the MCP boundary: callers must choose a concrete ID from the filtered list. Fail startup if the owner or budget allowlist is empty.

Use integer `int64` milliunits internally with checked arithmetic. Return money as an exact decimal string plus currency code and milliunits encoded as a decimal string to avoid JavaScript precision loss. Never sum unrelated currencies. Include date boundaries, source timestamp, freshness and coverage with results. Preserve nulls, transfer relationships and split structure. Avoid double-counting a split parent and its children or counting both sides of an internal transfer as spending. These are tested semantics, not LLM instructions to improvise totals.

Proposed defaults: list limit 50, maximum 200 items; transaction date window at most 366 days per call; memo/note text excluded unless explicitly requested. Distinguish posted transactions, uncleared transactions and scheduled items. State the pending-transaction coverage limitation in tool metadata and transaction results.

## Upstream routing and compatibility

Use fixed `https://api.ynab.com/v1/plans` routes and typed `plans`/`plan` response models. Do not silently retry failures against legacy routes. If migration support is ever needed, add a separately selected adapter tested with legacy `budgets`/`budget` response keys. The same ID allowlist applies to either adapter. New code should not depend on undocumented legacy paths.

The YNAB data client permits GET only. OAuth POST requests belong to a separate, fixed-host credential client. A transport guard rejects all data-client methods other than GET and all unexpected hosts or redirects, even if a programming error reaches the HTTP layer. Production cannot override the YNAB base URL through tool arguments; mock endpoints are injected only by tests.

## Bounded data and consistent pagination

Pagination is a connector feature, not invented upstream pagination. Fetch the narrowest supported upstream collection, construct a bounded immutable snapshot, then return opaque short-lived cursors. Bind each cursor to owner, budget, filters, sort order, snapshot ID and expiry; use unpredictable server-side handles. Validate authorization again on every page. Reject expired or mismatched cursors rather than restarting silently and producing duplicates.

A cursor pages cached data without another upstream request. Sort transactions deterministically by date and ID. Proposed snapshot TTL is five minutes. Return `next_cursor`, `as_of` and whether the result covers the requested interval completely. Oversized upstream responses produce a clear request-to-narrow error, never an apparently complete truncated list. Date windows can be split internally within a bounded request budget; if a single-day result is still too large, fail explicitly.

Start with an in-memory cache and no financial-data persistence. Only credentials and non-content rate-limit accounting require protected persistence. Suggested safety limits: 64 KiB request bodies, 8 MiB decompressed upstream responses, 256 KiB tool responses, 32 MiB total cached financial data and a 15-second request deadline. Tune from synthetic load tests before release.

Cache identity includes owner/connection, budget, endpoint and normalized filters. Delta knowledge belongs to precisely that collection. Merge updates and tombstones by entity ID, then atomically commit the new data and knowledge. Never interpret a delta response as a full listing. Do not advance knowledge after decode or merge failure. Avoid delta sync on filtered transaction windows in v1: moved dates/categories could make records disappear from the filter without a useful tombstone. Use full bounded fetches there; introduce delta only for complete collections with deletion and filter-transition tests.

## Quotas and failure handling

Use one upstream request coordinator per credential, coalesce identical in-flight reads, limit upstream concurrency to two, and cap retries to two within the request deadline. Maintain a rolling-window ledger with headroom, initially targeting at most 180 calls/hour. Persist its non-content accounting or use conservative restart backoff so process restarts cannot reset the local quota. A separately used token can consume quota outside this process, so treat upstream 429 responses as authoritative. Do not claim an exact remaining quota from local counts.

Retry only safe GETs on transient network failures or selected 5xx responses with jitter. Honor a valid Retry-After when present. Without one, a 429 opens a conservative cooldown; return retry guidance instead of spinning or sleeping a tool call for an hour. Authentication failures get at most one coordinated credential refresh, then a clear reconnect error. Never retry permission failures as though they were outages.

Cached results must declare their age. Default to fresh-or-error; optionally permit explicitly requested stale data with a visible warning. Cancellation must propagate to upstream calls. Bound queue length, rate-limit rejected traffic separately, and keep metadata discovery cheap so unauthenticated traffic cannot exhaust financial API quota.

## Network deployment choices

**Public authenticated HTTPS:** simplest interoperable first deployment, subject to approval. Put the Go listener on loopback behind a configured TLS proxy, or use a managed ingress with a private backend. Validate allowed hosts and browser origins, trust forwarding headers only from the actual proxy, and preserve OAuth challenges. Reject unexpected Origin headers; allow legitimate non-browser requests without one. Expose minimal health status only, with no financial or configuration details. No public pprof, metrics payloads or administrative credential endpoints.

**Private tsnet:** optional listener implementation with dedicated state and a narrowly granted service identity. Tailscale documents embedding a tailnet node in a Go application using tsnet. [Tailscale tsnet documentation](https://tailscale.com/docs/features/tsnet) This does not make an OpenAI-hosted client a member of a tailnet. Verify end-to-end client reachability before selecting private-only transport. Keep OAuth protection even on the private listener.

**Secure MCP tunnel:** consider only after confirming availability for this account and target client, how it binds to the server, identity preservation, connection lifetime and failure behavior. It is not assumed available. Tailscale Funnel, if later selected, is public exposure and still requires application authorization. No tunnel or tailnet enrollment is created by this design.

## Threat model

| Threat | Required control | Residual risk |
| --- | --- | --- |
| Wrong caller or tenant | Exact issuer/subject and tenant allowlists; scope and audience checks | Compromised approved account can read allowed data |
| Cross-budget access | Concrete ID allowlist checked before upstream request and cache access | Owner can intentionally authorize too much |
| Stolen bearer token | TLS, short-lived issuer tokens, log redaction, revocation/runbook | Bearer possession remains usable until expiry or denial |
| Prompt injection in payee, memo or category | Treat all text as untrusted data; no link fetching or execution; omit notes by default | A model receiving data can still be influenced |
| Financial exfiltration | No arbitrary outbound URLs, uploads, messaging or export tools; bounded results | Host can access and retain authorized tool results |
| SSRF/token theft | Fixed egress destinations, no cross-host redirects, pinned issuer config | Host or issuer compromise remains serious |
| Write-path exposure | No write tools, strict dispatch allowlist, GET guard and upstream read-only scope | Credential-store compromise can bypass this process |
| Resource exhaustion | Bounds, deadlines, coalescing, quotas, cache eviction and auth-first handling | Availability is not guaranteed during provider outages |
| Secret leakage | Secret store; synthetic fixtures; metadata-only logs and sanitized errors | Debugging outside these controls can leak data |

Read-only is not a confidentiality guarantee. Once balances or transactions are returned to dot, this connector cannot control every other tool the host might use. Host-side permission checks and explicit owner consent for the allowed financial data are part of the security boundary. Do not advertise prompt-injection immunity.

Log only request ID, tool name, status class, latency and coarse counters. Exclude bearer tokens, OAuth codes, refresh tokens, financial amounts, names, memos, raw arguments/results and upstream error bodies. Protect access logs too: OAuth query strings and authorization headers must be redacted. Disable public metrics labels containing owner or budget identifiers.

## Test and CI plan

All automated tests use synthetic data. A live financial account is never required in pull-request CI.

1. **Unit tests:** strict schemas; ID/date validation; negative amounts and overflow; currencies; nulls; split/transfer accounting; exact decimal output; limits; error normalization; allowlist policy; log redaction.
2. **YNAB contract tests:** mock all eight tool paths, response wrappers, pending coverage, date boundaries, malformed JSON, huge/decompressed responses, redirects, 401/403/404/429/5xx and cancellation. Pin a reviewed OpenAPI fixture/hash and detect schema drift without generating write handlers.
3. **Authentication tests:** missing/invalid/expired/not-yet-valid tokens; wrong signature, algorithm, issuer, audience, scope, subject or tenant; ID-token confusion; unknown key; key rotation; issuer/JWKS outage; malformed discovery; authentication on every MCP route.
4. **Authorization tests:** list filtering, guessed budget IDs, nested-resource mismatches, absent configuration, stale sessions, cursor cross-owner/cross-budget reuse and altered filters. Assert denied calls make zero YNAB requests.
5. **Read-only tests:** snapshot tool inventory; invoke guessed write/import/delete names and aliases; direct dispatcher rejection; prove the data transport cannot emit POST, PATCH, PUT or DELETE. OAuth POST exceptions are confined to fixed credential endpoints.
6. **State and concurrency tests:** full snapshot then delta/tombstones; atomic knowledge commits; expired cursors; stable pages during upstream changes; cache isolation and eviction; coalesced requests; simultaneous refresh; failed credential persistence; fake-clock quota windows and bounded retry storms. Run the Go race detector.
7. **Protocol integration:** real SDK client against an in-process Streamable HTTP server, mock issuer and mock YNAB. Exercise discovery, initialize, tools/list, tools/call, errors, reconnect, session behavior and authentication challenges end to end.
8. **Security regression fixtures:** injection-like memos, long Unicode strings, fake URLs and control characters remain inert data; no extra outbound traffic; no secret appears in logs or errors.

Proposed PR checks after approval: formatting, `go vet`, unit/integration tests, race tests, targeted fuzz smoke tests, dependency vulnerability checks with `govulncheck`, secret scanning and build on supported Go releases. Pin action revisions, grant read-only workflow permissions, and never expose secrets to untrusted forks. CI should not deploy. Future releases need reviewed dependency pins, an SBOM, reproducible artifact checks and a separate approved release process.

## Delivery phases and gates

**Phase 0, this delivery:** design and README only. Confirm issuer preference, network path, upstream credential approach and allowed budgets before implementation.

**Phase 1, protocol skeleton:** approved Go implementation against synthetic mocks; strict configuration, auth middleware and denied-write tests first. Exit when unauthorized requests and guessed write tools demonstrably fail without upstream calls.

**Phase 2, data adapter:** read handlers, bounded snapshots, money semantics, upstream OAuth and quota behavior. Exit when the full mock test suite and race checks pass. No deployment is implied.

**Phase 3, consent and connectivity:** separately approve issuer/client setup, secure credential entry and endpoint deployment. Test the actual OpenAI authorization flow first with synthetic results, then authorize the named budgets. Exit when real host access works and unauthenticated/wrong-identity access fails.

**Phase 4, operational acceptance:** verify redacted logs, revocation, reconnect, restart behavior, bounded cache and owner-visible freshness. Optional tsnet or tunnel work follows only if useful and authorized.

## Decisions still needed

- Which mature issuer is already trusted, and does it pass the target OpenAI client's resource/PKCE/registration tests? Recommendation: reuse a suitable issuer; otherwise evaluate a managed MCP-aware provider before building hosting around it.
- Which approved endpoint can dot actually reach? Recommendation: authenticated public HTTPS unless a supported secure tunnel is verified; tsnet alone is insufficient evidence of reachability.
- Is the extra upstream OAuth setup acceptable? Recommendation: yes, for enforced read-only access and refresh; keep personal-token use an explicit fallback.
- Which budget IDs and financial fields may be disclosed to dot? Recommendation: start with one named budget and notes disabled.
- Where will protected credential persistence live? Recommendation: the existing approved secret store; choose this before live OAuth.
- What repository license should apply? Select an explicit license before inviting reuse; this original design does not inherit another connector's license.

Completion means a tested, narrowly authorized read connector with verified host interoperability. A repository, a listening port, or a successful unauthenticated tool call alone does not meet that bar.
