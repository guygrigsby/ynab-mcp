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

## Domain model and ubiquitous language

The domain is **safe, bounded access to an owner's financial information**, not a replacement budgeting engine. YNAB owns the financial record and all financial mutations. This connector owns access policy, upstream-connection lifecycle, request admission and the consistency of each disclosed read. Domain-driven design here means explicit language, invariants and ownership boundaries in one small process; it does not require microservices, event sourcing, an event bus or a general CQRS framework.

| Term | Meaning in this connector |
| --- | --- |
| Owner | The one administratively approved person, identified by an exact authenticated issuer/subject/tenant tuple, never by an email or display name |
| Principal | A verified caller identity plus token scope; a request value, not a stored bearer token |
| Access grant | The owner's configured connection, explicit budget allowlist, field-disclosure policy and monotonically increasing policy version |
| Connection | One administrative link to a YNAB authorization, with lifecycle state and a versioned credential reference; it is not an MCP session |
| Budget / plan | The same upstream financial container: `BudgetID` in our public language maps to YNAB `plan_id`; names and aliases are not identity |
| Account | A YNAB account inside one budget, with upstream balances and account type; the connector cannot debit or reconcile it |
| Category group / category | Upstream grouping and spending-allocation identities; a category's monthly monetary state is separate from its identity |
| Month | A budget-scoped calendar month; category activity/assignment/available amounts must identify the month or current-view semantics |
| Recorded transaction | A transaction returned by the transaction API, with separate cleared and approved flags; this does not prove bank settlement |
| Scheduled transaction | A future/recurring instruction returned by YNAB, not a posted expense or a prediction of every future occurrence |
| Split / transfer | A parent's allocation children / upstream links between account movements; neither is inferred from text |
| Snapshot | An immutable, bounded connector-owned read result for one exact authorized query, with freshness and coverage metadata |
| Cursor | An opaque handle to a position in that snapshot, not an upstream page token or authorization credential |
| Collection knowledge | YNAB's delta checkpoint for one exact collection; not a timestamp, global revision, or pagination cursor |
| Quota reservation | A conservative durable count made before an upstream GET attempt; retries also consume reservations |

### Bounded contexts and context map

These are **logical modules**, not independently deployed services or databases.

| Context | Owns | Does not own |
| --- | --- | --- |
| Access policy | `OwnerAccessGrant`, principal matching, allowed budget scope and disclosure rules | Issuing MCP tokens; financial data |
| Connection lifecycle | `YNABConnection`, credential generations, refresh/reconnect state and secret references | MCP identity; YNAB financial mutations |
| Budget inquiry | Financial read-model types, money/date semantics, `ReadSnapshot`, coverage and deterministic paging | Authoritative balances, transaction edits, goal calculations or a local ledger |
| Upstream admission | `QuotaWindow`, reservations, cooldown and bounded concurrency policy | Financial payloads or an exact claim about quota consumed elsewhere |
| External identity provider | MCP authorization and access-token issuance | Budget allowlists and YNAB credentials |
| External YNAB | Authoritative budgets, accounts, categories, transactions and OAuth token exchange | This connector's disclosure policy and MCP contract |

```text
OpenAI host -> MCP adapter -> inquiry application services
                    |                |
           verified Principal -> Access policy -> authorized ReadScope
                                     |
                  Budget inquiry ----+----> Upstream admission
                         |                         |
                    YNAB read port <---- admitted GET attempt
                         |
                YNAB anti-corruption adapter -> external YNAB API
                         |
                  Connection lifecycle -> secret store + YNAB OAuth

External issuer -> token-verification adapter -> verified Principal
```

YNAB is an upstream supplier. The anti-corruption layer translates upstream `plan`, nullable DTO fields, delta tombstones and money formats into our read language; it does not leak arbitrary upstream routes into tool handlers. The identity provider is a separate supplier whose verified identity is consumed by access policy. MCP is the published external read contract. Budget inquiry consumes only an authorized `ReadScope`; authorization is checked again before returning a page. Shared types are deliberately small (typed IDs, time, money and error codes), with no shared mutable “budget” object across contexts.

### Aggregates, roots and invariants

An aggregate is a local consistency boundary. The first three durable roots below have repository operations; the snapshot is ephemeral. Domain methods return state changes or errors, while application services perform I/O and persist with expected versions.

| Root | Owned state / child entities | Required invariant and lifecycle |
| --- | --- | --- |
| `OwnerAccessGrant` (`OwnerID`) | Exact principal key, one connection ID, budget-ID set, field policy, enabled flag, policy version | Enabled grant has a nonempty explicit allowlist and exactly one owned connection. No aliases or name-based identity. A policy edit atomically replaces the grant and increments its version. Disabled owners disclose nothing, including cached data. |
| `YNABConnection` (`ConnectionID`) | Auth mode, status, credential generation/ref, requested scope, refresh attempt and fencing version | Only `active` permits reads. Production OAuth scope policy is read-only. A generation is adopted only after its complete access/refresh pair is durably stored and its expected-version commit succeeds. One refresh may be unresolved at a time. States are `unconnected`, `active`, `refreshing`, `reconnect_required`, `disabled`; reconnect starts a new authorization lineage and invalidates cached reads. |
| `QuotaWindow` (`QuotaKey`) | Rolling attempt reservations and cooldown | Atomically admit only within the configured rolling budget, preserving headroom. Every retry reserves independently before send. Rotation/restart must not reset local accounting. Cooldown is checked at admission; a missing or corrupt ledger fails closed or imposes conservative restart backoff. |
| `ReadSnapshot` (`SnapshotID`) | Exact read scope/query, immutable ordered items, observation interval, coverage, expiry and page positions | No partial fetch is published as complete. Owner, connection lineage, policy version, budget, projection and filters cannot change after publication. A page neither mutates items nor extends expiry. Expired, evicted, unauthorized or mismatched cursors fail explicitly. |

`CredentialGeneration` and `RefreshAttempt` are connection-owned entities, not independent aggregate roots. `QuotaReservation` is a quota-owned entity. A cursor is a lookup value/handle into a snapshot, not another financial aggregate. Budget, account, category, transaction and scheduled-transaction identities are **upstream entities projected as immutable read models**. They are not locally saved financial aggregates: there is no `BudgetRepository.Save`, `Transaction.Post`, `Account.Debit`, or aggregate that loads an entire budget to answer one request.

Cross-aggregate consistency is intentionally limited. The administration repository atomically establishes owner/connection ownership and updates grants. An inquiry reads a consistent grant version, performs remote work outside database transactions, then revalidates enabled status, connection lineage and policy version before disclosure. A concurrent revocation invalidates the result and cursors. No local transaction can make YNAB calls or multiple upstream reads an atomic financial snapshot.

### Value objects and validation

- `PrincipalKey{issuer, subject, tenant}` uses exact configured issuer and subject matching. Represent “no tenant” explicitly, not as an unchecked wildcard; its storage sentinel cannot collide with a real tenant value.
- Distinct `OwnerID`, `ConnectionID`, `BudgetID`, `AccountID`, `CategoryGroupID`, `CategoryID`, `TransactionID`, `SubTransactionID`, `ScheduledTransactionID` and `PayeeID` types prevent accidental interchange. Validate against the reviewed upstream ID contract; never assume every resource ID is a UUID. All financial references carry `BudgetID`, even if YNAB currently issues globally unique IDs.
- `Money{milliunits int64, currency CurrencyCode}` uses checked signed arithmetic, with no float conversions. The exact decimal is derived from milliunits (e.g. `-12345` becomes `"-12.345"`); display precision is separate. Reject cross-currency addition and overflow, including negating the minimum int64. Upstream formatted strings are display data, never arithmetic inputs.
- `CurrencyFormat{isoCode, decimalDigits, symbol, separators, symbolFirst, displaySymbol}` comes from the budget's settings. An unresolved currency cannot silently become USD. Return an explicit currency-metadata error rather than fabricate currency-labeled money. A settings change invalidates affected projections.
- `LocalDate` is a validated `YYYY-MM-DD` calendar date, not a UTC-midnight instant shifted to the caller's time zone. `BudgetMonth` is canonical `YYYY-MM-01`. `DateRange{from,to}` is inclusive and ordered, with the 366-day call bound. Cache deadlines and `observed_at` are UTC instants.
- `ReadScope{owner, connection, authorizationLineage, policyVersion, budget}` is constructed only after authorization. `NormalizedQuery` additionally contains endpoint family, date/month bounds, account/category/status filters, include-closed, note projection, freshness mode, sort and schema version as applicable.
- `CredentialRef{provider, location, immutableVersion}` points to an encrypted secret bundle and never contains a token. `CredentialGeneration` is local versioning; it is unrelated to YNAB `server_knowledge`.
- `Coverage`, `Freshness`, `CollectionKey`, `ServerKnowledge` and `CursorHandle` are distinct types. Unknown enum values are preserved as explicitly unknown/unrecognized where safe; malformed required identity or money fields fail decoding. Absent, null, zero and redacted are not interchangeable.

## Financial read models and relationships

These logical schemas describe typed in-memory projections, not SQL tables or a durable copy of the owner's financial history. The adapter maps allowlisted upstream fields explicitly. Extra upstream fields are not automatically exposed. Import identifiers and original bank-statement payee text are omitted unless a future disclosure contract explicitly includes them.

| Read model / identity | Fields required for the proposed tools | Relationships and semantics |
| --- | --- | --- |
| `BudgetView(BudgetID)` | Name, currency/date formatting, upstream last-modified value when supplied | Contains account/category-group/month identities; not an eager graph of every transaction |
| `AccountView(BudgetID, AccountID)` | Name, account type, `on_budget`, `closed`, balance, cleared balance, uncleared balance; optional note | Balances are supplied by YNAB, not reconstructed from the bounded transaction query. Account type is not inferred from the sign. |
| `CategoryGroupView(BudgetID, GroupID)` | Name, hidden/deleted state where supplied | One group has many categories. Names can change and are not keys. |
| `CategoryView(BudgetID, CategoryID)` | Group ID, name, hidden/internal/deleted state and optional note | Static identity is separate from month-specific monetary state. A group may be absent from a narrow projection without the reference being invalid. |
| `CategoryMonthView(BudgetID, Month, CategoryID)` | Assigned (`budgeted`), activity, available (`balance`), nullable target/goal type, amount, target date, cadence and progress fields | The same category has different values in different months. Goals/progress are upstream observations, not locally recomputed funding rules. |
| `MonthView(BudgetID, Month)` | Income, assigned, activity, ready-to-assign (`to_be_budgeted`), nullable age-of-money and optional note | Contains bounded category-month projections. Do not claim monthly amounts equal a partial transaction query's totals. |
| `TransactionView(BudgetID, TransactionID)` | Account ID, date, amount, nullable payee/category refs and display names, cleared status, approved flag, transfer refs, split children, optional memo | Account is required. `uncleared`, `cleared`, `reconciled` and approval are separate dimensions. Transfer and matched-transaction references have different meanings. |
| `SplitView(BudgetID, TransactionID, SubTransactionID)` | Parent ID, amount, nullable payee/category, transfer account/transaction refs, optional memo | Children carry allocations; parent carries account/date/status context. Preserve children as children rather than flattening them into unrelated transactions. |
| `ScheduledTransactionView(BudgetID, ScheduledID)` | Account, first/next date, frequency, amount, nullable payee/category, optional transfer-account ref, split children and memo | A separate ID space and type. No cleared/approved or bank-settlement claim; no implicit conversion to a recorded transaction. |
| `ScheduledSplitView(BudgetID, ScheduledID, SplitID)` | Parent scheduled ID, amount, nullable payee/category and transfer-account refs, optional memo | Separate from recorded splits and their transfer-transaction links. |
| `PayeeRef(BudgetID, PayeeID?)` | Nullable ID and observed display name | Reference value only in v1; no additional payee tool or eager payee-table synchronization. |

The shape is grounded in the [official YNAB SDK read models](https://github.com/ynab/ynab-sdk-js/tree/main/src/models), including [transaction details](https://github.com/ynab/ynab-sdk-js/blob/main/src/models/TransactionDetail.ts), [split children](https://github.com/ynab/ynab-sdk-js/blob/main/src/models/SubTransaction.ts), [scheduled transactions](https://github.com/ynab/ynab-sdk-js/blob/main/src/models/ScheduledTransactionDetail.ts), [month details](https://github.com/ynab/ynab-sdk-js/blob/main/src/models/MonthDetail.ts) and [currency settings](https://github.com/ynab/ynab-sdk-js/blob/main/src/models/CurrencyFormat.ts). These are reference schemas, not dependencies or copied connector implementation. Pin the reviewed API specification during implementation.

```text
Budget --< Account --< RecordedTransaction --< RecordedSplit
   |                         |                    |
   +--< CategoryGroup --< Category <--------------+
   |                         |
   +--< BudgetMonth --< CategoryMonth
   |
   +--< ScheduledTransaction --< ScheduledSplit

RecordedTransaction/RecordedSplit --optional transfer ref--> Account + counterpart Transaction
ScheduledTransaction/ScheduledSplit --optional transfer ref--> Account
```

References are scoped to the same budget and are not automatic fetch instructions. A counterpart can be outside a date/account filter or absent from the fetched collection. Mark unresolved links as such; never fabricate the other side or expand a query beyond its bounds to resolve every relationship.

**Split and transfer rules:** account movement uses a split parent's amount once; category allocation uses its nondeleted children instead of adding parent plus children. Validate full split-detail consistency before producing allocation totals; on a mismatch, return an explicit data-consistency error for the derived calculation rather than changing YNAB values. A category filter matches parent category or any child category, returns each parent once, and identifies the matching children. A transfer marker alone does not mean “exclude from every spending calculation”: transfers involving tracking/off-budget accounts or categorized split transfers need their upstream category/account context. V1 returns relationships and upstream monthly totals, not a new generic spending-total tool. Any future derived total must declare its account/category scope, handle internal counterpart pairs once, and test missing counterparts and incomplete splits.

**Monthly category semantics:** when month is supplied, use that month-specific upstream route. Without it, return an explicitly labeled upstream-current category view with its observation time, not a fabricated historical month. A cursor retains that same view even across a month boundary. Scheduled date filtering means filtering `date_next` within the supplied bounds; it does not expand recurrence rules into a forecast. Unsupported filter combinations are rejected or applied locally after a complete bounded fetch, never sent as invented upstream parameters.

### Read-result envelope

Every tool returns typed `data` plus a common metadata envelope:

```text
ReadMetadata {
  budget_id?; snapshot_id?; next_cursor?;
  observed_from; observed_at; expires_at?;
  source_last_modified?; freshness: fresh | stale;
  requested_scope; applied_filters; sort;
  collection_complete; page_complete;
  pending_transactions_included: false; notes_included;
  unresolved_reference_count; warnings[];
}
```

`observed_from` and `observed_at` bracket upstream fetching; they do not claim a globally consistent YNAB point-in-time version. `source_last_modified` is nullable and only populated when the source provides it. `collection_complete=true` means all API-visible records matching the declared scope were fetched successfully within limits; it never means all bank activity, pending transactions, all history, or a complete graph of referenced entities. `page_complete` indicates whether this is the last page. Requested note omission is represented by `notes_included=false`, not fake null source values. Incomplete retrieval fails with a typed error; it is not a successful truncated snapshot. Multiple upstream fetches can observe changes between calls, so metadata and warnings must retain this weaker consistency.

## Application services, ports and package boundaries

The domain layer contains pure types and invariant-preserving functions. Application services sequence authorization, repositories, admission, upstream reads, snapshots and serialization. Infrastructure adapters implement those ports. The MCP adapter translates schemas and error codes; it contains no SQL, token refresh, arithmetic or financial business rules.

| Port (owned by consuming application module) | Contract | Adapter |
| --- | --- | --- |
| `AccessGrantRepository` | Load a consistent grant; administratively replace with expected version; validate owner/connection link | SQLite candidate or Firestore alternative |
| `ConnectionRepository` | Load metadata; begin/mark/commit refresh with expected generation and fencing version; disable/reconnect | Same selected durable-state adapter |
| `CredentialStore` | Read immutable secret version; create complete generation at a deterministic attempt ref; verify persisted bundle; retire old refs | Approved secret manager; no MCP-facing access |
| `YNABReadGateway` | Eight narrow read use cases returning typed data/coverage or typed errors; complete/delta modes explicit | Fixed-host GET-only HTTP adapter |
| `YNABOAuthGateway` | Authorized code exchange or coordinated refresh only | Separate fixed-host credential HTTP client |
| `QuotaRepository` | Atomically reserve an attempt and record cooldown using the quota window | Selected durable-state adapter |
| `SnapshotStore` | Publish immutable bounded snapshot, read owner-bound cursor, evict; no durable finance writes | Process-local bounded memory |
| `CollectionStateStore` | Atomically replace a complete baseline plus knowledge after valid merge; never checkpoint alone | Process-local bounded memory |
| `Clock`, `RandomSource` | UTC/monotonic time and unpredictable identifiers, injectable for tests | Standard library adapters |

The upstream adapter's token provider consumes the connection lifecycle service internally. Tokens never appear in financial read-model ports, tool DTOs, or domain error text. Authentication middleware is an inbound adapter using an issuer verifier, then passes only the verified principal to application services. Domain errors (`UnauthorizedScope`, `CursorExpired`, `NarrowQueryRequired`, `ReconnectRequired`, `RateLimited`, `UpstreamUnavailable`, `DataInvalid`) map to sanitized MCP results centrally.

Dependency direction is `adapters -> application -> domain`; application depends on interfaces, not on SQLite, Firestore, the MCP SDK or HTTP DTOs. Only the composition root selects concrete storage, issuer, transport and secret-store adapters. Avoid interface-per-struct ceremony: repository interfaces exist for real persistence/consistency boundaries, and use-case interfaces are kept narrow.

Suggested layout, to create only in the implementation phase:

```text
cmd/budget-mcp/                    composition root, configuration validation
internal/domain/access/           principal keys, grant and disclosure invariants
internal/domain/connection/       connection state, generation and refresh transitions
internal/domain/budget/           typed financial read models, money and dates
internal/domain/inquiry/          query, coverage, snapshot and cursor rules
internal/domain/admission/        rolling-window and cooldown policy
internal/application/             read use cases, administration, refresh coordinator
internal/application/ports/       repository, gateway, snapshot and credential contracts
internal/adapters/mcp/            tool schemas, SDK dispatch and result mapping
internal/adapters/auth/           issuer verification, challenges and discovery
internal/adapters/ynab/           upstream DTOs, anti-corruption mapping, guarded GETs
internal/adapters/ynaboauth/      fixed-host OAuth exchange, no financial API methods
internal/adapters/state/sqlite/   candidate durable metadata adapter (if selected)
internal/adapters/state/firestore/ alternative only (do not implement both by default)
internal/adapters/secrets/        chosen protected credential backend
internal/adapters/memory/         bounded financial snapshots, cursors, delta baselines
internal/transport/               HTTPS listener; optional tsnet adapter
internal/observability/           metadata-only logs and metrics
test/integration/                mock issuer, mock YNAB and real MCP client tests
testdata/                         synthetic fixtures only
docs/                            design, threat model and eventual runbooks
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

Require random, expiring, single-use state bound to the initiating owner session, exact callback checks and PKCE. Validate token response shape and expiry, request only the read-only scope, and reject an unexpected broader scope if the provider returns one. Do not use a live mutation attempt to probe scope. Refresh under a per-connection coordinator and durable version/fencing checks, as specified in the data model below. Publish a replacement credential generation only after protected persistence succeeds. An invalid/revoked grant or ambiguous refresh outcome blocks upstream access and requires reconnect; a transient read failure is handled separately. Never race old refresh tokens, replay an uncertain refresh, or silently change auth mode.

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

Use integer `int64` milliunits internally with checked arithmetic. Return money as an exact decimal string plus currency code and milliunits encoded as a decimal string to avoid JavaScript precision loss. Never sum unrelated currencies. Include date boundaries, observation timestamps, nullable source last-modified metadata, freshness and coverage with results. Preserve nulls, transfer relationships and split structure. Avoid double-counting a split parent and its children or counting both sides of an internal transfer as spending. These are tested semantics, not LLM instructions to improvise totals.

Proposed defaults: list limit 50, maximum 200 items; transaction date window at most 366 days per call; memo/note text excluded unless explicitly requested. Distinguish recorded transactions, their separate cleared/approved states, and scheduled items; a recorded transaction is not necessarily bank-settled. State the pending-transaction coverage limitation in tool metadata and transaction results.

## Upstream routing and compatibility

Use fixed `https://api.ynab.com/v1/plans` routes and typed `plans`/`plan` response models. Do not silently retry failures against legacy routes. If migration support is ever needed, add a separately selected adapter tested with legacy `budgets`/`budget` response keys. The same ID allowlist applies to either adapter. New code should not depend on undocumented legacy paths.

The YNAB data client permits GET only. OAuth POST requests belong to a separate, fixed-host credential client. A transport guard rejects all data-client methods other than GET and all unexpected hosts or redirects, even if a programming error reaches the HTTP layer. Production cannot override the YNAB base URL through tool arguments; mock endpoints are injected only by tests.

## Bounded data and consistent pagination

Pagination is a connector feature, not invented upstream pagination. Fetch the narrowest supported upstream collection, construct a bounded immutable snapshot, then return opaque short-lived cursors. Bind each cursor to owner, connection authorization lineage, policy version, budget, filters, projection, sort order, page limit, snapshot ID and expiry; use unpredictable server-side handles. Validate authorization again on every page. Reject expired or mismatched cursors rather than restarting silently and producing duplicates.

A cursor pages cached data without another upstream request. Sort transactions deterministically by date and ID. Proposed snapshot TTL is five minutes. Return `next_cursor`, `observed_at` and whether the result covers the requested interval completely. Oversized upstream responses produce a clear request-to-narrow error, never an apparently complete truncated list. Date windows can be split internally within a bounded request budget; if a single-day result is still too large, fail explicitly.

Start with an in-memory cache and no financial-data persistence. Persist only private control metadata (owner/grants, connection state, secret references, refresh recovery and non-content quota accounting) plus separately protected credentials; the durable model below defines the boundary. Suggested safety limits: 64 KiB request bodies, 8 MiB decompressed upstream responses, 256 KiB tool responses, 32 MiB total cached financial data and a 15-second request deadline. Tune from synthetic load tests before release.

Cache identity includes owner/connection authorization lineage, policy version, budget, adapter/schema version, endpoint and normalized filters/projection. Delta knowledge belongs to precisely that collection. Merge updates and tombstones by entity ID, then atomically commit the new data and knowledge. Never interpret a delta response as a full listing. Do not advance knowledge after decode or merge failure. Avoid delta sync on filtered transaction windows in v1: moved dates/categories could make records disappear from the filter without a useful tombstone. Use full bounded fetches there; introduce delta only for complete collections with deletion and filter-transition tests.

## Durable and ephemeral data model

**Storage selection is still open.** SQLite on an approved durable local volume is the recommended candidate for a single-instance process because this is a small metadata workload. Firestore is an alternative when the approved hosting environment favors managed durable state. Neither is selected, provisioned or required by this documentation delivery. Implement one adapter after that decision; do not introduce dual writes.

Three storage classes have different trust and retention boundaries:

1. **Durable configuration/control metadata:** owner grants, connection state, immutable secret references, refresh recovery records and rolling quota accounting. These are private operational data even without balances or memos.
2. **Protected secrets:** client secret and each complete access/refresh-token generation, encrypted in an approved secret manager. The database contains references only. The key/encryption authority is outside the metadata database and its backups; a database reader alone must not be able to decrypt credentials. The process uses a separately authorized workload identity with least-privilege read/write access to its own secret namespace. No client token receives this identity.
3. **Ephemeral financial content:** typed snapshots, cursor bindings and delta baselines only in bounded process memory. No financial SQL tables, Firestore documents, disk spill, payload logs, core dumps or financial backups in v1. Restart loses cursors and knowledge together and forces bounded full reads.

If a later deployment chooses encrypted database credential blobs instead of a secret manager, that is a separate security design decision: require authenticated envelope encryption, per-record nonces, versioned key IDs, an external KMS/wrapping-key boundary, key rotation and backup/recovery tests before accepting live tokens. Plaintext token columns, “encrypted volume” alone, or a key stored next to the database are not substitutes for this boundary.

### SQLite candidate schema

The following is a **proposed schema contract**, not an executed migration. Times are UTC Unix milliseconds in storage, rendered as RFC 3339 in results. IDs and references have bounded lengths validated by the adapter. Use parameterized statements, foreign keys enabled, checked affected-row counts for compare-and-swap, and reviewed migrations before implementation.

```sql
CREATE TABLE owners (
  owner_id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  tenant_key TEXT NOT NULL,                 -- explicit sentinel for no tenant
  enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
  policy_version INTEGER NOT NULL CHECK (policy_version > 0),
  UNIQUE (issuer, subject, tenant_key)
);

CREATE TABLE connections (
  connection_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL UNIQUE REFERENCES owners(owner_id),
  auth_mode TEXT NOT NULL CHECK (auth_mode IN ('oauth','personal_token')),
  status TEXT NOT NULL CHECK (status IN
    ('unconnected','active','refreshing','reconnect_required','disabled')),
  authorization_lineage TEXT NOT NULL,
  requested_scope TEXT NOT NULL,
  client_config_id TEXT REFERENCES oauth_client_configs(client_config_id),
  credential_generation INTEGER NOT NULL CHECK (credential_generation >= 0),
  credential_ref TEXT,                     -- immutable secret-bundle version only
  access_expires_at_ms INTEGER,
  state_version INTEGER NOT NULL CHECK (state_version > 0),
  updated_at_ms INTEGER NOT NULL,
  UNIQUE (owner_id, connection_id),
  CHECK ((auth_mode = 'oauth' AND client_config_id IS NOT NULL)
      OR (auth_mode = 'personal_token' AND client_config_id IS NULL))
);

CREATE TABLE access_grants (
  owner_id TEXT PRIMARY KEY REFERENCES owners(owner_id),
  connection_id TEXT NOT NULL,
  notes_permitted INTEGER NOT NULL CHECK (notes_permitted IN (0,1)),
  field_policy_version INTEGER NOT NULL CHECK (field_policy_version > 0),
  FOREIGN KEY (owner_id, connection_id)
    REFERENCES connections(owner_id, connection_id)
);

CREATE TABLE allowed_budgets (
  owner_id TEXT NOT NULL REFERENCES access_grants(owner_id),
  budget_id TEXT NOT NULL,
  PRIMARY KEY (owner_id, budget_id)
);

CREATE TABLE oauth_client_configs (
  client_config_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  client_secret_ref TEXT NOT NULL,          -- secret reference, never client secret
  callback_url TEXT NOT NULL,
  config_version INTEGER NOT NULL CHECK (config_version > 0)
);

CREATE TABLE refresh_attempts (
  attempt_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES connections(connection_id),
  base_generation INTEGER NOT NULL,
  fence_version INTEGER NOT NULL,
  candidate_ref TEXT NOT NULL UNIQUE,      -- predetermined protected-store location
  phase TEXT NOT NULL CHECK (phase IN
    ('prepared','request_started','secret_saved','committed','abandoned','ambiguous')),
  started_at_ms INTEGER NOT NULL,
  lease_owner TEXT NOT NULL,
  lease_expires_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER
);
CREATE UNIQUE INDEX one_unresolved_refresh ON refresh_attempts(connection_id)
  WHERE phase IN ('prepared','request_started','secret_saved','ambiguous');

CREATE TABLE quota_windows (
  quota_key TEXT PRIMARY KEY,              -- stable local connection accounting key
  connection_id TEXT NOT NULL UNIQUE REFERENCES connections(connection_id),
  cooldown_until_ms INTEGER,
  last_observed_clock_ms INTEGER NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0)
);
CREATE TABLE quota_reservations (
  quota_key TEXT NOT NULL REFERENCES quota_windows(quota_key),
  attempt_id TEXT NOT NULL,
  reserved_at_ms INTEGER NOT NULL,
  PRIMARY KEY (quota_key, attempt_id)
);
CREATE INDEX quota_by_time ON quota_reservations(quota_key, reserved_at_ms);
```

`client_config_id` references OAuth-only configuration; it is required in OAuth mode and null in the explicitly approved personal-token fallback. A personal token is still kept in the protected credential store and does not pretend to have a refresh token. The schema may be refined before implementation, but must never store credentials in metadata columns.

Nonempty allowlists, one configured owner in v1, correct active-state credential references, scope policy, monotonic versions and allowed state transitions are repository/domain invariants; do not assume a SQL foreign key proves them. Startup validates the complete configuration before serving financial reads. Initial configuration, owner/connection association and allowlist replacement are atomic transactions. Administrative changes are outside the MCP tool surface and require separate authorization.

Use one process initially. Keep write transactions short, handle bounded `SQLITE_BUSY` retries and persist on a durable volume with restricted permissions and encrypted backups for private metadata. SQLite permits multiple readers but one writer; no transaction remains open during OAuth, YNAB or secret-manager network calls. [SQLite transaction semantics](https://www.sqlite.org/lang_transaction.html)

### Refresh rotation, version CAS and crash recovery

A database and an external secret manager cannot atomically commit with YNAB's token endpoint. “Save refresh tokens atomically” means committing the local active-generation pointer only after the new secret bundle is durable, not promising an impossible cross-system transaction. Do not assume refresh-token replay, provider idempotency, token-rotation grace, or successful network delivery after timeout.

1. Under the per-connection coordinator, load the current active generation and state version. In a short database transaction, compare-and-swap to `refreshing`, increment the fencing version, and create one `prepared` attempt with a unique ID, bounded lease and deterministic candidate secret reference. Other callers wait only within their request deadline or receive a retryable unavailable result.
2. Durably mark `request_started` before invoking the fixed OAuth endpoint. Make exactly one refresh exchange for this attempt. Never issue OAuth from inside a database transaction or an automatically retried transaction callback.
3. Validate the returned complete credential bundle, expiry and scope policy, then write it under the attempt's predetermined secret reference with immutable/create-once semantics. Secret-store retries operate on this same candidate, not by reissuing refresh. Confirm persistence/readback according to that backend's guarantee. Only then mark `secret_saved`.
4. In one metadata transaction, require the original generation, matching attempt/fence, permitted connection status and unchanged authorization lineage. Swap to the new immutable reference, increment generation and state version, mark `active`, and mark the attempt `committed`. Only after this commit may data clients obtain the replacement access token. Disabling/reconnecting a connection wins over a late refresh result.
5. Retire obsolete secret generations only after the active pointer is verified and in-flight users are no longer dependent on them. Cleanup is bounded, authorized and recoverable; retention/backup policy must not resurrect an old active pointer. Keep no secret content in the journal.

Recovery cases are explicit:

| Durable observation after restart/failure | Recovery |
| --- | --- |
| `prepared`, with no request-start marker | No external attempt was admitted; once prior worker termination/lease safety is established, abandon and start a new fenced attempt. |
| Candidate secret exists for `request_started` or `secret_saved` | Validate its complete bundle and metadata, then finish the generation CAS if still authorized; no second refresh exchange. |
| `request_started`, candidate absent, previous process gone or timeout outcome unknown | The token may have rotated without a durable response. Mark `ambiguous` / `reconnect_required`; do not reuse the old refresh token automatically. Require owner reconnect unless a documented provider-safe recovery mechanism is later implemented and tested. |
| Metadata commit succeeded but acknowledgment was lost | Reload active reference and generation; matching committed attempt is success, not a reason to refresh again. |
| CAS lost to disable/reconnect/new lineage | Never adopt the stale candidate. Stop reads and retire the orphan through the approved cleanup path. |
| Secret store is unavailable | Do not expose an uncommitted generation or silently use a personal token. Preserve recovery metadata and return a safe unavailable/reconnect result as appropriate. |

A lease only limits local ownership; its expiry cannot cancel an upstream request already in flight. An unresolved `request_started` attempt must not be stolen and replayed by another worker. V1 is single-instance; a multi-instance deployment would require tested fencing, safe worker-death handling and shared admission semantics before approval. Connection/recovery state is operational, not a financial event log. An ordinary transient read error does not force reconnect; a revoked/invalid grant or ambiguous refresh does.

The initial OAuth flow keeps state/PKCE verifier in a bounded, owner-session-bound ephemeral store (proposed ten-minute TTL), consumes state once, and loses pending flows on restart. A returned first credential generation is persisted before activating the connection. Missing state or an interrupted ambiguous exchange requires restarting consent; no authorization code or verifier belongs in durable metadata logs.

### Quota transaction and retention

Use a stable `QuotaKey` per connection/credential lineage for local accounting and conservatively retain the preceding hour across access-token rotation and reconnect. Do not derive it from a plaintext token or expose token hashes. This deliberately errs on the side of fewer calls even if a new token has a separate upstream quota. It cannot account for other applications using the same token.

In one short transaction: read/update the quota root, reject active cooldown, prune reservations strictly older than the rolling hour, count retained reservations, and insert a unique reservation before permitting the HTTP attempt. Use conservative boundary handling and a fake-clock-tested policy for clock rollback. A crash after reserve but before send overcounts safely; uncertain network failures still count. Never roll back a reservation merely because a request timed out. Every HTTP retry obtains a new attempt ID and reservation. Persist 429 cooldown independently, including when a downstream tool request is cancelled. OAuth exchanges are separate from this GET ledger and have their own bounded retry policy (no automatic refresh replay).

Reservations contain no URL, budget ID, amount or payload and normally expire after an hour plus a small clock-safety margin. Completed refresh journal metadata can be compacted after an explicitly chosen recovery retention period (proposed seven days); unresolved attempts must remain until reconciled or reconnect resolves them. Owner/grant/configuration records remain until authorized change/removal. Database backups and restore runbooks must treat restored refresh pointers as potentially stale and require reconciliation/reconnect before reads.

### Ephemeral snapshot, cursor and delta schemas

```text
SnapshotRecord {
  id; owner_id; connection_id; authorization_lineage; policy_version;
  budget_id; normalized_query; projection_version;
  items[]; observed_from; observed_at; source_last_modified?;
  coverage; expires_at; byte_size;
}
CursorRecord {
  handle_hash; snapshot_id; next_offset; page_limit;
  owner_id; connection_id; authorization_lineage; policy_version;
  query_fingerprint; expires_at;
}
CollectionState {
  collection_key; baseline_items_by_id; server_knowledge;
  observation_metadata; baseline_complete; expires_at; byte_size;
}
CollectionKey = owner + connection + authorization_lineage + policy_version
              + budget + API-adapter/schema-version + exact endpoint family
              + canonical upstream collection parameters + projection
```

Cursor handles are random, high-entropy server-side capabilities but are insufficient without the correct authenticated owner and current authorization. Store handle hashes where practical. Use the same five-minute absolute expiry as the snapshot, not a sliding TTL; bind limit and sort so page meaning cannot change. Bound cursor count as well as item bytes to prevent tiny-handle exhaustion. Evicting a snapshot invalidates all its cursors. Repeat use of the same valid cursor returns the same page; it is not a one-use financial command. Process restart invalidates every cursor.

Delta baselines use a five-minute absolute retention policy initially, within the same total financial-memory cap; a delta refresh may publish a new baseline with a new expiry, while existing paginated snapshots remain immutable. Eviction drops data and knowledge together. Never persist a checkpoint without its complete corresponding dataset. Start v1 with full bounded fetches; enable delta only for a specifically tested complete collection. Exact scope includes month for month-scoped collections, account for account-scoped collections, and any upstream filters. Because transitions into/out of filtered transaction windows are unsafe without stronger proofs, v1 does not use delta for those queries. Do not share a `server_knowledge` value across endpoints because its numeric value happens to match.

Merge a delta into a private candidate map, process entity and child tombstones, validate structure/limits, then atomically swap both map and new knowledge. If decoding, merging or validation fails, retain the prior pair and return an error; never publish a half-merged set. Full refetch is required if no baseline exists. Policy changes, reconnect, adapter/schema changes and currency-setting changes invalidate relevant cached projections. No snapshot claims atomicity across independently fetched upstream collections.

### Firestore alternative mapping

If selected instead of SQLite, store one `owners/{ownerId}` document for the grant/allowlist and policy version, one `connections/{connectionId}` for connection metadata and the single unresolved refresh attempt, and one `quotaWindows/{quotaKey}` for cooldown plus a bounded rolling reservation list. Store OAuth client configuration separately with secret references only. Use transactions for version comparisons and grant/connection integrity; serialized quota admission must update the quota root so concurrent callers cannot independently pass the same count check. A bounded list is acceptable at this single-owner call budget; do not grow an unbounded history document.

Transaction callbacks can retry, so perform no OAuth, secret-store writes or YNAB calls inside them. Keep all financial snapshots, cursor state and delta baselines in process memory exactly as above; Firestore is not permission to persist financial payloads. Expiration checks are application logic: TTL cleanup is delayed and cannot enforce cursor expiry or quota correctness. [Firestore transactions](https://firebase.google.com/docs/firestore/manage-data/transactions), [Firestore TTL behavior](https://firebase.google.com/docs/firestore/ttl)

Firestore requires a separately approved project, region, workload identity, IAM, backup/retention policy and cost review. Server-side authorization and owner scoping remain mandatory. Choosing it does not automatically authorize multi-instance hosting or solve the cross-system refresh gap. Both adapters must pass the same repository contract and recovery tests before live use.

## Example application flows and transaction boundaries

### Bounded transaction inquiry

1. MCP validates the schema; middleware verifies issuer token and passes a `Principal`. `ReadTransactions` loads the grant and active connection and constructs a `ReadScope`. A guessed budget or mismatched child ID is rejected without an unauthorized upstream fetch.
2. Normalize the explicit date window and filters. If a cursor is supplied, resolve it only under the current scope/query and return its immutable page after rechecking policy; no new upstream request is needed.
3. On a cache miss, coalesce identical authorized queries. Obtain a committed credential generation and durable quota reservation, then issue a guarded GET with cancellation and response bounds. No database transaction spans this network operation.
4. Map upstream DTOs to typed read models, apply only defined local filters, validate complete bounded coverage, sort by date then transaction ID, and publish the immutable snapshot under the memory-store lock. A multi-call fetch records its entire observation interval and does not claim upstream snapshot isolation.
5. Revalidate enabled grant, policy version and connection lineage before disclosure. Serialize exact money and coverage metadata; issue a bound cursor only when another page exists. A changed policy discards the response and invalidates the affected handles.

### Owner removes an allowed budget

The authorized administration use case replaces the allowlist and increments policy version in one repository transaction. Its in-process invalidation drops affected financial snapshots and delta state. Even if cleanup is delayed, every page read compares current policy and is denied. No distributed event bus or eventual cache-invalidation message is needed for a single process. Calls already delivered cannot be recalled.

### Delta update with a deleted split

For a future enabled complete-collection delta, load the matching complete baseline/knowledge pair. Fetch with that knowledge, merge into a private candidate using parent/child IDs, apply tombstones and validate split structure. Commit the candidate map and new knowledge together under a lock. A malformed child or out-of-bounds candidate leaves the old pair intact. Previously issued pages continue reading their original immutable snapshot until expiry.


## Quotas and failure handling

Use one upstream request coordinator per connection with conservative accounting across credential rotation, coalesce identical in-flight reads, limit upstream concurrency to two, and cap retries to two within the request deadline. Maintain a rolling-window ledger with headroom, initially targeting at most 180 calls/hour. Persist its non-content reservations before each attempt; if state is missing/untrustworthy, use conservative restart backoff so process restarts cannot reset the local quota. A separately used token can consume quota outside this process, so treat upstream 429 responses as authoritative. Do not claim an exact remaining quota from local counts.

Retry only safe GETs on transient network failures or selected 5xx responses with jitter. Honor a valid Retry-After when present. Without one, a 429 opens a conservative cooldown; return retry guidance instead of spinning or sleeping a tool call for an hour. Authentication failures get at most one coordinated credential refresh under the generation/recovery rules, then a clear reconnect error; the GET retry policy never implies retrying an uncertain OAuth exchange. Never retry permission failures as though they were outages.

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

### Domain and repository acceptance examples

- An enabled grant with an empty budget set, a foreign-owned connection, or a name/alias instead of an explicit budget ID is rejected; grant replacement increments policy version atomically.
- Revoking a budget while a GET is in flight prevents its later disclosure; every existing cursor for the old version fails even before cache cleanup.
- `Money(-12345, USD)` renders exactly `-12.345`; int64 boundaries, currency mismatch, null target versus zero target, and display rounding cannot change arithmetic values.
- An account movement of `-100000` split into `-60000` and `-40000` is `-100000`, never `-200000`; a category filter returns its parent once with the matching child identified. Transfers with an absent counterpart or tracking account do not acquire invented spending semantics.
- Category C in September and October has separate month keys and amounts; a current-view response is never labeled as a fetched historical month. Scheduled items never enter recorded-transaction totals or gain a cleared status.
- An upstream null payee, redacted memo, empty memo and absent optional field retain their distinct output semantics. Unknown safe enums remain explicitly unknown; invalid required IDs/money fail.
- Concurrent refresh requests create one unresolved attempt; a secret-store write failure cannot expose an uncommitted generation. Crash injection at every step covers prepared, request-started/no response, saved candidate/no pointer, committed pointer/no acknowledgment, disable races and orphan cleanup. Ambiguous exchanges are not replayed.
- SQLite/Firestore repository contract tests verify expected-version CAS, atomic owner/allowlist changes, connection ownership, reservation admission and rollback behavior. Firestore transaction retries cannot cause additional external calls. No test assumes TTL deletion is punctual.
- A reservation survives a crash before send, every GET retry counts, token rotation retains the window, and clock rollback never grants extra quota. Restore from a stale database forces safe refresh reconciliation rather than blindly using old tokens.
- Snapshot pages retain order through upstream edits; replaying a cursor yields the same page, changing notes/filter/limit or owner fails, and expiration/eviction/restart fails explicitly. Delta knowledge never survives eviction of its baseline; malformed child tombstones do not advance it.

### Layered test plan

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

**Phase 0, this delivery:** design and README only. Confirm issuer preference, network path, upstream credential approach, allowed budgets, durable-state backend and secret-store boundary before implementation.

**Phase 1, protocol skeleton:** approved Go implementation against synthetic mocks; pure domain/value-object tests, strict configuration, auth middleware and denied-write tests first. Exit when unauthorized requests and guessed write tools demonstrably fail without upstream calls.

**Phase 2, data adapter:** read handlers, bounded snapshots, money semantics, upstream OAuth and quota behavior. Exit when the full mock test suite, selected repository contract tests, refresh crash-injection tests and race checks pass. No deployment is implied.

**Phase 3, consent and connectivity:** separately approve issuer/client setup, secure credential entry and endpoint deployment. Test the actual OpenAI authorization flow first with synthetic results, then authorize the named budgets. Exit when real host access works and unauthenticated/wrong-identity access fails.

**Phase 4, operational acceptance:** verify redacted logs, revocation, reconnect, restart behavior, bounded cache and owner-visible freshness. Optional tsnet or tunnel work follows only if useful and authorized.

## Decisions still needed

- Which mature issuer is already trusted, and does it pass the target OpenAI client's resource/PKCE/registration tests? Recommendation: reuse a suitable issuer; otherwise evaluate a managed MCP-aware provider before building hosting around it.
- Which approved endpoint can dot actually reach? Recommendation: authenticated public HTTPS unless a supported secure tunnel is verified; tsnet alone is insufficient evidence of reachability.
- Is the extra upstream OAuth setup acceptable? Recommendation: yes, for enforced read-only access and refresh; keep personal-token use an explicit fallback.
- Which budget IDs and financial fields may be disclosed to dot? Recommendation: start with one named budget and notes disabled.
- Which durable-state backend and protected credential store fit the approved host? Recommendation: SQLite on an approved durable volume for a single instance, or Firestore if managed state better fits the host; neither is selected yet. Use an approved secret manager with immutable credential versions and a separate encryption/workload-identity boundary. Decide retention, backup/restore and ambiguous-refresh recovery before live OAuth.
- What repository license should apply? Select an explicit license before inviting reuse; this original design does not inherit another connector's license.

Completion means a tested, narrowly authorized read connector with verified host interoperability. A repository, a listening port, or a successful unauthenticated tool call alone does not meet that bar.
