# Budget MCP for YNAB

A single-owner, read-only Go MCP resource-server foundation for bounded access to YNAB financial information.

**Status: initial implementation, synthetic tests only. Not production-ready or deployed.** This branch is stacked on the proposed [design](docs/DESIGN.md). It contains real protocol, domain, authorization, read-adapter and snapshot code, but deliberately has no production executable or selected state/secret-store adapter. There are no live credentials or account connections.

## Implemented

- Exactly eight tools: `list_budgets`, `get_budget`, `list_accounts`, `list_categories`, `get_month`, `list_transactions`, `get_transaction`, `list_scheduled_transactions`
- Official Go MCP SDK with stateless Streamable HTTP; strict argument parsing and read-only inventory
- Exact issuer/subject/tenant policy, resource audience and scope enforcement; JOSE access-token verification, bounded trusted JWKS and protected-resource metadata
- Explicit host/origin allowlists; owner checks on initialization, discovery and calls; request and response limits
- Fixed-host YNAB GET adapter with explicit projections, mandatory quota-reservation port, no redirect or legacy-route fallback
- Integer milliunit money with exact string serialization, validated dates/IDs, split and transfer semantics, distinct recorded/scheduled models
- Bounded memory-only immutable snapshots, opaque scope-bound cursors, absolute expiry, deterministic replay and revocation rechecks
- Pure connection-refresh/fencing and quota domain state machines, plus a separate fixed-destination OAuth exchange adapter

Read [implementation status and remaining gates](docs/IMPLEMENTATION.md) before integrating or running against an account. The design remains the target contract; this foundation does not claim to implement every operational acceptance criterion.

## Development

Use Go **1.27.2** or newer. All automated tests use generated keys and synthetic financial fixtures. Nothing requires a live account or API token.

```sh
make check
make fuzz
make vuln
```

`make check` runs formatting checks, vet, unit/integration tests, the race detector, and package builds. The integration test runs the official SDK client against an in-process Streamable HTTP server with synthetic signed access tokens and a synthetic inquiry gateway. Separate adapter tests exercise fixed YNAB HTTP routes and mapping.

No GitHub Actions workflow is activated by this implementation. No command starts a public listener, enrolls a network, configures an issuer or creates credentials. `internal/bootstrap.NewHandler` requires explicit state, key, inquiry and snapshot ports; a deployment composition root remains gated on the decisions below.

## Architecture

Dependencies point inward: adapters → application → domain. Financial read models are upstream projections, not local accounting aggregates. Financial snapshots never go to disk. The metadata repository contracts are separate from protected credentials; no storage backend or credential encryption scheme has been silently chosen.

The application maps one exact owner identity to one connection and explicit budget IDs. There is no multi-user hosting, billing, mutation tool, arbitrary URL/method parameter, bulk export or remote administration endpoint.

## Before live use

Select and approve the issuer/client registration, endpoint, upstream read-only OAuth application, durable metadata backend, protected secret store and named budget allowlist. Implement and test durable refresh orchestration, restart recovery and quota transactions, then test the actual host's authorization flow. Deployment, account permissions, live credentials and release remain separate approval gates.

This is an independent implementation. No third-party connector implementation has been copied. A repository license must be selected before inviting reuse. The application display name is **Budget MCP for YNAB**; review application/domain branding requirements before release.

## References

- [Design and threat model](docs/DESIGN.md)
- [YNAB API](https://api.ynab.com/)
- [Official Go MCP SDK](https://github.com/modelcontextprotocol/go-sdk)
- [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
