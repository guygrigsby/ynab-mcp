# Budget MCP for YNAB

Design for a small, single-owner, read-only YNAB connector written in Go and intended for dot through a custom remote MCP connection.

**Status: documentation only.** There is no runnable server, dependency manifest, test suite or deployment in this initial repository. The tool names, package layout, limits and CI checks in the design are proposals for a later approved implementation.

Read the [design](docs/DESIGN.md) for the domain model, bounded contexts, aggregate invariants, financial read models, application ports, concrete storage proposals, authorization boundaries, tool contracts, threat model, test plan and delivery gates.

## Intended capabilities

- Read allowed budgets, account balances, categories and monthly summaries
- Query transactions and scheduled transactions with explicit bounds
- Preserve exact money values, freshness and coverage
- Deny every write operation and every budget outside the configured allowlist

## Proposed approach

Use the official Go MCP SDK with Streamable HTTP. A mature OAuth issuer authenticates the OpenAI host; separate read-only YNAB OAuth credentials authorize upstream reads. The server validates the approved owner and resource audience on every request. Tokens and financial content never belong in logs.

For initial connectivity, use approved authenticated HTTPS or a secure MCP tunnel whose support is verified. Optional tsnet can provide private transport but does not by itself give dot access to a tailnet.

The proposed application display name is **Budget MCP for YNAB**. Application and domain branding must be reviewed before release.

## Domain and storage design

YNAB remains the source of truth for budgets, accounts, categories and transactions. The connector owns access grants, connection/refresh state, request admission and bounded read snapshots. It does not implement a local financial ledger or financial write aggregates.

The design separates durable private control metadata and protected secret references from ephemeral financial data. It includes a candidate SQLite schema, a Firestore alternative, refresh crash-recovery rules and domain/repository acceptance tests. The storage backend is not yet selected; financial snapshots and cursors remain in memory for v1.

## Next decisions

Choose the issuer, reachable endpoint, upstream credential approach, durable-state backend, secret store and initial budget allowlist. Account grants, credentials, CI activation and deployment are not part of the documentation delivery.

## Security boundary

Read-only access still exposes private financial information. The eventual server must minimize fields, reject unauthorized identities, use bounded results, and treat payee names, notes and memos as untrusted data. It cannot guarantee what the client does with results after receiving them.

## Primary references

- [YNAB API](https://api.ynab.com/)
- [Official Go MCP SDK](https://github.com/modelcontextprotocol/go-sdk)
- [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [Tailscale tsnet](https://tailscale.com/docs/features/tsnet)

Documentation reviewed 13 October 2026. This is an independent design; no existing connector code has been copied.
