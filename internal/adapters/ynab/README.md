# Fixed YNAB read adapter

This package implements the eight inquiry operations with explicit upstream DTOs and domain projections. Its production constructor accepts committed-token and durable-admission ports, with no default credentials or quota bypass. No public base URL or transport option exists. Tests inject a private RoundTripper and use synthetic data only.

## Reviewed source

- Source: https://api.ynab.com/papi/open_api_spec.yaml
- Reviewed: 2026-10-13
- API version: 1.87.0; OpenAPI version: 3.1.1
- SHA-256: `69411d596ee4b6f79720615038ac9cdfea43875013ca9d0e5d235ba505ebf26f`

`testdata/read-contract.json` is a concise projection manifest of source facts, not a copied API implementation or complete specification. Its test checks adapter DTO field names against the reviewed schema property inventory. To assess upstream drift, download the official source separately, compare the hash, and review changed read routes and fields before updating this manifest and the synthetic fixtures. Tests do not contact YNAB or silently regenerate code.

## Deliberate behavior

- Fixed HTTPS `/v1/plans` GETs only. Redirects, legacy fallback, and arbitrary caller routes are unavailable.
- Full bounded reads only; no delta parameters, partial-baseline interpretation, or automatic retries. Connection reuse and HTTP/2 replay are disabled to avoid implicit unreserved attempts inside the HTTP stack.
- Fresh currency settings are read before every monetary endpoint. Missing currency fails explicitly; there is no USD default or formatted-string arithmetic.
- `get_budget` filters the plan summary collection, avoiding the full nested plan endpoint. `list_budgets` returns internal discovery projections; the application must filter these by the current grant before publishing or disclosing them.
- Category transaction filters are local over complete parent details. This avoids upstream category-route hybrid split records and preserves one parent with matching child IDs.
- Explicit month routes are used for historical categories. Current categories identify current-view semantics. Scheduled date filters apply only to `date_next`; no recurrence forecast is created.
- A Read has a 15-second context deadline; each decompressed upstream body and the total projected payload are capped at 8 MiB. Oversized reads fail without publishing partial data.
- Notes are explicitly redacted unless requested. Extra upstream fields, including import IDs and original bank-payee text, never cross the projection boundary.

Durable quota storage, the protected credential backend, and live composition remain separately gated. This adapter intentionally supplies none of them.
