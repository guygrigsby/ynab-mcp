// Package ynaboauth implements the fixed-destination, read-only YNAB OAuth
// boundary. It has no financial API methods and does not expose an automatically
// refreshing HTTP client or TokenSource.
//
// This is an adapter foundation, not an authorization-flow or persistence
// service. Before Exchange, the caller must verify the exact registered callback
// and consume random, expiring, single-use state bound to the initiating owner's
// session. It must retain the corresponding PKCE verifier securely. Before
// Refresh, a durable coordinator must exclusively claim the connection's refresh
// attempt with its expected generation and fencing version. Never replay an
// attempt with an uncertain outcome. A returned credential pair must be stored
// and verified in an approved protected store before committing its generation;
// this package neither selects nor implements that store. A failed refresh
// requires reconnect. The opaque in-memory credentials deliberately provide no
// general serialization or refresh-token export; persistence integration remains
// a separate, release-blocking boundary.
//
// Endpoint and parameter policy follows https://api.ynab.com/ (reviewed
// 2026-10-13). Token requests use golang.org/x/oauth2 with a fixed authentication
// style so its automatic credential-style probing cannot replay a request.
package ynaboauth
