// These tests use an actual SDK client and Streamable HTTP server, synthetic
// access tokens, and an in-process financial gateway. No live issuer or YNAB
// credentials are required. Upstream HTTP mapping is tested in adapters/ynab.
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/guygrigsby/ynab-mcp/internal/adapters/auth"
	"github.com/guygrigsby/ynab-mcp/internal/adapters/memory"
	"github.com/guygrigsby/ynab-mcp/internal/bootstrap"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
	"github.com/guygrigsby/ynab-mcp/internal/transport"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const issuer = "https://issuer.example"
const resource = "https://budget.example/mcp"

type state struct {
	grant   access.OwnerAccessGrant
	binding access.ConnectionBinding
}

func (s state) ReadAccessState(context.Context) (access.OwnerAccessGrant, access.ConnectionBinding, error) {
	return s.grant, s.binding, nil
}

type gateway struct{ calls atomic.Int64 }

func (g *gateway) Read(_ context.Context, _ access.ReadScope, q inquiry.Query) (inquiry.ReadResult, error) {
	g.calls.Add(1)
	now := time.Now().UTC()
	items := []json.RawMessage{json.RawMessage(`{"id":"a1","name":"synthetic"}`), json.RawMessage(`{"id":"a2","name":"inert https://untrusted.example"}`)}
	if q.Tool == "list_budgets" {
		items = []json.RawMessage{json.RawMessage(`{"id":"b1","name":"allowed"}`), json.RawMessage(`{"id":"b2","name":"not allowed"}`)}
	}
	return inquiry.ReadResult{Items: items, ObservedFrom: now, ObservedAt: now, Coverage: inquiry.Coverage{CollectionComplete: true}}, nil
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = "budget.example"
	if t.token != "" {
		r.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(r)
}
func testServer(t *testing.T) (*httptest.Server, *gateway, func(string) string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "key1"))
	if err != nil {
		t.Fatal(err)
	}
	token := func(sub string) string {
		now := time.Now()
		s, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: issuer, Subject: sub, Audience: jwt.Audience{resource}, Expiry: jwt.NewNumericDate(now.Add(time.Minute)), NotBefore: jwt.NewNumericDate(now.Add(-time.Second))}).Claims(map[string]any{"scope": "budget:read"}).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	keys, err := auth.NewStaticKeyProvider([]jose.JSONWebKey{{Key: pub, KeyID: "key1", Algorithm: "EdDSA", Use: "sig"}})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", PrincipalKey: access.PrincipalKey{Issuer: issuer, Subject: "owner-sub"}, ConnectionID: "connection", ConnectionOwnerID: "owner", BudgetIDs: []budget.BudgetID{"b1"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	st := state{grant, access.ConnectionBinding{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: "lineage", Active: true}}
	store, err := memory.NewSnapshotStore(memory.Options{})
	if err != nil {
		t.Fatal(err)
	}
	g := &gateway{}
	h, err := bootstrap.NewHandler(context.Background(), bootstrap.Config{Auth: auth.Config{Issuer: issuer, Resource: resource, Algorithms: []jose.SignatureAlgorithm{jose.EdDSA}}, Transport: transport.Config{AllowedHosts: []string{"budget.example"}}}, keys, st, g, store)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts, g, token
}
func TestSDKReadOnlyFlow(t *testing.T) {
	ts, g, token := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "synthetic-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: bearerTransport{http.DefaultTransport, token("owner-sub")}}, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	inventory, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Tools) != 8 {
		t.Fatalf("got %d tools", len(inventory.Tools))
	}
	for _, tool := range inventory.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatal("not read-only")
		}
	}
	if g.calls.Load() != 0 {
		t.Fatal("initialization/discovery called YNAB")
	}
	budgets, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "list_budgets", Arguments: map[string]any{}})
	if err != nil || budgets.IsError {
		t.Fatal("list budgets failed", err)
	}
	data, _ := json.Marshal(budgets.StructuredContent)
	if strings.Contains(string(data), "not allowed") {
		t.Fatal("foreign budget disclosed")
	}
	page, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "list_accounts", Arguments: map[string]any{"budget_id": "b1", "limit": 1}})
	if err != nil || page.IsError {
		t.Fatal("account read failed", err)
	}
	data, _ = json.Marshal(page.StructuredContent)
	var parsed inquiry.Page
	if json.Unmarshal(data, &parsed) != nil || parsed.Metadata.NextCursor == "" {
		t.Fatal("missing snapshot cursor")
	}
	calls := g.calls.Load()
	next, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "list_accounts", Arguments: map[string]any{"budget_id": "b1", "limit": 1, "cursor": parsed.Metadata.NextCursor}})
	if err != nil || next.IsError || g.calls.Load() != calls {
		t.Fatal("cursor page failed", err)
	}
	for _, name := range []string{"create_transaction", "update_transaction", "delete_transaction", "import_transactions", "POST", "list_budgets_alias"} {
		res, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: map[string]any{}})
		if err == nil && (res == nil || !res.IsError) {
			t.Fatalf("guessed tool %q admitted", name)
		}
	}
	denied, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "list_accounts", Arguments: map[string]any{"budget_id": "b2"}})
	if err != nil || !denied.IsError {
		t.Fatal("foreign budget admitted", err)
	}
	if g.calls.Load() != calls {
		t.Fatal("denied/write tool reached upstream")
	}
}
func TestHTTPAuthenticationAndDiscovery(t *testing.T) {
	ts, g, token := testServer(t)
	for _, method := range []string{"GET", "POST", "DELETE", "OPTIONS"} {
		req, _ := http.NewRequest(method, ts.URL+"/mcp", strings.NewReader(`{}`))
		req.Host = "budget.example"
		req.Header.Set("Mcp-Session-Id", "not-authentication")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "https://budget.example/.well-known/oauth-protected-resource/mcp") {
			t.Fatalf("%s: %d missing challenge", method, res.StatusCode)
		}
	}
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Host = "budget.example"
	req.Header.Set("Authorization", "Bearer "+token("wrong-owner"))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("wrong owner reached protocol", res.StatusCode)
	}
	req, _ = http.NewRequest("GET", ts.URL+"/.well-known/oauth-protected-resource/mcp", nil)
	req.Host = "budget.example"
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(data), resource) {
		t.Fatal("metadata not available")
	}
	if g.calls.Load() != 0 {
		t.Fatal("auth/discovery consumed YNAB quota")
	}
}
