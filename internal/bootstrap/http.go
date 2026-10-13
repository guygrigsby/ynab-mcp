// Package bootstrap composes a fail-closed resource server from explicitly
// supplied ports. This package does not provision an issuer, listener, secrets,
// durable database, live YNAB authorization or deployment.
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/guygrigsby/ynab-mcp/internal/adapters/auth"
	mcpadapter "github.com/guygrigsby/ynab-mcp/internal/adapters/mcp"
	"github.com/guygrigsby/ynab-mcp/internal/application"
	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/transport"
)

type Config struct {
	Auth      auth.Config
	Transport transport.Config
}

// NewHandler verifies required owner policy at startup, protects every /mcp
// request (including initialize/tools/list), and exposes only public discovery
// metadata and a content-free health endpoint outside that authentication wall.
func NewHandler(ctx context.Context, c Config, keys auth.KeyProvider, state ports.AccessStateRepository, gateway ports.YNABReadGateway, snapshots ports.SnapshotStore) (http.Handler, error) {
	if state == nil || gateway == nil || snapshots == nil {
		return nil, errors.New("all persistence and inquiry ports must be supplied")
	}
	resource, err := url.Parse(c.Auth.Resource)
	if err != nil || resource.Path != "/mcp" || resource.RawQuery != "" || resource.Fragment != "" {
		return nil, errors.New("canonical HTTPS resource must end in /mcp")
	}
	allowed := false
	for _, h := range c.Transport.AllowedHosts {
		if h == resource.Host {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("canonical resource host must be explicitly allowed")
	}
	grant, binding, err := state.ReadAccessState(ctx)
	if err != nil || !grant.Enabled() || len(grant.BudgetIDs()) == 0 || grant.PrincipalKey().Issuer != c.Auth.Issuer || binding.OwnerID != grant.OwnerID() || binding.ConnectionID != grant.ConnectionID() {
		return nil, errors.New("valid enabled owner policy and owned connection are required")
	}
	verifier, err := auth.NewVerifier(c.Auth, keys)
	if err != nil {
		return nil, err
	}
	authentication, err := auth.NewMiddleware(auth.MiddlewareConfig{Resource: c.Auth.Resource, Issuer: c.Auth.Issuer}, verifier)
	if err != nil {
		return nil, err
	}
	service, err := application.NewReadService(state, gateway, snapshots)
	if err != nil {
		return nil, err
	}
	rpc, err := mcpadapter.NewHTTPHandler(service, c.Transport)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	ownerGate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		current, connection, err := state.ReadAccessState(r.Context())
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if _, err = current.AuthorizeList(principal, connection); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		rpc.ServeHTTP(w, r)
	})
	mux.Handle("/mcp", authentication.Wrap(ownerGate))
	mux.Handle(authentication.MetadataPath(), authentication.MetadataHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	return transport.NewHandler(c.Transport, mux)
}
