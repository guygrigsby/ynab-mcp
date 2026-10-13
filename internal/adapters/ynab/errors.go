package ynab

import (
	"errors"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

// Never wrap upstream bodies, transport errors, request URLs, or credential
// provider errors. Those may contain secrets or personal financial content.
func unavailable() error  { return inquiry.ErrUpstreamUnavailable }
func reconnect() error    { return inquiry.ErrReconnectRequired }
func unauthorized() error { return inquiry.ErrUnauthorizedScope }
func notFound() error     { return inquiry.ErrNotFound }
func rateLimited() error  { return inquiry.ErrRateLimited }
func dataInvalid() error  { return inquiry.ErrDataInvalid }
func narrowQuery() error  { return inquiry.ErrNarrowQueryRequired }
func quotaDenied(err error) error {
	if errors.Is(err, inquiry.ErrRateLimited) {
		return rateLimited()
	}
	return unavailable()
}
