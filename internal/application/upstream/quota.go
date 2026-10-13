// Package upstream connects authorized read scopes to durable admission ports.
package upstream

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

type QuotaAdmission struct {
	state  ports.AccessStateRepository
	ledger ports.QuotaRepository
	now    func() time.Time
	random io.Reader
}

func NewQuotaAdmission(state ports.AccessStateRepository, ledger ports.QuotaRepository) (*QuotaAdmission, error) {
	if state == nil || ledger == nil {
		return nil, errors.New("durable access and quota repositories are required")
	}
	return &QuotaAdmission{state: state, ledger: ledger, now: time.Now, random: rand.Reader}, nil
}
func (q *QuotaAdmission) Reserve(ctx context.Context, scope access.ReadScope) error {
	grant, binding, err := q.state.ReadAccessState(ctx)
	if err != nil || !grant.Enabled() || !binding.Active || grant.OwnerID() != scope.OwnerID || grant.ConnectionID() != scope.ConnectionID || binding.OwnerID != scope.OwnerID || binding.ConnectionID != scope.ConnectionID || binding.AuthorizationLineage != scope.AuthorizationLineage || grant.PolicyVersion() != scope.PolicyVersion || scope.BudgetID != "" && !grant.AllowsBudget(scope.BudgetID) {
		return inquiry.ErrUnauthorizedScope
	}
	var bytes [24]byte
	if _, err := io.ReadFull(q.random, bytes[:]); err != nil {
		return inquiry.ErrUpstreamUnavailable
	}
	_, err = q.ledger.Reserve(ctx, admission.QuotaKey(scope.ConnectionID), base64.RawURLEncoding.EncodeToString(bytes[:]), q.now().UTC())
	if errors.Is(err, admission.ErrCooldown) || errors.Is(err, admission.ErrRateLimited) {
		return inquiry.ErrRateLimited
	}
	if err != nil {
		return inquiry.ErrUpstreamUnavailable
	}
	return nil
}

// RecordCooldown persists authoritative upstream 429 guidance even when the
// downstream request has been canceled. It remains bounded, and neither quota
// reservations nor this cooldown are refunded by a failed financial request.
func (q *QuotaAdmission) RecordCooldown(ctx context.Context, scope access.ReadScope, until time.Time) error {
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	grant, binding, err := q.state.ReadAccessState(recovery)
	// Revocation does not erase accounting for a GET that already happened.
	if err != nil || grant.OwnerID() != scope.OwnerID || grant.ConnectionID() != scope.ConnectionID || binding.OwnerID != scope.OwnerID || binding.ConnectionID != scope.ConnectionID {
		return inquiry.ErrUnauthorizedScope
	}
	if err := q.ledger.RecordCooldown(recovery, admission.QuotaKey(scope.ConnectionID), until.UTC(), q.now().UTC()); err != nil {
		return inquiry.ErrUpstreamUnavailable
	}
	return nil
}
