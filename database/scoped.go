package database

import (
	"context"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// WithWorkspace returns ctx carrying workspace ws as its tenant, for code that
// resolved the workspace from a credential or a row it already trusts (a login
// ticket, an OAuth client, a CIBA request, a background job's row) rather than
// from an authenticated request, whose context already carries it.
func WithWorkspace(ctx context.Context, ws uuid.UUID) context.Context {
	if tc, err := tenancy.FromContext(ctx); err == nil && tc.WorkspaceID == ws {
		return ctx
	}
	return tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws})
}

// ctxWorkspace returns the workspace carried by ctx.
func ctxWorkspace(ctx context.Context) (uuid.UUID, error) {
	tc, err := tenancy.FromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return tc.WorkspaceID, nil
}
