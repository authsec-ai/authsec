package services

import (
	"context"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// inWorkspace returns ctx carrying workspace ws as its tenant, for service
// code that resolved the workspace from a row or credential it trusts (a
// service account, a token, a campaign) rather than from the request.
func inWorkspace(ctx context.Context, ws uuid.UUID) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if tc, err := tenancy.FromContext(ctx); err == nil && tc.WorkspaceID == ws {
		return ctx
	}
	return tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws})
}
