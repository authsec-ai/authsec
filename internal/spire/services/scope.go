package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// The services read the request's workspace from ctx, where the HTTP layer
// put it after verifying a credential (a platform token, an agent or
// workload certificate, a join token). They never take a workspace from a
// request body, query or header.

// workspaceFromContext returns ctx's workspace, or 401 when there is none.
func workspaceFromContext(ctx context.Context) (string, error) {
	tc, err := tenancy.FromContext(ctx)
	if err != nil {
		return "", errors.NewUnauthorizedError("No workspace resolved for this request", err)
	}
	return tc.WorkspaceID.String(), nil
}

// withWorkspace returns ctx carrying workspaceID, for callers that resolved
// it themselves from a verified credential (in-process callers, a consumed
// join token). If ctx already carries a different workspace the request is
// refused as not found: a workspace is never switched mid-request.
func withWorkspace(ctx context.Context, workspaceID, kind string) (context.Context, error) {
	ws, err := uuid.Parse(workspaceID)
	if err != nil {
		return nil, errors.NewNotFoundError("Workspace not found", nil)
	}
	if tc, err := tenancy.FromContext(ctx); err == nil {
		if tc.WorkspaceID != ws {
			return nil, errors.NewNotFoundError("Workspace not found", nil)
		}
		return ctx, nil
	}
	return tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws, PrincipalKind: kind, Realm: "spire"}), nil
}
