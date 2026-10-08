package repositories

import (
	"context"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/tenancy"
)

// The repositories in this package work on the shared database. Every
// statement goes through internal/tenancy with workspace_id bound to $1 from
// the tenant context carried by ctx (tenancy.WithContext), so a repository
// cannot be asked for another workspace's rows: the caller decides the
// workspace once, from a verified credential, and puts it on ctx.

// workspaceOf returns the workspace carried by ctx.
func workspaceOf(ctx context.Context) (uuid.UUID, error) {
	tc, err := tenancy.FromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return tc.WorkspaceID, nil
}

// nullString maps "" to NULL.
func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
