package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Helpers for repositories that open their own workspace transaction
// (tenancy.InWorkspace / InWorkspaceRead) on the handle they were built
// with (AS-108). The handle is a base connection (a new transaction under
// row-level security), or a caller's transaction (a savepoint inside it).

// wsTxContext is the context a repository opens its workspace transaction
// with: the handle's own (a request's or a job's, for cancellation), or
// Background.
func wsTxContext(db *gorm.DB) context.Context {
	if db != nil && db.Statement != nil && db.Statement.Context != nil {
		return db.Statement.Context
	}
	return context.Background()
}

// wsTxGuard wraps fn so the workspace transaction refuses ws when the
// handle it was opened on already belongs to ANOTHER workspace (a
// transaction under row-level security for it, or a request's context): a
// repository built on workspace A's transaction never switches it to B's.
// The savepoint is rolled back with the refusal, so A's setting stands.
func wsTxGuard(outer *gorm.DB, ws uuid.UUID, fn func(tx *gorm.DB) error) func(tx *gorm.DB) error {
	return func(tx *gorm.DB) error {
		if tc, err := tenancy.FromContext(wsTxContext(outer)); err == nil && tc.WorkspaceID != ws {
			return fmt.Errorf("tenancy: a handle of workspace %s used for workspace %s", tc.WorkspaceID, ws)
		}
		return fn(tx)
	}
}
