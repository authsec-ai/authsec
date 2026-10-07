package platform

import (
	"context"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// inWorkspace is a background context whose tenant is workspace ws, for
// statements that run on a row's workspace inside a GORM transaction.
func inWorkspace(ws uuid.UUID) context.Context {
	return tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: ws})
}
