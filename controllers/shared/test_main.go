package shared

import (
	"os"

	"github.com/google/uuid"
)

// seededWorkspaceID is kept for backward compat with testing_exports.go.
// It is never populated — all integration tests in this package are skipped
// unless a future test harness sets it.
var seededWorkspaceID uuid.UUID

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
