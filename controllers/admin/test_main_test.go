//go:build !integration

package admin

import (
	"os"
	"testing"

	"github.com/google/uuid"
)

// seededWorkspaceID is kept for backward compat with tests that call
// skipIfNoSeed(t). It is never populated — all dependent tests skip.
var seededWorkspaceID uuid.UUID

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
