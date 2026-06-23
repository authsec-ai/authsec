//go:build integration

package flows

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

func Test_Bootstrap_SchemaContract(t *testing.T) {
	_ = testsupport.Get(t)

	tables := []string{
		"workspaces",
		"users",
		"resource_servers",
		"oauth_scopes",
		"mcp_oauth_clients",
		"service_accounts",
		"native_tokens",
		"role_bindings",
	}

	for _, table := range tables {
		result := config.DB.Exec("SELECT 1 FROM " + table + " LIMIT 1")
		if result.Error != nil && strings.Contains(result.Error.Error(), "does not exist") {
			t.Errorf("schema contract broken: table %q does not exist", table)
		}
	}
}
