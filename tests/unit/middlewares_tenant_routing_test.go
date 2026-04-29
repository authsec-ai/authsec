package unit

import (
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── GetConnectionDynamically ─────────────────────────────────────────────────

func TestGetConnectionDynamically_NilPointer_ReturnsMasterDB(t *testing.T) {
	db, err := middlewares.GetConnectionDynamically(nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

func TestGetConnectionDynamically_EmptyString_ReturnsMasterDB(t *testing.T) {
	empty := ""
	db, err := middlewares.GetConnectionDynamically(nil, nil, &empty)
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

func TestGetConnectionDynamically_NoPlugin_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, nil)

	tid := "tenant-123"
	db, err := middlewares.GetConnectionDynamically(nil, nil, &tid)
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

func TestGetConnectionDynamically_PluginUnavailable_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, &pluginMock{available: false})

	tid := "tenant-456"
	db, err := middlewares.GetConnectionDynamically(nil, nil, &tid)
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

// Extra args (masterDB, userEmail) must be silently ignored.
func TestGetConnectionDynamically_ExtraArgsIgnored(t *testing.T) {
	db1, err1 := middlewares.GetConnectionDynamically(nil, nil, nil)

	someObj := struct{ x int }{42}
	email := "user@example.com"
	db2, err2 := middlewares.GetConnectionDynamically(someObj, &email, nil)

	assert.Equal(t, err1, err2)
	assert.Equal(t, db1, db2)
}

// ── ConnectToTenantDB (deprecated alias) ─────────────────────────────────────

func TestConnectToTenantDB_BehavesLikeGetConnection(t *testing.T) {
	db1, err1 := middlewares.GetConnectionDynamically(nil, nil, nil)
	db2, err2 := middlewares.ConnectToTenantDB(nil, nil, nil)
	assert.Equal(t, err1, err2)
	assert.Equal(t, db1, db2)
}

// ── CloseTenantDB ─────────────────────────────────────────────────────────────

func TestCloseTenantDB_NoOp_NilDB(t *testing.T) {
	assert.NoError(t, middlewares.CloseTenantDB(nil))
}

func TestCloseTenantDB_NoOp_MasterDB(t *testing.T) {
	assert.NoError(t, middlewares.CloseTenantDB(config.DB))
}
