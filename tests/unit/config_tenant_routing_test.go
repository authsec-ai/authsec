// Package unit contains unit tests for the single-tenant/multi-tenant refactoring.
// All tests here exercise only exported APIs so they can live in this neutral package.
//
// Run:
//
//	go test ./tests/unit/...              # unit tests (no DB required)
//	RUN_INTEGRATION=1 go test ./tests/unit/... # integration tests (real Postgres required)
package unit

import (
	"testing"

	"github.com/authsec-ai/authsec/config"
	pb "github.com/authsec-ai/authsec/internal/mtplugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pluginMock is a shared test double for config.MTPluginClientIface.
// Defined once here; all files in this package can use it.
type pluginMock struct{ available bool }

func (m *pluginMock) IsAvailable() bool { return m.available }
func (m *pluginMock) NotifyAdminRegistered(_ *pb.AdminRegisteredRequest) (*pb.AdminRegisteredResponse, error) {
	return &pb.AdminRegisteredResponse{Success: true}, nil
}
func (m *pluginMock) ListTenants() (*pb.ListTenantsResponse, error) {
	return &pb.ListTenantsResponse{}, nil
}
func (m *pluginMock) DeleteTenant(_ string) (*pb.DeleteTenantResponse, error) {
	return &pb.DeleteTenantResponse{Success: true}, nil
}
func (m *pluginMock) ResolveTenant(_ string) (*pb.ResolveByDomainResponse, error) {
	return &pb.ResolveByDomainResponse{}, nil
}

// swapPlugin replaces config.MTPluginClient for the duration of t and restores it.
func swapPlugin(t *testing.T, p config.MTPluginClientIface) {
	t.Helper()
	orig := config.MTPluginClient
	t.Cleanup(func() { config.MTPluginClient = orig })
	config.MTPluginClient = p
}

// ── Interface contract ────────────────────────────────────────────────────────

func TestMTPluginClientIface_MockSatisfies(t *testing.T) {
	var _ config.MTPluginClientIface = &pluginMock{}
}

func TestMTPluginClientIface_NilAssignable(t *testing.T) {
	var c config.MTPluginClientIface
	assert.Nil(t, c)
}

// ── GetTenantGORMDB ───────────────────────────────────────────────────────────

func TestGetTenantGORMDB_NilPlugin_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, nil)

	db, err := config.GetTenantGORMDB("any-tenant")
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

func TestGetTenantGORMDB_EmptyTenantID_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, &pluginMock{available: true})

	db, err := config.GetTenantGORMDB("")
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

func TestGetTenantGORMDB_PluginUnavailable_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, &pluginMock{available: false})

	db, err := config.GetTenantGORMDB("tenant-xyz")
	require.NoError(t, err)
	assert.Equal(t, config.DB, db)
}

// ── GetTenantDatabase ─────────────────────────────────────────────────────────

func TestGetTenantDatabase_NilPlugin_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, nil)

	conn, err := config.GetTenantDatabase("tenant-abc")
	require.NoError(t, err)
	assert.Equal(t, config.Database, conn)
}

func TestGetTenantDatabase_EmptyTenantID_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, &pluginMock{available: true})

	conn, err := config.GetTenantDatabase("")
	require.NoError(t, err)
	assert.Equal(t, config.Database, conn)
}

func TestGetTenantDatabase_PluginUnavailable_ReturnsMasterDB(t *testing.T) {
	swapPlugin(t, &pluginMock{available: false})

	conn, err := config.GetTenantDatabase("tenant-xyz")
	require.NoError(t, err)
	assert.Equal(t, config.Database, conn)
}
