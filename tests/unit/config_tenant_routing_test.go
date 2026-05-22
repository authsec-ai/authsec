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

// GetTenantGORMDB / GetTenantDatabase have been removed. AuthSec is single-DB
// at the product layer — callers use config.DB / config.Database directly and
// scope by workspace_id at row level. The MT plugin remains for tenant
// lifecycle operations exercised by other tests in this package.
