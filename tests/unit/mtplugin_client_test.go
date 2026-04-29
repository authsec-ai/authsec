package unit

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/mtplugin"
	pb "github.com/authsec-ai/authsec/internal/mtplugin/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufConnSize = 1 << 20 // 1 MiB

// ── Fake gRPC server ──────────────────────────────────────────────────────────

type fakePluginServer struct {
	pb.UnimplementedTenantPluginServer

	healthErr    error
	adminRegResp *pb.AdminRegisteredResponse
	listResp     *pb.ListTenantsResponse
	deleteErr    error
	resolveResp  *pb.ResolveByDomainResponse
}

func (f *fakePluginServer) HealthCheck(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	if f.healthErr != nil {
		return nil, f.healthErr
	}
	return &pb.HealthResponse{Status: "ok", Version: "test"}, nil
}

func (f *fakePluginServer) AdminRegistered(_ context.Context, req *pb.AdminRegisteredRequest) (*pb.AdminRegisteredResponse, error) {
	if f.adminRegResp != nil {
		return f.adminRegResp, nil
	}
	return &pb.AdminRegisteredResponse{Success: true, DbName: "tenant_" + req.TenantId}, nil
}

func (f *fakePluginServer) ListTenants(_ context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	if f.listResp != nil {
		return f.listResp, nil
	}
	return &pb.ListTenantsResponse{}, nil
}

func (f *fakePluginServer) DeleteTenant(_ context.Context, req *pb.DeleteTenantRequest) (*pb.DeleteTenantResponse, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	return &pb.DeleteTenantResponse{Success: true, Message: "deleted " + req.TenantId}, nil
}

func (f *fakePluginServer) ResolveTenantByDomain(_ context.Context, req *pb.ResolveByDomainRequest) (*pb.ResolveByDomainResponse, error) {
	if f.resolveResp != nil {
		return f.resolveResp, nil
	}
	return &pb.ResolveByDomainResponse{Found: false}, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func startServer(t *testing.T, fake *fakePluginServer) func(context.Context, string) (net.Conn, error) {
	t.Helper()
	lis := bufconn.Listen(bufConnSize)
	s := grpc.NewServer()
	pb.RegisterTenantPluginServer(s, fake)
	t.Cleanup(func() { s.Stop(); lis.Close() })
	go func() { _ = s.Serve(lis) }()
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}
}

func connectBufconn(t *testing.T, fake *fakePluginServer) *mtplugin.Client {
	t.Helper()
	dialer := startServer(t, fake)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return mtplugin.NewClientFromConn(conn) // exported constructor
}

// ── IsAvailable ───────────────────────────────────────────────────────────────

func TestMTPluginClient_InitiallyUnavailable(t *testing.T) {
	c := mtplugin.NewClient("unreachable:9999")
	assert.False(t, c.IsAvailable())
}

func TestMTPluginClient_AvailableAfterSuccessfulPing(t *testing.T) {
	c := connectBufconn(t, &fakePluginServer{})
	c.PingOnce()
	assert.True(t, c.IsAvailable())
}

func TestMTPluginClient_UnavailableWhenHealthFails(t *testing.T) {
	fake := &fakePluginServer{
		healthErr: status.Error(codes.Unavailable, "down"),
	}
	c := connectBufconn(t, fake)
	c.PingOnce()
	assert.False(t, c.IsAvailable())
}

// ── NotifyAdminRegistered ─────────────────────────────────────────────────────

func TestMTPluginClient_NotifyAdminRegistered_Success(t *testing.T) {
	c := connectBufconn(t, &fakePluginServer{})

	resp, err := c.NotifyAdminRegistered(&pb.AdminRegisteredRequest{
		TenantId: "t-abc",
		Email:    "admin@example.com",
		DbName:   "tenant_abc",
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestMTPluginClient_NotifyAdminRegistered_CustomResponse(t *testing.T) {
	fake := &fakePluginServer{
		adminRegResp: &pb.AdminRegisteredResponse{Success: false, DbName: "custom_db"},
	}
	c := connectBufconn(t, fake)

	resp, err := c.NotifyAdminRegistered(&pb.AdminRegisteredRequest{TenantId: "t1"})
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Equal(t, "custom_db", resp.DbName)
}

// ── ListTenants ───────────────────────────────────────────────────────────────

func TestMTPluginClient_ListTenants_Empty(t *testing.T) {
	c := connectBufconn(t, &fakePluginServer{})

	resp, err := c.ListTenants()
	require.NoError(t, err)
	assert.Empty(t, resp.Tenants)
}

func TestMTPluginClient_ListTenants_Multiple(t *testing.T) {
	fake := &fakePluginServer{
		listResp: &pb.ListTenantsResponse{
			Tenants: []*pb.TenantInfo{
				{TenantId: "t1", Email: "a@example.com"},
				{TenantId: "t2", Email: "b@example.com"},
			},
			Total: 2,
		},
	}
	c := connectBufconn(t, fake)

	resp, err := c.ListTenants()
	require.NoError(t, err)
	assert.Len(t, resp.Tenants, 2)
	assert.EqualValues(t, 2, resp.Total)
}

// ── DeleteTenant ──────────────────────────────────────────────────────────────

func TestMTPluginClient_DeleteTenant_Success(t *testing.T) {
	c := connectBufconn(t, &fakePluginServer{})

	resp, err := c.DeleteTenant("tenant-x")
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Contains(t, resp.Message, "tenant-x")
}

func TestMTPluginClient_DeleteTenant_NotFound(t *testing.T) {
	fake := &fakePluginServer{
		deleteErr: status.Error(codes.NotFound, "tenant not found"),
	}
	c := connectBufconn(t, fake)

	_, err := c.DeleteTenant("ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant not found")
}

// ── ResolveTenant ─────────────────────────────────────────────────────────────

func TestMTPluginClient_ResolveTenant_NotFound(t *testing.T) {
	c := connectBufconn(t, &fakePluginServer{})

	resp, err := c.ResolveTenant("unknown.host")
	require.NoError(t, err)
	assert.False(t, resp.Found)
}

func TestMTPluginClient_ResolveTenant_Found(t *testing.T) {
	fake := &fakePluginServer{
		resolveResp: &pb.ResolveByDomainResponse{TenantId: "found-uuid", Found: true},
	}
	c := connectBufconn(t, fake)

	resp, err := c.ResolveTenant("my.tenant.host")
	require.NoError(t, err)
	assert.True(t, resp.Found)
	assert.Equal(t, "found-uuid", resp.TenantId)
}

// ── Heartbeat (skipped in -short) ─────────────────────────────────────────────

func TestMTPluginClient_PingOnce_FlipsAvailability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heartbeat timing test in -short mode")
	}

	fake := &fakePluginServer{}
	c := connectBufconn(t, fake)

	assert.False(t, c.IsAvailable(), "initially unavailable")
	c.PingOnce()
	assert.True(t, c.IsAvailable(), "available after successful ping")

	fake.healthErr = status.Error(codes.Internal, "crash")
	c.PingOnce()
	assert.False(t, c.IsAvailable(), "unavailable after failed ping")
}

func TestMTPluginClient_StartHeartbeat_SetsAvailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heartbeat timing test in -short mode")
	}

	fake := &fakePluginServer{}
	c := connectBufconn(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.StartHeartbeat(ctx, 50*time.Millisecond)

	time.Sleep(300 * time.Millisecond)
	assert.True(t, c.IsAvailable())
}
