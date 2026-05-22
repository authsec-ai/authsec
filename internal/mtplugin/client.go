package mtplugin

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	pb "github.com/authsec-ai/authsec/internal/mtplugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client is the gRPC client for the mt-plugin microservice.
// authsec uses it to notify mt-plugin about new admin registrations and
// to query multi-tenant state when the plugin is available.
type Client struct {
	addr       string
	conn       *grpc.ClientConn
	grpcClient pb.TenantPluginClient
	available  atomic.Bool
}

// NewClient creates a new mt-plugin gRPC client.
// addr is the gRPC address (e.g. "localhost:7469"). Call StartHeartbeat to begin detection.
func NewClient(addr string) *Client {
	return &Client{addr: addr}
}

// connect (re)establishes the gRPC connection.
func (c *Client) connect() error {
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	c.conn = conn
	c.grpcClient = pb.NewTenantPluginClient(conn)
	return nil
}

// StartHeartbeat starts a background goroutine that pings mt-plugin every interval.
// It updates the availability state atomically. Returns immediately.
func (c *Client) StartHeartbeat(ctx context.Context, interval time.Duration) {
	go func() {
		if c.grpcClient == nil {
			if err := c.connect(); err != nil {
				log.Printf("[mtplugin] Initial connect failed: %v — starting in single-tenant mode", err)
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				if c.conn != nil {
					c.conn.Close()
				}
				return
			case <-ticker.C:
				c.ping()
			}
		}
	}()

	// Run first check after a short delay so startup logs appear in order.
	go func() {
		time.Sleep(2 * time.Second)
		c.ping()
	}()
}

func (c *Client) ping() {
	if c.grpcClient == nil {
		if err := c.connect(); err != nil {
			c.available.Store(false)
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := c.grpcClient.HealthCheck(ctx, &pb.HealthRequest{})
	if err != nil {
		if c.available.Load() {
			log.Printf("[mtplugin] Plugin unavailable: %v — operating in single-tenant mode", err)
		}
		c.available.Store(false)
		return
	}

	if !c.available.Load() {
		log.Printf("[mtplugin] Plugin available at %s — multi-tenant admin registration enabled", c.addr)
	}
	c.available.Store(true)
}

// NewClientFromConn creates a Client using an already-established gRPC connection.
// The caller owns the connection lifecycle. The client will not reconnect automatically.
// Useful in tests where callers supply a bufconn-backed connection.
func NewClientFromConn(conn *grpc.ClientConn) *Client {
	c := &Client{}
	c.conn = conn
	c.grpcClient = pb.NewTenantPluginClient(conn)
	return c
}

// IsAvailable reports whether the mt-plugin is reachable.
func (c *Client) IsAvailable() bool {
	return c.available.Load()
}

// PingOnce performs a single HealthCheck round-trip and updates availability.
// It is exported for use in tests; production code uses StartHeartbeat.
func (c *Client) PingOnce() {
	c.ping()
}

// NotifyAdminRegistered informs mt-plugin that a new admin was persisted in the master DB.
// mt-plugin will asynchronously create the tenant DB, run migrations, and seed it.
func (c *Client) NotifyAdminRegistered(req *pb.AdminRegisteredRequest) (*pb.AdminRegisteredResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.grpcClient.AdminRegistered(ctx, req)
}

// ListTenants returns all tenant records via mt-plugin.
func (c *Client) ListTenants() (*pb.ListTenantsResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.grpcClient.ListTenants(ctx, &pb.ListTenantsRequest{})
}

// DeleteTenant asks mt-plugin to drop the tenant DB and remove master DB records.
func (c *Client) DeleteTenant(tenantID string) (*pb.DeleteTenantResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.grpcClient.DeleteTenant(ctx, &pb.DeleteTenantRequest{TenantId: tenantID})
}

// ResolveTenant maps a hostname to a tenant_id via mt-plugin.
func (c *Client) ResolveTenant(hostname string) (*pb.ResolveByDomainResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.grpcClient.ResolveTenantByDomain(ctx, &pb.ResolveByDomainRequest{Hostname: hostname})
}
