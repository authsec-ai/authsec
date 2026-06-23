package database

import (
	"context"
	"database/sql"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
)

// ConnectionManager manages database connections for multiple tenants.
// It can operate in two modes:
// 1. Adapter mode: wraps an existing master *sql.DB (e.g. from GORM)
// 2. Standalone mode: manages its own connections
type ConnectionManager struct {
	masterDB          *sql.DB
	tenantConnections map[string]*sql.DB
	mu                sync.RWMutex
	logger            *logrus.Entry
	workspaceRepo        repositories.WorkspaceRepository
	maxOpenConns      int
	maxIdleConns      int
	connMaxLifetime   time.Duration
	dbHost            string
	dbPort            int
	dbUsername        string
	dbPassword        string
	dbSSLMode         string
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager(
	masterDB *sql.DB,
	logger *logrus.Entry,
	workspaceRepo repositories.WorkspaceRepository,
	maxOpenConns, maxIdleConns int,
	connMaxLifetime time.Duration,
	dbHost string,
	dbPort int,
	dbUsername, dbPassword, dbSSLMode string,
) *ConnectionManager {
	return &ConnectionManager{
		masterDB:          masterDB,
		tenantConnections: make(map[string]*sql.DB),
		logger:            logger,
		workspaceRepo:        workspaceRepo,
		maxOpenConns:      maxOpenConns,
		maxIdleConns:      maxIdleConns,
		connMaxLifetime:   connMaxLifetime,
		dbHost:            dbHost,
		dbPort:            dbPort,
		dbUsername:        dbUsername,
		dbPassword:        dbPassword,
		dbSSLMode:         dbSSLMode,
	}
}

// GetWorkspaceDB returns the master database connection.
//
// Single master DB architecture: there are no per-tenant databases. All
// workspace data lives in the one master DB, scoped by workspace_id columns.
// This returns masterDB unconditionally so no code path ever tries to open a
// tenant_<workspaceID> database (which does not exist).
func (cm *ConnectionManager) GetWorkspaceDB(ctx context.Context, workspaceID string) (*sql.DB, error) {
	return cm.masterDB, nil
}

// GetWorkspaceDBByName returns the master database connection.
// See GetWorkspaceDB — single master DB architecture, no per-tenant databases.
func (cm *ConnectionManager) GetWorkspaceDBByName(ctx context.Context, workspaceID, dbName string) (*sql.DB, error) {
	return cm.masterDB, nil
}

// Close is a no-op. The master DB is owned by the caller (GORM), not this
// manager, and there are no per-tenant connections to close.
func (cm *ConnectionManager) Close() error {
	return nil
}

// GetMasterDB returns the master database connection
func (cm *ConnectionManager) GetMasterDB() *sql.DB {
	return cm.masterDB
}
