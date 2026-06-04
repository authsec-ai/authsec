package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	spireerrors "github.com/authsec-ai/authsec/internal/spire/errors"
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

// GetWorkspaceDB returns a database connection for the given tenant
func (cm *ConnectionManager) GetWorkspaceDB(ctx context.Context, workspaceID string) (*sql.DB, error) {
	cm.mu.RLock()
	db, exists := cm.tenantConnections[workspaceID]
	cm.mu.RUnlock()

	if exists {
		if err := db.PingContext(ctx); err == nil {
			return db, nil
		}
		cm.removeTenantConnection(workspaceID)
	}

	return cm.createTenantConnection(ctx, workspaceID)
}

// GetWorkspaceDBByName returns a database connection using the tenant database name directly
func (cm *ConnectionManager) GetWorkspaceDBByName(ctx context.Context, workspaceID, dbName string) (*sql.DB, error) {
	cm.mu.RLock()
	db, exists := cm.tenantConnections[workspaceID]
	cm.mu.RUnlock()

	if exists {
		if err := db.PingContext(ctx); err == nil {
			return db, nil
		}
		cm.removeTenantConnection(workspaceID)
	}

	return cm.createTenantConnectionByName(ctx, workspaceID, dbName)
}

func (cm *ConnectionManager) createTenantConnection(ctx context.Context, workspaceID string) (*sql.DB, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if db, exists := cm.tenantConnections[workspaceID]; exists {
		return db, nil
	}

	tenant, err := cm.workspaceRepo.GetByID(ctx, workspaceID)
	if err != nil {
		return nil, spireerrors.NewNotFoundError("Tenant not found", err)
	}

	if !tenant.IsActive() {
		return nil, spireerrors.NewForbiddenError("Tenant is not active", nil)
	}

	tenantDBName := "tenant_" + strings.ReplaceAll(workspaceID, "-", "_")

	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cm.dbHost, cm.dbPort, tenantDBName, cm.dbUsername, cm.dbPassword, cm.dbSSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		cm.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "db_name": tenantDBName}).WithError(err).Error("Failed to open tenant database")
		return nil, spireerrors.NewInternalError("Failed to connect to tenant database", err)
	}

	db.SetMaxOpenConns(cm.maxOpenConns)
	db.SetMaxIdleConns(cm.maxIdleConns)
	db.SetConnMaxLifetime(cm.connMaxLifetime)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		cm.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "db_name": tenantDBName}).WithError(err).Error("Failed to ping tenant database")
		return nil, spireerrors.NewInternalError("Failed to connect to tenant database", err)
	}

	cm.tenantConnections[workspaceID] = db
	cm.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "db_name": tenantDBName}).Info("Created tenant database connection")
	return db, nil
}

func (cm *ConnectionManager) createTenantConnectionByName(ctx context.Context, workspaceID, dbName string) (*sql.DB, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if db, exists := cm.tenantConnections[workspaceID]; exists {
		return db, nil
	}

	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		cm.dbHost, cm.dbPort, dbName, cm.dbUsername, cm.dbPassword, cm.dbSSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		cm.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "db_name": dbName}).WithError(err).Error("Failed to open tenant database")
		return nil, spireerrors.NewInternalError("Failed to connect to tenant database", err)
	}

	db.SetMaxOpenConns(cm.maxOpenConns)
	db.SetMaxIdleConns(cm.maxIdleConns)
	db.SetConnMaxLifetime(cm.connMaxLifetime)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		cm.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "db_name": dbName}).WithError(err).Error("Failed to ping tenant database")
		return nil, spireerrors.NewInternalError("Failed to connect to tenant database", err)
	}

	cm.tenantConnections[workspaceID] = db
	cm.logger.WithFields(logrus.Fields{"workspace_id": workspaceID, "db_name": dbName}).Info("Created tenant database connection by name")
	return db, nil
}

func (cm *ConnectionManager) removeTenantConnection(workspaceID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if db, exists := cm.tenantConnections[workspaceID]; exists {
		db.Close()
		delete(cm.tenantConnections, workspaceID)
		cm.logger.WithField("workspace_id", workspaceID).Info("Removed tenant database connection")
	}
}

// Close closes all connections
func (cm *ConnectionManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var lastErr error
	for workspaceID, db := range cm.tenantConnections {
		if err := db.Close(); err != nil {
			cm.logger.WithField("workspace_id", workspaceID).WithError(err).Error("Failed to close tenant connection")
			lastErr = err
		}
	}
	return lastErr
}

// GetMasterDB returns the master database connection
func (cm *ConnectionManager) GetMasterDB() *sql.DB {
	return cm.masterDB
}
