package services

import (
	"fmt"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BrokerResourceURI returns the canonical resource_uri (token audience) for a
// workspace's Connector Broker Resource Server. Every runtime token that the
// broker data plane accepts must be audience-bound to this URI (RFC 8707).
func BrokerResourceURI(workspaceID uuid.UUID) string {
	return fmt.Sprintf("authsec://broker/connectors/%s", workspaceID.String())
}

// EnsureBrokerResourceServer get-or-creates the per-workspace Connector Broker
// Resource Server. It is idempotent and safe to call on any path that needs the
// broker to exist (connector create, action execution). The broker RS is
// system-managed (managed=true, application_type='connector_broker') and is the
// audience for all runtime connector tokens — it is NOT an admin Application and
// carries none of the scanning/manifest lifecycle of a real deployed RS.
func EnsureBrokerResourceServer(db *gorm.DB, workspaceID uuid.UUID) (*models.ResourceServer, error) {
	resourceURI := BrokerResourceURI(workspaceID)

	var rs models.ResourceServer
	err := db.Where("workspace_id = ? AND resource_uri = ?", workspaceID, resourceURI).First(&rs).Error
	if err == nil {
		// Broker RS already exists. Re-assert the connector:execute scope + its
		// permission link here too (idempotent): a broker RS provisioned before
		// this wiring existed would otherwise never get the link, and scope
		// resolution would fail with "no scopes granted" forever.
		if sErr := ensureBrokerExecuteScope(db, workspaceID, rs.ID); sErr != nil {
			return &rs, fmt.Errorf("broker RS exists but failed to reassert execute scope: %w", sErr)
		}
		return &rs, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("lookup broker RS: %w", err)
	}

	rs = models.ResourceServer{
		WorkspaceID:     workspaceID,
		Name:            "Connector Broker",
		PublicBaseURL:   resourceURI,
		ResourceURI:     resourceURI,
		ApplicationType: models.ApplicationTypeConnectorBroker,
		Managed:         true,
		// The broker RS declares the runtime action scope so the scope resolver
		// can grant it into tokens (requested ∩ RS.scopes_supported ∩ RBAC).
		ScopesSupported: []string{BrokerExecuteScope},
		// A managed broker is immediately usable: no scan/setup lifecycle.
		State:  models.RSStateReady,
		Status: "ready",
		Active: true,
	}
	if err := db.Create(&rs).Error; err != nil {
		// Lost a race? Re-read; the unique (workspace_id, resource_uri) makes
		// the winner authoritative.
		var existing models.ResourceServer
		if e2 := db.Where("workspace_id = ? AND resource_uri = ?", workspaceID, resourceURI).First(&existing).Error; e2 == nil {
			return &existing, nil
		}
		return nil, fmt.Errorf("create broker RS: %w", err)
	}

	// Bind the connector:execute OAuth scope to this broker RS and link it to the
	// global connector:execute permission, so the RBAC chain (role → permission →
	// scope) can grant it. Best-effort: a failure here doesn't undo the RS.
	if err := ensureBrokerExecuteScope(db, workspaceID, rs.ID); err != nil {
		return &rs, fmt.Errorf("broker RS created but failed to wire execute scope: %w", err)
	}
	return &rs, nil
}

// BrokerExecuteScope is the OAuth scope a token must carry to invoke connector
// actions on the broker data plane.
const BrokerExecuteScope = "connector:execute"

// ensureBrokerExecuteScope creates the connector:execute oauth_scopes row for
// the broker RS and links it to the global connector:execute permission.
// Idempotent (unique on workspace_id, resource_server_id, scope_string).
func ensureBrokerExecuteScope(db *gorm.DB, workspaceID, rsID uuid.UUID) error {
	scope := models.OAuthScope{
		WorkspaceID:      workspaceID,
		ResourceServerID: &rsID,
		ScopeString:      BrokerExecuteScope,
		DisplayName:      "Execute connector actions",
		Description:      "Invoke connector actions through the AuthSec broker",
		RiskLevel:        "high",
		Source:           "preset",
	}
	if err := db.Where("workspace_id = ? AND resource_server_id = ? AND scope_string = ?",
		workspaceID, rsID, BrokerExecuteScope).FirstOrCreate(&scope).Error; err != nil {
		return fmt.Errorf("create execute scope: %w", err)
	}

	// Link to the global connector:execute permission (workspace_id IS NULL).
	var permID uuid.UUID
	if err := db.Table("permissions").
		Where("workspace_id IS NULL AND resource = 'connector' AND action = 'execute'").
		Limit(1).Pluck("id", &permID).Error; err != nil || permID == uuid.Nil {
		// Permission missing (not seeded) — nothing to link; scope still exists.
		return nil
	}
	link := models.OAuthScopePermission{ScopeID: scope.ID, PermissionID: permID}
	if err := db.Where("scope_id = ? AND permission_id = ?", scope.ID, permID).
		FirstOrCreate(&link).Error; err != nil {
		return fmt.Errorf("link execute scope to permission: %w", err)
	}
	return nil
}
