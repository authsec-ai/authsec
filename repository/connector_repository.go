package repositories

import (
	"encoding/json"
	"fmt"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ConnectorRepository provides workspace-scoped CRUD for connectors and
// read access to the provider catalog.
type ConnectorRepository interface {
	ListProviders() ([]models.ConnectorProvider, error)
	GetProvider(key string) (*models.ConnectorProvider, error)

	Create(c *models.Connector) error
	GetByID(workspaceID uuid.UUID, id uuid.UUID) (*models.Connector, error)
	ListByWorkspace(workspaceID uuid.UUID) ([]models.Connector, error)
	Update(c *models.Connector) error
	Delete(workspaceID uuid.UUID, id uuid.UUID) error

	CreateConnection(conn *models.ConnectorConnection) error
	ListConnections(connectorID uuid.UUID) ([]models.ConnectorConnection, error)
	GetWorkspaceConnection(connectorID uuid.UUID) (*models.ConnectorConnection, error)
	GetUserConnection(connectorID uuid.UUID, subjectUserID string) (*models.ConnectorConnection, error)
	// ListUserConnectionsBySubject returns all of a user's connections in a
	// workspace (their own "connected accounts" view). R4.
	ListUserConnectionsBySubject(workspaceID uuid.UUID, subjectUserID string) ([]models.ConnectorConnection, error)
	// RevokeUserConnection marks a user's connection revoked (status + revoked_at)
	// — the user disconnecting their own provider account. Returns rows affected.
	RevokeUserConnection(workspaceID, connectorID uuid.UUID, subjectUserID string) (int64, error)

	CreateAssignment(a *models.ConnectorAssignment) error
	ListAssignments(connectorID uuid.UUID) ([]models.ConnectorAssignment, error)
	DeleteAssignment(workspaceID, id uuid.UUID) error
	// AssignmentAllows reports whether client_id may invoke action on connector:
	// an all-actions row (action_key IS NULL) OR a row matching the action.
	AssignmentAllows(connectorID uuid.UUID, clientID, actionKey string) (bool, error)
	// MatchingAssignment returns the assignment authorizing (client, connector,
	// action) — action-specific preferred over all-actions — or nil.
	MatchingAssignment(connectorID uuid.UUID, clientID, actionKey string) (*models.ConnectorAssignment, error)

	ListActions(providerKey string) ([]models.ConnectorAction, error)
	GetAction(providerKey, actionKey string) (*models.ConnectorAction, error)

	RecordActionAudit(a *models.ConnectorActionAudit) error
	ListActionAudit(workspaceID, connectorID uuid.UUID, limit int) ([]models.ConnectorActionAudit, error)

	GetProviderApp(workspaceID uuid.UUID, providerKey string) (*models.ConnectorProviderApp, error)
	UpsertProviderApp(app *models.ConnectorProviderApp) error

	// GrantAssignmentTx creates, in ONE transaction: the connector assignment,
	// the broker-RS client registration (approved), and the connector-executor
	// role binding for the client's service account. Idempotent per piece.
	GrantAssignmentTx(in GrantAssignmentInput) (*models.ConnectorAssignment, error)
	// RevokeAssignmentTx deletes an assignment and, if it was the client's LAST
	// assignment in the workspace, tears down the registration + role binding.
	RevokeAssignmentTx(workspaceID, assignmentID uuid.UUID, brokerRSID uuid.UUID) error

	// BrokerGrantContext returns the workspace's broker RS id and the global
	// connector:execute permission id needed to wire a grant.
	BrokerGrantContext(workspaceID uuid.UUID, brokerResourceURI string) (brokerRSID, executePermID uuid.UUID, err error)
}

// GrantAssignmentInput carries everything the one-transaction grant needs. The
// service resolves brokerRSID (EnsureBrokerResourceServer) and the executor
// permission id before calling.
type GrantAssignmentInput struct {
	WorkspaceID      uuid.UUID
	ConnectorID      uuid.UUID
	ClientID         string          // OAuth client_id string of the agent
	ActionKey        *string         // nil => all actions
	InputConstraints json.RawMessage // F3: optional per-assignment input predicate
	CreatedBy        string
	BrokerRSID       uuid.UUID
	ExecutePermID    uuid.UUID // the connector:execute permission to bind
	ExecuteRoleName  string    // e.g. "connector-executor"
}

type connectorRepository struct{ db *gorm.DB }

// NewConnectorRepository constructs a ConnectorRepository.
func NewConnectorRepository(db *gorm.DB) ConnectorRepository {
	return &connectorRepository{db}
}

func (r *connectorRepository) ListProviders() ([]models.ConnectorProvider, error) {
	var providers []models.ConnectorProvider
	err := r.db.Order("display_name").Find(&providers).Error
	return providers, err
}

func (r *connectorRepository) GetProvider(key string) (*models.ConnectorProvider, error) {
	var p models.ConnectorProvider
	err := r.db.First(&p, "key = ?", key).Error
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *connectorRepository) Create(c *models.Connector) error {
	return r.db.Create(c).Error
}

func (r *connectorRepository) GetByID(workspaceID, id uuid.UUID) (*models.Connector, error) {
	var c models.Connector
	err := r.db.First(&c, "id = ? AND workspace_id = ?", id, workspaceID).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *connectorRepository) ListByWorkspace(workspaceID uuid.UUID) ([]models.Connector, error) {
	var conns []models.Connector
	err := r.db.Where("workspace_id = ?", workspaceID).Order("created_at DESC").Find(&conns).Error
	return conns, err
}

func (r *connectorRepository) Update(c *models.Connector) error {
	return r.db.Save(c).Error
}

func (r *connectorRepository) Delete(workspaceID, id uuid.UUID) error {
	return r.db.Delete(&models.Connector{}, "id = ? AND workspace_id = ?", id, workspaceID).Error
}

func (r *connectorRepository) CreateConnection(conn *models.ConnectorConnection) error {
	return r.db.Create(conn).Error
}

func (r *connectorRepository) ListConnections(connectorID uuid.UUID) ([]models.ConnectorConnection, error) {
	var conns []models.ConnectorConnection
	err := r.db.Where("connector_id = ?", connectorID).Order("scope, created_at").Find(&conns).Error
	return conns, err
}

func (r *connectorRepository) GetWorkspaceConnection(connectorID uuid.UUID) (*models.ConnectorConnection, error) {
	var conn models.ConnectorConnection
	err := r.db.First(&conn, "connector_id = ? AND binding_type = ?", connectorID, models.ConnectionBindingWorkspace).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

func (r *connectorRepository) GetUserConnection(connectorID uuid.UUID, subjectUserID string) (*models.ConnectorConnection, error) {
	var conn models.ConnectorConnection
	err := r.db.First(&conn, "connector_id = ? AND binding_type = ? AND subject_user_id = ?::uuid",
		connectorID, models.ConnectionBindingUser, subjectUserID).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

func (r *connectorRepository) ListUserConnectionsBySubject(workspaceID uuid.UUID, subjectUserID string) ([]models.ConnectorConnection, error) {
	var conns []models.ConnectorConnection
	err := r.db.Where("workspace_id = ? AND binding_type = ? AND subject_user_id = ?::uuid",
		workspaceID, models.ConnectionBindingUser, subjectUserID).
		Order("created_at DESC").Find(&conns).Error
	return conns, err
}

func (r *connectorRepository) RevokeUserConnection(workspaceID, connectorID uuid.UUID, subjectUserID string) (int64, error) {
	res := r.db.Model(&models.ConnectorConnection{}).
		Where("workspace_id = ? AND connector_id = ? AND binding_type = ? AND subject_user_id = ?::uuid",
			workspaceID, connectorID, models.ConnectionBindingUser, subjectUserID).
		Updates(map[string]interface{}{"status": models.ConnectionStatusRevoked, "revoked_at": gorm.Expr("now()")})
	return res.RowsAffected, res.Error
}

func (r *connectorRepository) CreateAssignment(a *models.ConnectorAssignment) error {
	return r.db.Create(a).Error
}

func (r *connectorRepository) ListAssignments(connectorID uuid.UUID) ([]models.ConnectorAssignment, error) {
	var as []models.ConnectorAssignment
	err := r.db.Where("connector_id = ?", connectorID).Order("created_at").Find(&as).Error
	return as, err
}

func (r *connectorRepository) DeleteAssignment(workspaceID, id uuid.UUID) error {
	return r.db.Delete(&models.ConnectorAssignment{}, "id = ? AND workspace_id = ?", id, workspaceID).Error
}

func (r *connectorRepository) AssignmentAllows(connectorID uuid.UUID, clientID, actionKey string) (bool, error) {
	var count int64
	err := r.db.Model(&models.ConnectorAssignment{}).
		Where("connector_id = ? AND client_id = ? AND (action_key IS NULL OR action_key = ?)",
			connectorID, clientID, actionKey).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// MatchingAssignment returns the assignment that authorizes (client, connector,
// action), or nil if none. An action-specific row (action_key = actionKey) wins
// over an all-actions row (action_key IS NULL) so its input_constraints apply.
func (r *connectorRepository) MatchingAssignment(connectorID uuid.UUID, clientID, actionKey string) (*models.ConnectorAssignment, error) {
	var as []models.ConnectorAssignment
	if err := r.db.Where("connector_id = ? AND client_id = ? AND (action_key IS NULL OR action_key = ?)",
		connectorID, clientID, actionKey).Find(&as).Error; err != nil {
		return nil, err
	}
	if len(as) == 0 {
		return nil, nil
	}
	best := &as[0]
	for i := range as {
		if as[i].ActionKey != nil && *as[i].ActionKey == actionKey {
			return &as[i], nil // exact-action match takes precedence
		}
	}
	return best, nil
}

func (r *connectorRepository) ListActions(providerKey string) ([]models.ConnectorAction, error) {
	var actions []models.ConnectorAction
	err := r.db.Where("provider_key = ?", providerKey).Order("action_key").Find(&actions).Error
	return actions, err
}

func (r *connectorRepository) GetAction(providerKey, actionKey string) (*models.ConnectorAction, error) {
	var a models.ConnectorAction
	err := r.db.First(&a, "provider_key = ? AND action_key = ?", providerKey, actionKey).Error
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *connectorRepository) RecordActionAudit(a *models.ConnectorActionAudit) error {
	return r.db.Create(a).Error
}

func (r *connectorRepository) ListActionAudit(workspaceID, connectorID uuid.UUID, limit int) ([]models.ConnectorActionAudit, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows []models.ConnectorActionAudit
	err := r.db.Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Order("created_at DESC").Limit(limit).Find(&rows).Error
	return rows, err
}

func (r *connectorRepository) GetProviderApp(workspaceID uuid.UUID, providerKey string) (*models.ConnectorProviderApp, error) {
	var app models.ConnectorProviderApp
	err := r.db.First(&app, "workspace_id = ? AND provider_key = ?", workspaceID, providerKey).Error
	if err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *connectorRepository) UpsertProviderApp(app *models.ConnectorProviderApp) error {
	// Upsert on (workspace_id, provider_key): update all mutable fields, incl. the
	// app kind + GitHub-App id so an oauth2↔github_app reconfigure takes effect.
	return r.db.Where("workspace_id = ? AND provider_key = ?", app.WorkspaceID, app.ProviderKey).
		Assign(map[string]interface{}{
			"app_kind":      app.AppKind,
			"client_id":     app.ClientID,
			"redirect_uri":  app.RedirectURI,
			"github_app_id": app.GitHubAppID,
			"vault_path":    app.VaultPath,
			"updated_at":    gorm.Expr("now()"),
		}).
		FirstOrCreate(app).Error
}

// resolveClientPrincipals maps an OAuth client_id string to the mcp_oauth_clients
// row id (for RS registration) and the owning service_account id (for the role
// binding — role_bindings.check_principal requires a service_account_id).
func resolveClientPrincipals(tx *gorm.DB, clientID string) (oauthClientID, serviceAccountID, saWorkspaceID uuid.UUID, err error) {
	var mc struct{ ID uuid.UUID }
	if e := tx.Table("mcp_oauth_clients").Select("id").Where("client_id = ?", clientID).First(&mc).Error; e != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("no OAuth client for client_id %q: %w", clientID, e)
	}
	var sa struct {
		ID          uuid.UUID
		WorkspaceID uuid.UUID
	}
	if e := tx.Table("service_accounts").Select("id, workspace_id").Where("oauth_client_id = ?", mc.ID).First(&sa).Error; e != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, fmt.Errorf("no service account owns client %q: %w", clientID, e)
	}
	return mc.ID, sa.ID, sa.WorkspaceID, nil
}

func (r *connectorRepository) BrokerGrantContext(workspaceID uuid.UUID, brokerResourceURI string) (uuid.UUID, uuid.UUID, error) {
	var rs struct{ ID uuid.UUID }
	if err := r.db.Table("resource_servers").Select("id").
		Where("workspace_id = ? AND resource_uri = ?", workspaceID, brokerResourceURI).First(&rs).Error; err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("broker resource server not found (create a connector first): %w", err)
	}
	var perm struct{ ID uuid.UUID }
	if err := r.db.Table("permissions").Select("id").
		Where("resource = 'connector' AND action = 'execute' AND workspace_id IS NULL").First(&perm).Error; err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("connector:execute permission not found: %w", err)
	}
	return rs.ID, perm.ID, nil
}

func (r *connectorRepository) GrantAssignmentTx(in GrantAssignmentInput) (*models.ConnectorAssignment, error) {
	assignment := &models.ConnectorAssignment{
		WorkspaceID:      in.WorkspaceID,
		ConnectorID:      in.ConnectorID,
		ClientID:         in.ClientID,
		ActionKey:        in.ActionKey,
		InputConstraints: in.InputConstraints,
		CreatedBy:        in.CreatedBy,
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		// 1. The assignment row (connector → agent allowlist).
		if err := tx.Create(assignment).Error; err != nil {
			return fmt.Errorf("create assignment: %w", err)
		}

		oauthClientID, serviceAccountID, saWorkspaceID, err := resolveClientPrincipals(tx, in.ClientID)
		if err != nil {
			return err
		}
		// D6 — same-workspace only. A foreign-workspace client_id would bind a
		// service account into this connector's workspace, which the role-binding
		// FK forbids; reject it cleanly rather than fail awkwardly. Cross-workspace
		// grants are the A2A case and will reuse the XAA first-contact machinery.
		if saWorkspaceID != in.WorkspaceID {
			return fmt.Errorf("client %q belongs to a different workspace; cross-workspace connector grants are not supported", in.ClientID)
		}

		// 2. Broker-RS registration (approved) — the gateway gate. Idempotent on
		//    (resource_server_id, oauth_client_id).
		if err := tx.Exec(`
			INSERT INTO resource_server_client_registrations
			  (id, resource_server_id, oauth_client_id, status, registration_type, workspace_id, created_at, updated_at)
			VALUES (gen_random_uuid(), ?, ?, 'approved', 'prereg', ?, now(), now())
			ON CONFLICT (resource_server_id, oauth_client_id) DO UPDATE SET status='approved', updated_at=now()`,
			in.BrokerRSID, oauthClientID, in.WorkspaceID).Error; err != nil {
			return fmt.Errorf("broker registration: %w", err)
		}

		// 3. connector-executor role (get-or-create), linked to the execute perm.
		var roleID uuid.UUID
		if err := tx.Raw(`
			INSERT INTO roles (id, name, description, workspace_id, is_system, created_at, updated_at)
			VALUES (gen_random_uuid(), ?, 'Can execute connector actions', ?, false, now(), now())
			ON CONFLICT (workspace_id, name) DO UPDATE SET updated_at=now()
			RETURNING id`, in.ExecuteRoleName, in.WorkspaceID).Scan(&roleID).Error; err != nil {
			return fmt.Errorf("executor role: %w", err)
		}
		if err := tx.Exec(`
			INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)
			ON CONFLICT DO NOTHING`, roleID, in.ExecutePermID).Error; err != nil {
			return fmt.Errorf("link execute perm: %w", err)
		}

		// 4. Role binding on the service account, scoped to the broker RS.
		//    Idempotent: skip if an equivalent binding already exists.
		if err := tx.Exec(`
			INSERT INTO role_bindings
			  (id, service_account_id, role_id, scope_type, scope_id, workspace_id, assignment_source, created_at, updated_at)
			SELECT gen_random_uuid(), ?, ?, 'resource_server', ?, ?, 'connector', now(), now()
			WHERE NOT EXISTS (
			  SELECT 1 FROM role_bindings
			  WHERE service_account_id=? AND role_id=? AND scope_type='resource_server' AND scope_id=?
			)`,
			serviceAccountID, roleID, in.BrokerRSID, in.WorkspaceID,
			serviceAccountID, roleID, in.BrokerRSID).Error; err != nil {
			return fmt.Errorf("role binding: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return assignment, nil
}

func (r *connectorRepository) RevokeAssignmentTx(workspaceID, assignmentID, brokerRSID uuid.UUID) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Find the assignment (to learn the client_id) before deleting.
		var a models.ConnectorAssignment
		if err := tx.First(&a, "id = ? AND workspace_id = ?", assignmentID, workspaceID).Error; err != nil {
			return nil // already gone — nothing to tear down
		}
		if err := tx.Delete(&models.ConnectorAssignment{}, "id = ? AND workspace_id = ?", assignmentID, workspaceID).Error; err != nil {
			return fmt.Errorf("delete assignment: %w", err)
		}

		// If the client still has ANY assignment in this workspace, keep its
		// registration + binding. Only tear down on the last one.
		var remaining int64
		if err := tx.Model(&models.ConnectorAssignment{}).
			Where("workspace_id = ? AND client_id = ?", workspaceID, a.ClientID).
			Count(&remaining).Error; err != nil {
			return fmt.Errorf("count remaining: %w", err)
		}
		if remaining > 0 {
			return nil
		}

		oauthClientID, serviceAccountID, _, err := resolveClientPrincipals(tx, a.ClientID)
		if err != nil {
			return nil // client/SA already gone; assignment delete stands
		}
		// Tear down the broker-RS registration + the executor role binding.
		if err := tx.Exec(`DELETE FROM resource_server_client_registrations
			WHERE resource_server_id = ? AND oauth_client_id = ?`, brokerRSID, oauthClientID).Error; err != nil {
			return fmt.Errorf("delete registration: %w", err)
		}
		if err := tx.Exec(`DELETE FROM role_bindings
			WHERE service_account_id = ? AND scope_type='resource_server' AND scope_id = ?`,
			serviceAccountID, brokerRSID).Error; err != nil {
			return fmt.Errorf("delete role binding: %w", err)
		}
		return nil
	})
}
