package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/authsec-ai/authsec/internal/tenancy"
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
	// SubjectInAnyGroup reports whether userID is a member of any of groupIDs in
	// the workspace (F5 subject-group gate).
	SubjectInAnyGroup(workspaceID uuid.UUID, userID string, groupIDs []string) (bool, error)

	ListActions(providerKey string) ([]models.ConnectorAction, error)
	GetAction(providerKey, actionKey string) (*models.ConnectorAction, error)

	RecordActionAudit(a *models.ConnectorActionAudit) error
	ListActionAudit(workspaceID, connectorID uuid.UUID, limit int) ([]models.ConnectorActionAudit, error)

	GetProviderApp(workspaceID uuid.UUID, providerKey string) (*models.ConnectorProviderApp, error)
	UpsertProviderApp(app *models.ConnectorProviderApp) error
	DeleteProviderApp(workspaceID uuid.UUID, providerKey string) error

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

func (r *connectorRepository) SubjectInAnyGroup(workspaceID uuid.UUID, userID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}
	var count int64
	err := r.db.Table("user_groups").
		Where("workspace_id = ? AND user_id = ?::uuid AND group_id IN ?", workspaceID, userID, groupIDs).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
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

func (r *connectorRepository) DeleteProviderApp(workspaceID uuid.UUID, providerKey string) error {
	return r.db.Delete(&models.ConnectorProviderApp{},
		"workspace_id = ? AND provider_key = ?", workspaceID, providerKey).Error
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

// workspaceContext carries workspaceID as the tenant context for the
// transactional grant and revoke. The callers pass the workspace the request's
// token resolved (and the service has already found the connector in it).
func workspaceContext(workspaceID uuid.UUID) context.Context {
	return tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: workspaceID})
}

// sqlConn is the connection of a transaction opened by tenancy.Transaction,
// for the raw statements that run through tenancy.ExecContext/QueryRowContext
// in that same row-level security transaction.
func sqlConn(tx *gorm.DB) tenancy.Querier { return tx.Statement.ConnPool }

// resolveClientPrincipals maps an OAuth client_id string to the mcp_oauth_clients
// row id (for RS registration) and the owning service_account id (for the role
// binding — role_bindings.check_principal requires a service_account_id). Only
// a service account of ctx's workspace qualifies: a client of another
// workspace is not found.
func resolveClientPrincipals(ctx context.Context, q tenancy.Querier, clientID string) (oauthClientID, serviceAccountID uuid.UUID, err error) {
	err = tenancy.QueryRowContext(ctx, q, `
		SELECT c.id, sa.id
		  FROM service_accounts sa
		  JOIN mcp_oauth_clients c ON c.id = sa.oauth_client_id
		 WHERE sa.workspace_id = $1 AND c.client_id = $2
		 LIMIT 1`, []interface{}{clientID}, &oauthClientID, &serviceAccountID)
	if errors.Is(err, tenancy.ErrNotFound) {
		return uuid.Nil, uuid.Nil, fmt.Errorf("%w: client %q", errClientNotInWorkspace, clientID)
	}
	return oauthClientID, serviceAccountID, err
}

// errClientNotInWorkspace: the client_id is not owned by a service account of
// the connector's workspace. Cross-workspace grants are the A2A case and will
// reuse the XAA first-contact machinery.
var errClientNotInWorkspace = errors.New("no service account of this workspace owns the client; cross-workspace connector grants are not supported")

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

// GrantAssignmentTx runs in one transaction under row-level security for
// in.WorkspaceID; every statement is bound to that workspace.
func (r *connectorRepository) GrantAssignmentTx(in GrantAssignmentInput) (*models.ConnectorAssignment, error) {
	assignment := &models.ConnectorAssignment{
		WorkspaceID:      in.WorkspaceID,
		ConnectorID:      in.ConnectorID,
		ClientID:         in.ClientID,
		ActionKey:        in.ActionKey,
		InputConstraints: in.InputConstraints,
		CreatedBy:        in.CreatedBy,
	}
	ctx := workspaceContext(in.WorkspaceID)
	err := tenancy.Transaction(ctx, r.db, func(tx *gorm.DB) error {
		q := sqlConn(tx)
		// 1. The assignment row (connector → agent allowlist).
		if err := tx.Create(assignment).Error; err != nil {
			return fmt.Errorf("create assignment: %w", err)
		}

		// D6 — same-workspace only: the client must belong to a service account
		// of this workspace.
		oauthClientID, serviceAccountID, err := resolveClientPrincipals(ctx, q, in.ClientID)
		if err != nil {
			return err
		}

		// 2. Broker-RS registration (approved) — the gateway gate. Idempotent on
		//    (resource_server_id, oauth_client_id). The broker RS must be this
		//    workspace's.
		res, err := tenancy.ExecContext(ctx, q, `
			INSERT INTO resource_server_client_registrations
			  (id, resource_server_id, oauth_client_id, status, registration_type, workspace_id, created_at, updated_at)
			SELECT gen_random_uuid(), rs.id, $3, 'approved', 'prereg', rs.workspace_id, now(), now()
			  FROM resource_servers rs
			 WHERE rs.workspace_id = $1 AND rs.id = $2
			ON CONFLICT (resource_server_id, oauth_client_id) DO UPDATE SET status='approved', updated_at=now()`,
			in.BrokerRSID, oauthClientID)
		if err != nil {
			return fmt.Errorf("broker registration: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 0 {
			return fmt.Errorf("broker registration: broker resource server %s not found in the workspace", in.BrokerRSID)
		}

		// 3. connector-executor role (get-or-create), linked to the execute perm.
		if _, err := tenancy.ExecContext(ctx, q, `INSERT INTO roles (id, name, description, workspace_id, is_system, created_at, updated_at)
			SELECT gen_random_uuid(), $2::text, 'Can execute connector actions', $1, false, now(), now()
			 WHERE NOT EXISTS (SELECT 1 FROM roles WHERE workspace_id = $1 AND name = $2::text)
			ON CONFLICT (workspace_id, name) DO NOTHING`, in.ExecuteRoleName); err != nil {
			return fmt.Errorf("executor role: %w", err)
		}
		var roleID uuid.UUID
		if err := tenancy.QueryRowContext(ctx, q,
			`SELECT id FROM roles WHERE workspace_id = $1 AND name = $2`,
			[]interface{}{in.ExecuteRoleName}, &roleID); err != nil {
			return fmt.Errorf("executor role: %w", err)
		}
		// The permission must be a platform one or this workspace's.
		if _, err := tenancy.ExecContext(ctx, q, `
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT r.id, p.id
			  FROM roles r
			  JOIN permissions p ON p.id = $3 AND (p.workspace_id IS NULL OR p.workspace_id = r.workspace_id)
			 WHERE r.workspace_id = $1 AND r.id = $2
			ON CONFLICT DO NOTHING`, roleID, in.ExecutePermID); err != nil {
			return fmt.Errorf("link execute perm: %w", err)
		}

		// 4. Role binding on the service account, scoped to the broker RS.
		//    Idempotent: skip if an equivalent binding already exists.
		if _, err := tenancy.ExecContext(ctx, q, `INSERT INTO role_bindings (id, service_account_id, role_id, scope_type, scope_id, workspace_id, assignment_source, created_at, updated_at)
			SELECT gen_random_uuid(), $2, $3, 'resource_server', $4, $1, 'connector', now(), now() WHERE NOT EXISTS (
			  SELECT 1 FROM role_bindings
			   WHERE workspace_id = $1 AND service_account_id = $2 AND role_id = $3
			     AND scope_type = 'resource_server' AND scope_id = $4
			)`,
			serviceAccountID, roleID, in.BrokerRSID); err != nil {
			return fmt.Errorf("role binding: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return assignment, nil
}

// RevokeAssignmentTx runs in one transaction under row-level security for
// workspaceID; every statement is bound to that workspace.
func (r *connectorRepository) RevokeAssignmentTx(workspaceID, assignmentID, brokerRSID uuid.UUID) error {
	ctx := workspaceContext(workspaceID)
	return tenancy.Transaction(ctx, r.db, func(tx *gorm.DB) error {
		q := sqlConn(tx)
		// Find the assignment (to learn the client_id) before deleting.
		var a models.ConnectorAssignment
		if err := tx.First(&a, "id = ?", assignmentID).Error; err != nil {
			return nil // already gone — nothing to tear down
		}
		if err := tx.Delete(&models.ConnectorAssignment{}, "id = ?", assignmentID).Error; err != nil {
			return fmt.Errorf("delete assignment: %w", err)
		}

		// If the client still has ANY assignment in this workspace, keep its
		// registration + binding. Only tear down on the last one.
		var remaining int64
		if err := tx.Model(&models.ConnectorAssignment{}).
			Where("client_id = ?", a.ClientID).
			Count(&remaining).Error; err != nil {
			return fmt.Errorf("count remaining: %w", err)
		}
		if remaining > 0 {
			return nil
		}

		oauthClientID, serviceAccountID, err := resolveClientPrincipals(ctx, q, a.ClientID)
		if err != nil {
			return nil // client/SA already gone; assignment delete stands
		}
		// Tear down the broker-RS registration + the executor role binding.
		if _, err := tenancy.ExecContext(ctx, q, `DELETE FROM resource_server_client_registrations
			WHERE workspace_id = $1 AND resource_server_id = $2 AND oauth_client_id = $3`, brokerRSID, oauthClientID); err != nil {
			return fmt.Errorf("delete registration: %w", err)
		}
		if _, err := tenancy.ExecContext(ctx, q, `DELETE FROM role_bindings
			WHERE workspace_id = $1 AND service_account_id = $2 AND scope_type = 'resource_server' AND scope_id = $3`,
			serviceAccountID, brokerRSID); err != nil {
			return fmt.Errorf("delete role binding: %w", err)
		}
		return nil
	})
}
