package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
)

// ConnectorManager holds business logic for connectors: catalog validation,
// the config/secret split, Vault storage, and workspace-scoped CRUD.
type ConnectorManager interface {
	ListProviders() ([]models.ConnectorProvider, error)
	Create(workspaceID uuid.UUID, createdBy string, in ConnectorInput) (*models.Connector, error)
	Get(workspaceID, id uuid.UUID) (*models.Connector, error)
	List(workspaceID uuid.UUID) ([]models.Connector, error)
	Update(workspaceID, id uuid.UUID, in ConnectorUpdateInput) (*models.Connector, error)
	Delete(workspaceID, id uuid.UUID) error
	Connections(connectorID uuid.UUID) ([]models.ConnectorConnection, error)

	// ResolveActionCredential selects the connection to use for a broker action
	// and reads its secret from Vault. If subjectUserID is non-empty (delegated
	// call), it prefers the matching user-scope connection; otherwise it uses the
	// workspace-scope connection. Fails closed on missing/inactive connection.
	// This is broker-side only — the secret is never returned to a caller.
	ResolveActionCredential(connectorID uuid.UUID, subjectUserID string) (*ResolvedCredential, error)

	// Assignment management (grant an agent access to a connector + action).
	GrantAssignment(workspaceID, connectorID uuid.UUID, clientID string, actionKey *string, createdBy string) (*models.ConnectorAssignment, error)
	ListAssignments(workspaceID, connectorID uuid.UUID) ([]models.ConnectorAssignment, error)
	RevokeAssignment(workspaceID, assignmentID uuid.UUID) error

	// AuditLog returns recent action-audit records for a connector (who/act/
	// token/outcome). Workspace-scoped.
	AuditLog(workspaceID, connectorID uuid.UUID, limit int) ([]models.ConnectorActionAudit, error)
}

// ResolvedCredential is the broker-side result of connection resolution: the
// secret material for the adapter plus the connection it came from (for audit).
type ResolvedCredential struct {
	Connection *models.ConnectorConnection
	Secret     map[string]interface{}
}

// ConnectorInput is the validated create payload.
type ConnectorInput struct {
	ProviderKey     string
	Name            string
	Enabled         *bool
	Config          map[string]interface{}
	Subscriptions   json.RawMessage
	AgentAccessible bool
	Secrets         map[string]interface{}
}

// ConnectorUpdateInput captures the patchable fields on a connector.
type ConnectorUpdateInput struct {
	Name            *string
	Enabled         *bool
	Config          map[string]interface{}
	Subscriptions   json.RawMessage
	AgentAccessible *bool
	Secrets         map[string]interface{}
}

type connectorManager struct {
	repo  repositories.ConnectorRepository
	vault vault.VaultClient
}

// NewConnectorManager constructs a ConnectorManager.
func NewConnectorManager(repo repositories.ConnectorRepository, vaultClient vault.VaultClient) ConnectorManager {
	return &connectorManager{repo: repo, vault: vaultClient}
}

func (m *connectorManager) ListProviders() ([]models.ConnectorProvider, error) {
	return m.repo.ListProviders()
}

func (m *connectorManager) Create(workspaceID uuid.UUID, createdBy string, in ConnectorInput) (*models.Connector, error) {
	if in.Name == "" || in.ProviderKey == "" {
		return nil, errors.New("name and provider_key are required")
	}
	provider, err := m.repo.GetProvider(in.ProviderKey)
	if err != nil {
		return nil, fmt.Errorf("unknown provider_key %q", in.ProviderKey)
	}

	// Any config key declared secret for this provider must come via Secrets,
	// not Config — keep secrets out of Postgres.
	if err := rejectSecretsInConfig(provider, in.Config); err != nil {
		return nil, err
	}

	configJSON, err := marshalConfig(in.Config)
	if err != nil {
		return nil, err
	}
	subs := in.Subscriptions
	if len(subs) == 0 {
		subs = json.RawMessage("[]")
	}

	id := uuid.New()
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/connectors/%s", workspaceID.String(), id.String())

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	conn := &models.Connector{
		ID:              id,
		WorkspaceID:     workspaceID,
		ProviderKey:     in.ProviderKey,
		Name:            in.Name,
		Enabled:         enabled,
		Config:          configJSON,
		Subscriptions:   subs,
		AgentAccessible: in.AgentAccessible,
		CreatedBy:       createdBy,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	hasSecrets := len(in.Secrets) > 0
	if hasSecrets {
		if m.vault == nil {
			return nil, errors.New("vault client not initialized, cannot store secrets")
		}
		if err := m.vault.WriteSecret(vaultPath, in.Secrets); err != nil {
			return nil, fmt.Errorf("failed to store credentials in vault: %w", err)
		}
		conn.VaultPath = vaultPath
	}

	if err := m.repo.Create(conn); err != nil {
		if conn.VaultPath != "" {
			m.vault.DeleteSecret(conn.VaultPath) // best-effort rollback
		}
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	// P1: a static api_key connector materializes a workspace-scope Connection
	// holding the credential binding. The Connection reuses the connector's
	// Vault path so existing secret material is unaffected.
	if hasSecrets {
		wsConn := &models.ConnectorConnection{
			WorkspaceID: workspaceID,
			ConnectorID: conn.ID,
			BindingType: models.ConnectionBindingWorkspace,
			Status:      models.ConnectionStatusActive,
			AuthMethod:  models.ConnectionAuthAPIKey,
			VaultPath:   conn.VaultPath,
		}
		if err := m.repo.CreateConnection(wsConn); err != nil {
			// Connector is created; surface the binding failure rather than
			// silently leaving it without a Connection.
			return nil, fmt.Errorf("connector created but failed to record workspace connection: %w", err)
		}
	}
	return conn, nil
}

func (m *connectorManager) Get(workspaceID, id uuid.UUID) (*models.Connector, error) {
	return m.repo.GetByID(workspaceID, id)
}

func (m *connectorManager) List(workspaceID uuid.UUID) ([]models.Connector, error) {
	return m.repo.ListByWorkspace(workspaceID)
}

func (m *connectorManager) Update(workspaceID, id uuid.UUID, in ConnectorUpdateInput) (*models.Connector, error) {
	conn, err := m.repo.GetByID(workspaceID, id)
	if err != nil {
		return nil, errors.New("connector not found")
	}
	provider, err := m.repo.GetProvider(conn.ProviderKey)
	if err != nil {
		return nil, fmt.Errorf("provider %q no longer in catalog", conn.ProviderKey)
	}

	if in.Name != nil {
		conn.Name = *in.Name
	}
	if in.Enabled != nil {
		conn.Enabled = *in.Enabled
	}
	if in.AgentAccessible != nil {
		conn.AgentAccessible = *in.AgentAccessible
	}
	if in.Config != nil {
		if err := rejectSecretsInConfig(provider, in.Config); err != nil {
			return nil, err
		}
		configJSON, err := marshalConfig(in.Config)
		if err != nil {
			return nil, err
		}
		conn.Config = configJSON
	}
	if in.Subscriptions != nil {
		conn.Subscriptions = in.Subscriptions
	}

	if len(in.Secrets) > 0 {
		if m.vault == nil {
			return nil, errors.New("vault client not configured")
		}
		if conn.VaultPath == "" {
			conn.VaultPath = fmt.Sprintf("kv/data/secret/workspaces/%s/connectors/%s", workspaceID.String(), conn.ID.String())
		}
		if err := m.vault.WriteSecret(conn.VaultPath, in.Secrets); err != nil {
			return nil, fmt.Errorf("failed to update credentials in vault: %w", err)
		}
	}

	conn.UpdatedAt = time.Now()
	if err := m.repo.Update(conn); err != nil {
		return nil, err
	}
	return conn, nil
}

func (m *connectorManager) Delete(workspaceID, id uuid.UUID) error {
	conn, err := m.repo.GetByID(workspaceID, id)
	if err != nil {
		return errors.New("connector not found")
	}
	if err := m.repo.Delete(workspaceID, id); err != nil {
		return err
	}
	if m.vault != nil && conn.VaultPath != "" {
		if err := m.vault.DeleteSecret(conn.VaultPath); err != nil {
			log.Printf("CONNECTOR: failed to delete vault secret for %s: %v", id, err)
		}
	}
	return nil
}

// Connections returns all credential bindings for a connector (workspace + user
// scope) with their lifecycle metadata. Secret material is never included.
func (m *connectorManager) Connections(connectorID uuid.UUID) ([]models.ConnectorConnection, error) {
	return m.repo.ListConnections(connectorID)
}

// GrantAssignment grants a client (agent) access to a connector, optionally
// scoped to one action (nil actionKey => all actions). Validates the connector
// belongs to the workspace and, when an action is named, that it exists for the
// provider.
func (m *connectorManager) GrantAssignment(workspaceID, connectorID uuid.UUID, clientID string, actionKey *string, createdBy string) (*models.ConnectorAssignment, error) {
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}
	conn, err := m.repo.GetByID(workspaceID, connectorID)
	if err != nil {
		return nil, errors.New("connector not found")
	}
	if actionKey != nil && *actionKey != "" {
		if _, err := m.repo.GetAction(conn.ProviderKey, *actionKey); err != nil {
			return nil, fmt.Errorf("unknown action %q for provider %q", *actionKey, conn.ProviderKey)
		}
	} else {
		actionKey = nil // normalize "" → all-actions
	}
	// One-transaction grant: assignment + broker-RS registration (approved) +
	// connector-executor role binding, all-or-nothing. Enabling an agent is now a
	// single API call instead of 4 authorizations across 4 tables.
	brokerRSID, permID, err := m.brokerGrantContext(workspaceID)
	if err != nil {
		return nil, err
	}
	a, err := m.repo.GrantAssignmentTx(repositories.GrantAssignmentInput{
		WorkspaceID:     workspaceID,
		ConnectorID:     connectorID,
		ClientID:        clientID,
		ActionKey:       actionKey,
		CreatedBy:       createdBy,
		BrokerRSID:      brokerRSID,
		ExecutePermID:   permID,
		ExecuteRoleName: "connector-executor",
	})
	if err != nil {
		return nil, fmt.Errorf("grant assignment: %w", err)
	}
	return a, nil
}

// ListAssignments lists a connector's assignments (workspace-scoped).
func (m *connectorManager) ListAssignments(workspaceID, connectorID uuid.UUID) ([]models.ConnectorAssignment, error) {
	if _, err := m.repo.GetByID(workspaceID, connectorID); err != nil {
		return nil, errors.New("connector not found")
	}
	return m.repo.ListAssignments(connectorID)
}

// brokerGrantContext resolves the workspace broker RS id + the global
// connector:execute permission id used when wiring a grant.
func (m *connectorManager) brokerGrantContext(workspaceID uuid.UUID) (uuid.UUID, uuid.UUID, error) {
	return m.repo.BrokerGrantContext(workspaceID, BrokerResourceURI(workspaceID))
}

// RevokeAssignment removes an assignment and, if it was the client's last one in
// the workspace, tears down the broker registration + executor role binding — the
// inverse of the one-transaction grant.
func (m *connectorManager) RevokeAssignment(workspaceID, assignmentID uuid.UUID) error {
	brokerRSID, _, err := m.brokerGrantContext(workspaceID)
	if err != nil {
		// Broker RS gone — fall back to a plain delete so revoke still works.
		return m.repo.DeleteAssignment(workspaceID, assignmentID)
	}
	return m.repo.RevokeAssignmentTx(workspaceID, assignmentID, brokerRSID)
}

// AuditLog returns recent action-audit records for a connector, after checking
// the connector belongs to the workspace.
func (m *connectorManager) AuditLog(workspaceID, connectorID uuid.UUID, limit int) ([]models.ConnectorActionAudit, error) {
	if _, err := m.repo.GetByID(workspaceID, connectorID); err != nil {
		return nil, errors.New("connector not found")
	}
	return m.repo.ListActionAudit(workspaceID, connectorID, limit)
}

// ResolveActionCredential is the broker-side internal resolver: it selects the
// connection for an action and reads its secret from Vault. The secret NEVER
// leaves the broker — callers use it only to build a provider request. Fails
// closed: no connection, or a non-active connection, is an error.
//
// Delegated call (subjectUserID set): prefer the user-scope connection for that
// subject; there is no fallback to the workspace connection, because a user
// acting on their own behalf must use their own grant. Non-delegated (M2M /
// empty subject): use the workspace-scope connection.
func (m *connectorManager) ResolveActionCredential(connectorID uuid.UUID, subjectUserID string) (*ResolvedCredential, error) {
	var (
		conn *models.ConnectorConnection
		err  error
	)
	if subjectUserID != "" {
		conn, err = m.repo.GetUserConnection(connectorID, subjectUserID)
	} else {
		conn, err = m.repo.GetWorkspaceConnection(connectorID)
	}
	if err != nil || conn == nil {
		return nil, errors.New("no connection for this connector")
	}
	if conn.Status != models.ConnectionStatusActive {
		return nil, fmt.Errorf("connection %s", conn.Status) // expired|error|revoked|disconnected
	}
	if conn.VaultPath == "" {
		return nil, errors.New("connection has no credential")
	}
	if m.vault == nil {
		return nil, errors.New("vault client not configured")
	}
	secret, err := m.vault.ReadSecret(conn.VaultPath)
	if err != nil {
		return nil, fmt.Errorf("read credential: %w", err)
	}
	return &ResolvedCredential{Connection: conn, Secret: secret}, nil
}

// rejectSecretsInConfig fails if the caller put a provider-declared secret key
// into the non-secret config blob.
func rejectSecretsInConfig(provider *models.ConnectorProvider, config map[string]interface{}) error {
	for _, secretKey := range provider.SecretKeys {
		if _, ok := config[secretKey]; ok {
			return fmt.Errorf("config key %q is a secret for provider %q; send it under secrets instead", secretKey, provider.Key)
		}
	}
	return nil
}

func marshalConfig(config map[string]interface{}) (json.RawMessage, error) {
	if config == nil {
		return json.RawMessage("{}"), nil
	}
	b, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return b, nil
}
