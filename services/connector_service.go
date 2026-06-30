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
	Credentials(svc *models.Connector) (map[string]interface{}, error)
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
	vaultPath := fmt.Sprintf("kv/data/secret/tenants/%s/connectors/%s", workspaceID.String(), id.String())

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

	if len(in.Secrets) > 0 {
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
			conn.VaultPath = fmt.Sprintf("kv/data/secret/tenants/%s/connectors/%s", workspaceID.String(), conn.ID.String())
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

func (m *connectorManager) Credentials(conn *models.Connector) (map[string]interface{}, error) {
	if conn.VaultPath == "" {
		return map[string]interface{}{}, nil
	}
	if m.vault == nil {
		return nil, errors.New("vault client not configured")
	}
	return m.vault.ReadSecret(conn.VaultPath)
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
