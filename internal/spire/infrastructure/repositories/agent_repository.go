package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresAgentRepository stores attested agents in spire_agents, scoped to
// the workspace carried by ctx.
type PostgresAgentRepository struct {
	db     *sql.DB
	logger *logrus.Entry
}

// NewPostgresAgentRepository creates the agent repository.
func NewPostgresAgentRepository(db *sql.DB, logger *logrus.Entry) repositories.AgentRepository {
	return &PostgresAgentRepository{db: db, logger: logger}
}

const agentColumns = `id::text, workspace_id::text, node_id, spiffe_id, attestation_type,
	node_selectors, COALESCE(certificate_serial, ''), status, COALESCE(cluster_name, ''),
	last_seen, last_heartbeat, created_at, updated_at`

// Create inserts an agent for ctx's workspace.
func (r *PostgresAgentRepository) Create(ctx context.Context, agent *models.Agent) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	now := time.Now()
	agent.WorkspaceID = ws.String()
	agent.CreatedAt, agent.UpdatedAt = now, now
	if agent.LastHeartbeat.IsZero() {
		agent.LastHeartbeat = agent.LastSeen
	}
	selectors, err := json.Marshal(nonNilMap(agent.NodeSelectors))
	if err != nil {
		return errors.NewInternalError("Failed to marshal node selectors", err)
	}
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_agents (
			workspace_id, id, node_id, spiffe_id, attestation_type, node_selectors,
			certificate_serial, status, cluster_name, last_seen, last_heartbeat,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		agent.ID, agent.NodeID, agent.SpiffeID, agent.AttestationType, selectors,
		nullString(agent.CertificateSerial), agent.Status, nullString(agent.ClusterName),
		nullTime(agent.LastSeen), nullTime(agent.LastHeartbeat), agent.CreatedAt, agent.UpdatedAt)
	if err != nil {
		r.logger.WithError(err).Error("Failed to create agent")
		return errors.NewInternalError("Failed to create agent", err)
	}
	return nil
}

// GetByID returns the agent with this id in ctx's workspace.
func (r *PostgresAgentRepository) GetByID(ctx context.Context, id string) (*models.Agent, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, errors.NewNotFoundError("Agent not found", nil)
	}
	return r.getOne(ctx, `SELECT `+agentColumns+` FROM spire_agents WHERE workspace_id = $1 AND id = $2`, id)
}

// GetBySpiffeID returns the agent with this SPIFFE ID in ctx's workspace.
func (r *PostgresAgentRepository) GetBySpiffeID(ctx context.Context, spiffeID string) (*models.Agent, error) {
	return r.getOne(ctx, `SELECT `+agentColumns+` FROM spire_agents WHERE workspace_id = $1 AND spiffe_id = $2`, spiffeID)
}

// GetByNode returns the agent for this node in ctx's workspace.
func (r *PostgresAgentRepository) GetByNode(ctx context.Context, nodeID string) (*models.Agent, error) {
	return r.getOne(ctx, `SELECT `+agentColumns+` FROM spire_agents WHERE workspace_id = $1 AND node_id = $2`, nodeID)
}

func (r *PostgresAgentRepository) getOne(ctx context.Context, query string, arg interface{}) (*models.Agent, error) {
	a := &models.Agent{}
	var selectors []byte
	var lastSeen, lastHeartbeat sql.NullTime
	err := tenancy.QueryRowContext(ctx, r.db, query, []interface{}{arg},
		&a.ID, &a.WorkspaceID, &a.NodeID, &a.SpiffeID, &a.AttestationType, &selectors,
		&a.CertificateSerial, &a.Status, &a.ClusterName, &lastSeen, &lastHeartbeat,
		&a.CreatedAt, &a.UpdatedAt)
	if stderrors.Is(err, tenancy.ErrNotFound) {
		return nil, errors.NewNotFoundError("Agent not found", err)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get agent", err)
	}
	a.LastSeen, a.LastHeartbeat = lastSeen.Time, lastHeartbeat.Time
	if len(selectors) > 0 {
		if err := json.Unmarshal(selectors, &a.NodeSelectors); err != nil {
			return nil, errors.NewInternalError("Failed to parse node selectors", err)
		}
	}
	return a, nil
}

// Update rewrites an agent of ctx's workspace.
func (r *PostgresAgentRepository) Update(ctx context.Context, agent *models.Agent) error {
	agent.UpdatedAt = time.Now()
	if agent.LastHeartbeat.IsZero() {
		agent.LastHeartbeat = agent.LastSeen
	}
	selectors, err := json.Marshal(nonNilMap(agent.NodeSelectors))
	if err != nil {
		return errors.NewInternalError("Failed to marshal node selectors", err)
	}
	res, err := tenancy.ExecContext(ctx, r.db, `
		UPDATE spire_agents
		   SET node_id = $3, spiffe_id = $4, attestation_type = $5, node_selectors = $6,
		       certificate_serial = $7, status = $8, cluster_name = $9, last_seen = $10,
		       last_heartbeat = $11, updated_at = $12
		 WHERE workspace_id = $1 AND id = $2`,
		agent.ID, agent.NodeID, agent.SpiffeID, agent.AttestationType, selectors,
		nullString(agent.CertificateSerial), agent.Status, nullString(agent.ClusterName),
		nullTime(agent.LastSeen), nullTime(agent.LastHeartbeat), agent.UpdatedAt)
	if err != nil {
		return errors.NewInternalError("Failed to update agent", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Agent not found", nil)
	}
	return nil
}

// List returns ctx's workspace's agents, newest first.
func (r *PostgresAgentRepository) List(ctx context.Context) ([]*models.Agent, error) {
	rows, err := tenancy.QueryContext(ctx, r.db,
		`SELECT `+agentColumns+` FROM spire_agents WHERE workspace_id = $1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, errors.NewInternalError("Failed to list agents", err)
	}
	defer rows.Close()
	agents := []*models.Agent{}
	for rows.Next() {
		a := &models.Agent{}
		var selectors []byte
		var lastSeen, lastHeartbeat sql.NullTime
		if err := rows.Scan(&a.ID, &a.WorkspaceID, &a.NodeID, &a.SpiffeID, &a.AttestationType, &selectors,
			&a.CertificateSerial, &a.Status, &a.ClusterName, &lastSeen, &lastHeartbeat,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, errors.NewInternalError("Failed to scan agent", err)
		}
		a.LastSeen, a.LastHeartbeat = lastSeen.Time, lastHeartbeat.Time
		if len(selectors) > 0 {
			_ = json.Unmarshal(selectors, &a.NodeSelectors)
		}
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewInternalError("Failed to iterate agents", err)
	}
	return agents, nil
}

// UpdateLastSeen records a heartbeat for an agent of ctx's workspace.
func (r *PostgresAgentRepository) UpdateLastSeen(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.NewNotFoundError("Agent not found", nil)
	}
	now := time.Now()
	res, err := tenancy.ExecContext(ctx, r.db,
		`UPDATE spire_agents SET last_seen = $3, last_heartbeat = $3, updated_at = $3 WHERE workspace_id = $1 AND id = $2`,
		id, now)
	if err != nil {
		return errors.NewInternalError("Failed to update last_seen", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Agent not found", nil)
	}
	return nil
}

func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
