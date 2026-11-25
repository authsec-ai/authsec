package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Pushed collectors (SPEC-secops-backend-upgrade W1, C1):
//
//   POST /authsec/ingest/azure/events  Azure diagnostic settings, forwarded
//        from an Event Hub ({"records": [...]}). The header
//        X-AuthSec-Event-Secret carries the Azure connector's ingest secret
//        (azev_...), exactly as the AWS stream: the secret's row ALONE decides
//        workspace and connector; nothing in the body is trusted for either.
//        A record that states a tenant other than the connector's is refused.
//   POST /authsec/ingest/k8s/audit     audit.k8s.io/v1 EventList from the
//        iga-agent. Authorization: Bearer with the cluster connector's
//        actuation credential (decides workspace and source), or a discovery
//        ingest token (decides the workspace; a token bound to a source
//        decides the source, a workspace-wide one names it in
//        X-AuthSec-Discovery-Source, which must be a Kubernetes source of THAT
//        workspace and must not hold an actuation credential -- AS-014).
//
// Accepted events go to the agent-runtime sinks (agentruntime.Dispatch) with
// their delivery, so the evidence sink stores them (idempotent by provider
// event id) and refreshes the source's heartbeat. Nothing here logs a secret,
// a token or a record.

// Collector wire constants.
const (
	AzureEventSecretPrefix   = "azev_"
	azureEventSecretLen      = len(AzureEventSecretPrefix) + 43
	azureEventSecretShown    = 9
	AzureEventIngestPath     = "/authsec/ingest/azure/events"
	K8sAuditIngestPath       = "/authsec/ingest/k8s/audit"
	K8sAuditSourceHeader     = "X-AuthSec-Discovery-Source"
	CollectorMaxRequestBytes = 4 << 20
	CollectorMaxRecords      = 2000
	collectorDispatchTimeout = 10 * time.Second
	ingestSecretKindAzure    = "azure_diag"
)

var (
	// ErrCollectorTooLarge: too many records in one request (413).
	ErrCollectorTooLarge = fmt.Errorf("the request carries more than %d records", CollectorMaxRecords)
	// ErrAzureIngestNotFound: the connector has no Azure ingest secret.
	ErrAzureIngestNotFound = errors.New("no diagnostic-settings ingest for this connector")
)

// CollectorResult is what one collector call did.
type CollectorResult struct {
	Received int `json:"received"`
	Accepted int `json:"accepted"` // handed to the sinks (a redelivery is stored once)
	Rejected int `json:"rejected"`
	// RejectedTenant: an Azure record stating another tenant.
	RejectedTenant int `json:"rejected_tenant,omitempty"`
	// Skipped: a Kubernetes audit stage other than ResponseComplete / Panic.
	Skipped int `json:"skipped,omitempty"`
}

// CollectorPrincipal is what a verified collector credential resolves to.
// It comes from the credential's row, never from a request.
type CollectorPrincipal struct {
	WorkspaceID uuid.UUID
	ConnectorID uuid.UUID // the Azure connector or the cluster's discovery source
	// Scope is the Azure tenant id, or the cluster's source id.
	Scope string
}

// CollectorService owns the Azure ingest secrets and both collectors.
type CollectorService struct {
	db       *gorm.DB
	dispatch func(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error

	limitMu  sync.Mutex
	limiters map[uuid.UUID]*rate.Limiter
}

// NewCollectorService builds the service over db.
func NewCollectorService(db *gorm.DB) *CollectorService {
	return &CollectorService{db: db, dispatch: agentruntime.Dispatch, limiters: map[uuid.UUID]*rate.Limiter{}}
}

// WithDispatch replaces agentruntime.Dispatch (tests).
func (s *CollectorService) WithDispatch(f func(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error) *CollectorService {
	s.dispatch = f
	return s
}

// Allow takes one request from the connector's rate limit (429 otherwise).
func (s *CollectorService) Allow(connectorID uuid.UUID) bool {
	s.limitMu.Lock()
	l, ok := s.limiters[connectorID]
	if !ok {
		l = rate.NewLimiter(rate.Limit(envPositiveInt(AgentEventIngestRPSEnv, defaultAgentEventRPS)),
			envPositiveInt(AgentEventIngestBurstEnv, defaultAgentEventBurst))
		s.limiters[connectorID] = l
	}
	s.limitMu.Unlock()
	return l.Allow()
}

/* ---------------------------- Azure ingest secret ---------------------------- */

// GenerateAzureEventSecret returns "azev_" + base64url (no padding) of 32
// random bytes.
func GenerateAzureEventSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate event secret: %w", err)
	}
	return AzureEventSecretPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func wellFormedAzureEventSecret(s string) bool {
	if len(s) != azureEventSecretLen || !strings.HasPrefix(s, AzureEventSecretPrefix) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s[len(AzureEventSecretPrefix):])
	return err == nil
}

// AzureIngestView is a connector's diagnostic-settings ingest as the admin
// API shows it (never the secret).
type AzureIngestView struct {
	ConnectorID    uuid.UUID  `json:"connector_id" gorm:"column:connector_id"`
	TenantID       string     `json:"tenant_id" gorm:"-"`
	State          string     `json:"state" gorm:"-"`
	SecretPrefix   string     `json:"secret_prefix,omitempty" gorm:"column:secret_prefix"`
	CreatedBy      string     `json:"created_by,omitempty" gorm:"column:created_by"`
	CreatedAt      *time.Time `json:"created_at,omitempty" gorm:"column:created_at"`
	RotatedAt      *time.Time `json:"rotated_at,omitempty" gorm:"column:rotated_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty" gorm:"column:revoked_at"`
	LastReceivedAt *time.Time `json:"last_received_at,omitempty" gorm:"column:last_received_at"`
	ReceivedCount  int64      `json:"received_count" gorm:"column:received_count"`
	RejectedCount  int64      `json:"rejected_count" gorm:"column:rejected_count"`
	EndpointPath   string     `json:"endpoint_path" gorm:"-"`
	SecretHeader   string     `json:"secret_header" gorm:"-"`
}

type azureConnectorRef struct {
	ID       uuid.UUID
	TenantID string
	Status   string
}

func loadAzureConnector(tx *gorm.DB, ws, id uuid.UUID) (azureConnectorRef, error) {
	var c models.CloudConnector
	err := tx.Select("id", "workspace_id", "provider", "scope_id", "status").
		Where("workspace_id = ? AND id = ? AND provider = ?", ws, id, models.CloudProviderAzure).Take(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return azureConnectorRef{}, repositories.ErrCloudConnectorNotFound
	}
	if err != nil {
		return azureConnectorRef{}, err
	}
	return azureConnectorRef{ID: c.ID, TenantID: strings.ToLower(strings.TrimSpace(c.ScopeID)), Status: c.Status}, nil
}

func readAzureIngest(tx *gorm.DB, ws uuid.UUID, conn azureConnectorRef) (AzureIngestView, error) {
	v := AzureIngestView{ConnectorID: conn.ID, TenantID: conn.TenantID, State: AgentEventStreamNotConfigured,
		EndpointPath: AzureEventIngestPath, SecretHeader: AgentEventSecretHeader}
	var rows []AzureIngestView
	if err := tx.Raw(`SELECT connector_id, secret_prefix, created_by, created_at, rotated_at, revoked_at, last_received_at,
	                         received_count, rejected_count
	                    FROM agent_ingest_secret WHERE workspace_id = ? AND connector_id = ? AND kind = ?`,
		ws, conn.ID, ingestSecretKindAzure).Scan(&rows).Error; err != nil {
		return v, err
	}
	if len(rows) == 0 {
		return v, nil
	}
	r := rows[0]
	r.TenantID, r.EndpointPath, r.SecretHeader = v.TenantID, v.EndpointPath, v.SecretHeader
	r.State = AgentEventStreamActive
	if r.RevokedAt != nil {
		r.State = AgentEventStreamRevoked
	}
	return r, nil
}

// EnableOrRotateAzure turns the connector's diagnostic-settings ingest on
// with a new secret (shown once), or rotates it (the old one stops at once).
func (s *CollectorService) EnableOrRotateAzure(ctx context.Context, ws, connectorID uuid.UUID, actor string) (AzureIngestView, string, error) {
	secret, err := GenerateAzureEventSecret()
	if err != nil {
		return AzureIngestView{}, "", err
	}
	var v AzureIngestView
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		conn, err := loadAzureConnector(tx, ws, connectorID)
		if err != nil {
			return err
		}
		if conn.Status == models.CloudConnectorRevoked {
			return ErrAzureConnectorRevoked
		}
		if err := tx.Exec(`INSERT INTO agent_ingest_secret (connector_id, workspace_id, kind, secret_hash, secret_prefix, created_by)
		                   VALUES (?, ?, ?, ?, ?, ?)
		                   ON CONFLICT (workspace_id, connector_id, kind) DO UPDATE SET
		                     secret_hash = EXCLUDED.secret_hash, secret_prefix = EXCLUDED.secret_prefix,
		                     rotated_at = now(), revoked_at = NULL`,
			connectorID, ws, ingestSecretKindAzure, HashAgentEventSecret(secret), secret[:azureEventSecretShown],
			truncate(strings.TrimSpace(actor), 200)).Error; err != nil {
			return err
		}
		v, err = readAzureIngest(tx, ws, conn)
		return err
	})
	if err != nil {
		return AzureIngestView{}, "", err
	}
	return v, secret, nil
}

// GetAzure returns the connector's ingest (not_configured when none).
func (s *CollectorService) GetAzure(ctx context.Context, ws, connectorID uuid.UUID) (AzureIngestView, error) {
	var v AzureIngestView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		conn, err := loadAzureConnector(tx, ws, connectorID)
		if err != nil {
			return err
		}
		v, err = readAzureIngest(tx, ws, conn)
		return err
	})
	return v, err
}

// RevokeAzure stops the connector's ingest: its secret is refused from now on.
func (s *CollectorService) RevokeAzure(ctx context.Context, ws, connectorID uuid.UUID) (AzureIngestView, error) {
	var v AzureIngestView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		conn, err := loadAzureConnector(tx, ws, connectorID)
		if err != nil {
			return err
		}
		res := tx.Exec(`UPDATE agent_ingest_secret SET revoked_at = COALESCE(revoked_at, now())
		                 WHERE workspace_id = ? AND connector_id = ? AND kind = ?`, ws, connectorID, ingestSecretKindAzure)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrAzureIngestNotFound
		}
		v, err = readAzureIngest(tx, ws, conn)
		return err
	})
	return v, err
}

// AuthenticateAzure resolves a presented secret to its workspace, Azure
// connector and tenant, or nil when it is not a live secret. An error is a
// database failure, never an invalid secret.
func (s *CollectorService) AuthenticateAzure(ctx context.Context, presented string) (*CollectorPrincipal, error) {
	if !wellFormedAzureEventSecret(presented) {
		return nil, nil
	}
	h := HashAgentEventSecret(presented)
	var cred struct {
		WorkspaceID uuid.UUID
		ConnectorID uuid.UUID
		SecretHash  string
	}
	// TENANT-EXEMPT: the presented ingest secret decides the workspace, so it is looked up by its hash across workspaces (as the AWS event secret); everything after runs under the secret's workspace.
	res := s.db.WithContext(ctx).Table("agent_ingest_secret").Select("workspace_id", "connector_id", "secret_hash").
		Where("secret_hash = ? AND kind = ? AND revoked_at IS NULL", h, ingestSecretKindAzure).Limit(1).Scan(&cred)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 || subtle.ConstantTimeCompare([]byte(cred.SecretHash), []byte(h)) != 1 {
		return nil, nil
	}
	var conn azureConnectorRef
	err := tenancy.InWorkspaceRead(ctx, s.db, cred.WorkspaceID, func(tx *gorm.DB) error {
		var err error
		conn, err = loadAzureConnector(tx, cred.WorkspaceID, cred.ConnectorID)
		return err
	})
	if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if conn.Status == models.CloudConnectorRevoked || conn.TenantID == "" {
		return nil, nil
	}
	return &CollectorPrincipal{WorkspaceID: cred.WorkspaceID, ConnectorID: cred.ConnectorID, Scope: conn.TenantID}, nil
}

// IngestAzure takes one diagnostic-settings push for an authenticated
// connector. Errors: agentruntime.ErrCollectorBody (400), ErrCollectorTooLarge
// (413), ErrAgentEventUnauthenticated (401: revoked mid-call),
// ErrAgentEventDispatch (503), or a database failure.
func (s *CollectorService) IngestAzure(ctx context.Context, p CollectorPrincipal, body []byte) (CollectorResult, error) {
	var res CollectorResult
	raws, err := agentruntime.SplitAzureBody(body)
	if err != nil {
		return res, err
	}
	if len(raws) > CollectorMaxRecords {
		return res, ErrCollectorTooLarge
	}
	res.Received = len(raws)
	var events []agentruntime.Event
	inReq := map[string]bool{}
	for _, raw := range raws {
		r := agentruntime.ParseAzureRecord(raw)
		switch {
		case r.Err != nil || len(r.Event.EventID) > agentEvidenceMaxIDLen:
			res.Rejected++
			continue
		case r.TenantID != "" && r.TenantID != p.Scope:
			res.Rejected++
			res.RejectedTenant++
			continue
		}
		if inReq[r.Event.EventID] {
			continue
		}
		inReq[r.Event.EventID] = true
		events = append(events, r.Event)
	}
	err = tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		upd := tx.Exec(`UPDATE agent_ingest_secret SET received_count = received_count + ?, rejected_count = rejected_count + ?,
		                       last_received_at = CASE WHEN ? > 0 THEN now() ELSE last_received_at END
		                 WHERE workspace_id = ? AND connector_id = ? AND kind = ? AND revoked_at IS NULL`,
			len(events), res.Rejected, len(events), p.WorkspaceID, p.ConnectorID, ingestSecretKindAzure)
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected == 0 {
			return ErrAgentEventUnauthenticated
		}
		return nil
	})
	if err != nil {
		return res, err
	}
	return s.dispatchCollected(ctx, p, agentruntime.DeliveryAzureDiag, events, res)
}

func (s *CollectorService) dispatchCollected(ctx context.Context, p CollectorPrincipal, kind string, events []agentruntime.Event, res CollectorResult) (CollectorResult, error) {
	if len(events) == 0 {
		return res, nil
	}
	dctx, cancel := context.WithTimeout(ctx, collectorDispatchTimeout)
	defer cancel()
	dctx = agentruntime.WithDelivery(dctx, agentruntime.Delivery{Kind: kind, Ref: HeartbeatRef(p.ConnectorID)})
	if err := s.dispatch(dctx, p.WorkspaceID, p.ConnectorID, events); err != nil {
		log.Printf("[collector] kind=%s workspace=%s connector=%s events=%d outcome=dispatch_failed err=%v",
			kind, p.WorkspaceID, p.ConnectorID, len(events), err)
		return res, ErrAgentEventDispatch
	}
	res.Accepted = len(events)
	return res, nil
}

/* ------------------------------ Kubernetes audit ----------------------------- */

// K8s audit authentication refusals.
var (
	// ErrK8sAuditUnauthenticated: no live credential (401).
	ErrK8sAuditUnauthenticated = errors.New("unauthenticated")
	// ErrK8sAuditSourceUnknown: the named source is not a Kubernetes source of
	// the token's workspace (404, confirming nothing).
	ErrK8sAuditSourceUnknown = errors.New("not found")
	// ErrK8sAuditNeedsConnectorCredential: the source holds an actuation
	// credential, and only it may speak for the source (401, AS-014).
	ErrK8sAuditNeedsConnectorCredential = errors.New("this connector has a credential: send it as the bearer token")
)

// AuthenticateK8s resolves the bearer credential (and, for a workspace-wide
// ingest token, the named source) to a workspace and cluster source.
func (s *CollectorService) AuthenticateK8s(ctx context.Context, bearer, namedSource string) (*CollectorPrincipal, error) {
	bearer = strings.TrimSpace(bearer)
	if bearer == "" {
		return nil, ErrK8sAuditUnauthenticated
	}
	// TENANT-EXEMPT: not a statement here: the actuation credential is resolved by its hash (ActuationManager.AuthenticateAgent), which decides the workspace.
	if src, err := NewActuationManager(s.db).AuthenticateAgent(bearer); err == nil {
		if src.Kind != models.DiscoverySourceK8sWebhook {
			return nil, ErrK8sAuditUnauthenticated
		}
		return &CollectorPrincipal{WorkspaceID: src.WorkspaceID, ConnectorID: src.ID, Scope: src.ID.String()}, nil
	}
	if strings.HasPrefix(bearer, connectorCredentialPrefixSvc) {
		return nil, ErrK8sAuditUnauthenticated
	}
	// TENANT-EXEMPT: not a statement here: the ingest token is resolved by its hash (DiscoveryIngestTokenRepository.Verify), which decides the workspace.
	tok, err := repositories.NewDiscoveryIngestTokenRepository(s.db).Verify(bearer)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, ErrK8sAuditUnauthenticated
	}
	var sourceID uuid.UUID
	switch {
	case tok.DiscoverySourceID != nil:
		sourceID = *tok.DiscoverySourceID
		if namedSource != "" && namedSource != sourceID.String() {
			return nil, ErrK8sAuditSourceUnknown
		}
	case tok.SourceBound:
		return nil, ErrK8sAuditUnauthenticated
	default:
		id, perr := uuid.Parse(strings.TrimSpace(namedSource))
		if perr != nil {
			return nil, ErrK8sAuditSourceUnknown
		}
		sourceID = id
	}
	var src []struct {
		Kind               string
		Enabled            bool
		ActuationTokenHash string
	}
	if err := tenancy.InWorkspaceRead(ctx, s.db, tok.WorkspaceID, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT kind, enabled, actuation_token_hash FROM discovery_sources WHERE workspace_id = ? AND id = ?`,
			tok.WorkspaceID, sourceID).Scan(&src).Error
	}); err != nil {
		return nil, err
	}
	if len(src) == 0 || src[0].Kind != models.DiscoverySourceK8sWebhook || !src[0].Enabled {
		return nil, ErrK8sAuditSourceUnknown
	}
	if src[0].ActuationTokenHash != "" {
		return nil, ErrK8sAuditNeedsConnectorCredential
	}
	return &CollectorPrincipal{WorkspaceID: tok.WorkspaceID, ConnectorID: sourceID, Scope: sourceID.String()}, nil
}

// connectorCredentialPrefixSvc marks an actuation credential (the
// controllers' connectorCredentialPrefix): a malformed one is refused, never
// tried as an ingest token.
const connectorCredentialPrefixSvc = "authsec_act_"

// IngestK8sAudit takes one EventList for an authenticated cluster source.
func (s *CollectorService) IngestK8sAudit(ctx context.Context, p CollectorPrincipal, body []byte) (CollectorResult, error) {
	var res CollectorResult
	raws, err := agentruntime.SplitK8sAuditBody(body)
	if err != nil {
		return res, err
	}
	if len(raws) > CollectorMaxRecords {
		return res, ErrCollectorTooLarge
	}
	res.Received = len(raws)
	var events []agentruntime.Event
	inReq := map[string]bool{}
	for _, raw := range raws {
		r := agentruntime.ParseK8sAuditEvent(raw, "cluster/"+p.Scope)
		switch {
		case r.Skipped:
			res.Skipped++
			continue
		case r.Err != nil || len(r.Event.EventID) > agentEvidenceMaxIDLen:
			res.Rejected++
			continue
		}
		if inReq[r.Event.EventID] {
			continue
		}
		inReq[r.Event.EventID] = true
		events = append(events, r.Event)
	}
	return s.dispatchCollected(ctx, p, agentruntime.DeliveryK8sAudit, events, res)
}
