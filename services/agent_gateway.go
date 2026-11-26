package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Agent runtime gateway (SPEC-agent-runtime-gateway.md): AuthSec is the
// policy decision point for MCP tool calls and model calls made through a
// gateway in the customer's environment. This file owns the gateways (their
// credentials), the workspace settings and the PDP's authentication; the
// policies and the evaluation are in agent_gateway_policy.go, the decision
// log in agent_gateway_decisions.go.
//
// A gateway credential ("agw_" + 43 base64url characters) is the ONLY thing
// that decides the workspace and the gateway of a PDP call (CLAUDE.md §4
// rule 2). It is shown once and stored as its sha256; lookup by hash is the
// one cross-workspace statement (TENANT-EXEMPT, as event secrets); every
// other statement runs under tenancy.InWorkspace for the credential's or the
// token's workspace.
//
// One service instance per database handle (AgentGatewayServiceFor) holds the
// caches, the rate limits and the decision writer, so the admin routes and
// the PDP routes in one process share them: a policy change or a revocation
// takes effect at once in this process, and within agentGatewayPolicyCacheTTL
// / agentGatewayCredCacheTTL in the others.

// Credential and cache constants.
const (
	AgentGatewayCredentialPrefix = "agw_"
	agentGatewayCredentialLen    = len(AgentGatewayCredentialPrefix) + 43
	agentGatewayCredentialShown  = 12

	agentGatewayCredCacheTTL   = 10 * time.Second
	agentGatewayPolicyCacheTTL = 5 * time.Second
	agentGatewayTouchEvery     = time.Minute

	// AgentGatewayPDPRPSEnv / AgentGatewayPDPBurstEnv set the per-gateway
	// PDP rate limit (requests per second, burst), per process.
	AgentGatewayPDPRPSEnv   = "AGENT_GATEWAY_PDP_RPS"
	AgentGatewayPDPBurstEnv = "AGENT_GATEWAY_PDP_BURST"
	defaultAgentGatewayRPS  = 500
	defaultAgentGatewayBurs = 1000

	// Workspace setting defaults and bounds.
	AgentGatewayDefaultCacheTTL  = 30
	AgentGatewayMaxCacheTTL      = 300
	AgentGatewayDefaultRetention = 30
	AgentGatewayMinRetention     = 7
	AgentGatewayMaxRetention     = 3650
)

// Gateway states.
const (
	AgentGatewayActive  = "active"
	AgentGatewayRevoked = "revoked"
)

// GenerateAgentGatewayCredential returns "agw_" + base64url (no padding) of
// 32 bytes from crypto/rand.
func GenerateAgentGatewayCredential() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate gateway credential: %w", err)
	}
	return AgentGatewayCredentialPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAgentGatewayCredential is the stored form: sha256, lower-case hex. The
// credential is 256 random bits, so an unsalted fast hash leaves nothing to
// brute-force and keeps the lookup an index probe.
func HashAgentGatewayCredential(c string) string {
	sum := sha256.Sum256([]byte(c))
	return hex.EncodeToString(sum[:])
}

func wellFormedAgentGatewayCredential(s string) bool {
	if len(s) != agentGatewayCredentialLen || !strings.HasPrefix(s, AgentGatewayCredentialPrefix) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s[len(AgentGatewayCredentialPrefix):])
	return err == nil
}

/* ---------------------------------- views --------------------------------- */

// AgentGatewayView is a gateway as the admin API shows it (never the
// credential or its hash).
type AgentGatewayView struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	State            string     `json:"state"`
	CredentialPrefix string     `json:"credential_prefix"`
	CreatedBy        uuid.UUID  `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	RotatedAt        *time.Time `json:"rotated_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
	SoftwareVersion  string     `json:"software_version,omitempty"`
	Version          int        `json:"version"`
}

type agentGatewayRow struct {
	ID               uuid.UUID
	Name             string
	CredentialPrefix string
	CreatedBy        uuid.UUID
	CreatedAt        time.Time
	UpdatedAt        time.Time
	RotatedAt        *time.Time
	RevokedAt        *time.Time
	LastSeenAt       *time.Time
	SoftwareVersion  string
	Version          int
}

func (r agentGatewayRow) view() AgentGatewayView {
	v := AgentGatewayView{ID: r.ID, Name: r.Name, State: AgentGatewayActive, CredentialPrefix: r.CredentialPrefix,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(),
		RotatedAt: utcPtr(r.RotatedAt), RevokedAt: utcPtr(r.RevokedAt), LastSeenAt: utcPtr(r.LastSeenAt),
		SoftwareVersion: r.SoftwareVersion, Version: r.Version}
	if r.RevokedAt != nil {
		v.State = AgentGatewayRevoked
	}
	return v
}

const agentGatewayCols = `id, name, credential_prefix, created_by, created_at, updated_at, rotated_at,
	revoked_at, last_seen_at, software_version, version`

// AgentGatewaySettings are a workspace's gateway settings.
type AgentGatewaySettings struct {
	Mode                  string     `json:"mode"`
	CacheTTLSeconds       int        `json:"cache_ttl_seconds"`
	DecisionRetentionDays int        `json:"decision_retention_days"`
	UpdatedBy             *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt             *time.Time `json:"updated_at,omitempty"`
	Version               int        `json:"version"`
}

func defaultAgentGatewaySettings() AgentGatewaySettings {
	return AgentGatewaySettings{Mode: agentgateway.ModeObserve, CacheTTLSeconds: AgentGatewayDefaultCacheTTL,
		DecisionRetentionDays: AgentGatewayDefaultRetention, Version: 0}
}

// AgentGatewaySettingsUpdate changes the given fields; Version, when set,
// must be the current one (0 = no row yet).
type AgentGatewaySettingsUpdate struct {
	Mode                  *string `json:"mode"`
	CacheTTLSeconds       *int    `json:"cache_ttl_seconds"`
	DecisionRetentionDays *int    `json:"decision_retention_days"`
	Version               *int    `json:"version"`
}

// AgentGatewayPrincipal is what a verified gateway credential resolves to.
type AgentGatewayPrincipal struct {
	WorkspaceID uuid.UUID
	GatewayID   uuid.UUID
	Name        string
}

/* --------------------------------- service -------------------------------- */

type agentGatewayCredEntry struct {
	p       *AgentGatewayPrincipal
	expires time.Time
}

type agentGatewayPolicySet struct {
	policies []agentgateway.Policy
	settings AgentGatewaySettings
	loaded   time.Time
}

// AgentGatewayService is the PDP and the admin model. Use
// AgentGatewayServiceFor.
type AgentGatewayService struct {
	db  *gorm.DB
	now func() time.Time

	credMu sync.Mutex
	creds  map[string]agentGatewayCredEntry

	polMu sync.Mutex
	pols  map[uuid.UUID]*agentGatewayPolicySet

	limMu    sync.Mutex
	limiters map[uuid.UUID]*rate.Limiter
	rps      rate.Limit
	burst    int

	buckets *agentGatewayBuckets

	touchMu   sync.Mutex
	lastTouch map[uuid.UUID]time.Time

	writer *agentGatewayDecisionWriter

	purgeMu   sync.Mutex
	lastPurge map[uuid.UUID]time.Time
}

var (
	agentGatewaySvcMu sync.Mutex
	agentGatewaySvcs  = map[*gorm.DB]*AgentGatewayService{}
)

// AgentGatewayServiceFor returns the one service of this database handle
// (created on first use).
func AgentGatewayServiceFor(db *gorm.DB) *AgentGatewayService {
	agentGatewaySvcMu.Lock()
	defer agentGatewaySvcMu.Unlock()
	if s, ok := agentGatewaySvcs[db]; ok {
		return s
	}
	s := &AgentGatewayService{
		db:        db,
		now:       time.Now,
		creds:     map[string]agentGatewayCredEntry{},
		pols:      map[uuid.UUID]*agentGatewayPolicySet{},
		limiters:  map[uuid.UUID]*rate.Limiter{},
		rps:       rate.Limit(envPositiveInt(AgentGatewayPDPRPSEnv, defaultAgentGatewayRPS)),
		burst:     envPositiveInt(AgentGatewayPDPBurstEnv, defaultAgentGatewayBurs),
		buckets:   newAgentGatewayBuckets(),
		lastTouch: map[uuid.UUID]time.Time{},
		lastPurge: map[uuid.UUID]time.Time{},
	}
	s.writer = newAgentGatewayDecisionWriter(s)
	agentGatewaySvcs[db] = s
	return s
}

// WithRateLimit sets the per-gateway limit (tests).
func (s *AgentGatewayService) WithRateLimit(rps float64, burst int) *AgentGatewayService {
	s.limMu.Lock()
	s.rps, s.burst, s.limiters = rate.Limit(rps), burst, map[uuid.UUID]*rate.Limiter{}
	s.limMu.Unlock()
	return s
}

// Allow takes one request from the gateway's PDP rate limit.
func (s *AgentGatewayService) Allow(gatewayID uuid.UUID) bool {
	s.limMu.Lock()
	l, ok := s.limiters[gatewayID]
	if !ok {
		l = rate.NewLimiter(s.rps, s.burst)
		s.limiters[gatewayID] = l
	}
	s.limMu.Unlock()
	return l.Allow()
}

// invalidateCreds drops every cached credential of the gateway.
func (s *AgentGatewayService) invalidateCreds(gatewayID uuid.UUID) {
	s.credMu.Lock()
	for k, e := range s.creds {
		if e.p == nil || e.p.GatewayID == gatewayID {
			delete(s.creds, k)
		}
	}
	s.credMu.Unlock()
}

// invalidatePolicies drops the workspace's cached policies and settings.
func (s *AgentGatewayService) invalidatePolicies(ws uuid.UUID) {
	s.polMu.Lock()
	delete(s.pols, ws)
	s.polMu.Unlock()
}

func agentGatewayNameErr(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return govErr(http.StatusUnprocessableEntity, "validation_failed", "name is required (at most 200 characters).",
			map[string]any{"field": "name"})
	}
	return nil
}

func readAgentGateway(tx *gorm.DB, ws, id uuid.UUID) (*agentGatewayRow, error) {
	var row agentGatewayRow
	res := tx.Raw(`SELECT `+agentGatewayCols+` FROM agent_gateway WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&row)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, GovNotFound()
	}
	return &row, nil
}

// CreateGateway registers a gateway and returns it with its credential,
// shown this once.
func (s *AgentGatewayService) CreateGateway(ctx context.Context, ws, actor uuid.UUID, name string) (AgentGatewayView, string, error) {
	if err := agentGatewayNameErr(name); err != nil {
		return AgentGatewayView{}, "", err
	}
	cred, err := GenerateAgentGatewayCredential()
	if err != nil {
		return AgentGatewayView{}, "", err
	}
	var row *agentGatewayRow
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		id := uuid.New()
		if err := tx.Exec(`INSERT INTO agent_gateway (id, workspace_id, name, credential_hash, credential_prefix, created_by)
			VALUES (?, ?, ?, ?, ?, ?)`, id, ws, strings.TrimSpace(name), HashAgentGatewayCredential(cred),
			cred[:agentGatewayCredentialShown], actor).Error; err != nil {
			return err
		}
		var err error
		row, err = readAgentGateway(tx, ws, id)
		return err
	})
	if isUniqueViolation(err, "uq_agent_gateway_live_name") {
		return AgentGatewayView{}, "", govErr(http.StatusConflict, "name_taken", "An active gateway already has this name.",
			map[string]any{"field": "name"})
	}
	if err != nil {
		return AgentGatewayView{}, "", err
	}
	return row.view(), cred, nil
}

// ListGateways lists the workspace's gateways, newest first.
func (s *AgentGatewayService) ListGateways(ctx context.Context, ws uuid.UUID) ([]AgentGatewayView, error) {
	var rows []agentGatewayRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentGatewayCols+` FROM agent_gateway WHERE workspace_id = ?
			ORDER BY created_at DESC, id`, ws).Scan(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	out := make([]AgentGatewayView, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.view())
	}
	return out, nil
}

// GetGateway reads one gateway; another workspace's is 404.
func (s *AgentGatewayService) GetGateway(ctx context.Context, ws, id uuid.UUID) (AgentGatewayView, error) {
	var row *agentGatewayRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		row, err = readAgentGateway(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentGatewayView{}, err
	}
	return row.view(), nil
}

// RenameGateway renames a gateway at the expected version.
func (s *AgentGatewayService) RenameGateway(ctx context.Context, ws, id uuid.UUID, name string, version int) (AgentGatewayView, AgentGatewayView, error) {
	if err := agentGatewayNameErr(name); err != nil {
		return AgentGatewayView{}, AgentGatewayView{}, err
	}
	var before, after *agentGatewayRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readAgentGateway(tx, ws, id); err != nil {
			return err
		}
		if before.Version != version {
			return govConflict(GovCodeVersionConflict, "The gateway changed since you opened it.",
				map[string]any{"version": before.Version})
		}
		if err := tx.Exec(`UPDATE agent_gateway SET name = ?, updated_at = now(), version = version + 1
			WHERE workspace_id = ? AND id = ?`, strings.TrimSpace(name), ws, id).Error; err != nil {
			return err
		}
		after, err = readAgentGateway(tx, ws, id)
		return err
	})
	if isUniqueViolation(err, "uq_agent_gateway_live_name") {
		return AgentGatewayView{}, AgentGatewayView{}, govErr(http.StatusConflict, "name_taken",
			"An active gateway already has this name.", map[string]any{"field": "name"})
	}
	if err != nil {
		return AgentGatewayView{}, AgentGatewayView{}, err
	}
	return before.view(), after.view(), nil
}

// RotateGateway replaces an active gateway's credential; the old one is
// refused at once (in this process; within agentGatewayCredCacheTTL in
// others).
func (s *AgentGatewayService) RotateGateway(ctx context.Context, ws, id uuid.UUID) (AgentGatewayView, string, error) {
	cred, err := GenerateAgentGatewayCredential()
	if err != nil {
		return AgentGatewayView{}, "", err
	}
	var row *agentGatewayRow
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, err := readAgentGateway(tx, ws, id)
		if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return govConflict("gateway_revoked", "A revoked gateway cannot be rotated; create a new one.", nil)
		}
		if err := tx.Exec(`UPDATE agent_gateway SET credential_hash = ?, credential_prefix = ?, rotated_at = now(),
			    updated_at = now(), version = version + 1
			WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`,
			HashAgentGatewayCredential(cred), cred[:agentGatewayCredentialShown], ws, id).Error; err != nil {
			return err
		}
		row, err = readAgentGateway(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentGatewayView{}, "", err
	}
	s.invalidateCreds(id)
	return row.view(), cred, nil
}

// RevokeGateway refuses the gateway's credential from now on. The row and
// its decisions stay. Revoking twice keeps the first revoked_at.
func (s *AgentGatewayService) RevokeGateway(ctx context.Context, ws, id uuid.UUID) (AgentGatewayView, AgentGatewayView, error) {
	var before, after *agentGatewayRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readAgentGateway(tx, ws, id); err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_gateway SET revoked_at = COALESCE(revoked_at, now()), updated_at = now(),
			    version = version + CASE WHEN revoked_at IS NULL THEN 1 ELSE 0 END
			WHERE workspace_id = ? AND id = ?`, ws, id).Error; err != nil {
			return err
		}
		after, err = readAgentGateway(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentGatewayView{}, AgentGatewayView{}, err
	}
	s.invalidateCreds(id)
	return before.view(), after.view(), nil
}

/* -------------------------------- settings -------------------------------- */

func readAgentGatewaySettings(tx *gorm.DB, ws uuid.UUID) (AgentGatewaySettings, error) {
	var row struct {
		Mode                  string
		CacheTTLSeconds       int
		DecisionRetentionDays int
		UpdatedBy             *uuid.UUID
		UpdatedAt             time.Time
		Version               int
	}
	res := tx.Raw(`SELECT mode, cache_ttl_seconds, decision_retention_days, updated_by, updated_at, version
		FROM agent_gateway_setting WHERE workspace_id = ?`, ws).Scan(&row)
	if res.Error != nil {
		return AgentGatewaySettings{}, res.Error
	}
	if res.RowsAffected == 0 {
		return defaultAgentGatewaySettings(), nil
	}
	at := row.UpdatedAt.UTC()
	return AgentGatewaySettings{Mode: row.Mode, CacheTTLSeconds: row.CacheTTLSeconds,
		DecisionRetentionDays: row.DecisionRetentionDays, UpdatedBy: row.UpdatedBy, UpdatedAt: &at, Version: row.Version}, nil
}

// Settings returns the workspace's gateway settings (defaults when unset).
func (s *AgentGatewayService) Settings(ctx context.Context, ws uuid.UUID) (AgentGatewaySettings, error) {
	var out AgentGatewaySettings
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = readAgentGatewaySettings(tx, ws)
		return err
	})
	return out, err
}

// UpdateSettings changes the given settings.
func (s *AgentGatewayService) UpdateSettings(ctx context.Context, ws, actor uuid.UUID, u AgentGatewaySettingsUpdate) (AgentGatewaySettings, AgentGatewaySettings, error) {
	var before, after AgentGatewaySettings
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readAgentGatewaySettings(tx, ws); err != nil {
			return err
		}
		if u.Version != nil && *u.Version != before.Version {
			return govConflict(GovCodeVersionConflict, "The settings changed since you opened them.",
				map[string]any{"version": before.Version})
		}
		next := before
		if u.Mode != nil {
			if *u.Mode != agentgateway.ModeObserve && *u.Mode != agentgateway.ModeEnforce {
				return govErr(http.StatusUnprocessableEntity, "validation_failed", "mode must be observe or enforce.",
					map[string]any{"field": "mode"})
			}
			next.Mode = *u.Mode
		}
		if u.CacheTTLSeconds != nil {
			if *u.CacheTTLSeconds < 0 || *u.CacheTTLSeconds > AgentGatewayMaxCacheTTL {
				return govErr(http.StatusUnprocessableEntity, "validation_failed",
					fmt.Sprintf("cache_ttl_seconds must be between 0 and %d.", AgentGatewayMaxCacheTTL),
					map[string]any{"field": "cache_ttl_seconds"})
			}
			next.CacheTTLSeconds = *u.CacheTTLSeconds
		}
		if u.DecisionRetentionDays != nil {
			if *u.DecisionRetentionDays < AgentGatewayMinRetention || *u.DecisionRetentionDays > AgentGatewayMaxRetention {
				return govErr(http.StatusUnprocessableEntity, "validation_failed",
					fmt.Sprintf("decision_retention_days must be between %d and %d.", AgentGatewayMinRetention, AgentGatewayMaxRetention),
					map[string]any{"field": "decision_retention_days"})
			}
			next.DecisionRetentionDays = *u.DecisionRetentionDays
		}
		if err := tx.Exec(`INSERT INTO agent_gateway_setting
			    (workspace_id, mode, cache_ttl_seconds, decision_retention_days, updated_by)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id) DO UPDATE SET
			    mode = EXCLUDED.mode, cache_ttl_seconds = EXCLUDED.cache_ttl_seconds,
			    decision_retention_days = EXCLUDED.decision_retention_days,
			    updated_by = EXCLUDED.updated_by, updated_at = now(),
			    version = agent_gateway_setting.version + 1`,
			ws, next.Mode, next.CacheTTLSeconds, next.DecisionRetentionDays, actor).Error; err != nil {
			return err
		}
		after, err = readAgentGatewaySettings(tx, ws)
		return err
	})
	if err != nil {
		return before, after, err
	}
	s.invalidatePolicies(ws)
	return before, after, nil
}

/* ----------------------------- authentication ----------------------------- */

// Authenticate resolves a presented gateway credential to its workspace and
// gateway, or nil when it is not a live credential (malformed, unknown,
// rotated away or revoked). An error is a database failure.
func (s *AgentGatewayService) Authenticate(ctx context.Context, presented string) (*AgentGatewayPrincipal, error) {
	if !wellFormedAgentGatewayCredential(presented) {
		return nil, nil
	}
	h := HashAgentGatewayCredential(presented)
	now := s.now()
	s.credMu.Lock()
	if e, ok := s.creds[h]; ok && now.Before(e.expires) {
		s.credMu.Unlock()
		return e.p, nil
	}
	s.credMu.Unlock()

	var cred struct {
		WorkspaceID    uuid.UUID
		ID             uuid.UUID
		Name           string
		CredentialHash string
	}
	// TENANT-EXEMPT: the presented gateway credential decides the workspace, so it is looked up by its hash across workspaces (as event secrets); everything after runs under its workspace.
	res := s.db.WithContext(ctx).Table("agent_gateway").
		Select("workspace_id", "id", "name", "credential_hash").
		Where("credential_hash = ? AND revoked_at IS NULL", h).
		Limit(1).Scan(&cred)
	if res.Error != nil {
		return nil, res.Error
	}
	var p *AgentGatewayPrincipal
	if res.RowsAffected > 0 && subtle.ConstantTimeCompare([]byte(cred.CredentialHash), []byte(h)) == 1 {
		p = &AgentGatewayPrincipal{WorkspaceID: cred.WorkspaceID, GatewayID: cred.ID, Name: cred.Name}
	}
	if p != nil {
		// Unknown credentials are not cached: a garbage flood must not grow the map.
		s.credMu.Lock()
		if len(s.creds) > 10000 {
			s.creds = map[string]agentGatewayCredEntry{}
		}
		s.creds[h] = agentGatewayCredEntry{p: p, expires: now.Add(agentGatewayCredCacheTTL)}
		s.credMu.Unlock()
	}
	return p, nil
}

// Touch records the gateway's last contact and software version, at most
// once a minute per gateway per process, off the request path.
func (s *AgentGatewayService) Touch(p AgentGatewayPrincipal, softwareVersion string) {
	now := s.now()
	s.touchMu.Lock()
	if last, ok := s.lastTouch[p.GatewayID]; ok && now.Sub(last) < agentGatewayTouchEvery {
		s.touchMu.Unlock()
		return
	}
	s.lastTouch[p.GatewayID] = now
	s.touchMu.Unlock()
	if len(softwareVersion) > 64 {
		softwareVersion = softwareVersion[:64]
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE agent_gateway SET last_seen_at = now(),
				    software_version = CASE WHEN ? <> '' THEN ? ELSE software_version END
				WHERE workspace_id = ? AND id = ?`, softwareVersion, softwareVersion, p.WorkspaceID, p.GatewayID).Error
		})
		if err != nil {
			log.Printf("[agent-gateway] stage=touch workspace=%s gateway=%s outcome=failed err=%v", p.WorkspaceID, p.GatewayID, err)
		}
	}()
}

// gatewayExists reports whether id is one of the workspace's gateways.
func gatewayExists(tx *gorm.DB, ws, id uuid.UUID) (bool, error) {
	var n int64
	err := tx.Raw(`SELECT count(*) FROM agent_gateway WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&n).Error
	return n > 0, err
}
