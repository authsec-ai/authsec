package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentactivity"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// OTLP/HTTP trace receiver (SPEC-agent-runtime-activity.md §4.3).
//
// POST /authsec/ingest/otlp/v1/traces carries no session: the per-workspace
// OTLP token (Authorization: Bearer aot_... or X-AuthSec-Ingest-Token) is the
// credential, and it ALONE decides the workspace (CLAUDE.md §4 rule 2). It is
// looked up by its sha256 -- the one statement not under a workspace
// transaction -- and everything after runs under row-level security for the
// token's workspace. Resource attributes may attribute a span to a workload
// or identity of THAT workspace only; nothing in a body names a workspace.
//
// Tokens are stored as sha256 hex (agent_otlp_token, migration 155), shown
// once at creation, revocable, optionally expiring. Nothing here logs a
// token or a span body.

// OTLP wire constants and limits.
const (
	AgentOTLPTokenHeader = "X-AuthSec-Ingest-Token"
	AgentOTLPTokenPrefix = "aot_"
	agentOTLPTokenLen    = len(AgentOTLPTokenPrefix) + 43
	agentOTLPTokenShown  = 8

	// AgentOTLPMaxBodyBytes bounds a request, compressed and decompressed (413).
	AgentOTLPMaxBodyBytes = 4 << 20

	AgentOTLPIngestPath = "/authsec/ingest/otlp/v1/traces"

	AgentOTLPIngestRPSEnv   = "AGENT_OTLP_INGEST_RPS"
	AgentOTLPIngestBurstEnv = "AGENT_OTLP_INGEST_BURST"
	defaultAgentOTLPRPS     = 20
	defaultAgentOTLPBurst   = 40

	// MaxAgentOTLPTokens bounds a workspace's live tokens.
	MaxAgentOTLPTokens = 25
	// MaxAgentOTLPTokenDays bounds a token's expiry.
	MaxAgentOTLPTokenDays = 365
)

var (
	// ErrAgentOTLPUnauthenticated: the token stopped being valid while the
	// call ran (revoked or expired) (401).
	ErrAgentOTLPUnauthenticated = errors.New("unknown, revoked or expired OTLP token")
)

// GenerateAgentOTLPToken returns "aot_" + base64url (no padding) of 32 bytes
// from crypto/rand.
func GenerateAgentOTLPToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate OTLP token: %w", err)
	}
	return AgentOTLPTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// wellFormedAgentOTLPToken is a shape check before any database work.
func wellFormedAgentOTLPToken(s string) bool {
	if len(s) != agentOTLPTokenLen || !strings.HasPrefix(s, AgentOTLPTokenPrefix) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s[len(AgentOTLPTokenPrefix):])
	return err == nil
}

// AgentOTLPToken is a token as the admin API shows it: never the token or
// its hash.
type AgentOTLPToken struct {
	ID          uuid.UUID  `json:"id" gorm:"column:id"`
	Label       string     `json:"label" gorm:"column:label"`
	TokenPrefix string     `json:"token_prefix" gorm:"column:token_prefix"`
	CreatedBy   string     `json:"created_by" gorm:"column:created_by"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at"`
	ExpiresAt   *time.Time `json:"expires_at" gorm:"column:expires_at"`
	RevokedAt   *time.Time `json:"revoked_at" gorm:"column:revoked_at"`
	LastUsedAt  *time.Time `json:"last_used_at" gorm:"column:last_used_at"`
	State       string     `json:"state" gorm:"-"`
}

func (t *AgentOTLPToken) setState(now time.Time) {
	switch {
	case t.RevokedAt != nil:
		t.State = "revoked"
	case t.ExpiresAt != nil && !t.ExpiresAt.After(now):
		t.State = "expired"
	default:
		t.State = "active"
	}
}

const agentOTLPTokenColumns = `id, label, token_prefix, created_by, created_at, expires_at, revoked_at, last_used_at`

// AgentOTLPPrincipal is what a verified token resolves to.
type AgentOTLPPrincipal struct {
	WorkspaceID uuid.UUID
	TokenID     uuid.UUID
}

// AgentOTLPIngestResult is what one export did.
type AgentOTLPIngestResult struct {
	Received   int `json:"received"`   // spans in the request
	Accepted   int `json:"accepted"`   // new rows stored
	Duplicates int `json:"duplicates"` // already stored (a retry)
	Ignored    int `json:"ignored"`    // not GenAI / agent / MCP spans
	Rejected   int `json:"rejected"`   // without ids, or outside retention / in the future
	Attributed int `json:"attributed"` // rows tied to a workload or identity
}

// AgentOTLPService owns agent_otlp_token and the ingest. One instance serves
// every request (it holds the per-token rate limits).
type AgentOTLPService struct {
	db  *gorm.DB
	now func() time.Time

	limitMu  sync.Mutex
	limiters map[uuid.UUID]*rate.Limiter
	rps      rate.Limit
	burst    int
}

// NewAgentOTLPService builds the service; the rate limit comes from
// AGENT_OTLP_INGEST_RPS / AGENT_OTLP_INGEST_BURST.
func NewAgentOTLPService(db *gorm.DB) *AgentOTLPService {
	return &AgentOTLPService{db: db, now: time.Now, limiters: map[uuid.UUID]*rate.Limiter{},
		rps:   rate.Limit(envPositiveInt(AgentOTLPIngestRPSEnv, defaultAgentOTLPRPS)),
		burst: envPositiveInt(AgentOTLPIngestBurstEnv, defaultAgentOTLPBurst)}
}

// WithRateLimit sets the per-token limit (tests).
func (s *AgentOTLPService) WithRateLimit(rps float64, burst int) *AgentOTLPService {
	s.limitMu.Lock()
	s.rps, s.burst, s.limiters = rate.Limit(rps), burst, map[uuid.UUID]*rate.Limiter{}
	s.limitMu.Unlock()
	return s
}

// Allow takes one request from the token's rate limit; false is 429.
func (s *AgentOTLPService) Allow(tokenID uuid.UUID) bool {
	s.limitMu.Lock()
	l, ok := s.limiters[tokenID]
	if !ok {
		l = rate.NewLimiter(s.rps, s.burst)
		s.limiters[tokenID] = l
	}
	s.limitMu.Unlock()
	return l.Allow()
}

/* -------------------------------- admin API ------------------------------- */

// CreateToken mints a token for ws. The token is returned once and never
// stored. expiresInDays 0 means no expiry.
func (s *AgentOTLPService) CreateToken(ctx context.Context, ws uuid.UUID, actor, label string, expiresInDays int) (AgentOTLPToken, string, error) {
	label = strings.TrimSpace(label)
	if len(label) > 200 {
		return AgentOTLPToken{}, "", GovBadParam("label", "label must be at most 200 characters.")
	}
	if expiresInDays < 0 || expiresInDays > MaxAgentOTLPTokenDays {
		return AgentOTLPToken{}, "", GovBadParam("expires_in_days",
			fmt.Sprintf("expires_in_days must be between 1 and %d (or omitted).", MaxAgentOTLPTokenDays))
	}
	token, err := GenerateAgentOTLPToken()
	if err != nil {
		return AgentOTLPToken{}, "", err
	}
	var expires *time.Time
	if expiresInDays > 0 {
		t := s.now().UTC().AddDate(0, 0, expiresInDays)
		expires = &t
	}
	var out AgentOTLPToken
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		// One minting at a time per workspace, so the cap holds.
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "agent_otlp_token:"+ws.String()).Error; err != nil {
			return err
		}
		var live int64
		if err := tx.Raw(`SELECT count(*) FROM agent_otlp_token WHERE workspace_id = ? AND revoked_at IS NULL
		                  AND (expires_at IS NULL OR expires_at > now())`, ws).Scan(&live).Error; err != nil {
			return err
		}
		if live >= MaxAgentOTLPTokens {
			return govErr(http.StatusConflict, "token_limit",
				fmt.Sprintf("A workspace may hold at most %d live OTLP tokens; revoke one first.", MaxAgentOTLPTokens), nil)
		}
		id := uuid.New()
		if err := tx.Exec(`INSERT INTO agent_otlp_token (id, workspace_id, label, token_hash, token_prefix, created_by, expires_at)
		                   VALUES (?, ?, ?, ?, ?, ?, ?)`, id, ws, label, HashAgentEventSecret(token),
			token[:agentOTLPTokenShown], strings.TrimSpace(actor), expires).Error; err != nil {
			return err
		}
		return tx.Raw(`SELECT `+agentOTLPTokenColumns+` FROM agent_otlp_token WHERE workspace_id = ? AND id = ?`, ws, id).
			Scan(&out).Error
	})
	if err != nil {
		return AgentOTLPToken{}, "", err
	}
	out.setState(s.now())
	return out, token, nil
}

// ListTokens returns the workspace's tokens, newest first.
func (s *AgentOTLPService) ListTokens(ctx context.Context, ws uuid.UUID) ([]AgentOTLPToken, error) {
	var rows []AgentOTLPToken
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentOTLPTokenColumns+` FROM agent_otlp_token WHERE workspace_id = ?
		               ORDER BY created_at DESC, id`, ws).Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	now := s.now()
	for i := range rows {
		rows[i].setState(now)
	}
	if rows == nil {
		rows = []AgentOTLPToken{}
	}
	return rows, nil
}

// RevokeToken revokes one of the workspace's tokens (idempotent). Another
// workspace's token is not found.
func (s *AgentOTLPService) RevokeToken(ctx context.Context, ws, id uuid.UUID) (AgentOTLPToken, error) {
	var rows []AgentOTLPToken
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE agent_otlp_token SET revoked_at = COALESCE(revoked_at, now())
		                   WHERE workspace_id = ? AND id = ?`, ws, id).Error; err != nil {
			return err
		}
		return tx.Raw(`SELECT `+agentOTLPTokenColumns+` FROM agent_otlp_token WHERE workspace_id = ? AND id = ?`, ws, id).
			Scan(&rows).Error
	})
	if err != nil {
		return AgentOTLPToken{}, err
	}
	if len(rows) == 0 {
		return AgentOTLPToken{}, GovNotFound()
	}
	rows[0].setState(s.now())
	return rows[0], nil
}

/* ---------------------------------- ingest -------------------------------- */

// Authenticate resolves a presented token to its workspace, or nil when it
// is not a live token (malformed, unknown, revoked, expired). An error is a
// database failure, never an invalid token.
func (s *AgentOTLPService) Authenticate(ctx context.Context, presented string) (*AgentOTLPPrincipal, error) {
	if !wellFormedAgentOTLPToken(presented) {
		return nil, nil
	}
	h := HashAgentEventSecret(presented)
	var cred struct {
		ID          uuid.UUID
		WorkspaceID uuid.UUID
		TokenHash   string
	}
	// TENANT-EXEMPT: the presented OTLP token decides the workspace, so it is looked up by its hash across workspaces (as event secrets and discovery ingest tokens); everything after runs under the token's workspace.
	res := s.db.WithContext(ctx).Table("agent_otlp_token").
		Select("id", "workspace_id", "token_hash").
		Where("token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())", h).
		Limit(1).Scan(&cred)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, nil
	}
	if subtle.ConstantTimeCompare([]byte(cred.TokenHash), []byte(h)) != 1 {
		return nil, nil
	}
	return &AgentOTLPPrincipal{WorkspaceID: cred.WorkspaceID, TokenID: cred.ID}, nil
}

// Ingest stores the GenAI / agent / MCP spans of one decoded export for an
// authenticated token. Spans are normalised (content dropped, tool arguments
// digested), attributed within the token's workspace, and inserted once
// (by trace and span id).
func (s *AgentOTLPService) Ingest(ctx context.Context, p AgentOTLPPrincipal, spans []agentactivity.Span) (AgentOTLPIngestResult, error) {
	res := AgentOTLPIngestResult{Received: len(spans)}
	var acts []agentactivity.Activity
	for _, sp := range spans {
		if agentactivity.NormaliseID(sp.TraceID) == "" || agentactivity.NormaliseID(sp.SpanID) == "" {
			res.Rejected++
			continue
		}
		a, ok := agentactivity.Normalise(sp, agentactivity.SourceOTLP)
		if !ok {
			res.Ignored++
			continue
		}
		acts = append(acts, a)
	}
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		// Still live? (revoked or expired since Authenticate refuses the call.)
		upd := tx.Exec(`UPDATE agent_otlp_token SET last_used_at = now()
		                WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
			p.WorkspaceID, p.TokenID)
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected == 0 {
			return ErrAgentOTLPUnauthenticated
		}
		if len(acts) == 0 {
			return nil
		}
		rows, err := attributeActivities(tx, p.WorkspaceID, nil, acts)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.IdentityID != nil || r.WorkloadID != nil {
				res.Attributed++
			}
		}
		inserted, dropped, err := insertActivities(tx, p.WorkspaceID, rows, now)
		if err != nil {
			return err
		}
		res.Accepted, res.Rejected = inserted, res.Rejected+dropped
		res.Duplicates = len(rows) - dropped - inserted
		return nil
	})
	return res, err
}
