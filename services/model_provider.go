package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/modelprovider"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
)

/* model_provider.go is the connection of a workspace's OpenAI / Anthropic
   organisations (SPEC-agent-runtime-provider-usage.md): connect, rotate,
   revoke, request a sync, and the reads (connections, keys, usage).

   Opt-in: nothing runs for a workspace until an administrator connects an
   organisation. The admin key is write-only: it is validated with one read
   call, stored in Vault under the workspace's path (the row holds only the
   path, secret_ref, and a fingerprint), never returned, never logged, and
   destroyed from Vault on revoke and rotate. Every statement runs under
   row-level security for the token's workspace (tenancy.InWorkspace /
   InWorkspaceRead); another workspace's connection is 404. */

// Connection states.
const (
	ModelProviderActive  = "active"
	ModelProviderError   = "error"
	ModelProviderRevoked = "revoked"
)

// Limits (spec §9) and sync cadence (§8).
const (
	ModelProviderMaxLive      = 5
	modelProviderMaxKeys      = 5000
	modelProviderSyncEvery    = time.Hour
	modelProviderManualGap    = 5 * time.Minute
	modelProviderLease        = 15 * time.Minute
	modelProviderFirstWindow  = 30 * 24 * time.Hour
	modelProviderOverlap      = 2 * time.Hour
	modelProviderRetention    = 180 * 24 * time.Hour
	modelProviderMaxUsageRead = 90 * 24 * time.Hour
	modelProviderCallTimeout  = 10 * time.Minute
)

/* ------------------------------- process wiring ----------------------------- */

var modelProviderDeps struct {
	sync.RWMutex
	vault vault.VaultClient
}

// SetModelProviderVault installs the Vault client that stores admin keys
// (nil: none can be stored or read). It returns the undo (tests).
func SetModelProviderVault(vc vault.VaultClient) (restore func()) {
	modelProviderDeps.Lock()
	prev := modelProviderDeps.vault
	modelProviderDeps.vault = vc
	modelProviderDeps.Unlock()
	return func() { SetModelProviderVault(prev) }
}

func modelProviderVault() vault.VaultClient {
	modelProviderDeps.RLock()
	defer modelProviderDeps.RUnlock()
	return modelProviderDeps.vault
}

// InstallModelProviders installs the Vault client (VAULT_ADDR /
// VAULT_TOKEN; without them no organisation can be connected and syncs
// wait). cmd/main.go calls it once at startup.
func InstallModelProviders() {
	addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || tok == "" {
		log.Printf("[model-providers] VAULT_ADDR/VAULT_TOKEN not set: model provider connections unavailable")
		return
	}
	vc, err := vault.NewClient(addr, tok)
	if err != nil {
		log.Printf("[model-providers] vault client: %v; model provider connections unavailable", err)
		return
	}
	SetModelProviderVault(vc)
}

// ModelProviderSecretPath is the Vault path of a connection's admin key; the
// nonce makes a rotated key's path new, so the old one can be destroyed.
func ModelProviderSecretPath(ws, connection uuid.UUID, nonce string) string {
	return "kv/data/secret/workspaces/" + ws.String() + "/agent-runtime/model-provider-" + connection.String() + "-" + nonce
}

func modelProviderNonce() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ModelProviderKeyFingerprint is what the console shows of an admin key:
// its last 4 characters and a sha256 prefix. Never more.
func ModelProviderKeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	last := key
	if len(last) > 4 {
		last = last[len(last)-4:]
	}
	return "..." + last + " sha256:" + hex.EncodeToString(sum[:])[:12]
}

/* --------------------------------- the service ------------------------------ */

// ModelProviderService is the connections, their sync and their reads.
type ModelProviderService struct {
	db        *gorm.DB
	now       func() time.Time
	newClient func(provider, adminKey string) (modelprovider.Client, error)
}

// NewModelProviderService builds the service over db.
func NewModelProviderService(db *gorm.DB) *ModelProviderService {
	return &ModelProviderService{db: db, now: time.Now, newClient: func(p, k string) (modelprovider.Client, error) {
		return modelprovider.New(p, k, nil)
	}}
}

// WithClock overrides the clock (tests).
func (s *ModelProviderService) WithClock(f func() time.Time) *ModelProviderService {
	cp := *s
	cp.now = f
	return &cp
}

// WithClientFactory overrides how provider clients are built (tests).
func (s *ModelProviderService) WithClientFactory(f func(provider, adminKey string) (modelprovider.Client, error)) *ModelProviderService {
	cp := *s
	cp.newClient = f
	return &cp
}

// ModelProviderConnection is a connection as the API shows it: never the key.
type ModelProviderConnection struct {
	ID                uuid.UUID  `json:"id"`
	Provider          string     `json:"provider"`
	DisplayName       string     `json:"display_name"`
	KeyFingerprint    string     `json:"key_fingerprint"`
	OrgID             string     `json:"org_id"`
	OrgName           string     `json:"org_name"`
	Status            string     `json:"status"`
	LastSyncAt        *time.Time `json:"last_sync_at"`
	LastSyncAttemptAt *time.Time `json:"last_sync_attempt_at"`
	NextSyncAt        *time.Time `json:"next_sync_at"`
	LastError         string     `json:"last_error"`
	CreatedBy         uuid.UUID  `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	RevokedAt         *time.Time `json:"revoked_at"`
	RevokedBy         *uuid.UUID `json:"revoked_by"`
}

const modelProviderColumns = `id, provider, display_name, key_fingerprint, org_id, org_name, status, last_sync_at,
	last_sync_attempt_at, next_sync_at, last_error, created_by, created_at, revoked_at, revoked_by`

func errModelProviderNotFound() error { return GovNotFound() }

// validateAdminKey checks the shape only; the provider decides the rest.
func validateAdminKey(key string) error {
	if len(key) < 20 || len(key) > 512 {
		return GovBadParam("admin_key", "admin_key must be 20 to 512 characters.")
	}
	for _, r := range key {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII {
			return GovBadParam("admin_key", "admin_key must be printable ASCII without spaces.")
		}
	}
	return nil
}

// validateWithProvider makes the one read call; the error never carries the key.
func (s *ModelProviderService) validateWithProvider(ctx context.Context, provider, key string) (modelprovider.Org, error) {
	c, err := s.newClient(provider, key)
	if err != nil {
		return modelprovider.Org{}, GovBadParam("provider", "provider must be openai or anthropic.")
	}
	vctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	org, err := c.Validate(vctx)
	if err == nil {
		return org, nil
	}
	if modelprovider.IsAuth(err) {
		return org, govErr(http.StatusUnprocessableEntity, "provider_rejected_key",
			"The provider refused the admin key. Use an organisation admin key.", map[string]any{"provider_error": modelprovider.Scrub(err.Error())})
	}
	var pe *modelprovider.Error
	if errors.As(err, &pe) && pe.Status >= 400 && pe.Status < 500 && pe.Status != http.StatusTooManyRequests {
		return org, govErr(http.StatusUnprocessableEntity, "provider_rejected_key",
			"The provider did not accept the key for its admin API.", map[string]any{"provider_error": modelprovider.Scrub(err.Error())})
	}
	return org, govErr(http.StatusBadGateway, "provider_unavailable", "The provider could not be reached to validate the key; try again shortly.", nil)
}

func isLiveUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "uq_model_provider_connection_live")
}

// Connect is POST /model-providers.
func (s *ModelProviderService) Connect(ctx context.Context, ws, actor uuid.UUID, provider, adminKey, displayName string) (*ModelProviderConnection, error) {
	provider = strings.TrimSpace(provider)
	if !modelprovider.Valid(provider) {
		return nil, GovBadParam("provider", "provider must be openai or anthropic.")
	}
	if err := validateAdminKey(adminKey); err != nil {
		return nil, err
	}
	displayName = strings.TrimSpace(displayName)
	if len(displayName) > 200 {
		return nil, GovBadParam("display_name", "display_name is at most 200 characters.")
	}
	vc := modelProviderVault()
	if vc == nil {
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable",
			"The secrets store is not configured; an admin key cannot be stored.", nil)
	}
	var live int64
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT count(*) FROM model_provider_connection WHERE workspace_id = ? AND status <> 'revoked'`, ws).Scan(&live).Error
	}); err != nil {
		return nil, err
	}
	if live >= ModelProviderMaxLive {
		return nil, govErr(http.StatusConflict, "model_provider_limit", "A workspace has at most 5 connected model provider organisations.", nil)
	}
	org, err := s.validateWithProvider(ctx, provider, adminKey)
	if err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = map[string]string{modelprovider.OpenAI: "OpenAI", modelprovider.Anthropic: "Anthropic"}[provider]
		if org.Name != "" {
			displayName += " - " + org.Name
		}
	}
	id := uuid.New()
	nonce, err := modelProviderNonce()
	if err != nil {
		return nil, err
	}
	ref := ModelProviderSecretPath(ws, id, nonce)
	if err := vc.WriteSecret(ref, map[string]interface{}{"admin_key": adminKey}); err != nil {
		log.Printf("[model-providers] workspace %s: storing an admin key failed (%T)", ws, err)
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable", "The admin key could not be stored; try again shortly.", nil)
	}
	now := s.now().UTC()
	var out []ModelProviderConnection
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`INSERT INTO model_provider_connection
			  (id, workspace_id, provider, display_name, secret_ref, key_fingerprint, org_id, org_name, status,
			   next_sync_at, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
			RETURNING `+modelProviderColumns,
			id, ws, provider, displayName, ref, ModelProviderKeyFingerprint(adminKey), truncate(org.ID, 200), truncate(org.Name, 200),
			now, actor, now, now).Scan(&out).Error
	})
	if err == nil && len(out) != 1 {
		err = errors.New("model provider insert returned no row")
	}
	if err != nil {
		if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[model-providers] workspace %s: removing an unused admin key failed (left in Vault): %v", ws, derr)
		}
		if isLiveUniqueViolation(err) {
			return nil, govErr(http.StatusConflict, "model_provider_exists",
				"This organisation is already connected; rotate its key or revoke it first.", nil)
		}
		return nil, err
	}
	return &out[0], nil
}

// List is GET /model-providers: newest first, revoked included.
func (s *ModelProviderService) List(ctx context.Context, ws uuid.UUID) ([]ModelProviderConnection, error) {
	var out []ModelProviderConnection
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+modelProviderColumns+` FROM model_provider_connection
		                WHERE workspace_id = ? ORDER BY created_at DESC, id DESC LIMIT 200`, ws).Scan(&out).Error
	})
	if out == nil {
		out = []ModelProviderConnection{}
	}
	return out, err
}

// Get is GET /model-providers/:id.
func (s *ModelProviderService) Get(ctx context.Context, ws, id uuid.UUID) (*ModelProviderConnection, error) {
	var out []ModelProviderConnection
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+modelProviderColumns+` FROM model_provider_connection WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&out).Error
	}); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errModelProviderNotFound()
	}
	return &out[0], nil
}

type modelProviderSecretRow struct {
	Provider  string
	SecretRef string
	OrgID     string
	Status    string
}

// Rotate is POST /model-providers/:id/rotate: the new key must read the same
// organisation; it is stored at a new path and the old path is destroyed.
func (s *ModelProviderService) Rotate(ctx context.Context, ws, id uuid.UUID, adminKey string) (*ModelProviderConnection, error) {
	if err := validateAdminKey(adminKey); err != nil {
		return nil, err
	}
	vc := modelProviderVault()
	if vc == nil {
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable", "The secrets store is not configured.", nil)
	}
	var rows []modelProviderSecretRow
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT provider, secret_ref, org_id, status FROM model_provider_connection WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errModelProviderNotFound()
	}
	cur := rows[0]
	if cur.Status == ModelProviderRevoked {
		return nil, govErr(http.StatusConflict, "model_provider_revoked", "The connection is revoked; connect the organisation again.", nil)
	}
	org, err := s.validateWithProvider(ctx, cur.Provider, adminKey)
	if err != nil {
		return nil, err
	}
	if org.ID != cur.OrgID {
		return nil, govErr(http.StatusConflict, "organization_mismatch", "The new key belongs to another organisation than the connection's.", nil)
	}
	nonce, err := modelProviderNonce()
	if err != nil {
		return nil, err
	}
	ref := ModelProviderSecretPath(ws, id, nonce)
	if err := vc.WriteSecret(ref, map[string]interface{}{"admin_key": adminKey}); err != nil {
		log.Printf("[model-providers] workspace %s: storing a rotated admin key failed (%T)", ws, err)
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable", "The admin key could not be stored; try again shortly.", nil)
	}
	now := s.now().UTC()
	var out []ModelProviderConnection
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`UPDATE model_provider_connection
			SET secret_ref = ?, key_fingerprint = ?, status = 'active', last_error = '', next_sync_at = ?, updated_at = ?
			WHERE workspace_id = ? AND id = ? AND status <> 'revoked' AND secret_ref = ?
			RETURNING `+modelProviderColumns,
			ref, ModelProviderKeyFingerprint(adminKey), now, now, ws, id, cur.SecretRef).Scan(&out).Error
	})
	if err == nil && len(out) == 0 {
		err = govErr(http.StatusConflict, "model_provider_changed", "The connection changed meanwhile; reload it and try again.", nil)
	}
	if err != nil {
		if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[model-providers] workspace %s: removing an unused admin key failed (left in Vault): %v", ws, derr)
		}
		return nil, err
	}
	if _, derr := vault.Destroy(vc, cur.SecretRef); derr != nil {
		log.Printf("[model-providers] workspace %s: removing a rotated admin key failed (left in Vault): %v", ws, derr)
	}
	return &out[0], nil
}

// Revoke is DELETE /model-providers/:id: the connection stops, its open
// findings resolve, and its admin key is destroyed in Vault after the
// commit. Revoking a revoked connection returns it unchanged.
func (s *ModelProviderService) Revoke(ctx context.Context, ws, actor, id uuid.UUID) (*ModelProviderConnection, error) {
	var ref string
	var out []ModelProviderConnection
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []modelProviderSecretRow
		if err := tx.Raw(`SELECT provider, secret_ref, org_id, status FROM model_provider_connection
		                   WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return errModelProviderNotFound()
		}
		if rows[0].Status != ModelProviderRevoked {
			ref = rows[0].SecretRef
			if err := tx.Exec(`UPDATE model_provider_connection
				SET status = 'revoked', revoked_at = ?, revoked_by = ?, secret_ref = '', next_sync_at = NULL,
				    sync_lease_until = NULL, updated_at = ?
				WHERE workspace_id = ? AND id = ?`, now, actor, now, ws, id).Error; err != nil {
				return err
			}
			if err := tx.Exec(`UPDATE agent_finding
				SET state = 'resolved', resolved_at = ?, updated_at = ?,
				    evidence = evidence || '{"resolved_reason": "connection_revoked"}'::jsonb
				WHERE workspace_id = ? AND provider_connection_id = ? AND state = 'open'`, now, now, ws, id).Error; err != nil {
				return err
			}
		}
		return tx.Raw(`SELECT `+modelProviderColumns+` FROM model_provider_connection WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&out).Error
	})
	if err != nil {
		return nil, err
	}
	if ref != "" {
		if vc := modelProviderVault(); vc == nil {
			log.Printf("[model-providers] workspace %s: a revoked admin key could not be removed: no secrets store", ws)
		} else if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[model-providers] workspace %s: removing a revoked admin key failed (left in Vault): %v", ws, derr)
		}
	}
	return &out[0], nil
}

// RequestSync is POST /model-providers/:id/sync: the next sync is due now,
// or 5 minutes after the last attempt, whichever is later.
func (s *ModelProviderService) RequestSync(ctx context.Context, ws, id uuid.UUID) (time.Time, error) {
	var next time.Time
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []struct {
			Status            string
			LastSyncAttemptAt *time.Time
		}
		if err := tx.Raw(`SELECT status, last_sync_attempt_at FROM model_provider_connection
		                   WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return errModelProviderNotFound()
		}
		if rows[0].Status == ModelProviderRevoked {
			return govErr(http.StatusConflict, "model_provider_revoked", "The connection is revoked.", nil)
		}
		next = now
		if a := rows[0].LastSyncAttemptAt; a != nil && a.Add(modelProviderManualGap).After(next) {
			next = a.Add(modelProviderManualGap).UTC()
		}
		return tx.Exec(`UPDATE model_provider_connection SET next_sync_at = ?, updated_at = ? WHERE workspace_id = ? AND id = ?`,
			next, now, ws, id).Error
	})
	return next, err
}

/* ----------------------------------- reads ---------------------------------- */

// ModelProviderKeyView is one provider key as GET /:id/keys shows it.
type ModelProviderKeyView struct {
	ProviderKeyID     string          `json:"provider_key_id"`
	Name              string          `json:"name"`
	KeyHint           string          `json:"key_hint"`
	ProjectID         string          `json:"project_id"`
	ProjectName       string          `json:"project_name"`
	OwnerType         string          `json:"owner_type"`
	OwnerID           string          `json:"owner_id"`
	OwnerName         string          `json:"owner_name"`
	CreatedAtProvider *time.Time      `json:"created_at_provider"`
	LastUsedAt        *time.Time      `json:"last_used_at"`
	Status            string          `json:"status"`
	Links             json.RawMessage `json:"links"`
	Requests7d        *int64          `json:"requests_7d"`
	InputTokens7d     int64           `json:"input_tokens_7d"`
	OutputTokens7d    int64           `json:"output_tokens_7d"`
	Unaccounted       bool            `json:"unaccounted"`
	FirstSeen         time.Time       `json:"first_seen"`
	LastSeen          time.Time       `json:"last_seen"`
}

func (s *ModelProviderService) exists(tx *gorm.DB, ws, id uuid.UUID) error {
	var n int64
	if err := tx.Raw(`SELECT count(*) FROM model_provider_connection WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return errModelProviderNotFound()
	}
	return nil
}

// Keys is GET /model-providers/:id/keys.
func (s *ModelProviderService) Keys(ctx context.Context, ws, id uuid.UUID) ([]ModelProviderKeyView, error) {
	since := s.now().UTC().Add(-unaccountedWindow)
	var out []ModelProviderKeyView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := s.exists(tx, ws, id); err != nil {
			return err
		}
		return tx.Raw(`SELECT k.provider_key_id, k.name, k.key_hint, k.project_id, k.project_name, k.owner_type, k.owner_id,
			       k.owner_name, k.created_at_provider, k.last_used_at, k.status, k.links, k.first_seen, k.last_seen,
			       u.requests AS requests7d, COALESCE(u.input_tokens, 0) AS input_tokens7d,
			       COALESCE(u.output_tokens, 0) AS output_tokens7d,
			       EXISTS (SELECT 1 FROM agent_finding f WHERE f.workspace_id = k.workspace_id AND f.provider_connection_id = k.connection_id
			                  AND f.kind = ? AND f.subject_key = ?::text || k.provider_key_id AND f.state = 'open') AS unaccounted
			  FROM model_provider_key k
			  LEFT JOIN (SELECT provider_key_id,
			                    CASE WHEN count(requests) = 0 THEN NULL ELSE sum(requests) END AS requests,
			                    sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens
			               FROM model_provider_usage
			              WHERE workspace_id = ? AND connection_id = ? AND bucket_start >= ?
			              GROUP BY provider_key_id) u ON u.provider_key_id = k.provider_key_id
			 WHERE k.workspace_id = ? AND k.connection_id = ?
			 ORDER BY k.status, k.name, k.provider_key_id
			 LIMIT ?`,
			FindingUnaccountedModelUsage, unaccountedSubjectPrefix(id), ws, id, since, ws, id, modelProviderMaxKeys).Scan(&out).Error
	})
	if out == nil {
		out = []ModelProviderKeyView{}
	}
	return out, err
}

// ModelProviderUsageRow is one group of GET /model-providers/:id/usage.
type ModelProviderUsageRow struct {
	Group             string    `json:"group"`
	Name              string    `json:"name,omitempty"`
	Requests          *int64    `json:"requests"`
	InputTokens       int64     `json:"input_tokens"`
	CachedInputTokens int64     `json:"cached_input_tokens"`
	OutputTokens      int64     `json:"output_tokens"`
	FirstBucket       time.Time `json:"first_bucket"`
	LastBucket        time.Time `json:"last_bucket"`
}

var modelProviderGroupColumns = map[string]string{"key": "provider_key_id", "model": "model", "project": "project_id"}

// Usage is GET /model-providers/:id/usage: totals per key, model or project
// over [from, to) (default the last 7 days; at most 90 days).
func (s *ModelProviderService) Usage(ctx context.Context, ws, id uuid.UUID, from, to *time.Time, groupBy string) ([]ModelProviderUsageRow, time.Time, time.Time, error) {
	if groupBy == "" {
		groupBy = "key"
	}
	col, ok := modelProviderGroupColumns[groupBy]
	if !ok {
		return nil, time.Time{}, time.Time{}, GovBadParam("group_by", "group_by must be key, model or project.")
	}
	end := s.now().UTC()
	if to != nil {
		end = to.UTC()
	}
	start := end.Add(-unaccountedWindow)
	if from != nil {
		start = from.UTC()
	}
	if !start.Before(end) {
		return nil, start, end, GovBadParam("from", "from must be before to.")
	}
	if end.Sub(start) > modelProviderMaxUsageRead {
		return nil, start, end, GovBadParam("from", "The window is at most 90 days.")
	}
	var out []ModelProviderUsageRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := s.exists(tx, ws, id); err != nil {
			return err
		}
		// col is one of three fixed column names (modelProviderGroupColumns).
		if err := tx.Raw(`SELECT `+col+` AS "group",
			       CASE WHEN count(requests) = 0 THEN NULL ELSE sum(requests) END AS requests,
			       sum(input_tokens) AS input_tokens, sum(cached_input_tokens) AS cached_input_tokens,
			       sum(output_tokens) AS output_tokens, min(bucket_start) AS first_bucket, max(bucket_start) AS last_bucket
			  FROM model_provider_usage
			 WHERE workspace_id = ? AND connection_id = ? AND bucket_start >= ? AND bucket_start < ?
			 GROUP BY `+col+`
			 ORDER BY sum(input_tokens) + sum(output_tokens) DESC, 1
			 LIMIT 1000`, ws, id, start, end).Scan(&out).Error; err != nil {
			return err
		}
		if groupBy == "model" || len(out) == 0 {
			return nil
		}
		var names []struct {
			ProviderKeyID string
			Name          string
			ProjectID     string
			ProjectName   string
		}
		if err := tx.Raw(`SELECT provider_key_id, name, project_id, project_name FROM model_provider_key
		                   WHERE workspace_id = ? AND connection_id = ?`, ws, id).Scan(&names).Error; err != nil {
			return err
		}
		byID := map[string]string{}
		for _, n := range names {
			if groupBy == "key" {
				byID[n.ProviderKeyID] = n.Name
			} else if n.ProjectName != "" {
				byID[n.ProjectID] = n.ProjectName
			}
		}
		for i := range out {
			out[i].Name = byID[out[i].Group]
		}
		return nil
	})
	if out == nil {
		out = []ModelProviderUsageRow{}
	}
	return out, start, end, err
}
