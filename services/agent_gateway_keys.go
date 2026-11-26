package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
)

/* agent_gateway_keys.go: the keys AuthSec holds for gateways (W6, C6).

   Provider keys. A workspace's model provider API keys move from each
   gateway's environment to AuthSec's Vault: per workspace, under
   kv/data/secret/workspaces/<ws>/agent-gateway/provider-keys/<id>-<nonce>
   (the nonce makes a rotated key's path new, so the old one is destroyed).
   The console sees a fingerprint only. A gateway fetches the keys assigned
   to it with its agw_ credential (GET /authsec/pdp/v1/provider-keys) and
   keeps them in memory, never on disk, for ttl_seconds. Nothing here logs a
   key or puts one in an error.

   Agent keys. AuthSec issues each agent its gateway key ("agk_" + 32 random
   bytes, shown once, stored as its sha256), bound to a workload identity: a
   SPIFFE id, an AuthSec workload id, or both. Gateways receive the hashes
   and bindings in their policy hints (so a revocation reaches them within
   the hints interval) and accept a key only when the caller also presents
   the workload identity it is bound to.

   Every statement runs under row-level security for the token's or the
   gateway credential's workspace (tenancy.InWorkspace / InWorkspaceRead). */

// Key constants.
const (
	AgentGatewayAgentKeyPrefix   = "agk_"
	agentGatewayAgentKeyShown    = 12
	agentGatewayMaxAgentKeys     = 5000
	agentGatewayMaxProviderKeys  = 200
	AgentGatewayProviderKeysTTL  = 300
	agentGatewayProviderKeyField = "api_key"
)

// AgentGatewayProviderKeySecretPath is a provider key's Vault path.
func AgentGatewayProviderKeySecretPath(ws, id uuid.UUID, nonce string) string {
	return "kv/data/secret/workspaces/" + ws.String() + "/agent-gateway/provider-keys/" + id.String() + "-" + nonce
}

// GenerateAgentGatewayAgentKey returns "agk_" + base64url of 32 random bytes.
func GenerateAgentGatewayAgentKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate agent key: %w", err)
	}
	return AgentGatewayAgentKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAgentGatewayAgentKey is the stored form of an agent key (sha256 hex),
// the same form the gateway compares (gateway.HashAgentKey).
func HashAgentGatewayAgentKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

/* --------------------------------- provider keys --------------------------- */

// AgentGatewayProviderKeyView is a provider key as the console sees it:
// never the key.
type AgentGatewayProviderKeyView struct {
	ID             uuid.UUID  `json:"id" gorm:"column:id"`
	Name           string     `json:"name" gorm:"column:name"`
	Provider       string     `json:"provider" gorm:"column:provider"`
	GatewayID      *uuid.UUID `json:"gateway_id" gorm:"column:gateway_id"`
	KeyFingerprint string     `json:"key_fingerprint" gorm:"column:key_fingerprint"`
	ProviderKeyID  string     `json:"provider_key_id" gorm:"column:provider_key_id"`
	ConnectionID   *uuid.UUID `json:"connection_id" gorm:"column:connection_id"`
	State          string     `json:"state" gorm:"column:state"`
	CreatedBy      uuid.UUID  `json:"created_by" gorm:"column:created_by"`
	CreatedAt      time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt      time.Time  `json:"updated_at" gorm:"column:updated_at"`
	RotatedAt      *time.Time `json:"rotated_at" gorm:"column:rotated_at"`
	RevokedAt      *time.Time `json:"revoked_at" gorm:"column:revoked_at"`
	LastFetchedAt  *time.Time `json:"last_fetched_at" gorm:"column:last_fetched_at"`
	Version        int        `json:"version" gorm:"column:version"`
}

const agentGatewayProviderKeyCols = `id, name, provider, gateway_id, key_fingerprint, provider_key_id, connection_id, state,
	created_by, created_at, updated_at, rotated_at, revoked_at, last_fetched_at, version`

// AgentGatewayProviderKeyInput adds a provider key. Key is write-only.
type AgentGatewayProviderKeyInput struct {
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Key           string `json:"key"`
	GatewayID     string `json:"gateway_id"`
	ProviderKeyID string `json:"provider_key_id"`
}

var reGatewayProvider = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validateProviderSecret(key string) error {
	if len(key) < 16 || len(key) > 1024 {
		return GovBadParam("key", "key must be 16 to 1024 characters.")
	}
	for _, r := range key {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII {
			return GovBadParam("key", "key must be printable ASCII without spaces.")
		}
	}
	return nil
}

func gatewayVault() (vault.VaultClient, error) {
	vc := modelProviderVault()
	if vc == nil {
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable",
			"The secrets store is not configured; a provider key cannot be stored.", nil)
	}
	return vc, nil
}

func readProviderKeyView(tx *gorm.DB, ws, id uuid.UUID) (*AgentGatewayProviderKeyView, error) {
	var out []AgentGatewayProviderKeyView
	if err := tx.Raw(`SELECT `+agentGatewayProviderKeyCols+` FROM agent_gateway_provider_key
	                   WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&out).Error; err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, GovNotFound()
	}
	return &out[0], nil
}

// matchProviderKeyID ties a key to the provider's own key id when the
// caller named none: the one listed key (of a live connection of that
// provider) whose redacted hint ends in the key's last four characters.
func matchProviderKeyID(tx *gorm.DB, ws uuid.UUID, provider, key string) (string, *uuid.UUID, error) {
	if provider != "openai" && provider != "anthropic" || len(key) < 8 {
		return "", nil, nil
	}
	var rows []struct {
		ProviderKeyID string
		ConnectionID  uuid.UUID
	}
	if err := tx.Raw(`SELECT k.provider_key_id, k.connection_id FROM model_provider_key k
	                   JOIN model_provider_connection c ON c.workspace_id = k.workspace_id AND c.id = k.connection_id
	                  WHERE k.workspace_id = ? AND c.provider = ? AND c.status <> 'revoked'
	                    AND k.status NOT IN ('deleted') AND k.key_hint <> '' AND right(k.key_hint, 4) = ?
	                  LIMIT 2`, ws, provider, key[len(key)-4:]).Scan(&rows).Error; err != nil {
		return "", nil, err
	}
	if len(rows) != 1 {
		return "", nil, nil
	}
	id := rows[0].ConnectionID
	return rows[0].ProviderKeyID, &id, nil
}

// AddProviderKey stores a provider key in Vault and records it.
func (s *AgentGatewayService) AddProviderKey(ctx context.Context, ws, actor uuid.UUID, in AgentGatewayProviderKeyInput) (*AgentGatewayProviderKeyView, error) {
	in.Name, in.Provider = strings.TrimSpace(in.Name), strings.ToLower(strings.TrimSpace(in.Provider))
	if in.Name == "" || len(in.Name) > 200 {
		return nil, GovBadParam("name", "name is required (at most 200 characters).")
	}
	if !reGatewayProvider.MatchString(in.Provider) {
		return nil, GovBadParam("provider", "provider is the provider's policy name (openai, anthropic, groq ...).")
	}
	if err := validateProviderSecret(in.Key); err != nil {
		return nil, err
	}
	if len(in.ProviderKeyID) > 200 {
		return nil, GovBadParam("provider_key_id", "provider_key_id is at most 200 characters.")
	}
	var gw *uuid.UUID
	if in.GatewayID != "" {
		id, err := uuid.Parse(in.GatewayID)
		if err != nil {
			return nil, GovBadParam("gateway_id", "gateway_id must be one of the workspace's gateways.")
		}
		gw = &id
	}
	vc, err := gatewayVault()
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	nonce, err := modelProviderNonce()
	if err != nil {
		return nil, err
	}
	ref := AgentGatewayProviderKeySecretPath(ws, id, nonce)
	if err := vc.WriteSecret(ref, map[string]interface{}{agentGatewayProviderKeyField: in.Key}); err != nil {
		log.Printf("[agent-gateway] workspace %s: storing a provider key failed (%T)", ws, err)
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable", "The key could not be stored; try again shortly.", nil)
	}
	var out *AgentGatewayProviderKeyView
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if gw != nil {
			ok, err := gatewayExists(tx, ws, *gw)
			if err != nil {
				return err
			}
			if !ok {
				return GovBadParam("gateway_id", "gateway_id must be one of the workspace's gateways.")
			}
		}
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM agent_gateway_provider_key WHERE workspace_id = ? AND state = 'active'`, ws).Scan(&n).Error; err != nil {
			return err
		}
		if n >= agentGatewayMaxProviderKeys {
			return govErr(http.StatusConflict, "provider_key_limit", fmt.Sprintf("A workspace has at most %d active provider keys.", agentGatewayMaxProviderKeys), nil)
		}
		pkID, conn := strings.TrimSpace(in.ProviderKeyID), (*uuid.UUID)(nil)
		if pkID == "" {
			var err error
			if pkID, conn, err = matchProviderKeyID(tx, ws, in.Provider, in.Key); err != nil {
				return err
			}
		}
		if err := tx.Exec(`INSERT INTO agent_gateway_provider_key
			  (id, workspace_id, name, provider, gateway_id, secret_ref, key_fingerprint, provider_key_id, connection_id, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, ws, in.Name, in.Provider, gw, ref,
			ModelProviderKeyFingerprint(in.Key), pkID, conn, actor).Error; err != nil {
			return err
		}
		var err error
		out, err = readProviderKeyView(tx, ws, id)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventGatewayProviderKeyAdded, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"provider_key_id": id, "name": in.Name, "provider": in.Provider, "fingerprint": out.KeyFingerprint})
	})
	if err != nil {
		if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[agent-gateway] workspace %s: removing an unused provider key failed (left in Vault)", ws)
		}
		if isUniqueViolation(err, "uq_agent_gateway_provider_key_live_name") {
			return nil, govErr(http.StatusConflict, "name_taken", "An active provider key already has this name.", map[string]any{"field": "name"})
		}
		return nil, err
	}
	s.bumpProviderKeys(ws)
	return out, nil
}

// ListProviderKeys lists the workspace's provider keys (never the keys).
func (s *AgentGatewayService) ListProviderKeys(ctx context.Context, ws uuid.UUID) ([]AgentGatewayProviderKeyView, error) {
	out := []AgentGatewayProviderKeyView{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentGatewayProviderKeyCols+` FROM agent_gateway_provider_key WHERE workspace_id = ?
		                ORDER BY state, created_at DESC, id LIMIT 500`, ws).Scan(&out).Error
	})
	return out, err
}

// GetProviderKey reads one provider key (404 for another workspace's).
func (s *AgentGatewayService) GetProviderKey(ctx context.Context, ws, id uuid.UUID) (*AgentGatewayProviderKeyView, error) {
	var out *AgentGatewayProviderKeyView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = readProviderKeyView(tx, ws, id)
		return err
	})
	return out, err
}

// RotateProviderKey replaces a provider key's value: stored at a new path,
// the old path destroyed after the commit.
func (s *AgentGatewayService) RotateProviderKey(ctx context.Context, ws, actor, id uuid.UUID, key string) (*AgentGatewayProviderKeyView, error) {
	if err := validateProviderSecret(key); err != nil {
		return nil, err
	}
	vc, err := gatewayVault()
	if err != nil {
		return nil, err
	}
	nonce, err := modelProviderNonce()
	if err != nil {
		return nil, err
	}
	ref := AgentGatewayProviderKeySecretPath(ws, id, nonce)
	var old string
	var out *AgentGatewayProviderKeyView
	// The row is checked first so nothing is written to Vault for another
	// workspace's id.
	if _, err := s.GetProviderKey(ctx, ws, id); err != nil {
		return nil, err
	}
	if err := vc.WriteSecret(ref, map[string]interface{}{agentGatewayProviderKeyField: key}); err != nil {
		log.Printf("[agent-gateway] workspace %s: storing a rotated provider key failed (%T)", ws, err)
		return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable", "The key could not be stored; try again shortly.", nil)
	}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var cur []struct {
			State     string
			SecretRef string
		}
		if err := tx.Raw(`SELECT state, secret_ref FROM agent_gateway_provider_key WHERE workspace_id = ? AND id = ? FOR UPDATE`,
			ws, id).Scan(&cur).Error; err != nil {
			return err
		}
		if len(cur) == 0 {
			return GovNotFound()
		}
		if cur[0].State != "active" {
			return govConflict("provider_key_revoked", "A revoked provider key cannot be rotated; add a new one.", nil)
		}
		old = cur[0].SecretRef
		if err := tx.Exec(`UPDATE agent_gateway_provider_key SET secret_ref = ?, key_fingerprint = ?, rotated_at = now(),
		                     updated_at = now(), version = version + 1 WHERE workspace_id = ? AND id = ?`,
			ref, ModelProviderKeyFingerprint(key), ws, id).Error; err != nil {
			return err
		}
		var err error
		if out, err = readProviderKeyView(tx, ws, id); err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventGatewayProviderKeyRotated, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"provider_key_id": id, "fingerprint": out.KeyFingerprint})
	})
	if err != nil {
		if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[agent-gateway] workspace %s: removing an unused provider key failed (left in Vault)", ws)
		}
		return nil, err
	}
	if old != "" {
		if _, derr := vault.Destroy(vc, old); derr != nil {
			log.Printf("[agent-gateway] workspace %s: removing a rotated provider key failed (left in Vault)", ws)
		}
	}
	s.bumpProviderKeys(ws)
	return out, nil
}

// RevokeProviderKey stops gateways from fetching the key and destroys it in
// Vault after the commit. Revoking twice returns it unchanged.
func (s *AgentGatewayService) RevokeProviderKey(ctx context.Context, ws, actor, id uuid.UUID) (*AgentGatewayProviderKeyView, error) {
	var ref string
	var out *AgentGatewayProviderKeyView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var cur []struct {
			State     string
			SecretRef string
		}
		if err := tx.Raw(`SELECT state, secret_ref FROM agent_gateway_provider_key WHERE workspace_id = ? AND id = ? FOR UPDATE`,
			ws, id).Scan(&cur).Error; err != nil {
			return err
		}
		if len(cur) == 0 {
			return GovNotFound()
		}
		if cur[0].State == "active" {
			ref = cur[0].SecretRef
			if err := tx.Exec(`UPDATE agent_gateway_provider_key SET state = 'revoked', revoked_at = now(), revoked_by = ?,
			                     secret_ref = '', updated_at = now(), version = version + 1
			                   WHERE workspace_id = ? AND id = ?`, actor, ws, id).Error; err != nil {
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventGatewayProviderKeyRevoked, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"provider_key_id": id}); err != nil {
				return err
			}
		}
		var err error
		out, err = readProviderKeyView(tx, ws, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	if ref != "" {
		if vc := modelProviderVault(); vc == nil {
			log.Printf("[agent-gateway] workspace %s: a revoked provider key could not be removed: no secrets store", ws)
		} else if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[agent-gateway] workspace %s: removing a revoked provider key failed (left in Vault)", ws)
		}
	}
	s.bumpProviderKeys(ws)
	return out, nil
}

// bumpProviderKeys drops the workspace's cached hints (the key list
// version is part of them).
func (s *AgentGatewayService) bumpProviderKeys(ws uuid.UUID) { s.invalidatePolicies(ws) }

// AgentGatewayProviderSecret is one key a gateway fetched: the ONLY place a
// key value leaves AuthSec, over the PDP route to the gateway it is assigned to.
type AgentGatewayProviderSecret struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Provider      string    `json:"provider"`
	Key           string    `json:"key"`
	Fingerprint   string    `json:"fingerprint"`
	ProviderKeyID string    `json:"provider_key_id,omitempty"`
}

// AgentGatewayProviderSecrets is GET /pdp/v1/provider-keys.
type AgentGatewayProviderSecrets struct {
	Keys       []AgentGatewayProviderSecret `json:"keys"`
	TTLSeconds int                          `json:"ttl_seconds"`
	// Unavailable names keys that could not be read from Vault (ids only).
	Unavailable []uuid.UUID `json:"unavailable,omitempty"`
}

// ProviderSecretsFor returns the live provider keys assigned to the
// authenticated gateway (its own and the workspace-wide ones), read from
// Vault. A key Vault cannot return is listed by id in Unavailable.
func (s *AgentGatewayService) ProviderSecretsFor(ctx context.Context, p AgentGatewayPrincipal) (AgentGatewayProviderSecrets, error) {
	out := AgentGatewayProviderSecrets{Keys: []AgentGatewayProviderSecret{}, TTLSeconds: AgentGatewayProviderKeysTTL}
	var rows []struct {
		ID             uuid.UUID
		Name           string
		Provider       string
		SecretRef      string
		KeyFingerprint string
		ProviderKeyID  string
	}
	if err := tenancy.InWorkspaceRead(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, name, provider, secret_ref, key_fingerprint, provider_key_id FROM agent_gateway_provider_key
		                WHERE workspace_id = ? AND state = 'active' AND (gateway_id IS NULL OR gateway_id = ?)
		                ORDER BY provider, name, id`, p.WorkspaceID, p.GatewayID).Scan(&rows).Error
	}); err != nil {
		return out, err
	}
	if len(rows) == 0 {
		return out, nil
	}
	vc := modelProviderVault()
	if vc == nil {
		return out, errors.New("secrets store not configured")
	}
	var fetched []uuid.UUID
	for _, r := range rows {
		sec, err := vc.ReadSecret(r.SecretRef)
		key, _ := sec[agentGatewayProviderKeyField].(string)
		if err != nil || key == "" {
			log.Printf("[agent-gateway] workspace %s gateway %s: provider key %s could not be read from the secrets store",
				p.WorkspaceID, p.GatewayID, r.ID)
			out.Unavailable = append(out.Unavailable, r.ID)
			continue
		}
		out.Keys = append(out.Keys, AgentGatewayProviderSecret{ID: r.ID, Name: r.Name, Provider: r.Provider, Key: key,
			Fingerprint: r.KeyFingerprint, ProviderKeyID: r.ProviderKeyID})
		fetched = append(fetched, r.ID)
	}
	if len(fetched) > 0 {
		if err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE agent_gateway_provider_key SET last_fetched_at = now()
			                 WHERE workspace_id = ? AND id IN ?`, p.WorkspaceID, fetched).Error
		}); err != nil {
			log.Printf("[agent-gateway] workspace %s: recording a provider key fetch failed: %v", p.WorkspaceID, err)
		}
	}
	return out, nil
}

/* ----------------------------------- agent keys ---------------------------- */

// AgentGatewayAgentKeyView is an agent key as the console sees it.
type AgentGatewayAgentKeyView struct {
	ID              uuid.UUID  `json:"id" gorm:"column:id"`
	Name            string     `json:"name" gorm:"column:name"`
	ClientID        string     `json:"client_id" gorm:"column:client_id"`
	KeyPrefix       string     `json:"key_prefix" gorm:"column:key_prefix"`
	SPIFFEID        string     `json:"spiffe_id" gorm:"column:spiffe_id"`
	WorkloadID      *uuid.UUID `json:"workload_id" gorm:"column:workload_id"`
	IdentityID      *uuid.UUID `json:"identity_id" gorm:"column:identity_id"`
	Labels          JSONText   `json:"labels" gorm:"column:labels"`
	AgentID         *uuid.UUID `json:"agent_id" gorm:"column:agent_id"`
	PrincipalUserID *uuid.UUID `json:"principal_user_id" gorm:"column:principal_user_id"`
	GatewayID       *uuid.UUID `json:"gateway_id" gorm:"column:gateway_id"`
	State           string     `json:"state" gorm:"-"`
	CreatedBy       uuid.UUID  `json:"created_by" gorm:"column:created_by"`
	CreatedAt       time.Time  `json:"created_at" gorm:"column:created_at"`
	RotatedAt       *time.Time `json:"rotated_at" gorm:"column:rotated_at"`
	RevokedAt       *time.Time `json:"revoked_at" gorm:"column:revoked_at"`
	RevokedReason   string     `json:"revoked_reason" gorm:"column:revoked_reason"`
	Version         int        `json:"version" gorm:"column:version"`
}

const agentGatewayAgentKeyCols = `id, name, client_id, key_prefix, spiffe_id, workload_id, identity_id, labels::text AS labels,
	agent_id, principal_user_id, gateway_id, created_by, created_at, rotated_at, revoked_at, revoked_reason, version`

func (v *AgentGatewayAgentKeyView) finish() {
	v.State = AgentGatewayActive
	if v.RevokedAt != nil {
		v.State = AgentGatewayRevoked
	}
	if len(v.Labels) == 0 {
		v.Labels = "[]"
	}
}

// AgentGatewayAgentKeyInput issues an agent key.
type AgentGatewayAgentKeyInput struct {
	Name            string   `json:"name"`
	ClientID        string   `json:"client_id"`
	SPIFFEID        string   `json:"spiffe_id"`
	WorkloadID      string   `json:"workload_id"`
	IdentityID      string   `json:"identity_id"`
	Labels          []string `json:"labels"`
	AgentID         string   `json:"agent_id"`
	PrincipalUserID string   `json:"principal_user_id"`
	GatewayID       string   `json:"gateway_id"`
}

func optUUIDParam(field, v string) (*uuid.UUID, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, GovBadParam(field, field+" must be a UUID.")
	}
	return &id, nil
}

func readAgentKeyView(tx *gorm.DB, ws, id uuid.UUID) (*AgentGatewayAgentKeyView, error) {
	var out []AgentGatewayAgentKeyView
	if err := tx.Raw(`SELECT `+agentGatewayAgentKeyCols+` FROM agent_gateway_agent_key WHERE workspace_id = ? AND id = ?`,
		ws, id).Scan(&out).Error; err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, GovNotFound()
	}
	out[0].finish()
	return &out[0], nil
}

// IssueAgentKey issues an agent's gateway key bound to a workload identity;
// the key is returned this once.
func (s *AgentGatewayService) IssueAgentKey(ctx context.Context, ws, actor uuid.UUID, in AgentGatewayAgentKeyInput) (*AgentGatewayAgentKeyView, string, error) {
	in.Name, in.SPIFFEID, in.ClientID = strings.TrimSpace(in.Name), strings.TrimSpace(in.SPIFFEID), strings.TrimSpace(in.ClientID)
	if in.Name == "" || len(in.Name) > 200 {
		return nil, "", GovBadParam("name", "name is required (at most 200 characters).")
	}
	if in.SPIFFEID != "" && (!strings.HasPrefix(in.SPIFFEID, "spiffe://") || len(in.SPIFFEID) > 512 || strings.ContainsAny(in.SPIFFEID, " \r\n")) {
		return nil, "", GovBadParam("spiffe_id", "spiffe_id must be a spiffe:// URI.")
	}
	if len(in.ClientID) > 512 {
		return nil, "", GovBadParam("client_id", "client_id is at most 512 characters.")
	}
	if len(in.Labels) > 32 {
		return nil, "", GovBadParam("labels", "at most 32 labels.")
	}
	for _, l := range in.Labels {
		if l == "" || len(l) > 200 {
			return nil, "", GovBadParam("labels", "labels are non-empty strings of at most 200 characters.")
		}
	}
	ids := map[string]*uuid.UUID{}
	for field, v := range map[string]string{"workload_id": in.WorkloadID, "identity_id": in.IdentityID, "agent_id": in.AgentID,
		"principal_user_id": in.PrincipalUserID, "gateway_id": in.GatewayID} {
		id, err := optUUIDParam(field, v)
		if err != nil {
			return nil, "", err
		}
		ids[field] = id
	}
	if in.SPIFFEID == "" && ids["workload_id"] == nil {
		return nil, "", govErr(http.StatusUnprocessableEntity, "workload_identity_required",
			"An agent key is bound to a workload identity: give spiffe_id, workload_id or both.", map[string]any{"field": "spiffe_id"})
	}
	key, err := GenerateAgentGatewayAgentKey()
	if err != nil {
		return nil, "", err
	}
	id := uuid.New()
	if in.ClientID == "" {
		in.ClientID = "agk:" + id.String()
	}
	labels, _ := json.Marshal(append([]string{}, in.Labels...))
	var out *AgentGatewayAgentKeyView
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if g := ids["gateway_id"]; g != nil {
			ok, err := gatewayExists(tx, ws, *g)
			if err != nil {
				return err
			}
			if !ok {
				return GovBadParam("gateway_id", "gateway_id must be one of the workspace's gateways.")
			}
		}
		if a := ids["agent_id"]; a != nil {
			if _, err := loadAgent(tx, ws, *a, false); err != nil {
				var ge *GovError
				if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
					return GovBadParam("agent_id", "agent_id must be one of the workspace's agents.")
				}
				return err
			}
		}
		if u := ids["principal_user_id"]; u != nil {
			ok, err := isWorkspaceMember(tx, ws, *u)
			if err != nil {
				return err
			}
			if !ok {
				return GovBadParam("principal_user_id", "principal_user_id must be a member of the workspace.")
			}
		}
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM agent_gateway_agent_key WHERE workspace_id = ? AND revoked_at IS NULL`, ws).Scan(&n).Error; err != nil {
			return err
		}
		if n >= agentGatewayMaxAgentKeys {
			return govErr(http.StatusConflict, "agent_key_limit", fmt.Sprintf("A workspace has at most %d live agent keys.", agentGatewayMaxAgentKeys), nil)
		}
		if err := tx.Exec(`INSERT INTO agent_gateway_agent_key
			  (id, workspace_id, name, client_id, key_hash, key_prefix, spiffe_id, workload_id, identity_id, labels, agent_id,
			   principal_user_id, gateway_id, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)`,
			id, ws, in.Name, in.ClientID, HashAgentGatewayAgentKey(key), key[:agentGatewayAgentKeyShown], in.SPIFFEID,
			ids["workload_id"], ids["identity_id"], string(labels), ids["agent_id"], ids["principal_user_id"], ids["gateway_id"],
			actor).Error; err != nil {
			return err
		}
		var err error
		if out, err = readAgentKeyView(tx, ws, id); err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventGatewayAgentKeyIssued, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"agent_key_id": id, "client_id": in.ClientID, "key_prefix": out.KeyPrefix, "spiffe_id": in.SPIFFEID,
				"workload_id": ids["workload_id"], "agent_id": ids["agent_id"]})
	})
	if isUniqueViolation(err, "uq_agent_gateway_agent_key_live_client") {
		return nil, "", govErr(http.StatusConflict, "client_id_taken", "A live agent key already has this client_id.", map[string]any{"field": "client_id"})
	}
	if err != nil {
		return nil, "", err
	}
	s.invalidatePolicies(ws)
	return out, key, nil
}

// ListAgentKeys lists the workspace's agent keys (never a key or its hash).
func (s *AgentGatewayService) ListAgentKeys(ctx context.Context, ws uuid.UUID) ([]AgentGatewayAgentKeyView, error) {
	out := []AgentGatewayAgentKeyView{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentGatewayAgentKeyCols+` FROM agent_gateway_agent_key WHERE workspace_id = ?
		                ORDER BY created_at DESC, id LIMIT 1000`, ws).Scan(&out).Error
	})
	for i := range out {
		out[i].finish()
	}
	return out, err
}

// RotateAgentKey replaces a live agent key; the old one is refused from the
// gateways' next hints refresh.
func (s *AgentGatewayService) RotateAgentKey(ctx context.Context, ws, actor, id uuid.UUID) (*AgentGatewayAgentKeyView, string, error) {
	key, err := GenerateAgentGatewayAgentKey()
	if err != nil {
		return nil, "", err
	}
	var out *AgentGatewayAgentKeyView
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, err := readAgentKeyView(tx, ws, id)
		if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return govConflict("agent_key_revoked", "A revoked agent key cannot be rotated; issue a new one.", nil)
		}
		if err := tx.Exec(`UPDATE agent_gateway_agent_key SET key_hash = ?, key_prefix = ?, rotated_at = now(), updated_at = now(),
		                     version = version + 1 WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`,
			HashAgentGatewayAgentKey(key), key[:agentGatewayAgentKeyShown], ws, id).Error; err != nil {
			return err
		}
		if out, err = readAgentKeyView(tx, ws, id); err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventGatewayAgentKeyRotated, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"agent_key_id": id, "key_prefix": out.KeyPrefix})
	})
	if err != nil {
		return nil, "", err
	}
	s.invalidatePolicies(ws)
	return out, key, nil
}

func revokeAgentKeysTx(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID, actor *uuid.UUID, reason string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res := tx.Exec(`UPDATE agent_gateway_agent_key SET revoked_at = now(), revoked_by = ?, revoked_reason = ?, updated_at = now(),
	                  version = version + 1 WHERE workspace_id = ? AND id IN ? AND revoked_at IS NULL`,
		actor, truncate(reason, 500), ws, ids)
	return res.RowsAffected, res.Error
}

// RevokeAgentKey revokes an agent key (twice: unchanged).
func (s *AgentGatewayService) RevokeAgentKey(ctx context.Context, ws, actor, id uuid.UUID, reason string) (*AgentGatewayAgentKeyView, error) {
	var out *AgentGatewayAgentKeyView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if _, err := readAgentKeyView(tx, ws, id); err != nil {
			return err
		}
		n, err := revokeAgentKeysTx(tx, ws, []uuid.UUID{id}, &actor, reason)
		if err != nil {
			return err
		}
		if n > 0 {
			if err := appendGovEvent(tx, ws, GovEventGatewayAgentKeyRevoked, models.GovActorUser, actor.String(), govEventRefs{},
				map[string]any{"agent_key_id": id, "reason": truncate(reason, 500)}); err != nil {
				return err
			}
		}
		out, err = readAgentKeyView(tx, ws, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.invalidatePolicies(ws)
	return out, nil
}

// AgentGatewayKeyHint is one live agent key as a gateway receives it in its
// hints: the hash and the workload identity it is bound to.
type AgentGatewayKeyHint struct {
	ID         string   `json:"id"`
	ClientID   string   `json:"client_id"`
	KeySHA256  string   `json:"key_sha256"`
	SPIFFEID   string   `json:"spiffe_id,omitempty"`
	WorkloadID string   `json:"workload_id,omitempty"`
	IdentityID string   `json:"identity_id,omitempty"`
	Labels     []string `json:"labels,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
}

// agentKeyHints reads the live agent keys a gateway may accept (its own
// and the workspace-wide ones), in a stable order.
func agentKeyHints(tx *gorm.DB, ws, gatewayID uuid.UUID) ([]AgentGatewayKeyHint, error) {
	var rows []struct {
		ID         uuid.UUID
		ClientID   string
		KeyHash    string
		SPIFFEID   string `gorm:"column:spiffe_id"`
		WorkloadID *uuid.UUID
		IdentityID *uuid.UUID
		Labels     string
		AgentID    *uuid.UUID
	}
	if err := tx.Raw(`SELECT id, client_id, key_hash, spiffe_id, workload_id, identity_id, labels::text AS labels, agent_id
	                   FROM agent_gateway_agent_key
	                  WHERE workspace_id = ? AND revoked_at IS NULL AND (gateway_id IS NULL OR gateway_id = ?)
	                  ORDER BY id LIMIT ?`, ws, gatewayID, agentGatewayMaxAgentKeys).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]AgentGatewayKeyHint, 0, len(rows))
	for _, r := range rows {
		h := AgentGatewayKeyHint{ID: r.ID.String(), ClientID: r.ClientID, KeySHA256: r.KeyHash, SPIFFEID: r.SPIFFEID}
		if r.WorkloadID != nil {
			h.WorkloadID = r.WorkloadID.String()
		}
		if r.IdentityID != nil {
			h.IdentityID = r.IdentityID.String()
		}
		if r.AgentID != nil {
			h.AgentID = r.AgentID.String()
		}
		_ = json.Unmarshal([]byte(r.Labels), &h.Labels)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

/* ------------------------------ W8: remove rules --------------------------- */

// GatewayRuleRemoval is what RemoveGatewayRulesForAgent did.
type GatewayRuleRemoval struct {
	AgentKeysRevoked  int64       `json:"agent_keys_revoked"`
	PoliciesDisabled  int64       `json:"policies_disabled"`
	AgentKeyIDs       []uuid.UUID `json:"agent_key_ids"`
	DisabledPolicyIDs []uuid.UUID `json:"disabled_policy_ids"`
}

// GatewayRuleRemover is the interface W8's remediation (retire) calls.
type GatewayRuleRemover interface {
	RemoveGatewayRulesForAgent(ctx context.Context, ws uuid.UUID, agentRef string) (GatewayRuleRemoval, error)
}

var _ GatewayRuleRemover = (*AgentGatewayService)(nil)

// RemoveGatewayRulesForAgent removes an agent's way through the workspace's
// gateways (W8 retire): every live agent key of the agent is revoked -- by
// W7 agent id, agent key id or gateway client id -- and every enabled ALLOW
// tool policy whose subject names exactly one of those keys' client ids is
// disabled. Policies for wider selectors (identity, workload, label, glob)
// are left alone: they govern other agents too. Idempotent; an unknown
// agentRef removes nothing.
func (s *AgentGatewayService) RemoveGatewayRulesForAgent(ctx context.Context, ws uuid.UUID, agentRef string) (GatewayRuleRemoval, error) {
	out := GatewayRuleRemoval{AgentKeyIDs: []uuid.UUID{}, DisabledPolicyIDs: []uuid.UUID{}}
	agentRef = strings.TrimSpace(agentRef)
	if agentRef == "" {
		return out, GovBadParam("agent_ref", "agent_ref is required.")
	}
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var keys []struct {
			ID       uuid.UUID
			ClientID string
		}
		if err := tx.Raw(`SELECT id, client_id FROM agent_gateway_agent_key
		                   WHERE workspace_id = ? AND (agent_id::text = ? OR id::text = ? OR client_id = ?)`,
			ws, agentRef, agentRef, agentRef).Scan(&keys).Error; err != nil {
			return err
		}
		clients := []string{agentRef}
		var live []uuid.UUID
		for _, k := range keys {
			live = append(live, k.ID)
			clients = append(clients, k.ClientID)
		}
		n, err := revokeAgentKeysTx(tx, ws, live, nil, "remediation: gateway rules removed for the agent")
		if err != nil {
			return err
		}
		out.AgentKeysRevoked = n
		out.AgentKeyIDs = append(out.AgentKeyIDs, live...)
		var pols []uuid.UUID
		if err := tx.Raw(`UPDATE agent_tool_policy SET enabled = false, updated_at = now(), version = version + 1
		                   WHERE workspace_id = ? AND enabled AND effect = 'allow' AND subject_client_id IN ?
		                     AND subject_identity_id IS NULL AND subject_workload_id IS NULL AND subject_agent_label = ''
		                   RETURNING id`, ws, clients).Scan(&pols).Error; err != nil {
			return err
		}
		out.PoliciesDisabled = int64(len(pols))
		out.DisabledPolicyIDs = append(out.DisabledPolicyIDs, pols...)
		if n == 0 && len(pols) == 0 {
			return nil
		}
		return appendGovEvent(tx, ws, GovEventGatewayRulesRemoved, models.GovActorSystem, "remediation", govEventRefs{},
			map[string]any{"agent_ref": truncate(agentRef, 200), "agent_key_ids": out.AgentKeyIDs, "disabled_policy_ids": pols})
	})
	if err != nil {
		return GatewayRuleRemoval{}, err
	}
	InvalidateAgentGatewayWorkspace(ws, uuid.Nil)
	return out, nil
}

/* ------------------------------------ events -------------------------------- */

// Governance events of W6's gateway keys and holds.
const (
	GovCatAgentGateway                = "agent_gateway"
	GovEventGatewayProviderKeyAdded   = "gateway.provider_key_added"
	GovEventGatewayProviderKeyRotated = "gateway.provider_key_rotated"
	GovEventGatewayProviderKeyRevoked = "gateway.provider_key_revoked"
	GovEventGatewayAgentKeyIssued     = "gateway.agent_key_issued"
	GovEventGatewayAgentKeyRotated    = "gateway.agent_key_rotated"
	GovEventGatewayAgentKeyRevoked    = "gateway.agent_key_revoked"
	GovEventGatewayRulesRemoved       = "gateway.rules_removed"
	GovEventGatewayAskNeeded          = "gateway.ask_needed"
	GovEventGatewayHoldDecided        = "gateway.hold_decided"
	GovEventGatewayHoldExpired        = "gateway.hold_expired"
)

func init() {
	GovEventVocabulary = append(GovEventVocabulary,
		GovEventKind{GovEventGatewayProviderKeyAdded, GovCatAgentGateway, "", "A model provider key was stored in AuthSec's secrets store for the workspace's gateways (fingerprint only)."},
		GovEventKind{GovEventGatewayProviderKeyRotated, GovCatAgentGateway, "", "A gateway provider key was rotated; the old value was destroyed."},
		GovEventKind{GovEventGatewayProviderKeyRevoked, GovCatAgentGateway, "", "A gateway provider key was revoked and destroyed in the secrets store."},
		GovEventKind{GovEventGatewayAgentKeyIssued, GovCatAgentGateway, "", "An agent gateway key was issued, bound to a workload identity."},
		GovEventKind{GovEventGatewayAgentKeyRotated, GovCatAgentGateway, "", "An agent gateway key was rotated."},
		GovEventKind{GovEventGatewayAgentKeyRevoked, GovCatAgentGateway, "", "An agent gateway key was revoked."},
		GovEventKind{GovEventGatewayRulesRemoved, GovCatAgentGateway, "", "Remediation removed an agent's gateway keys and its own allow rules."},
		GovEventKind{GovEventGatewayAskNeeded, GovCatAgentGateway, "", "A gateway held a call outside its argument bounds; its approver must decide (an ask once W4 lands)."},
		GovEventKind{GovEventGatewayHoldDecided, GovCatAgentGateway, "", "A person approved or denied a held gateway call."},
		GovEventKind{GovEventGatewayHoldExpired, GovCatAgentGateway, "", "A held gateway call expired undecided."},
	)
}
