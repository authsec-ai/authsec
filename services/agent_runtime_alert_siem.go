package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
)

// SIEM endpoints (SPEC-agent-runtime-visibility.md §5.7: "per-workspace URL
// and HMAC secret, through internal/safehttp").
//
// The signing secret is stored the way the workspace webhook's is
// (iga_gov_settings_service.go, GovDBChannelStore): in Vault under the
// workspace's path, with only the path (secret_ref) in the row. It is
// returned once, in the creation response, and never again. Deleting an
// endpoint keeps its row (deleted_at; its deliveries stay as the record)
// and removes the secret from Vault after the commit.

// AgentAlertSIEMEndpoint is one endpoint as the API shows it (no secret).
type AgentAlertSIEMEndpoint struct {
	ID        uuid.UUID `json:"id" gorm:"column:id"`
	URL       string    `json:"url" gorm:"column:url"`
	Enabled   bool      `json:"enabled" gorm:"column:enabled"`
	SecretSet bool      `json:"secret_set" gorm:"column:secret_set"`
	CreatedBy uuid.UUID `json:"created_by" gorm:"column:created_by"`
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at"`
}

// AgentAlertSIEMTestResult is POST /siem-endpoints/:id/test.
type AgentAlertSIEMTestResult struct {
	Delivered  bool   `json:"delivered"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Error      string `json:"error,omitempty"`
}

const agentAlertMaxSIEMEndpoints = 10

// AgentAlertSIEMSecretPath is the Vault path of an endpoint's secret.
func AgentAlertSIEMSecretPath(ws, endpoint uuid.UUID) string {
	return "kv/data/secret/workspaces/" + ws.String() + "/agent-runtime/siem-endpoint-" + endpoint.String()
}

func readAgentAlertSIEMSecret(ref string) (string, error) {
	vc := agentAlertVault()
	if vc == nil {
		return "", errors.New("the secrets store is not configured")
	}
	if ref == "" {
		return "", &agentAlertPermanent{errors.New("the endpoint has no signing secret")}
	}
	sec, err := vc.ReadSecret(ref)
	if err != nil {
		return "", err
	}
	v, _ := sec["secret"].(string)
	if v == "" {
		return "", errors.New("the stored signing secret is empty")
	}
	return v, nil
}

// validateAgentAlertSIEMURL accepts an absolute https URL without user
// information. Where it may connect is decided at send time by safehttp.
func validateAgentAlertSIEMURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return "", GovBadParam("url", "url is required (at most 2048 characters).")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", GovBadParam("url", "url must be an absolute https URL without credentials or fragment.")
	}
	return u.String(), nil
}

// ListSIEMEndpoints is GET /siem-endpoints (deleted ones are not listed).
func (s *AgentAlertService) ListSIEMEndpoints(ctx context.Context, ws uuid.UUID) ([]AgentAlertSIEMEndpoint, error) {
	var out []AgentAlertSIEMEndpoint
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, url, enabled, secret_ref <> '' AS secret_set, created_by, created_at
		                 FROM agent_alert_siem_endpoint WHERE workspace_id = ? AND deleted_at IS NULL
		                ORDER BY created_at, id`, ws).Scan(&out).Error
	})
	if out == nil {
		out = []AgentAlertSIEMEndpoint{}
	}
	return out, err
}

// CreateSIEMEndpoint is POST /siem-endpoints. An empty secret is generated
// (32 random bytes, hex). The secret is returned here and never again.
func (s *AgentAlertService) CreateSIEMEndpoint(ctx context.Context, ws, actor uuid.UUID, rawURL, secret string) (*AgentAlertSIEMEndpoint, string, error) {
	u, err := validateAgentAlertSIEMURL(rawURL)
	if err != nil {
		return nil, "", err
	}
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, "", err
		}
		secret = hex.EncodeToString(buf)
	} else if len(secret) < 16 || len(secret) > 512 {
		return nil, "", GovBadParam("secret", "secret must be 16 to 512 characters (omit it to have one generated).")
	}
	vc := agentAlertVault()
	if vc == nil {
		return nil, "", govErr(http.StatusServiceUnavailable, "siem_secret_store_unavailable",
			"The secrets store is not configured; a SIEM endpoint's signing secret cannot be stored.", nil)
	}
	id := uuid.New()
	ref := AgentAlertSIEMSecretPath(ws, id)
	// Count first, so a workspace at its limit writes nothing to Vault.
	var n int64
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT count(*) FROM agent_alert_siem_endpoint WHERE workspace_id = ? AND deleted_at IS NULL`, ws).Scan(&n).Error
	}); err != nil {
		return nil, "", err
	}
	if n >= agentAlertMaxSIEMEndpoints {
		return nil, "", govErr(http.StatusConflict, "siem_endpoint_limit", "A workspace has at most 10 SIEM endpoints.", nil)
	}
	if err := vc.WriteSecret(ref, map[string]interface{}{"secret": secret}); err != nil {
		log.Printf("[agent-alerts] workspace %s: storing a SIEM secret failed: %v", ws, err)
		return nil, "", govErr(http.StatusServiceUnavailable, "siem_secret_store_unavailable",
			"The signing secret could not be stored; try again shortly.", nil)
	}
	var out AgentAlertSIEMEndpoint
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []AgentAlertSIEMEndpoint
		if err := tx.Raw(`INSERT INTO agent_alert_siem_endpoint (id, workspace_id, url, secret_ref, enabled, created_by)
		                  VALUES (?, ?, ?, ?, true, ?)
		                  RETURNING id, url, enabled, secret_ref <> '' AS secret_set, created_by, created_at`,
			id, ws, u, ref, actor).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) != 1 {
			return errors.New("SIEM endpoint insert returned no row")
		}
		out = rows[0]
		return nil
	})
	if err != nil {
		if _, derr := vault.Destroy(vc, ref); derr != nil {
			log.Printf("[agent-alerts] workspace %s: removing an unused SIEM secret failed (left in Vault): %v", ws, derr)
		}
		return nil, "", err
	}
	return &out, secret, nil
}

// DeleteSIEMEndpoint is DELETE /siem-endpoints/:id: the endpoint stops
// receiving (its pending deliveries fail), its secret is removed from Vault.
func (s *AgentAlertService) DeleteSIEMEndpoint(ctx context.Context, ws, id uuid.UUID) error {
	var refs []string
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Raw(`SELECT secret_ref FROM agent_alert_siem_endpoint
		                   WHERE workspace_id = ? AND id = ? AND deleted_at IS NULL FOR UPDATE`, ws, id).Scan(&refs).Error; err != nil {
			return err
		}
		if len(refs) == 0 {
			return errAgentAlertNotFound()
		}
		if err := tx.Exec(`UPDATE agent_alert_siem_endpoint SET enabled = false, deleted_at = now(), secret_ref = ''
		                   WHERE workspace_id = ? AND id = ?`, ws, id).Error; err != nil {
			return err
		}
		return tx.Exec(`UPDATE agent_alert_delivery SET status = 'failed', last_error = 'the SIEM endpoint was deleted', leased_until = NULL
		                 WHERE workspace_id = ? AND endpoint_id = ? AND status = 'pending'`, ws, id).Error
	})
	if err != nil {
		return err
	}
	if vc := agentAlertVault(); vc != nil && refs[0] != "" {
		if _, derr := vault.Destroy(vc, refs[0]); derr != nil {
			log.Printf("[agent-alerts] workspace %s: removing a deleted SIEM endpoint's secret failed (left in Vault): %v", ws, derr)
		}
	}
	return nil
}

// TestSIEMEndpoint is POST /siem-endpoints/:id/test: one signed test POST
// (type AgentAlertSIEMTestType), made now. Nothing is recorded.
func (s *AgentAlertService) TestSIEMEndpoint(ctx context.Context, ws, id uuid.UUID) (*AgentAlertSIEMTestResult, error) {
	var eps []agentAlertEndpointRow
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT url, secret_ref, enabled, deleted_at FROM agent_alert_siem_endpoint
		                WHERE workspace_id = ? AND id = ? AND deleted_at IS NULL`, ws, id).Scan(&eps).Error
	}); err != nil {
		return nil, err
	}
	if len(eps) == 0 {
		return nil, errAgentAlertNotFound()
	}
	secret, err := readAgentAlertSIEMSecret(eps[0].SecretRef)
	if err != nil {
		return nil, govErr(http.StatusServiceUnavailable, "siem_secret_unavailable", "The endpoint's signing secret cannot be read right now.", nil)
	}
	now := s.now()
	deliveryID := "test-" + uuid.NewString()
	body, err := json.Marshal(map[string]any{"type": AgentAlertSIEMTestType, "version": 1, "delivery_id": deliveryID,
		"sent_at": now.UTC(), "workspace_id": ws.String(), "endpoint_id": id.String(),
		"alert": map[string]any{}, "evidence": []any{}})
	if err != nil {
		return nil, err
	}
	status, err := PostAgentAlertSIEM(ctx, agentAlertSIEMClient(), eps[0].URL, secret, deliveryID, body, now)
	res := &AgentAlertSIEMTestResult{Delivered: err == nil, HTTPStatus: status}
	if err != nil {
		res.Error = truncate(err.Error(), 300)
	}
	return res, nil
}
