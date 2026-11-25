package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/askconnect"
	"github.com/authsec-ai/authsec/internal/safehttp"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
)

// Ticketing and paging connectors of asks (SPEC-secops-backend-upgrade.md
// W4, C13; migration 220).
//
// Configuration, per workspace and provider (agent_ask_integration):
//
//	ticketing  jira        site_url (https), email, project_key, issue_type, create_for (asks|cases|both)
//	           servicenow  instance_url (https), username, create_for
//	paging     pagerduty   region (us|eu); the secret is the Events v2 routing key
//	           opsgenie    region (us|eu); the secret is an API integration key
//
// The secret (API token, password, routing key) is written to Vault at
// kv/data/secret/workspaces/<ws>/agent-runtime/ask-integration-<provider>-<nonce>
// (a new path per write; the old one is destroyed); the row keeps the path
// and a fingerprint. It is never returned, logged or put in an event.
//
// Items (agent_ask_external): a ticket is queued for every new ask while a
// ticketing integration with create_for asks|both is on, and for a case on
// request (POST /agent-runtime/cases/:id/tickets); a page is queued for an
// ask of high severity or tier 3+ while a paging integration is on. The
// external worker (RunAgentAskExternalWorker, every minute, leader-locked,
// AUTHSEC_DISABLE_ASK_EXTERNAL_SYNC=true turns it off) opens them, reads a
// ticket's state back every 5 minutes and marks it resolved when the tool
// says done (askconnect's conservative mapping) -- that closes the link
// only: an ask is never answered by a ticket. A page is resolved when its
// ask is answered, withdrawn or expired. Every request goes through
// internal/safehttp (the site URL is the workspace's choice). A permanent
// failure (4xx, a refused address) or 8 attempts mark the item failed.

// Categories.
const (
	AskIntegrationTicketing = "ticketing"
	AskIntegrationPaging    = "paging"
)

const (
	askExternalBatch       = 50
	askExternalMaxAttempts = 8
	askTicketPoll          = 5 * time.Minute
	askPagePoll            = time.Hour
	askExternalTimeout     = 15 * time.Second
)

var askProviderCategory = map[string]string{
	askconnect.Jira: AskIntegrationTicketing, askconnect.ServiceNow: AskIntegrationTicketing,
	askconnect.PagerDuty: AskIntegrationPaging, askconnect.Opsgenie: AskIntegrationPaging,
}

/* ------------------------------------------------------------------------- */
/*                              Process wiring                                */
/* ------------------------------------------------------------------------- */

var agentAskDeps struct {
	sync.RWMutex
	vault  vault.VaultClient
	client *http.Client
	bases  map[string]string // provider/region -> base URL (tests)
}

// SetAgentAskVault installs the Vault client of integration secrets (nil:
// none can be stored). It returns the undo.
func SetAgentAskVault(vc vault.VaultClient) (restore func()) {
	agentAskDeps.Lock()
	prev := agentAskDeps.vault
	agentAskDeps.vault = vc
	agentAskDeps.Unlock()
	return func() { SetAgentAskVault(prev) }
}

func agentAskVault() vault.VaultClient {
	agentAskDeps.RLock()
	defer agentAskDeps.RUnlock()
	return agentAskDeps.vault
}

// SetAgentAskHTTPClient replaces the connectors' HTTP client (tests); nil
// restores the SSRF-safe default. It returns the undo.
func SetAgentAskHTTPClient(c *http.Client) (restore func()) {
	agentAskDeps.Lock()
	prev := agentAskDeps.client
	agentAskDeps.client = c
	agentAskDeps.Unlock()
	return func() { SetAgentAskHTTPClient(prev) }
}

// SetAgentAskProviderBases overrides the fixed PagerDuty / Opsgenie hosts
// (tests: "pagerduty", "opsgenie" -> a fake server). It returns the undo.
func SetAgentAskProviderBases(m map[string]string) (restore func()) {
	agentAskDeps.Lock()
	prev := agentAskDeps.bases
	agentAskDeps.bases = m
	agentAskDeps.Unlock()
	return func() { SetAgentAskProviderBases(prev) }
}

func agentAskHTTPClient() *http.Client {
	agentAskDeps.RLock()
	c := agentAskDeps.client
	agentAskDeps.RUnlock()
	if c != nil {
		return c
	}
	return safehttp.New(askExternalTimeout)
}

func agentAskProviderBase(provider, region string) string {
	agentAskDeps.RLock()
	b := agentAskDeps.bases[provider]
	agentAskDeps.RUnlock()
	if b != "" {
		return b
	}
	switch provider {
	case askconnect.PagerDuty:
		if region == "eu" {
			return askconnect.PagerDutyEventsEU
		}
		return askconnect.PagerDutyEventsUS
	case askconnect.Opsgenie:
		if region == "eu" {
			return askconnect.OpsgenieEU
		}
		return askconnect.OpsgenieUS
	}
	return ""
}

// InstallAgentAsks installs the Vault client for integration secrets
// (VAULT_ADDR / VAULT_TOKEN). cmd/main.go calls it once.
func InstallAgentAsks() {
	addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN")
	if addr == "" || tok == "" {
		log.Printf("[agent-asks] VAULT_ADDR/VAULT_TOKEN not set: ticketing and paging integrations unavailable")
		return
	}
	vc, err := vault.NewClient(addr, tok)
	if err != nil {
		log.Printf("[agent-asks] vault client: %v; ticketing and paging integrations unavailable", err)
		return
	}
	SetAgentAskVault(vc)
}

// AgentAskIntegrationSecretPath is the Vault path of an integration secret.
func AgentAskIntegrationSecretPath(ws uuid.UUID, provider, nonce string) string {
	return "kv/data/secret/workspaces/" + ws.String() + "/agent-runtime/ask-integration-" + provider + "-" + nonce
}

func askSecretFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	last := secret
	if len(last) > 4 {
		last = last[len(last)-4:]
	}
	return "..." + last + " sha256:" + hex.EncodeToString(sum[:])[:12]
}

/* ------------------------------------------------------------------------- */
/*                               Configuration                                */
/* ------------------------------------------------------------------------- */

// AgentAskIntegration is a configured integration (never its secret).
type AgentAskIntegration struct {
	ID                uuid.UUID       `json:"id" gorm:"column:id"`
	Provider          string          `json:"provider" gorm:"column:provider"`
	Category          string          `json:"category" gorm:"column:category"`
	Enabled           bool            `json:"enabled" gorm:"column:enabled"`
	Config            json.RawMessage `json:"config" gorm:"column:config"`
	SecretFingerprint string          `json:"secret_fingerprint" gorm:"column:secret_fingerprint"`
	LastError         string          `json:"last_error" gorm:"column:last_error"`
	LastOKAt          *time.Time      `json:"last_ok_at" gorm:"column:last_ok_at"`
	CreatedBy         *uuid.UUID      `json:"created_by" gorm:"column:created_by"`
	CreatedAt         time.Time       `json:"created_at" gorm:"column:created_at"`
	UpdatedAt         time.Time       `json:"updated_at" gorm:"column:updated_at"`
}

const agentAskIntegrationCols = `id, provider, category, enabled, config, secret_fingerprint, last_error, last_ok_at, created_by,
	created_at, updated_at`

// AgentAskIntegrationInput is PUT /integrations/{ticketing|paging}/:provider.
type AgentAskIntegrationInput struct {
	Enabled *bool
	Config  map[string]string
	// Secret is required when the integration is created; given later it
	// replaces the stored one.
	Secret *string
}

var askEmailRe = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,190}$`)

// ValidateAgentAskIntegrationConfig checks a provider's settings and
// returns them normalised.
func ValidateAgentAskIntegrationConfig(provider string, in map[string]string) (map[string]string, error) {
	allowed := map[string][]string{
		askconnect.Jira:       {"site_url", "email", "project_key", "issue_type", "create_for"},
		askconnect.ServiceNow: {"instance_url", "username", "create_for"},
		askconnect.PagerDuty:  {"region"},
		askconnect.Opsgenie:   {"region"},
	}[provider]
	ok := map[string]bool{}
	for _, k := range allowed {
		ok[k] = true
	}
	out := map[string]string{}
	for k, v := range in {
		if !ok[k] {
			return nil, GovBadParam("config."+k, "unknown setting "+k+" for "+provider+".")
		}
		v = strings.TrimSpace(v)
		if utf8.RuneCountInString(v) > 500 || strings.ContainsRune(v, 0) {
			return nil, GovBadParam("config."+k, k+" is at most 500 characters.")
		}
		out[k] = v
	}
	need := func(k, msg string) error {
		if out[k] == "" {
			return GovBadParam("config."+k, msg)
		}
		return nil
	}
	createFor := func() error {
		switch out["create_for"] {
		case "":
			out["create_for"] = "asks"
		case "asks", "cases", "both":
		default:
			return GovBadParam("config.create_for", "create_for must be asks, cases or both.")
		}
		return nil
	}
	region := func() error {
		switch out["region"] {
		case "":
			out["region"] = "us"
		case "us", "eu":
		default:
			return GovBadParam("config.region", "region must be us or eu.")
		}
		return nil
	}
	switch provider {
	case askconnect.Jira:
		u, err := askconnect.SiteURL(out["site_url"])
		if err != nil {
			return nil, GovBadParam("config.site_url", "site_url: "+err.Error())
		}
		out["site_url"] = u
		if !askEmailRe.MatchString(out["email"]) {
			return nil, GovBadParam("config.email", "email is the Jira account the API token belongs to.")
		}
		if !askconnect.JiraProjectKey.MatchString(out["project_key"]) {
			return nil, GovBadParam("config.project_key", "project_key is a Jira project key (e.g. SEC).")
		}
		if out["issue_type"] == "" {
			out["issue_type"] = "Task"
		}
		if err := createFor(); err != nil {
			return nil, err
		}
	case askconnect.ServiceNow:
		u, err := askconnect.SiteURL(out["instance_url"])
		if err != nil {
			return nil, GovBadParam("config.instance_url", "instance_url: "+err.Error())
		}
		out["instance_url"] = u
		if err := need("username", "username is required."); err != nil {
			return nil, err
		}
		if err := createFor(); err != nil {
			return nil, err
		}
	case askconnect.PagerDuty, askconnect.Opsgenie:
		if err := region(); err != nil {
			return nil, err
		}
	default:
		return nil, GovNotFound()
	}
	return out, nil
}

func askCheckCategory(category, provider string) error {
	if askProviderCategory[provider] != category || category == "" {
		return GovNotFound()
	}
	return nil
}

// ListIntegrations is GET /integrations/{ticketing|paging}.
func (s *AgentAskService) ListIntegrations(ctx context.Context, ws uuid.UUID, category string) ([]AgentAskIntegration, error) {
	out := []AgentAskIntegration{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentAskIntegrationCols+` FROM agent_ask_integration WHERE workspace_id = ? AND category = ?
		        ORDER BY provider`, ws, category).Scan(&out).Error
	})
	if out == nil {
		out = []AgentAskIntegration{}
	}
	return out, err
}

func askNonce() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// PutIntegration creates or updates an integration (iga:admin).
func (s *AgentAskService) PutIntegration(ctx context.Context, ws, actor uuid.UUID, category, provider string, in AgentAskIntegrationInput) (*AgentAskIntegration, error) {
	if err := askCheckCategory(category, provider); err != nil {
		return nil, err
	}
	cfg, err := ValidateAgentAskIntegrationConfig(provider, in.Config)
	if err != nil {
		return nil, err
	}
	var existing []struct {
		SecretRef string `gorm:"column:secret_ref"`
	}
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT secret_ref FROM agent_ask_integration WHERE workspace_id = ? AND provider = ?`, ws, provider).Scan(&existing).Error
	}); err != nil {
		return nil, err
	}
	if len(existing) == 0 && in.Secret == nil {
		return nil, GovBadParam("secret", "secret (the API token, password or routing key) is required.")
	}
	newRef, fp, oldRef := "", "", ""
	if in.Secret != nil {
		sec := strings.TrimSpace(*in.Secret)
		if sec == "" || len(sec) > 4096 {
			return nil, GovBadParam("secret", "secret is required (at most 4096 characters).")
		}
		vc := agentAskVault()
		if vc == nil {
			return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable",
				"The secrets store is not configured; the integration's secret cannot be stored.", nil)
		}
		nonce, err := askNonce()
		if err != nil {
			return nil, err
		}
		newRef, fp = AgentAskIntegrationSecretPath(ws, provider, nonce), askSecretFingerprint(sec)
		if err := vc.WriteSecret(newRef, map[string]interface{}{"secret": sec}); err != nil {
			log.Printf("[agent-asks] workspace %s: storing a %s secret failed (%T)", ws, provider, err)
			return nil, govErr(http.StatusServiceUnavailable, "secret_store_unavailable", "The secret could not be stored; try again shortly.", nil)
		}
		if len(existing) > 0 {
			oldRef = existing[0].SecretRef
		}
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	cfgRaw, _ := json.Marshal(cfg)
	now := s.now().UTC()
	var out []AgentAskIntegration
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if len(existing) == 0 {
			if err := tx.Raw(`INSERT INTO agent_ask_integration (workspace_id, provider, category, enabled, config, secret_ref,
			        secret_fingerprint, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?)
			        RETURNING `+agentAskIntegrationCols, ws, provider, category, enabled, string(cfgRaw), newRef, fp, actor, now, now).Scan(&out).Error; err != nil {
				return err
			}
		} else {
			q := `UPDATE agent_ask_integration SET enabled = ?, config = ?::jsonb, last_error = '', updated_at = ?`
			args := []any{enabled, string(cfgRaw), now}
			if newRef != "" {
				q += `, secret_ref = ?, secret_fingerprint = ?`
				args = append(args, newRef, fp)
			}
			q += ` WHERE workspace_id = ? AND provider = ? RETURNING ` + agentAskIntegrationCols
			args = append(args, ws, provider)
			if err := tx.Raw(q, args...).Scan(&out).Error; err != nil {
				return err
			}
		}
		if len(out) != 1 {
			return errors.New("integration write returned no row")
		}
		return appendGovEvent(tx, ws, GovEventAskIntegrationSet, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"provider": provider, "category": category, "enabled": enabled, "config": cfg,
				"secret_replaced": newRef != ""})
	})
	if err != nil {
		if newRef != "" {
			if _, derr := vault.Destroy(agentAskVault(), newRef); derr != nil {
				log.Printf("[agent-asks] workspace %s: removing an unused %s secret failed (left in Vault): %v", ws, provider, derr)
			}
		}
		return nil, err
	}
	if oldRef != "" {
		if _, derr := vault.Destroy(agentAskVault(), oldRef); derr != nil {
			log.Printf("[agent-asks] workspace %s: removing a replaced %s secret failed (left in Vault): %v", ws, provider, derr)
		}
	}
	return &out[0], nil
}

// DeleteIntegration removes an integration and destroys its secret; its open
// items stop syncing (they fail with "integration removed").
func (s *AgentAskService) DeleteIntegration(ctx context.Context, ws, actor uuid.UUID, category, provider string) error {
	if err := askCheckCategory(category, provider); err != nil {
		return err
	}
	var ref string
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []struct {
			SecretRef string `gorm:"column:secret_ref"`
		}
		if err := tx.Raw(`DELETE FROM agent_ask_integration WHERE workspace_id = ? AND provider = ? RETURNING secret_ref`,
			ws, provider).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		ref = rows[0].SecretRef
		return appendGovEvent(tx, ws, GovEventAskIntegrationRemoved, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"provider": provider, "category": category})
	})
	if err != nil {
		return err
	}
	if ref != "" {
		if vc := agentAskVault(); vc != nil {
			if _, derr := vault.Destroy(vc, ref); derr != nil {
				log.Printf("[agent-asks] workspace %s: removing a %s secret failed (left in Vault): %v", ws, provider, derr)
			}
		}
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                   Items                                    */
/* ------------------------------------------------------------------------- */

// enqueueAskExternalsTx queues the tickets and pages of a new ask (a
// savepoint: a failure is logged, never loses the ask).
func enqueueAskExternalsTx(tx *gorm.DB, ws uuid.UUID, row *agentAskRow) {
	err := tx.Transaction(func(sp *gorm.DB) error {
		var ints []struct {
			Provider  string `gorm:"column:provider"`
			Category  string `gorm:"column:category"`
			CreateFor string `gorm:"column:create_for"`
		}
		if err := sp.Raw(`SELECT provider, category, COALESCE(config->>'create_for', '') AS create_for FROM agent_ask_integration
		        WHERE workspace_id = ? AND enabled`, ws).Scan(&ints).Error; err != nil {
			return err
		}
		for _, in := range ints {
			kind := ""
			switch {
			case in.Category == AskIntegrationTicketing && (in.CreateFor == "asks" || in.CreateFor == "both"):
				kind = "ticket"
			case in.Category == AskIntegrationPaging && (row.Severity == "high" || row.Tier >= 3):
				kind = "page"
			default:
				continue
			}
			if err := sp.Exec(`INSERT INTO agent_ask_external (workspace_id, provider, kind, ask_id)
			        VALUES (?, ?, ?, ?) ON CONFLICT (workspace_id, provider, ask_id) WHERE ask_id IS NOT NULL DO NOTHING`,
				ws, in.Provider, kind, row.ID).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("[agent-asks] workspace %s: ask %s: tickets/pages not queued: %v", ws, row.ID, err)
	}
}

// RequestCaseTicket is POST /agent-runtime/cases/:id/tickets: a ticket for a
// case in the named ticketing tool (idempotent per case and provider).
func (s *AgentAskService) RequestCaseTicket(ctx context.Context, ws, actor, caseID uuid.UUID, provider string) (*AgentAskExternalVw, error) {
	if askProviderCategory[provider] != AskIntegrationTicketing {
		return nil, GovBadParam("provider", "provider must be jira or servicenow.")
	}
	var out *AgentAskExternalVw
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if _, err := getAgentCase(tx, ws, caseID); err != nil {
			return err
		}
		var on []bool
		if err := tx.Raw(`SELECT enabled FROM agent_ask_integration WHERE workspace_id = ? AND provider = ?`, ws, provider).Scan(&on).Error; err != nil {
			return err
		}
		if len(on) == 0 || !on[0] {
			return govConflict("integration_not_configured", "This ticketing integration is not configured or is turned off.", nil)
		}
		if err := tx.Exec(`INSERT INTO agent_ask_external (workspace_id, provider, kind, case_id, created_by)
		        VALUES (?, ?, 'ticket', ?, ?) ON CONFLICT (workspace_id, provider, case_id) WHERE case_id IS NOT NULL DO NOTHING`,
			ws, provider, caseID, actor).Error; err != nil {
			return err
		}
		var rows []AgentAskExternalVw
		if err := tx.Raw(`SELECT `+agentAskExternalCols+` FROM agent_ask_external WHERE workspace_id = ? AND provider = ? AND case_id = ?`,
			ws, provider, caseID).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return errors.New("case ticket insert returned no row")
		}
		out = &rows[0]
		return nil
	})
	return out, err
}

/* ------------------------------------------------------------------------- */
/*                                  Worker                                    */
/* ------------------------------------------------------------------------- */

type askExternalWork struct {
	ex        AgentAskExternalVw
	provider  string
	enabled   bool
	config    map[string]string
	secretRef string
	gone      bool // the integration was removed
	// the subject
	askLive   bool
	summary   string
	desc      string
	severity  string
	link      string
	subjectID uuid.UUID
}

func askBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 6 {
		return time.Hour
	}
	return time.Minute << uint(attempt-1)
}

// SyncExternals runs one pass of the external worker; it returns how many
// items it handled.
func (s *AgentAskService) SyncExternals(ctx context.Context) (int, error) {
	var due []struct {
		WorkspaceID uuid.UUID `gorm:"column:workspace_id"`
		ID          uuid.UUID `gorm:"column:id"`
	}
	// TENANT-EXEMPT: the external worker runs across workspaces (no request tenant) and lists due item ids only; each item is read, sent and recorded in its own workspace-bound transaction (tenancy.InWorkspace).
	if err := s.db.WithContext(ctx).Raw(`SELECT workspace_id, id FROM agent_ask_external
	        WHERE state IN ('pending', 'open', 'resolving') AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?`,
		s.now().UTC(), askExternalBatch).Scan(&due).Error; err != nil {
		return 0, err
	}
	var first error
	for _, d := range due {
		if ctx.Err() != nil {
			break
		}
		if err := s.SyncExternal(ctx, d.WorkspaceID, d.ID); err != nil && first == nil {
			first = fmt.Errorf("workspace %s: item %s: %w", d.WorkspaceID, d.ID, err)
		}
	}
	return len(due), first
}

// SyncExternal handles one item of a workspace now.
func (s *AgentAskService) SyncExternal(ctx context.Context, ws, id uuid.UUID) error {
	var w askExternalWork
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var exs []AgentAskExternalVw
		if err := tx.Raw(`SELECT `+agentAskExternalCols+` FROM agent_ask_external WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&exs).Error; err != nil {
			return err
		}
		if len(exs) == 0 {
			return GovNotFound()
		}
		w.ex = exs[0]
		var ints []struct {
			Enabled   bool   `gorm:"column:enabled"`
			Config    string `gorm:"column:config"`
			SecretRef string `gorm:"column:secret_ref"`
		}
		if err := tx.Raw(`SELECT enabled, config::text AS config, secret_ref FROM agent_ask_integration WHERE workspace_id = ? AND provider = ?`,
			ws, w.ex.Provider).Scan(&ints).Error; err != nil {
			return err
		}
		if len(ints) == 0 {
			w.gone = true
		} else {
			w.enabled, w.secretRef = ints[0].Enabled, ints[0].SecretRef
			_ = json.Unmarshal([]byte(ints[0].Config), &w.config)
		}
		if w.ex.AskID != nil {
			row, err := readAgentAsk(tx, ws, *w.ex.AskID, false)
			if err != nil {
				return err
			}
			w.askLive, w.severity, w.subjectID = row.live(), row.Severity, row.ID
			w.summary = "AuthSec asks: " + clipText(row.Question, 200)
			w.desc = row.Question + "\n\nAnswers: " + strings.Join(askChoiceLabels(row.choices()), " / ") +
				"\nAbout: " + row.AboutKind + " " + row.AboutID + "\nDue: " + row.DueAt.UTC().Format(time.RFC3339)
			w.link = AgentAskConsoleLink(row.ID)
		} else if w.ex.CaseID != nil {
			c, err := getAgentCase(tx, ws, *w.ex.CaseID)
			if err != nil {
				return err
			}
			w.severity, w.subjectID = c.Severity, c.ID
			w.summary = fmt.Sprintf("AuthSec case #%d: %s", c.Number, clipText(c.Title, 200))
			w.desc = fmt.Sprintf("Case #%d (%s severity, %s), %d alerts.", c.Number, c.Severity, c.State, c.AlertCount)
			w.link = govConsoleLink("/iga/agent-runtime/cases/" + c.ID.String())
		}
		return nil
	}); err != nil {
		return err
	}
	now := s.now().UTC()
	if w.gone || !w.enabled {
		if w.ex.Kind == "page" && w.ex.State == "pending" {
			return s.recordExternal(ctx, ws, w, askOutcome{state: "resolved", status: "not_needed"}, now)
		}
		return s.recordExternal(ctx, ws, w, askOutcome{state: "failed", err: errors.New("the integration was removed or turned off"), permanent: true}, now)
	}
	if w.ex.Kind == "page" && w.ex.State == "pending" && !w.askLive {
		return s.recordExternal(ctx, ws, w, askOutcome{state: "resolved", status: "not_needed"}, now)
	}
	if w.ex.Kind == "page" && w.ex.State == "open" && !w.askLive {
		w.ex.State = "resolving"
	}
	if w.ex.Kind == "page" && w.ex.State == "open" {
		return s.recordExternal(ctx, ws, w, askOutcome{state: "open", status: w.ex.LastStatus, next: askPagePoll}, now)
	}
	vc := agentAskVault()
	if vc == nil {
		return s.recordExternal(ctx, ws, w, askOutcome{err: errors.New("the secrets store is not configured")}, now)
	}
	data, err := vc.ReadSecret(w.secretRef)
	secret, _ := data["secret"].(string)
	if err != nil || secret == "" {
		return s.recordExternal(ctx, ws, w, askOutcome{err: errors.New("the integration's secret cannot be read")}, now)
	}
	out := s.callProvider(ctx, w, secret)
	return s.recordExternal(ctx, ws, w, out, now)
}

type askOutcome struct {
	state     string // the new state ("" = unchanged, a failure)
	key, url  string
	status    string
	next      time.Duration
	err       error
	permanent bool
}

func (s *AgentAskService) callProvider(ctx context.Context, w askExternalWork, secret string) askOutcome {
	client := agentAskHTTPClient()
	in := askconnect.Input{Summary: w.summary, Description: w.desc, Severity: w.severity, Link: w.link,
		DedupeKey: "authsec-" + w.ex.Provider + "-" + w.subjectID.String()}
	fail := func(err error) askOutcome {
		return askOutcome{err: err, permanent: askconnect.IsPermanent(err) || errors.Is(err, safehttp.ErrBlockedAddress)}
	}
	cfg := w.config
	switch w.ex.Provider {
	case askconnect.Jira, askconnect.ServiceNow:
		type ticketer interface {
			Create(context.Context, askconnect.Input) (askconnect.Item, error)
			Get(context.Context, string) (askconnect.Item, error)
		}
		var t ticketer
		if w.ex.Provider == askconnect.Jira {
			t = askconnect.JiraClient{Site: cfg["site_url"], Email: cfg["email"], Token: secret, ProjectKey: cfg["project_key"],
				IssueType: cfg["issue_type"], HTTP: client}
		} else {
			t = askconnect.ServiceNowClient{Instance: cfg["instance_url"], Username: cfg["username"], Password: secret, HTTP: client}
		}
		if w.ex.State == "pending" {
			it, err := t.Create(ctx, in)
			if err != nil {
				return fail(err)
			}
			key := it.Key
			return askOutcome{state: "open", key: key, url: it.URL, status: it.Status, next: askTicketPoll}
		}
		it, err := t.Get(ctx, w.ex.ExternalKey)
		if err != nil {
			return fail(err)
		}
		if it.Resolved {
			return askOutcome{state: "resolved", status: it.Status}
		}
		return askOutcome{state: "open", status: it.Status, next: askTicketPoll}
	case askconnect.PagerDuty, askconnect.Opsgenie:
		type pager interface {
			Trigger(context.Context, askconnect.Input) (askconnect.Item, error)
			Resolve(context.Context, string) error
		}
		var p pager
		base := agentAskProviderBase(w.ex.Provider, cfg["region"])
		if w.ex.Provider == askconnect.PagerDuty {
			p = askconnect.PagerDutyClient{Base: base, RoutingKey: secret, HTTP: client}
		} else {
			p = askconnect.OpsgenieClient{Base: base, APIKey: secret, HTTP: client}
		}
		if w.ex.State == "pending" {
			it, err := p.Trigger(ctx, in)
			if err != nil {
				return fail(err)
			}
			return askOutcome{state: "open", key: it.Key, status: it.Status, next: askPagePoll}
		}
		if err := p.Resolve(ctx, w.ex.ExternalKey); err != nil {
			return fail(err)
		}
		return askOutcome{state: "resolved", status: "resolved"}
	}
	return askOutcome{err: fmt.Errorf("unknown provider %q", w.ex.Provider), permanent: true}
}

// recordExternal writes an item's outcome and its events.
func (s *AgentAskService) recordExternal(ctx context.Context, ws uuid.UUID, w askExternalWork, o askOutcome, now time.Time) error {
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var cur []string
		if err := tx.Raw(`SELECT state FROM agent_ask_external WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, w.ex.ID).Scan(&cur).Error; err != nil {
			return err
		}
		if len(cur) == 0 || cur[0] != w.ex.State && !(cur[0] == "open" && w.ex.State == "resolving") {
			return nil // changed meanwhile (the ask closed): the next pass sees it
		}
		subject := map[string]any{"provider": w.ex.Provider, "kind": w.ex.Kind, "external_id": w.ex.ID}
		if w.ex.AskID != nil {
			subject["ask_id"] = *w.ex.AskID
		}
		if w.ex.CaseID != nil {
			subject["case_id"] = *w.ex.CaseID
		}
		askEvent := func(kind string, detail map[string]any) error {
			if w.ex.AskID == nil {
				return nil
			}
			var steps []int
			if err := tx.Raw(`SELECT step FROM agent_ask WHERE workspace_id = ? AND id = ?`, ws, *w.ex.AskID).Scan(&steps).Error; err != nil || len(steps) == 0 {
				return err
			}
			return appendAskEvent(tx, ws, *w.ex.AskID, kind, steps[0], "system", "", w.ex.Provider, detail)
		}
		if o.err != nil {
			attempts := w.ex.Attempts + 1
			msg := truncate(o.err.Error(), 500)
			if o.permanent || attempts >= askExternalMaxAttempts {
				if err := tx.Exec(`UPDATE agent_ask_external SET state = 'failed', attempts = ?, last_error = ?, updated_at = ?
				        WHERE workspace_id = ? AND id = ?`, attempts, msg, now, ws, w.ex.ID).Error; err != nil {
					return err
				}
				_ = tx.Exec(`UPDATE agent_ask_integration SET last_error = ?, updated_at = ? WHERE workspace_id = ? AND provider = ?`,
					msg, now, ws, w.ex.Provider).Error
				if err := askEvent(AskEventExternalFailed, map[string]any{"error": msg, "attempts": attempts}); err != nil {
					return err
				}
				subject["error"], subject["attempts"] = msg, attempts
				return appendGovEvent(tx, ws, GovEventAskExternalFailed, models.GovActorSystem, "ask-external-worker", govEventRefs{}, subject)
			}
			return tx.Exec(`UPDATE agent_ask_external SET attempts = ?, last_error = ?, next_attempt_at = ?, updated_at = ?
			        WHERE workspace_id = ? AND id = ?`, attempts, msg, now.Add(askBackoff(attempts)), now, ws, w.ex.ID).Error
		}
		key, url := w.ex.ExternalKey, w.ex.ExternalURL
		if o.key != "" {
			key = o.key
		}
		if o.url != "" {
			url = o.url
		}
		var resolvedAt any
		if o.state == "resolved" {
			resolvedAt = now
		}
		next := now.Add(o.next)
		if err := tx.Exec(`UPDATE agent_ask_external SET state = ?, external_key = ?, external_url = ?, last_status = ?, attempts = 0,
		        last_error = '', next_attempt_at = ?, resolved_at = ?, updated_at = ? WHERE workspace_id = ? AND id = ?`,
			o.state, key, url, truncate(o.status, 200), next, resolvedAt, now, ws, w.ex.ID).Error; err != nil {
			return err
		}
		if o.status != "not_needed" {
			_ = tx.Exec(`UPDATE agent_ask_integration SET last_ok_at = ?, last_error = '' WHERE workspace_id = ? AND provider = ?`,
				now, ws, w.ex.Provider).Error
		}
		subject["external_key"], subject["status"] = key, o.status
		switch {
		case w.ex.State == "pending" && o.state == "open":
			kind := AskEventTicketOpened
			if w.ex.Kind == "page" {
				kind = AskEventPaged
			}
			if err := askEvent(kind, map[string]any{"external_key": key, "url": url}); err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventAskExternalOpened, models.GovActorSystem, "ask-external-worker", govEventRefs{}, subject)
		case o.state == "resolved" && o.status != "not_needed":
			kind := AskEventTicketResolved
			if w.ex.Kind == "page" {
				kind = AskEventPageResolved
			}
			if err := askEvent(kind, map[string]any{"external_key": key, "status": o.status}); err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventAskExternalResolved, models.GovActorSystem, "ask-external-worker", govEventRefs{}, subject)
		}
		return nil
	})
}

// RunAgentAskExternalWorker runs SyncExternals every minute on the leader
// replica until ctx ends (AUTHSEC_DISABLE_ASK_EXTERNAL_SYNC=true: off).
func RunAgentAskExternalWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_ASK_EXTERNAL_SYNC") == "true" {
		log.Printf("[agent-asks] external worker not started: AUTHSEC_DISABLE_ASK_EXTERNAL_SYNC=true")
		return
	}
	svc := NewAgentAskService(db)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		if ok, reason := AgentAsksStatus(db); !ok {
			agentAsksGate.logWait("ask external worker", reason)
			continue
		}
		RunAsLeader(ctx, db, "agent-ask-external", func() {
			if _, err := svc.SyncExternals(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[agent-asks] external sync: %v", err)
			}
		})
	}
}

// RunAgentAskEscalationWorker escalates due asks every minute on the leader
// replica until ctx ends (AUTHSEC_DISABLE_ASK_ESCALATION=true: off).
func RunAgentAskEscalationWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_ASK_ESCALATION") == "true" {
		log.Printf("[agent-asks] escalation worker not started: AUTHSEC_DISABLE_ASK_ESCALATION=true")
		return
	}
	svc := NewAgentAskService(db)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
		if ok, reason := AgentAsksStatus(db); !ok {
			agentAsksGate.logWait("ask escalation worker", reason)
			continue
		}
		RunAsLeader(ctx, db, "agent-ask-escalation", func() {
			if _, err := svc.EscalateDue(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[agent-asks] escalation: %v", err)
			}
		})
	}
}
