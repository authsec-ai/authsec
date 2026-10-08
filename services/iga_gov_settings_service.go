package services

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Phase 3 workspace settings (SPEC-iga-phase3-policy.md §7.8, §4.3, §9.3
// S9; T3.20): GET /settings and PUT /settings over iga_gov_settings (055),
// plus the notification channels (email and webhook targets).
//
// Notification channels (§9.3 S9 "email and webhook targets"; the
// disposition plan's copy of the legacy addresses into "Phase 3 notification
// settings") are behind GovNotificationChannelStore. The production store is
// GovDBChannelStore (p3-wire): 055's iga_gov_settings notify_* columns, with
// the webhook signing secret in Vault (notify_webhook_secret_ref holds the
// path, never the secret). cmd/main.go installs it once the Phase 3 schema
// verifies. Without a store (the default before installation, and a test
// seam): owners are notified by email (and by any registered channel), no
// workspace webhook is sent, GET /settings says why, and PUT /settings with
// notifications is 409 notification_settings_unavailable.

// GovNotificationChannels are a workspace's notification targets.
type GovNotificationChannels struct {
	// EmailEnabled: owners are emailed (default true).
	EmailEnabled bool `json:"email_enabled"`
	// WebhookURL is the workspace webhook ("" = none); https only.
	WebhookURL string `json:"webhook_url"`
	// WebhookSecret signs the webhook (X-AuthSec-Signature); never returned.
	WebhookSecret string `json:"-"`
	// WebhookSecretRef is where the store keeps the secret (GovDBChannelStore:
	// the Vault path); "" = none. Never returned.
	WebhookSecretRef string `json:"-"`
	// SecretUnreadable: a secret is stored but could not be read (Vault
	// unavailable). The webhook is then never sent unsigned: its target
	// resolution fails and the notify job retries.
	SecretUnreadable bool `json:"-"`
	// Source is "phase3" (set through PUT /settings) or "legacy_copy".
	Source             string     `json:"source"`
	CopiedFromLegacyAt *time.Time `json:"copied_from_legacy_at"`
}

// GovNotificationChannelStore persists GovNotificationChannels.
type GovNotificationChannelStore interface {
	// Available reports whether the store can hold channels, and why not.
	Available() (bool, string)
	// GetTx returns the workspace's channels and whether a row exists.
	GetTx(tx *gorm.DB, ws uuid.UUID) (*GovNotificationChannels, bool, error)
	// SaveTx writes the workspace's channels.
	SaveTx(tx *gorm.DB, ws uuid.UUID, ch GovNotificationChannels) error
}

// GovChannelsUnavailableReason is why channels cannot be stored when no
// store is installed.
const GovChannelsUnavailableReason = "Notification channel settings are not available on this server (the Phase 3 policy product is not enabled). Owners are notified by email."

type unavailableChannelStore struct{}

func (unavailableChannelStore) Available() (bool, string) { return false, GovChannelsUnavailableReason }
func (unavailableChannelStore) GetTx(*gorm.DB, uuid.UUID) (*GovNotificationChannels, bool, error) {
	return nil, false, errGovChannelsUnavailable
}
func (unavailableChannelStore) SaveTx(*gorm.DB, uuid.UUID, GovNotificationChannels) error {
	return errGovChannelsUnavailable
}

var errGovChannelsUnavailable = errors.New(GovChannelsUnavailableReason)

var (
	govChannelStoreMu sync.RWMutex
	govChannelStore   GovNotificationChannelStore = unavailableChannelStore{}
)

// SetGovNotificationChannelStore installs the channel store (cmd/main.go:
// GovDBChannelStore; tests may install a fake, or nil for the unavailable
// store). It returns a function restoring the previous store.
func SetGovNotificationChannelStore(s GovNotificationChannelStore) (restore func()) {
	govChannelStoreMu.Lock()
	prev := govChannelStore
	if s == nil {
		s = unavailableChannelStore{}
	}
	govChannelStore = s
	govChannelStoreMu.Unlock()
	return func() {
		govChannelStoreMu.Lock()
		govChannelStore = prev
		govChannelStoreMu.Unlock()
	}
}

func currentGovChannelStore() GovNotificationChannelStore {
	govChannelStoreMu.RLock()
	defer govChannelStoreMu.RUnlock()
	return govChannelStore
}

// DefaultGovNotificationChannels is a workspace without a channel row:
// email on, no webhook.
func DefaultGovNotificationChannels() GovNotificationChannels {
	return GovNotificationChannels{EmailEnabled: true, Source: "default"}
}

// govChannels returns the workspace's effective channels (defaults when the
// store is unavailable or has no row). It never copies: the copy happens on
// the settings read (GovSettingsService.Get).
func govChannels(db *gorm.DB, ws uuid.UUID) GovNotificationChannels {
	st := currentGovChannelStore()
	if ok, _ := st.Available(); !ok {
		return DefaultGovNotificationChannels()
	}
	ch, exists, err := st.GetTx(db, ws)
	if err != nil || !exists || ch == nil {
		return DefaultGovNotificationChannels()
	}
	return *ch
}

// GovWorkspaceWebhookTarget is the notifier's webhook resolver: the
// workspace webhook from the channel store, or nil. A stored secret that
// cannot be read is an error (the send is retried), never an unsigned send.
func GovWorkspaceWebhookTarget(db *gorm.DB, ws uuid.UUID) (*GovWebhookTarget, error) {
	ch := govChannels(db, ws)
	if ch.WebhookURL == "" {
		return nil, nil
	}
	if ch.SecretUnreadable {
		return nil, errGovWebhookSecretUnreadable
	}
	return &GovWebhookTarget{URL: ch.WebhookURL, Secret: ch.WebhookSecret}, nil
}

// GovWorkspaceWebhookConfigured reports whether the workspace has a webhook,
// without needing its secret (deciding to queue a notice).
func GovWorkspaceWebhookConfigured(db *gorm.DB, ws uuid.UUID) bool {
	return govChannels(db, ws).WebhookURL != ""
}

var errGovWebhookSecretUnreadable = errors.New("the workspace webhook's signing secret cannot be read right now")

/* ------------------------------------------------------------------------- */
/*                    The production store (055 + Vault)                      */
/* ------------------------------------------------------------------------- */

// GovDBChannelStore stores a workspace's channels in iga_gov_settings
// (notify_* columns, 055) and the webhook signing secret in Vault through
// the existing abstraction (internal/vault), at GovWebhookSecretPath -- under
// the workspace's iga-gov namespace. notify_webhook_secret_ref holds that
// path, never the secret.
//
// DECISIONS (p3-wire, item 6):
//   - A changed secret is written to a NEW path (a random nonce per write)
//     and the row is pointed at it in the caller's transaction, so a rolled
//     back settings change never leaves the committed row naming a secret it
//     did not commit. The superseded path is deleted after the commit
//     (ReleaseSecret, best effort; a leftover is logged).
//   - "A row exists" (GetTx's exists) means notify_channels_source is not
//     'default': a settings row saved for other fields has default channels
//     and is still copied from the legacy row on first read.
//   - Vault unreadable on read: the channels are returned with
//     SecretUnreadable (never an error, so GET /settings and owner
//     notification keep working); the webhook is not sent until the secret
//     can be read. Vault not configured: a secret cannot be stored (503
//     notification_secret_store_unavailable); email and the URL still can.
type GovDBChannelStore struct {
	vault vault.VaultClient
}

// NewGovDBChannelStore builds the store; vc may be nil (no secrets).
func NewGovDBChannelStore(vc vault.VaultClient) *GovDBChannelStore {
	return &GovDBChannelStore{vault: vc}
}

// GovWebhookSecretPath is the Vault path of one stored webhook secret.
func GovWebhookSecretPath(ws uuid.UUID, nonce string) string {
	return "kv/data/secret/workspaces/" + ws.String() + "/iga-gov/notifications/webhook-secret-" + nonce
}

// Available implements GovNotificationChannelStore.
func (s *GovDBChannelStore) Available() (bool, string) { return true, "" }

type govChannelRow struct {
	NotifyEmailEnabled     bool
	NotifyWebhookURL       string
	NotifyWebhookSecretRef string
	NotifyChannelsSource   string
	NotifyChannelsCopiedAt *time.Time
}

func (s *GovDBChannelStore) row(tx *gorm.DB, ws uuid.UUID) (*govChannelRow, error) {
	var rows []govChannelRow
	if err := tx.Raw(`SELECT notify_email_enabled, notify_webhook_url, notify_webhook_secret_ref, notify_channels_source,
	                         notify_channels_copied_at
	                    FROM iga_gov_settings WHERE workspace_id = ?`, ws).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

func (s *GovDBChannelStore) readSecret(ref string) (string, error) {
	if s.vault == nil {
		return "", errors.New("vault is not configured")
	}
	sec, err := s.vault.ReadSecret(ref)
	if err != nil {
		return "", err
	}
	v, _ := sec["secret"].(string)
	if v == "" {
		return "", errors.New("the stored webhook secret is empty")
	}
	return v, nil
}

// GetTx implements GovNotificationChannelStore.
func (s *GovDBChannelStore) GetTx(tx *gorm.DB, ws uuid.UUID) (*GovNotificationChannels, bool, error) {
	r, err := s.row(tx, ws)
	if err != nil || r == nil || r.NotifyChannelsSource == "default" {
		return nil, false, err
	}
	ch := &GovNotificationChannels{EmailEnabled: r.NotifyEmailEnabled, WebhookURL: r.NotifyWebhookURL,
		WebhookSecretRef: r.NotifyWebhookSecretRef, Source: r.NotifyChannelsSource, CopiedFromLegacyAt: r.NotifyChannelsCopiedAt}
	if ch.WebhookSecretRef != "" {
		sec, err := s.readSecret(ch.WebhookSecretRef)
		if err != nil {
			log.Printf("[policy] workspace %s: the webhook signing secret cannot be read: %v", ws, err)
			ch.SecretUnreadable = true
		} else {
			ch.WebhookSecret = sec
		}
	}
	return ch, true, nil
}

// SaveTx implements GovNotificationChannelStore.
func (s *GovDBChannelStore) SaveTx(tx *gorm.DB, ws uuid.UUID, ch GovNotificationChannels) error {
	cur, err := s.row(tx, ws)
	if err != nil {
		return err
	}
	curRef := ""
	if cur != nil {
		curRef = cur.NotifyWebhookSecretRef
	}
	ref := ""
	switch {
	case ch.WebhookURL == "":
		// No webhook, no secret.
	case ch.WebhookSecret == "" && ch.SecretUnreadable:
		ref = ch.WebhookSecretRef // unchanged, merely unreadable now
	case ch.WebhookSecret == "":
		// A webhook without a secret is sent unsigned (the legacy rule).
	default:
		if curRef != "" && ch.WebhookSecretRef == curRef {
			if old, err := s.readSecret(curRef); err == nil && old == ch.WebhookSecret {
				ref = curRef
			}
		}
		if ref == "" {
			if s.vault == nil {
				return govErr(http.StatusServiceUnavailable, "notification_secret_store_unavailable",
					"The secrets store is not configured; a webhook signing secret cannot be stored.", nil)
			}
			nonce := strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
			p := GovWebhookSecretPath(ws, nonce)
			if err := s.vault.WriteSecret(p, map[string]interface{}{"secret": ch.WebhookSecret}); err != nil {
				log.Printf("[policy] workspace %s: storing the webhook signing secret failed: %v", ws, err)
				return govErr(http.StatusServiceUnavailable, "notification_secret_store_unavailable",
					"The webhook signing secret could not be stored; try again shortly.", nil)
			}
			ref = p
		}
	}
	src := ch.Source
	if src != "legacy_copy" {
		src = "phase3"
	}
	return tx.Exec(`INSERT INTO iga_gov_settings (workspace_id, notify_email_enabled, notify_webhook_url, notify_webhook_secret_ref,
	                      notify_channels_source, notify_channels_copied_at)
	                VALUES (?, ?, ?, ?, ?, ?)
	                ON CONFLICT (workspace_id) DO UPDATE SET notify_email_enabled = EXCLUDED.notify_email_enabled,
	                      notify_webhook_url = EXCLUDED.notify_webhook_url, notify_webhook_secret_ref = EXCLUDED.notify_webhook_secret_ref,
	                      notify_channels_source = EXCLUDED.notify_channels_source,
	                      notify_channels_copied_at = EXCLUDED.notify_channels_copied_at`,
		ws, ch.EmailEnabled, ch.WebhookURL, ref, src, ch.CopiedFromLegacyAt).Error
}

// SecretRefTx is the workspace's stored secret path ("" = none).
func (s *GovDBChannelStore) SecretRefTx(db *gorm.DB, ws uuid.UUID) (string, error) {
	r, err := s.row(db, ws)
	if err != nil || r == nil {
		return "", err
	}
	return r.NotifyWebhookSecretRef, nil
}

// ReleaseSecret deletes a superseded secret from Vault.
func (s *GovDBChannelStore) ReleaseSecret(ref string) error {
	if s.vault == nil || ref == "" {
		return nil
	}
	return s.vault.DeleteSecret(ref)
}

// govChannelSecretReleaser is the optional post-commit cleanup a store may
// offer: after a settings change commits, a secret path the row no longer
// names is released.
type govChannelSecretReleaser interface {
	SecretRefTx(db *gorm.DB, ws uuid.UUID) (string, error)
	ReleaseSecret(ref string) error
}

// releaseSuperseded releases prev when the committed row no longer names it.
func releaseSuperseded(db *gorm.DB, st GovNotificationChannelStore, ws uuid.UUID, prev string) {
	r, ok := st.(govChannelSecretReleaser)
	if !ok || prev == "" {
		return
	}
	cur, err := r.SecretRefTx(db, ws)
	if err != nil || cur == prev {
		return
	}
	if err := r.ReleaseSecret(prev); err != nil {
		log.Printf("[policy] workspace %s: releasing a superseded webhook secret failed (left in Vault): %v", ws, err)
	}
}

// GovNotificationSettingsView is the notifications block of GET /settings.
type GovNotificationSettingsView struct {
	Available          bool       `json:"available"`
	Reason             string     `json:"reason,omitempty"`
	EmailEnabled       bool       `json:"email_enabled"`
	WebhookURL         string     `json:"webhook_url"`
	WebhookSecretSet   bool       `json:"webhook_secret_set"`
	Source             string     `json:"source"`
	CopiedFromLegacyAt *time.Time `json:"copied_from_legacy_at"`
	// Slack is T3.14's (workspace_slack_integration); reported here so the
	// Setup page has one place to read.
	Slack GovChannelAvailability `json:"slack"`
}

// GovChannelAvailability is whether an extra channel is installed.
type GovChannelAvailability struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Status is the workspace's Slack connection (T3.14), when available.
	Status *SlackStatusView `json:"status,omitempty"`
}

// GovSettingsView is GET /settings.
type GovSettingsView struct {
	models.IGAGovSettings
	// Saved is false when the workspace has no row (every value a default).
	Saved         bool                        `json:"saved"`
	Notifications GovNotificationSettingsView `json:"notifications"`
}

// GovSettingsService serves §7.8 settings.
type GovSettingsService struct {
	db *gorm.DB
}

// NewGovSettingsService builds the service over db and the installed
// channel store.
func NewGovSettingsService(db *gorm.DB) *GovSettingsService { return &GovSettingsService{db: db} }

// Get is GET /settings. On the first read of a workspace whose channel store
// has no row and whose LEGACY governance_notification_settings row exists,
// the legacy channel addresses are copied into the store in one transaction
// with a settings.notification_channels_copied event (disposition plan §2:
// copy, never move -- the legacy row is only read).
func (s *GovSettingsService) Get(ctx context.Context, ws uuid.UUID) (*GovSettingsView, error) {
	db := s.db.WithContext(ctx)
	if err := s.copyLegacyChannels(db, ws); err != nil {
		return nil, err
	}
	return s.view(db, ws)
}

func (s *GovSettingsService) view(db *gorm.DB, ws uuid.UUID) (*GovSettingsView, error) {
	var rows []models.IGAGovSettings
	if err := db.Where("workspace_id = ?", ws).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := &GovSettingsView{}
	if len(rows) == 1 {
		out.IGAGovSettings, out.Saved = rows[0], true
	} else {
		out.IGAGovSettings = models.DefaultIGAGovSettings(ws)
		out.IGAGovSettings.UpdatedAt = time.Time{}
	}
	st := currentGovChannelStore()
	ok, reason := st.Available()
	n := GovNotificationSettingsView{Available: ok, Reason: reason}
	ch := govChannels(db, ws)
	n.EmailEnabled, n.WebhookURL, n.WebhookSecretSet = ch.EmailEnabled, ch.WebhookURL, ch.WebhookSecret != "" || ch.SecretUnreadable
	if ch.SecretUnreadable {
		n.Reason = "The webhook signing secret cannot be read right now; webhook notices wait until it can."
	}
	n.Source, n.CopiedFromLegacyAt = ch.Source, ch.CopiedFromLegacyAt
	if _, has := govNoticeChannel(GovChannelSlack); has {
		n.Slack = GovChannelAvailability{Available: true, Status: SlackStatusForSettings(db, ws)}
	} else {
		_, why := SlackAvailable()
		n.Slack = GovChannelAvailability{Reason: why}
	}
	out.Notifications = n
	return out, nil
}

func (s *GovSettingsService) copyLegacyChannels(db *gorm.DB, ws uuid.UUID) error {
	st := currentGovChannelStore()
	if ok, _ := st.Available(); !ok {
		return nil
	}
	return db.Transaction(func(tx *gorm.DB) error {
		// Serialise first reads of one workspace on its settings row lock
		// (the row may not exist: lock the workspace's settings key instead).
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext('iga_gov_settings_channels:' || ?::text))`, ws.String()).Error; err != nil {
			return err
		}
		_, exists, err := st.GetTx(tx, ws)
		if err != nil || exists {
			return err
		}
		legacy, err := ReadLegacyNotificationChannels(tx, ws)
		if err != nil || legacy == nil {
			return err
		}
		now := time.Now().UTC()
		ch := GovNotificationChannels{EmailEnabled: legacy.EmailEnabled, WebhookURL: strings.TrimSpace(legacy.WebhookURL),
			WebhookSecret: legacy.WebhookSecret, Source: "legacy_copy", CopiedFromLegacyAt: &now}
		// DECISION (p3-wire): Phase 3 webhooks are https only (055 CHECK);
		// a legacy http:// address is not copied, and the event says so.
		skipped := ""
		if ch.WebhookURL != "" && !strings.HasPrefix(ch.WebhookURL, "https://") {
			ch.WebhookURL, ch.WebhookSecret, skipped = "", "", "not https"
		}
		if err := st.SaveTx(tx, ws, ch); err != nil {
			var ge *GovError
			if errors.As(err, &ge) {
				// The secret cannot be stored right now (Vault): nothing was
				// written; the copy is retried on the next read, and the
				// settings read itself still answers.
				log.Printf("[policy] workspace %s: legacy notification channels not copied yet: %s", ws, ge.Message)
				return nil
			}
			return err
		}
		payload := map[string]any{"from": "governance_notification_settings", "email_enabled": legacy.EmailEnabled,
			"webhook_configured": ch.WebhookURL != "", "webhook_signed": ch.WebhookSecret != ""}
		if skipped != "" {
			payload["webhook_not_copied"] = skipped
		}
		return appendGovEvent(tx, ws, GovEventSettingsChannelsCopied, models.GovActorSystem, "settings", govEventRefs{}, payload)
	})
}

// GovSettingsPatch is PUT /settings: every field optional (omitted keeps
// the current value).
type GovSettingsPatch struct {
	EnforcementMode        *string `json:"enforcement_mode"`
	DefaultWindowDays      *int    `json:"default_window_days"`
	DefaultObservationDays *int    `json:"default_observation_days"`
	OwnerReviewDays        *int    `json:"owner_review_days"`
	ApprovalValidDays      *int    `json:"approval_valid_days"`
	CanaryHours            *int    `json:"canary_hours"`
	IaCApplyHours          *int    `json:"iac_apply_hours"`
	EvidenceRetentionRevs  *int    `json:"evidence_retention_revs"`
	// Reason is required when switching to enforce (§7.8).
	Reason string `json:"reason"`
	// ExpectedUpdatedAt, when given, must equal the row's updated_at
	// (§7 "Concurrency"): a stale write is 409 version_conflict.
	ExpectedUpdatedAt *time.Time             `json:"expected_updated_at"`
	Notifications     *GovNotificationsPatch `json:"notifications"`
}

// GovNotificationsPatch changes the notification channels.
type GovNotificationsPatch struct {
	EmailEnabled  *bool   `json:"email_enabled"`
	WebhookURL    *string `json:"webhook_url"`
	WebhookSecret *string `json:"webhook_secret"`
}

// 055's CHECK ranges, checked here so a bad value is a 400 naming the field.
var govSettingsRanges = []struct {
	name     string
	get      func(*GovSettingsPatch) *int
	set      func(*models.IGAGovSettings, int)
	val      func(*models.IGAGovSettings) int
	min, max int
}{
	{"default_window_days", func(p *GovSettingsPatch) *int { return p.DefaultWindowDays }, func(s *models.IGAGovSettings, v int) { s.DefaultWindowDays = v }, func(s *models.IGAGovSettings) int { return s.DefaultWindowDays }, 30, 400},
	{"default_observation_days", func(p *GovSettingsPatch) *int { return p.DefaultObservationDays }, func(s *models.IGAGovSettings, v int) { s.DefaultObservationDays = v }, func(s *models.IGAGovSettings) int { return s.DefaultObservationDays }, 1, 90},
	{"owner_review_days", func(p *GovSettingsPatch) *int { return p.OwnerReviewDays }, func(s *models.IGAGovSettings, v int) { s.OwnerReviewDays = v }, func(s *models.IGAGovSettings) int { return s.OwnerReviewDays }, 1, 30},
	{"approval_valid_days", func(p *GovSettingsPatch) *int { return p.ApprovalValidDays }, func(s *models.IGAGovSettings, v int) { s.ApprovalValidDays = v }, func(s *models.IGAGovSettings) int { return s.ApprovalValidDays }, 1, 30},
	{"canary_hours", func(p *GovSettingsPatch) *int { return p.CanaryHours }, func(s *models.IGAGovSettings, v int) { s.CanaryHours = v }, func(s *models.IGAGovSettings) int { return s.CanaryHours }, 1, 336},
	{"iac_apply_hours", func(p *GovSettingsPatch) *int { return p.IaCApplyHours }, func(s *models.IGAGovSettings, v int) { s.IaCApplyHours = v }, func(s *models.IGAGovSettings) int { return s.IaCApplyHours }, 1, 336},
	{"evidence_retention_revs", func(p *GovSettingsPatch) *int { return p.EvidenceRetentionRevs }, func(s *models.IGAGovSettings, v int) { s.EvidenceRetentionRevs = v }, func(s *models.IGAGovSettings) int { return s.EvidenceRetentionRevs }, 5, 365},
}

// Update is PUT /settings: validated, written with a settings.updated event
// in one transaction. It returns the views before and after.
func (s *GovSettingsService) Update(ctx context.Context, ws, actor uuid.UUID, p GovSettingsPatch) (before, after *GovSettingsView, err error) {
	db := s.db.WithContext(ctx)
	if err := s.copyLegacyChannels(db, ws); err != nil {
		return nil, nil, err
	}
	st := currentGovChannelStore()
	prevSecretRef := ""
	if p.Notifications != nil {
		if ok, reason := st.Available(); !ok {
			return nil, nil, govErr(http.StatusConflict, "notification_settings_unavailable", reason, nil)
		}
		if u := p.Notifications.WebhookURL; u != nil {
			v := strings.TrimSpace(*u)
			if v != "" && !strings.HasPrefix(v, "https://") {
				return nil, nil, GovBadParam("notifications.webhook_url", "webhook_url must be an https:// URL or empty.")
			}
		}
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		var rows []models.IGAGovSettings
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("workspace_id = ?", ws).Limit(1).Find(&rows).Error; err != nil {
			return err
		}
		cur := models.DefaultIGAGovSettings(ws)
		saved := len(rows) == 1
		if saved {
			cur = rows[0]
		}
		if p.ExpectedUpdatedAt != nil {
			if !saved || !cur.UpdatedAt.Equal(*p.ExpectedUpdatedAt) {
				return govErr(http.StatusConflict, "version_conflict", "The settings changed since they were read; re-read and retry.",
					map[string]any{"updated_at": nullTime(saved, cur.UpdatedAt)})
			}
		}
		b, err := s.view(tx, ws)
		if err != nil {
			return err
		}
		before = b
		next := cur
		var changed []string
		if p.EnforcementMode != nil {
			m := *p.EnforcementMode
			if m != models.GovModeFindingsOnly && m != models.GovModeEnforce {
				return GovBadParam("enforcement_mode", "enforcement_mode must be findings_only or enforce.")
			}
			if m != cur.EnforcementMode {
				if m == models.GovModeEnforce && strings.TrimSpace(p.Reason) == "" {
					return GovBadParam("reason", "Switching to enforce requires a reason.")
				}
				next.EnforcementMode = m
				changed = append(changed, "enforcement_mode")
			}
		}
		for _, r := range govSettingsRanges {
			v := r.get(&p)
			if v == nil {
				continue
			}
			if *v < r.min || *v > r.max {
				return GovBadParam(r.name, r.name+" must be between "+strconv.Itoa(r.min)+" and "+strconv.Itoa(r.max)+".")
			}
			if *v != r.val(&cur) {
				r.set(&next, *v)
				changed = append(changed, r.name)
			}
		}
		var chBefore, chAfter GovNotificationChannels
		if p.Notifications != nil {
			got, exists, err := st.GetTx(tx, ws)
			if err != nil {
				return err
			}
			chBefore = DefaultGovNotificationChannels()
			if exists && got != nil {
				chBefore = *got
			}
			prevSecretRef = chBefore.WebhookSecretRef
			chAfter = chBefore
			if v := p.Notifications.EmailEnabled; v != nil && *v != chAfter.EmailEnabled {
				chAfter.EmailEnabled = *v
				changed = append(changed, "notifications.email_enabled")
			}
			if v := p.Notifications.WebhookURL; v != nil && strings.TrimSpace(*v) != chAfter.WebhookURL {
				chAfter.WebhookURL = strings.TrimSpace(*v)
				changed = append(changed, "notifications.webhook_url")
				if chAfter.WebhookURL == "" {
					chAfter.WebhookSecret, chAfter.WebhookSecretRef, chAfter.SecretUnreadable = "", "", false
				}
			}
			if v := p.Notifications.WebhookSecret; v != nil && (*v != chAfter.WebhookSecret || chAfter.SecretUnreadable) {
				chAfter.WebhookSecret, chAfter.SecretUnreadable = *v, false
				if *v == "" {
					chAfter.WebhookSecretRef = ""
				}
				changed = append(changed, "notifications.webhook_secret")
			}
			if chAfter != chBefore {
				chAfter.Source = "phase3"
				if err := st.SaveTx(tx, ws, chAfter); err != nil {
					return err
				}
			}
		}
		sort.Strings(changed)
		if len(changed) > 0 {
			next.UpdatedBy = &actor
			if err := repositories.NewIGAGovSettingsRepository(tx).SaveTx(tx, &next); err != nil {
				return err
			}
		}
		payload := map[string]any{"changed": changed, "reason": strings.TrimSpace(p.Reason),
			"before": govSettingsDigest(&cur), "after": govSettingsDigest(&next)}
		if p.Notifications != nil {
			payload["notifications_before"] = govChannelsDigest(chBefore)
			payload["notifications_after"] = govChannelsDigest(chAfter)
		}
		if cur.EnforcementMode != next.EnforcementMode {
			payload["enforcement_mode_changed"] = map[string]string{"from": cur.EnforcementMode, "to": next.EnforcementMode}
		}
		if err := appendGovEvent(tx, ws, GovEventSettingsUpdated, models.GovActorUser, actor.String(), govEventRefs{}, payload); err != nil {
			return err
		}
		a, err := s.view(tx, ws)
		after = a
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	releaseSuperseded(db, st, ws, prevSecretRef)
	return before, after, nil
}

func govSettingsDigest(s *models.IGAGovSettings) map[string]any {
	return map[string]any{"enforcement_mode": s.EnforcementMode, "default_window_days": s.DefaultWindowDays,
		"default_observation_days": s.DefaultObservationDays, "owner_review_days": s.OwnerReviewDays,
		"approval_valid_days": s.ApprovalValidDays, "canary_hours": s.CanaryHours, "iac_apply_hours": s.IaCApplyHours,
		"evidence_retention_revs": s.EvidenceRetentionRevs}
}

// govChannelsDigest never carries the secret, only whether one is set.
func govChannelsDigest(c GovNotificationChannels) map[string]any {
	return map[string]any{"email_enabled": c.EmailEnabled, "webhook_url": c.WebhookURL, "webhook_signed": c.WebhookSecret != ""}
}

func nullTime(ok bool, t time.Time) any {
	if !ok {
		return nil
	}
	return t
}
