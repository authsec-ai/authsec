package services

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/safehttp"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
)

// Alert delivery (SPEC-agent-runtime-visibility.md §5.7, §10 Q3).
//
// Slack reuses the governance notification outbox (iga_gov_notify.go): an
// opened alert enqueues an iga_gov_notification (subject agent_alert, channel
// GovChannelSlack, recipient the workspace's approvals channel) when the
// Slack app is installed in this process, the workspace has Slack connected
// with an approvals channel, and alert settings have Slack on. The notify job
// delivers it (attempt x 10 min, dead after 5) and its OnSent / OnDead hooks
// record the outcome on the alert's agent_alert_delivery row.
//
// SIEM: one agent_alert_delivery row per enabled endpoint, delivered by
// AgentAlertDeliverer (RunAgentRuntimeAlertWorker): due rows are listed
// across workspaces, then each is claimed (FOR UPDATE SKIP LOCKED, a short
// lease and the attempt number as the fence), sent and recorded under row-
// level security for its own workspace. The POST goes through
// internal/safehttp (the URL is the workspace's choice) and is signed:
//
//	X-AuthSec-Timestamp: <unix seconds>
//	X-AuthSec-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
//	X-AuthSec-Delivery:  <delivery id> (stable across retries)
//
// Retries back off 1, 2, 4 ... 60 minutes; after agentAlertSIEMMaxAttempts
// the row is failed. A blocked address, a deleted or disabled endpoint, or
// an alert purged by retention fails at once.

// Delivery channels and states (agent_alert_delivery).
const (
	AgentAlertChannelSlack = "slack"
	AgentAlertChannelSIEM  = "siem"

	AgentAlertDeliveryPending = "pending"
	AgentAlertDeliverySent    = "sent"
	AgentAlertDeliveryFailed  = "failed"

	agentAlertSIEMMaxAttempts = 8
	agentAlertSIEMLease       = 2 * time.Minute
	agentAlertSIEMTimeout     = 10 * time.Second
	agentAlertSIEMBatch       = 25

	// AgentAlertSIEMUserAgent is the SIEM webhook's User-Agent.
	AgentAlertSIEMUserAgent = "authsec-agent-alerts"
	// SIEM headers.
	AgentAlertSIEMSignatureHeader = "X-AuthSec-Signature"
	AgentAlertSIEMTimestampHeader = "X-AuthSec-Timestamp"
	AgentAlertSIEMDeliveryHeader  = "X-AuthSec-Delivery"
)

/* ------------------------------------------------------------------------- */
/*                              Process wiring                                */
/* ------------------------------------------------------------------------- */

var agentAlertDeps struct {
	sync.RWMutex
	vault  vault.VaultClient
	client func() *http.Client
}

// SetAgentAlertVault installs the Vault client that stores SIEM endpoint
// secrets (nil: none can be created or read). It returns the undo (tests).
func SetAgentAlertVault(vc vault.VaultClient) (restore func()) {
	agentAlertDeps.Lock()
	prev := agentAlertDeps.vault
	agentAlertDeps.vault = vc
	agentAlertDeps.Unlock()
	return func() { SetAgentAlertVault(prev) }
}

func agentAlertVault() vault.VaultClient {
	agentAlertDeps.RLock()
	defer agentAlertDeps.RUnlock()
	return agentAlertDeps.vault
}

// SetAgentAlertSIEMClient replaces the SIEM HTTP client (tests: a client
// that still dials through safehttp.DialContext but trusts a test TLS
// server). nil restores the default. It returns the undo.
func SetAgentAlertSIEMClient(c *http.Client) (restore func()) {
	agentAlertDeps.Lock()
	prev := agentAlertDeps.client
	if c == nil {
		agentAlertDeps.client = nil
	} else {
		agentAlertDeps.client = func() *http.Client { return c }
	}
	agentAlertDeps.Unlock()
	return func() {
		agentAlertDeps.Lock()
		agentAlertDeps.client = prev
		agentAlertDeps.Unlock()
	}
}

// agentAlertSIEMClient is the SSRF-safe client (internal/safehttp): the URL
// is the workspace's.
func agentAlertSIEMClient() *http.Client {
	agentAlertDeps.RLock()
	f := agentAlertDeps.client
	agentAlertDeps.RUnlock()
	if f != nil {
		return f()
	}
	return safehttp.New(agentAlertSIEMTimeout)
}

// InstallAgentRuntimeAlerts registers the "agent_alerts" sink and the Vault
// client for SIEM secrets (VAULT_ADDR / VAULT_TOKEN; without them SIEM
// endpoints cannot be created and deliveries wait). cmd/main.go calls it
// once at startup.
func InstallAgentRuntimeAlerts(db *gorm.DB) {
	if addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"); addr != "" && tok != "" {
		if vc, err := vault.NewClient(addr, tok); err != nil {
			log.Printf("[agent-alerts] vault client: %v; SIEM endpoints unavailable", err)
		} else {
			SetAgentAlertVault(vc)
		}
	} else {
		log.Printf("[agent-alerts] VAULT_ADDR/VAULT_TOKEN not set: SIEM endpoints unavailable")
	}
	agentruntime.RegisterSink(NewAgentAlertSink(db))
}

func init() {
	RegisterGovNoticeSubject(GovNoticeAgentAlert, GovNoticeSubject{
		Render: renderAgentAlertNotice,
		OnSent: func(tx *gorm.DB, n *models.IGAGovNotification, _ *uuid.UUID) error {
			return tx.Exec(`UPDATE agent_alert_delivery SET status = 'sent', attempt = ?, sent_at = now(), last_error = ''
			                 WHERE workspace_id = ? AND alert_id = ? AND channel = 'slack'`,
				n.AttemptCount+1, n.WorkspaceID, n.SubjectID).Error
		},
		OnDead: func(tx *gorm.DB, n *models.IGAGovNotification, _ *uuid.UUID) error {
			return tx.Exec(`UPDATE agent_alert_delivery SET status = 'failed', attempt = ?, last_error = ?
			                 WHERE workspace_id = ? AND alert_id = ? AND channel = 'slack'`,
				n.AttemptCount+1, "Slack delivery failed after its retries", n.WorkspaceID, n.SubjectID).Error
		},
	})
}

/* ------------------------------------------------------------------------- */
/*                                  Enqueue                                   */
/* ------------------------------------------------------------------------- */

// enqueueAgentAlertDeliveries queues an opened alert's deliveries in the
// alert's transaction: one SIEM row per enabled endpoint, and Slack when it
// is available (a savepoint: a Slack enqueue that fails is logged and never
// loses the alert).
func enqueueAgentAlertDeliveries(tx *gorm.DB, ws, alertID uuid.UUID, st AgentAlertSettings) error {
	if err := tx.Exec(`INSERT INTO agent_alert_delivery (workspace_id, alert_id, channel, endpoint_id, status, next_attempt_at)
	                   SELECT workspace_id, ?, 'siem', id, 'pending', now() FROM agent_alert_siem_endpoint
	                    WHERE workspace_id = ? AND enabled AND deleted_at IS NULL`, alertID, ws).Error; err != nil {
		return err
	}
	if !st.SlackEnabled {
		return nil
	}
	if _, ok := govNoticeChannel(GovChannelSlack); !ok {
		return nil
	}
	err := tx.Transaction(func(sp *gorm.DB) error {
		in, err := activeSlackIntegration(sp, ws)
		if err != nil || in == nil || in.ApprovalsChannelID == "" {
			return err
		}
		if _, err := EnqueueGovNotificationTx(sp, ws, GovNoticeAgentAlert, alertID, GovChannelSlack, SlackRecipientApprovals, false); err != nil {
			return err
		}
		return sp.Exec(`INSERT INTO agent_alert_delivery (workspace_id, alert_id, channel, status, next_attempt_at)
		                VALUES (?, ?, 'slack', 'pending', now())`, ws, alertID).Error
	})
	if err != nil {
		log.Printf("[agent-alerts] workspace %s: alert %s: Slack notice not queued: %v", ws, alertID, err)
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                   Slack                                    */
/* ------------------------------------------------------------------------- */

// AgentAlertConsoleLink is the console URL an alert links to ("" without a
// base URL): the console's alert page.
func AgentAlertConsoleLink(alertID uuid.UUID) string {
	if alertID == uuid.Nil {
		return ""
	}
	return govConsoleLink("/iga/agent-runtime/alerts/" + alertID.String())
}

func renderAgentAlertNotice(db *gorm.DB, n *models.IGAGovNotification, _ *uuid.UUID) (*GovNotice, error) {
	var rows []AgentAlert
	if err := tenancy.InWorkspaceRead(db.Statement.Context, db, n.WorkspaceID, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+agentAlertColumns+` FROM agent_alert WHERE workspace_id = ? AND id = ?`, n.WorkspaceID, n.SubjectID).Scan(&rows).Error
	}); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotifyPermanent(errors.New("the alert no longer exists"))
	}
	a := rows[0]
	link := AgentAlertConsoleLink(a.ID)
	title := fmt.Sprintf("AuthSec alert (%s): %s", a.Severity, a.Title)
	lines := []string{
		fmt.Sprintf("Detection %s: %s", a.Detection, detect.Name(detect.ID(a.Detection))),
		fmt.Sprintf("Events: %d, first %s, last %s", a.EventCount, a.FirstSeen.UTC().Format(time.RFC3339), a.LastSeen.UTC().Format(time.RFC3339)),
	}
	var refs []AgentAlertEventRef
	if json.Unmarshal(a.Evidence, &refs) == nil && len(refs) > 0 {
		r := refs[len(refs)-1]
		line := "Latest: " + strings.TrimSuffix(r.Source, ".amazonaws.com") + ":" + r.Name
		if r.Detail != "" {
			line += " (" + r.Detail + ")"
		}
		lines = append(lines, line)
	}
	if a.State != AgentAlertOpen {
		lines = append(lines, "State: "+a.State)
	}
	text := title + "\n\n" + strings.Join(lines, "\n") + "\n"
	if link != "" {
		text += "\nOpen it in AuthSec:\n  " + link + "\n"
	}
	return &GovNotice{Subject: title, Text: text, Title: title, Lines: lines, Link: link,
		Webhook: map[string]any{"type": "authsec.agent_runtime.alert", "version": 1, "workspace_id": a.WorkspaceID.String(),
			"alert_id": a.ID.String(), "detection": a.Detection, "severity": a.Severity, "title": a.Title, "link": link}}, nil
}

/* ------------------------------------------------------------------------- */
/*                                    SIEM                                    */
/* ------------------------------------------------------------------------- */

// SignAgentAlertSIEM is the X-AuthSec-Signature value: "sha256=" +
// hex(HMAC-SHA256(secret, timestamp + "." + body)).
func SignAgentAlertSIEM(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// AgentAlertSIEMAlert is the "alert" object of a SIEM payload.
type AgentAlertSIEMAlert struct {
	ID            uuid.UUID       `json:"id"`
	WorkspaceID   uuid.UUID       `json:"workspace_id"`
	ConnectorID   uuid.UUID       `json:"connector_id"`
	IdentityID    uuid.UUID       `json:"identity_id"`
	WorkloadIDs   json.RawMessage `json:"workload_ids"`
	SubjectLabel  string          `json:"subject_label"`
	SubjectName   string          `json:"subject_name"`
	Detection     string          `json:"detection"`
	DetectionName string          `json:"detection_name"`
	Severity      string          `json:"severity"`
	Title         string          `json:"title"`
	State         string          `json:"state"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	EventCount    int             `json:"event_count"`
	Link          string          `json:"link,omitempty"`
}

// AgentAlertSIEMPayload is the JSON body POSTed to a SIEM endpoint.
type AgentAlertSIEMPayload struct {
	Type       string               `json:"type"`
	Version    int                  `json:"version"`
	DeliveryID string               `json:"delivery_id"`
	SentAt     time.Time            `json:"sent_at"`
	Alert      AgentAlertSIEMAlert  `json:"alert"`
	Evidence   []AgentAlertEventRef `json:"evidence"`
}

// AgentAlertSIEMType is the payload type of an alert; a test delivery is
// AgentAlertSIEMTestType.
const (
	AgentAlertSIEMType     = "authsec.agent_runtime.alert"
	AgentAlertSIEMTestType = "authsec.agent_runtime.alert.test"
)

// BuildAgentAlertSIEMPayload renders a's SIEM body.
func BuildAgentAlertSIEMPayload(a AgentAlert, deliveryID string, now time.Time) ([]byte, error) {
	var refs []AgentAlertEventRef
	if len(a.Evidence) > 0 {
		if err := json.Unmarshal(a.Evidence, &refs); err != nil {
			refs = nil
		}
	}
	if refs == nil {
		refs = []AgentAlertEventRef{}
	}
	wl := a.WorkloadIDs
	if len(wl) == 0 {
		wl = json.RawMessage(`[]`)
	}
	return json.Marshal(AgentAlertSIEMPayload{Type: AgentAlertSIEMType, Version: 1, DeliveryID: deliveryID, SentAt: now.UTC(),
		Alert: AgentAlertSIEMAlert{ID: a.ID, WorkspaceID: a.WorkspaceID, ConnectorID: a.ConnectorID, IdentityID: a.IdentityID,
			WorkloadIDs: wl, SubjectLabel: a.SubjectLabel, SubjectName: a.SubjectName, Detection: a.Detection,
			DetectionName: detect.Name(detect.ID(a.Detection)), Severity: a.Severity, Title: a.Title, State: a.State,
			FirstSeen: a.FirstSeen.UTC(), LastSeen: a.LastSeen.UTC(), EventCount: a.EventCount, Link: AgentAlertConsoleLink(a.ID)},
		Evidence: refs})
}

// agentAlertPermanent marks a SIEM failure no retry can fix.
type agentAlertPermanent struct{ err error }

func (e *agentAlertPermanent) Error() string { return e.err.Error() }
func (e *agentAlertPermanent) Unwrap() error { return e.err }

// PostAgentAlertSIEM signs and POSTs body to url with client. It returns
// the HTTP status (0 when none) and an error for anything but a 2xx.
func PostAgentAlertSIEM(ctx context.Context, client *http.Client, url, secret, deliveryID string, body []byte, now time.Time) (int, error) {
	ts := strconv.FormatInt(now.Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, &agentAlertPermanent{fmt.Errorf("build request: %w", sanitizeAgentAlertSIEMError(err))}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", AgentAlertSIEMUserAgent)
	req.Header.Set(AgentAlertSIEMTimestampHeader, ts)
	req.Header.Set(AgentAlertSIEMSignatureHeader, SignAgentAlertSIEM(secret, ts, body))
	if deliveryID != "" {
		req.Header.Set(AgentAlertSIEMDeliveryHeader, deliveryID)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, safehttp.ErrBlockedAddress) {
			return 0, &agentAlertPermanent{fmt.Errorf("the endpoint's address is not allowed")}
		}
		return 0, fmt.Errorf("post: %w", sanitizeAgentAlertSIEMError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("the endpoint answered %s", resp.Status)
	}
	return resp.StatusCode, nil
}

// agentAlertSIEMBackoff is the delay after attempt n: 1, 2, 4 ... 60 min.
func agentAlertSIEMBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 7 {
		return time.Hour
	}
	d := time.Minute << uint(attempt-1)
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

/* ------------------------------------------------------------------------- */
/*                                   Worker                                   */
/* ------------------------------------------------------------------------- */

// AgentAlertDeliverer delivers SIEM rows and purges expired alerts.
type AgentAlertDeliverer struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentAlertDeliverer builds the deliverer over db.
func NewAgentAlertDeliverer(db *gorm.DB) *AgentAlertDeliverer {
	return &AgentAlertDeliverer{db: db, now: time.Now}
}

// RunAgentRuntimeAlertWorker delivers due SIEM rows every 15 s and purges
// expired alerts hourly, until ctx ends. Safe on every replica (rows are
// claimed). AUTHSEC_DISABLE_AGENT_ALERT_WORKER=true keeps a replica API-only.
func RunAgentRuntimeAlertWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_AGENT_ALERT_WORKER") == "true" {
		log.Printf("[agent-alerts] delivery worker not started: AUTHSEC_DISABLE_AGENT_ALERT_WORKER=true")
		return
	}
	d := NewAgentAlertDeliverer(db)
	var lastPurge time.Time
	for {
		if ok, reason := AgentAlertsStatus(db); !ok {
			agentAlertsGate.logWait("alert delivery worker", reason)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
			continue
		}
		if _, err := d.DeliverDue(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[agent-alerts] delivery: %v", err)
		}
		if time.Since(lastPurge) >= time.Hour {
			if err := d.Purge(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[agent-alerts] retention: %v", err)
			}
			lastPurge = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

type agentAlertDue struct {
	WorkspaceID uuid.UUID
	ID          uuid.UUID
}

type agentAlertClaim struct {
	delivery  AgentAlertDelivery
	alert     *AgentAlert
	url       string
	secretRef string
	gone      string // why the delivery cannot be made at all
}

type agentAlertEndpointRow struct {
	URL       string
	SecretRef string
	Enabled   bool
	DeletedAt *time.Time
}

// DeliverDue makes one pass: every due SIEM delivery (up to a batch) is
// claimed, sent and recorded in its workspace. It returns how many were sent.
func (d *AgentAlertDeliverer) DeliverDue(ctx context.Context) (int, error) {
	var due []agentAlertDue
	// TENANT-EXEMPT: the SIEM delivery worker runs across workspaces (no request tenant) and lists due delivery ids only; each is claimed, sent and recorded in its own workspace_id-bound transaction.
	if err := d.db.WithContext(ctx).Raw(`SELECT workspace_id, id FROM agent_alert_delivery
	                                  WHERE channel = 'siem' AND status = 'pending' AND next_attempt_at <= now()
	                                    AND (leased_until IS NULL OR leased_until < now())
	                                  ORDER BY next_attempt_at LIMIT ?`, agentAlertSIEMBatch).Scan(&due).Error; err != nil {
		return 0, err
	}
	sent := 0
	var first error
	for _, r := range due {
		ok, err := d.deliverOne(ctx, r.WorkspaceID, r.ID)
		if err != nil && first == nil {
			first = fmt.Errorf("workspace %s: delivery %s: %w", r.WorkspaceID, r.ID, err)
		}
		if ok {
			sent++
		}
	}
	return sent, first
}

func (d *AgentAlertDeliverer) deliverOne(ctx context.Context, ws, id uuid.UUID) (bool, error) {
	var c *agentAlertClaim
	if err := tenancy.InWorkspace(ctx, d.db, ws, func(tx *gorm.DB) error {
		var rows []AgentAlertDelivery
		if err := tx.Raw(`SELECT id, alert_id, channel, endpoint_id, attempt, status, next_attempt_at, last_error, sent_at, created_at
		                    FROM agent_alert_delivery
		                   WHERE workspace_id = ? AND id = ? AND channel = 'siem' AND status = 'pending' AND next_attempt_at <= now()
		                     AND (leased_until IS NULL OR leased_until < now())
		                   FOR UPDATE SKIP LOCKED`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil // claimed by another replica, or no longer due
		}
		cl := &agentAlertClaim{delivery: rows[0]}
		cl.delivery.Attempt++
		// The lease is set from the database clock, the one the claim
		// comparisons above and in DeliverDue use.
		if err := tx.Exec(`UPDATE agent_alert_delivery SET attempt = ?, leased_until = now() + make_interval(secs => ?)
		                    WHERE workspace_id = ? AND id = ?`, cl.delivery.Attempt, agentAlertSIEMLease.Seconds(), ws, id).Error; err != nil {
			return err
		}
		var alerts []AgentAlert
		if err := tx.Raw(`SELECT `+agentAlertColumns+` FROM agent_alert WHERE workspace_id = ? AND id = ?`, ws, cl.delivery.AlertID).Scan(&alerts).Error; err != nil {
			return err
		}
		if len(alerts) == 0 {
			cl.gone = "the alert no longer exists"
		} else {
			cl.alert = &alerts[0]
		}
		var eps []agentAlertEndpointRow
		if cl.delivery.EndpointID != nil {
			if err := tx.Raw(`SELECT url, secret_ref, enabled, deleted_at FROM agent_alert_siem_endpoint
			                   WHERE workspace_id = ? AND id = ?`, ws, *cl.delivery.EndpointID).Scan(&eps).Error; err != nil {
				return err
			}
		}
		switch {
		case len(eps) == 0 || eps[0].DeletedAt != nil:
			cl.gone = "the SIEM endpoint was deleted"
		case !eps[0].Enabled:
			cl.gone = "the SIEM endpoint is disabled"
		default:
			cl.url, cl.secretRef = eps[0].URL, eps[0].SecretRef
		}
		c = cl
		return nil
	}); err != nil {
		return false, err
	}
	if c == nil {
		return false, nil
	}
	var sendErr error
	if c.gone != "" {
		sendErr = &agentAlertPermanent{errors.New(c.gone)}
	} else {
		sendErr = d.send(ctx, c)
	}
	return sendErr == nil, d.record(ctx, ws, c.delivery, sendErr)
}

func (d *AgentAlertDeliverer) send(ctx context.Context, c *agentAlertClaim) error {
	secret, err := readAgentAlertSIEMSecret(c.secretRef)
	if err != nil {
		return err // retried: Vault can come back
	}
	now := d.now()
	body, err := BuildAgentAlertSIEMPayload(*c.alert, c.delivery.ID.String(), now)
	if err != nil {
		return &agentAlertPermanent{err}
	}
	_, err = PostAgentAlertSIEM(ctx, agentAlertSIEMClient(), c.url, secret, c.delivery.ID.String(), body, now)
	return err
}

// record writes one attempt's outcome, fenced on the attempt number this
// worker claimed (a lease taken over by another worker writes nothing). The
// outcomes that end a delivery (delivered, failed for good) are also
// iga_gov_event entries, as Slack's notify path writes its own; the error
// shown is sanitised (no endpoint URL).
func (d *AgentAlertDeliverer) record(ctx context.Context, ws uuid.UUID, dl AgentAlertDelivery, sendErr error) error {
	return tenancy.InWorkspace(ctx, d.db, ws, func(tx *gorm.DB) error {
		var perm *agentAlertPermanent
		payload := map[string]any{"alert_id": dl.AlertID, "delivery_id": dl.ID, "endpoint_id": dl.EndpointID, "attempt": dl.Attempt}
		var res *gorm.DB
		event := ""
		switch {
		case sendErr == nil:
			res = tx.Exec(`UPDATE agent_alert_delivery SET status = 'sent', sent_at = now(), last_error = '', leased_until = NULL
			                 WHERE workspace_id = ? AND id = ? AND attempt = ?`, ws, dl.ID, dl.Attempt)
			event = GovEventAgentAlertSIEMDelivered
		case errors.As(sendErr, &perm) || dl.Attempt >= agentAlertSIEMMaxAttempts:
			msg := truncate(sendErr.Error(), 1000)
			res = tx.Exec(`UPDATE agent_alert_delivery SET status = 'failed', last_error = ?, leased_until = NULL
			                 WHERE workspace_id = ? AND id = ? AND attempt = ?`, msg, ws, dl.ID, dl.Attempt)
			payload["error"] = truncate(msg, 300)
			event = GovEventAgentAlertSIEMFailed
		default:
			return tx.Exec(`UPDATE agent_alert_delivery SET last_error = ?, leased_until = NULL, next_attempt_at = ?
			                 WHERE workspace_id = ? AND id = ? AND attempt = ?`,
				truncate(sendErr.Error(), 1000), d.now().Add(agentAlertSIEMBackoff(dl.Attempt)), ws, dl.ID, dl.Attempt).Error
		}
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		return appendGovEvent(tx, ws, event, models.GovActorSystem, AgentAlertSinkName, govEventRefs{}, payload)
	})
}

// Purge applies retention in every workspace that has alert data: alerts
// whose last activity is older than the workspace's retention_days (their
// deliveries cascade), D5/D6 counter buckets and processed-event ids older
// than 8 days.
func (d *AgentAlertDeliverer) Purge(ctx context.Context) error {
	var wss []uuid.UUID
	// TENANT-EXEMPT: retention runs across workspaces (no request tenant) and lists workspace ids only; each workspace is purged in its own workspace_id-bound transaction.
	if err := d.db.WithContext(ctx).Raw(`SELECT workspace_id FROM agent_alert
	                                  UNION SELECT workspace_id FROM agent_alert_baseline WHERE kind IN ('hourly', 'denied')
	                                  UNION SELECT workspace_id FROM agent_alert_event_seen`).Scan(&wss).Error; err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if err := d.purgeWorkspace(ctx, ws); err != nil && first == nil {
			first = fmt.Errorf("workspace %s: %w", ws, err)
		}
	}
	return first
}

func (d *AgentAlertDeliverer) purgeWorkspace(ctx context.Context, ws uuid.UUID) error {
	return tenancy.InWorkspace(ctx, d.db, ws, func(tx *gorm.DB) error {
		st, err := readAgentAlertSettings(tx, ws)
		if err != nil {
			return err
		}
		now := d.now().UTC()
		cutoff := now.AddDate(0, 0, -st.RetentionDays)
		// An alert still open or acknowledged is closed on the record first.
		var stale []AgentAlert
		if err := tx.Raw(`SELECT `+agentAlertColumns+` FROM agent_alert
		                   WHERE workspace_id = ? AND last_seen < ? AND state <> ?`, ws, cutoff, AgentAlertResolved).Scan(&stale).Error; err != nil {
			return err
		}
		for _, a := range stale {
			if err := appendGovEvent(tx, ws, GovEventAgentAlertResolved, models.GovActorSystem, AgentAlertSinkName, govEventRefs{},
				map[string]any{"alert_id": a.ID, "detection": a.Detection, "identity_id": a.IdentityID, "reason": "retention",
					"event_count": a.EventCount}); err != nil {
				return err
			}
		}
		if err := tx.Exec(`DELETE FROM agent_alert WHERE workspace_id = ? AND last_seen < ?`, ws, cutoff).Error; err != nil {
			return err
		}
		short := now.Add(-time.Duration(detect.BaselineHours+24) * time.Hour)
		if err := tx.Exec(`DELETE FROM agent_alert_baseline WHERE workspace_id = ? AND kind IN ('hourly', 'denied') AND last_seen < ?`, ws, short).Error; err != nil {
			return err
		}
		return tx.Exec(`DELETE FROM agent_alert_event_seen WHERE workspace_id = ? AND seen_at < ?`, ws, short).Error
	})
}
