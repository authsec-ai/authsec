package services

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Agent runtime event stream (SPEC-agent-runtime-visibility.md §5.6).
//
// A connected AWS account sends its CloudTrail events to
// POST /authsec/ingest/aws/events through an EventBridge rule and API
// destination (the stack in internal/awsdiscovery/authsec-agent-event-stream.yaml).
// The API destination's connection uses API-key auth: the header
// X-AuthSec-Event-Secret carries the connector's event secret. That secret is
// the ONLY thing that decides the workspace and the connector of a call
// (CLAUDE.md §4 rule 2): it is looked up by its hash, and nothing in the body
// -- not the account, not a workspace -- is trusted. Each event's account must
// be the connector's AWS account, or the event is refused.
//
// Accepted events are deduplicated by CloudTrail eventID (agent_event_seen)
// and only new ones are handed to agentruntime.Dispatch, which fans them out
// to the registered sinks (evidence, detections, ...). Sinks are idempotent by
// eventID too: the scan poller reads the same events.
//
// Nothing here logs a secret or an event body.

// Ingest wire constants.
const (
	// AgentEventSecretHeader is the header the EventBridge connection sends
	// (ApiKeyName in the stack).
	AgentEventSecretHeader = "X-AuthSec-Event-Secret"
	// AgentEventSecretPrefix starts every event secret, so a leaked one is
	// recognisable in a log or a secret scanner.
	AgentEventSecretPrefix = "aev_"
	// agentEventSecretLen is "aev_" plus 43 base64url characters (32 random
	// bytes, unpadded).
	agentEventSecretLen = len(AgentEventSecretPrefix) + 43
	// agentEventSecretShown is how much of a secret is kept in clear.
	agentEventSecretShown = 8

	// AgentEventMaxEventBytes is EventBridge's own event size limit.
	AgentEventMaxEventBytes = 256 << 10
	// AgentEventMaxRequestBytes bounds one request (413 above it).
	AgentEventMaxRequestBytes = 1 << 20
	// AgentEventMaxEventsPerRequest bounds a JSON array (413 above it).
	AgentEventMaxEventsPerRequest = 500
	// agentEventMaxIDLen is the longest eventID kept (agent_event_seen's CHECK).
	agentEventMaxIDLen = 128

	// AgentEventSeenRetention is how long an accepted eventID is remembered.
	// EventBridge retries for at most 24 hours; 14 days also covers a replay.
	AgentEventSeenRetention = 14 * 24 * time.Hour
	// agentEventPurgeEvery bounds how often one workspace's purge runs.
	agentEventPurgeEvery = time.Hour

	// AgentEventDefaultSilentAfter is the gap after which a stream reads as
	// silent; the per-connector value is bounded by the two below.
	AgentEventDefaultSilentAfter = 6 * time.Hour
	AgentEventMinSilentAfter     = 15 * time.Minute
	AgentEventMaxSilentAfter     = 7 * 24 * time.Hour

	// AgentEventDispatchTimeout bounds the sinks. An API destination waits 5
	// seconds for a response before it counts the call as failed and
	// retries, so the sinks get less than that.
	AgentEventDispatchTimeout = 4 * time.Second

	// AgentEventIngestRPSEnv and AgentEventIngestBurstEnv set the per-connector
	// rate limit (requests per second, burst). Per process.
	AgentEventIngestRPSEnv   = "AGENT_EVENT_INGEST_RPS"
	AgentEventIngestBurstEnv = "AGENT_EVENT_INGEST_BURST"
	defaultAgentEventRPS     = 100
	defaultAgentEventBurst   = 200

	// AgentEventIngestURLEnv overrides the public ingest URL handed to the
	// stack (default: the OAuth base URL + AgentEventIngestPath).
	AgentEventIngestURLEnv = "AGENT_EVENT_INGEST_URL"
	AgentEventIngestPath   = "/authsec/ingest/aws/events"
)

// Event stream states (AgentEventStreamView.State).
const (
	AgentEventStreamNotConfigured = "not_configured"
	AgentEventStreamActive        = "active"
	AgentEventStreamRevoked       = "revoked"
)

// Why an event was refused.
const (
	agentEventRejectAccount  = "account"
	agentEventRejectInvalid  = "invalid"
	agentEventRejectOversize = "oversize"
)

var (
	// ErrAgentEventStreamNotFound: the connector has no event stream.
	ErrAgentEventStreamNotFound = errors.New("no event stream for this connector")
	// ErrAgentEventSilentAfter: silent_after outside its bounds.
	ErrAgentEventSilentAfter = fmt.Errorf("silent_after_minutes must be between %d and %d",
		int(AgentEventMinSilentAfter/time.Minute), int(AgentEventMaxSilentAfter/time.Minute))
	// ErrAgentEventTooLarge: one event over 256 KB, or too many events (413).
	ErrAgentEventTooLarge = errors.New("an event is larger than 256 KB or the request carries too many events")
	// ErrAgentEventBadBody: not an EventBridge event or a JSON array of them (400).
	ErrAgentEventBadBody = errors.New("the body must be one EventBridge event or a JSON array of them")
	// ErrAgentEventUnauthenticated: the secret stopped being valid while the
	// call ran (revoked or rotated) (401).
	ErrAgentEventUnauthenticated = errors.New("unknown or revoked event secret")
	// ErrAgentEventDispatch: the sinks failed or timed out; the events were not
	// recorded as seen, so a retry delivers them again (503).
	ErrAgentEventDispatch = errors.New("the events could not be processed; retry")
)

/* --------------------------------- secrets -------------------------------- */

// GenerateAgentEventSecret returns a new secret: "aev_" + base64url (no
// padding) of 32 bytes from crypto/rand.
func GenerateAgentEventSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate event secret: %w", err)
	}
	return AgentEventSecretPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashAgentEventSecret is the stored form of a secret: sha256, lower-case
// hex, as discovery ingest tokens (repository.HashDiscoveryIngestToken). The
// secret is high-entropy random, so an unsalted fast hash makes the lookup an
// index probe with nothing to brute-force.
func HashAgentEventSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// wellFormedAgentEventSecret is a shape check before any database work, so a
// garbage header costs no query.
func wellFormedAgentEventSecret(s string) bool {
	if len(s) != agentEventSecretLen || !strings.HasPrefix(s, AgentEventSecretPrefix) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s[len(AgentEventSecretPrefix):])
	return err == nil
}

/* ---------------------------------- views --------------------------------- */

// AgentEventStreamView is a connector's event stream as the admin API shows
// it. The secret is never part of it; SecretPrefix tells secrets apart.
type AgentEventStreamView struct {
	ConnectorID uuid.UUID `json:"connector_id"`
	AccountID   string    `json:"account_id"`
	// State is not_configured, active or revoked.
	State          string     `json:"state"`
	SecretPrefix   string     `json:"secret_prefix,omitempty"`
	CreatedBy      string     `json:"created_by,omitempty"`
	CreatedAt      *time.Time `json:"created_at,omitempty"`
	RotatedAt      *time.Time `json:"rotated_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	LastReceivedAt *time.Time `json:"last_received_at,omitempty"`
	// LastEventTime is the newest CloudTrail eventTime received.
	LastEventTime *time.Time `json:"last_event_time,omitempty"`
	// ReceivedCount counts accepted deliveries (new events, duplicates and
	// retries); RejectedCount refused events (wrong account, invalid, oversize).
	ReceivedCount      int64 `json:"received_count"`
	RejectedCount      int64 `json:"rejected_count"`
	SilentAfterMinutes int   `json:"silent_after_minutes"`
	// Silent: an active stream from which nothing arrived for
	// silent_after_minutes. SilentSince is when the silence began: the last
	// accepted event, or when the secret was set if none ever arrived.
	Silent      bool       `json:"silent"`
	SilentSince *time.Time `json:"silent_since,omitempty"`
	// EndpointURL and SecretHeader are what the stack needs.
	EndpointURL  string `json:"endpoint_url"`
	SecretHeader string `json:"secret_header"`
}

// agentEventStreamRow is agent_event_stream as read (never the hash).
type agentEventStreamRow struct {
	ConnectorID        uuid.UUID
	WorkspaceID        uuid.UUID
	SecretPrefix       string
	CreatedBy          string
	CreatedAt          time.Time
	RotatedAt          *time.Time
	RevokedAt          *time.Time
	LastReceivedAt     *time.Time
	LastEventTime      *time.Time
	ReceivedCount      int64
	RejectedCount      int64
	SilentAfterSeconds int64
}

// streamSilence decides whether an active stream is silent and since when.
// A stream that never delivered is silent from when its secret was set.
func streamSilence(state string, createdAt time.Time, rotatedAt, lastReceived *time.Time,
	silentAfter time.Duration, now time.Time) (bool, *time.Time) {
	if state != AgentEventStreamActive {
		return false, nil
	}
	since := createdAt
	switch {
	case lastReceived != nil:
		since = *lastReceived
	case rotatedAt != nil:
		since = *rotatedAt
	}
	if now.Sub(since) < silentAfter {
		return false, nil
	}
	s := since.UTC()
	return true, &s
}

// AgentEventIngestURL is the public ingest URL the stack posts to:
// AGENT_EVENT_INGEST_URL, else the OAuth base URL + AgentEventIngestPath.
// "" when neither is configured.
func AgentEventIngestURL() string {
	if u := strings.TrimSpace(os.Getenv(AgentEventIngestURLEnv)); u != "" {
		return u
	}
	if config.AppConfig == nil {
		return ""
	}
	base := strings.TrimRight(config.AppConfig.OAuthBaseURL(), "/")
	if base == "" {
		return ""
	}
	return base + AgentEventIngestPath
}

func (s *AgentRuntimeIngestService) view(conn awsConnectorRef, row *agentEventStreamRow) AgentEventStreamView {
	v := AgentEventStreamView{
		ConnectorID: conn.ID, AccountID: conn.AccountID, State: AgentEventStreamNotConfigured,
		SilentAfterMinutes: int(AgentEventDefaultSilentAfter / time.Minute),
		EndpointURL:        AgentEventIngestURL(), SecretHeader: AgentEventSecretHeader,
	}
	if row == nil {
		return v
	}
	v.State = AgentEventStreamActive
	if row.RevokedAt != nil {
		v.State = AgentEventStreamRevoked
	}
	created := row.CreatedAt.UTC()
	v.SecretPrefix, v.CreatedBy, v.CreatedAt = row.SecretPrefix, row.CreatedBy, &created
	v.RotatedAt, v.RevokedAt = utcPtr(row.RotatedAt), utcPtr(row.RevokedAt)
	v.LastReceivedAt, v.LastEventTime = utcPtr(row.LastReceivedAt), utcPtr(row.LastEventTime)
	v.ReceivedCount, v.RejectedCount = row.ReceivedCount, row.RejectedCount
	silentAfter := time.Duration(row.SilentAfterSeconds) * time.Second
	if silentAfter <= 0 {
		silentAfter = AgentEventDefaultSilentAfter
	}
	v.SilentAfterMinutes = int(silentAfter / time.Minute)
	v.Silent, v.SilentSince = streamSilence(v.State, row.CreatedAt, row.RotatedAt, row.LastReceivedAt, silentAfter, s.now())
	return v
}

/* --------------------------------- service -------------------------------- */

// AgentEventPrincipal is what a verified event secret resolves to. It comes
// from the secret's row and the connector's row, never from a request.
type AgentEventPrincipal struct {
	WorkspaceID uuid.UUID
	ConnectorID uuid.UUID
	// AccountID is the connector's AWS account (cloud_connector.scope_id).
	AccountID string
}

// AgentEventIngestResult is what one ingest call did.
type AgentEventIngestResult struct {
	Received   int `json:"received"`   // events in the request
	Accepted   int `json:"accepted"`   // new events handed to the sinks
	Duplicates int `json:"duplicates"` // already seen (a retry, or twice in the request)
	Rejected   int `json:"rejected"`   // refused, all reasons
	// RejectedAccount: the event's account is not the connector's.
	RejectedAccount int `json:"rejected_account"`
	// RejectedInvalid: not a CloudTrail event EventBridge delivers, or over 256 KB.
	RejectedInvalid int `json:"rejected_invalid"`
}

// AgentRuntimeIngestService owns agent_event_stream and agent_event_seen: the
// admin API's create/rotate, read and revoke, and the ingest. One instance
// serves every request (it holds the per-connector rate limits).
type AgentRuntimeIngestService struct {
	db              *gorm.DB
	now             func() time.Time
	dispatch        func(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error
	dispatchTimeout time.Duration

	limitMu  sync.Mutex
	limiters map[uuid.UUID]*rate.Limiter
	rps      rate.Limit
	burst    int

	purgeMu   sync.Mutex
	lastPurge map[uuid.UUID]time.Time
}

// NewAgentRuntimeIngestService constructs the service. The rate limit comes
// from AGENT_EVENT_INGEST_RPS / AGENT_EVENT_INGEST_BURST.
func NewAgentRuntimeIngestService(db *gorm.DB) *AgentRuntimeIngestService {
	return &AgentRuntimeIngestService{
		db:              db,
		now:             time.Now,
		dispatch:        agentruntime.Dispatch,
		dispatchTimeout: AgentEventDispatchTimeout,
		limiters:        map[uuid.UUID]*rate.Limiter{},
		rps:             rate.Limit(envPositiveInt(AgentEventIngestRPSEnv, defaultAgentEventRPS)),
		burst:           envPositiveInt(AgentEventIngestBurstEnv, defaultAgentEventBurst),
		lastPurge:       map[uuid.UUID]time.Time{},
	}
}

// WithDispatch replaces agentruntime.Dispatch (tests).
func (s *AgentRuntimeIngestService) WithDispatch(f func(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error) *AgentRuntimeIngestService {
	s.dispatch = f
	return s
}

// WithRateLimit sets the per-connector limit (tests).
func (s *AgentRuntimeIngestService) WithRateLimit(rps float64, burst int) *AgentRuntimeIngestService {
	s.limitMu.Lock()
	s.rps, s.burst, s.limiters = rate.Limit(rps), burst, map[uuid.UUID]*rate.Limiter{}
	s.limitMu.Unlock()
	return s
}

// WithClock replaces time.Now (tests).
func (s *AgentRuntimeIngestService) WithClock(f func() time.Time) *AgentRuntimeIngestService {
	s.now = f
	return s
}

func envPositiveInt(name string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil && v > 0 {
		return v
	}
	return def
}

// Allow takes one request from the connector's rate limit. false means 429:
// EventBridge retries it.
func (s *AgentRuntimeIngestService) Allow(connectorID uuid.UUID) bool {
	s.limitMu.Lock()
	l, ok := s.limiters[connectorID]
	if !ok {
		l = rate.NewLimiter(s.rps, s.burst)
		s.limiters[connectorID] = l
	}
	s.limitMu.Unlock()
	return l.Allow()
}

/* ------------------------------- connectors ------------------------------- */

type awsConnectorRef struct {
	ID        uuid.UUID
	AccountID string
	Status    string
}

// loadAWSConnector reads one AWS connector of the workspace, inside a
// workspace transaction. Another workspace's connector, or a non-AWS one, is
// repositories.ErrCloudConnectorNotFound (a 404 that confirms nothing).
func loadAWSConnector(tx *gorm.DB, ws, id uuid.UUID) (awsConnectorRef, error) {
	var c models.CloudConnector
	err := tx.Select("id", "workspace_id", "provider", "scope_id", "status").
		Where("workspace_id = ? AND id = ? AND provider = ?", ws, id, models.CloudProviderAWS).
		Take(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return awsConnectorRef{}, repositories.ErrCloudConnectorNotFound
	}
	if err != nil {
		return awsConnectorRef{}, err
	}
	return awsConnectorRef{ID: c.ID, AccountID: c.ScopeID, Status: c.Status}, nil
}

// readStreamRow reads the connector's stream row, or nil.
func readStreamRow(tx *gorm.DB, ws, connectorID uuid.UUID) (*agentEventStreamRow, error) {
	var row agentEventStreamRow
	res := tx.Raw(`SELECT connector_id, workspace_id, secret_prefix, created_by, created_at, rotated_at,
		       revoked_at, last_received_at, last_event_time, received_count, rejected_count,
		       EXTRACT(EPOCH FROM silent_after)::bigint AS silent_after_seconds
		  FROM agent_event_stream
		 WHERE workspace_id = ? AND connector_id = ?`, ws, connectorID).Scan(&row)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, nil
	}
	return &row, nil
}

/* -------------------------------- admin API ------------------------------- */

// EnableOrRotate turns the connector's event stream on with a new secret, or
// rotates the secret of an existing stream (and un-revokes it). It returns
// the view, the secret -- shown once, never stored -- and whether this was a
// rotation. silentAfter nil keeps the current value (6 h for a new stream).
// The old secret stops working at once: the stack's EventSecret parameter
// must be updated with the new one.
func (s *AgentRuntimeIngestService) EnableOrRotate(ctx context.Context, ws, connectorID uuid.UUID,
	actor string, silentAfter *time.Duration) (AgentEventStreamView, string, bool, error) {
	if silentAfter != nil && (*silentAfter < AgentEventMinSilentAfter || *silentAfter > AgentEventMaxSilentAfter) {
		return AgentEventStreamView{}, "", false, ErrAgentEventSilentAfter
	}
	secret, err := GenerateAgentEventSecret()
	if err != nil {
		return AgentEventStreamView{}, "", false, err
	}
	var (
		conn    awsConnectorRef
		row     *agentEventStreamRow
		rotated bool
	)
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if conn, err = loadAWSConnector(tx, ws, connectorID); err != nil {
			return err
		}
		if conn.Status == models.CloudConnectorRevoked {
			return ErrAWSConnectorRevoked
		}
		existing, err := readStreamRow(tx, ws, connectorID)
		if err != nil {
			return err
		}
		rotated = existing != nil
		secs := int64(AgentEventDefaultSilentAfter / time.Second)
		switch {
		case silentAfter != nil:
			secs = int64(*silentAfter / time.Second)
		case existing != nil && existing.SilentAfterSeconds > 0:
			secs = existing.SilentAfterSeconds
		}
		if err := tx.Exec(`INSERT INTO agent_event_stream
			    (connector_id, workspace_id, secret_hash, secret_prefix, created_by, silent_after)
			VALUES (?, ?, ?, ?, ?, make_interval(secs => ?))
			ON CONFLICT (connector_id) DO UPDATE SET
			    secret_hash   = EXCLUDED.secret_hash,
			    secret_prefix = EXCLUDED.secret_prefix,
			    silent_after  = EXCLUDED.silent_after,
			    rotated_at    = now(),
			    revoked_at    = NULL
			WHERE agent_event_stream.workspace_id = EXCLUDED.workspace_id`,
			connectorID, ws, HashAgentEventSecret(secret), secret[:agentEventSecretShown],
			strings.TrimSpace(actor), float64(secs)).Error; err != nil {
			return err
		}
		row, err = readStreamRow(tx, ws, connectorID)
		return err
	})
	if err != nil {
		return AgentEventStreamView{}, "", false, err
	}
	if row == nil {
		return AgentEventStreamView{}, "", false, errors.New("event stream row missing after write")
	}
	return s.view(conn, row), secret, rotated, nil
}

// Get returns the connector's event stream (state not_configured when it has
// none), with its silence.
func (s *AgentRuntimeIngestService) Get(ctx context.Context, ws, connectorID uuid.UUID) (AgentEventStreamView, error) {
	var (
		conn awsConnectorRef
		row  *agentEventStreamRow
	)
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if conn, err = loadAWSConnector(tx, ws, connectorID); err != nil {
			return err
		}
		row, err = readStreamRow(tx, ws, connectorID)
		return err
	})
	if err != nil {
		return AgentEventStreamView{}, err
	}
	return s.view(conn, row), nil
}

// Revoke stops the stream: its secret is refused from now on. Revoking twice
// keeps the first revoked_at. A connector without a stream is
// ErrAgentEventStreamNotFound. It returns the view before and after.
func (s *AgentRuntimeIngestService) Revoke(ctx context.Context, ws, connectorID uuid.UUID) (AgentEventStreamView, AgentEventStreamView, error) {
	var (
		conn          awsConnectorRef
		before, after *agentEventStreamRow
	)
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if conn, err = loadAWSConnector(tx, ws, connectorID); err != nil {
			return err
		}
		if before, err = readStreamRow(tx, ws, connectorID); err != nil {
			return err
		}
		if before == nil {
			return ErrAgentEventStreamNotFound
		}
		if err := tx.Exec(`UPDATE agent_event_stream SET revoked_at = COALESCE(revoked_at, now())
			WHERE workspace_id = ? AND connector_id = ?`, ws, connectorID).Error; err != nil {
			return err
		}
		after, err = readStreamRow(tx, ws, connectorID)
		return err
	})
	if err != nil {
		return AgentEventStreamView{}, AgentEventStreamView{}, err
	}
	return s.view(conn, before), s.view(conn, after), nil
}

/* ---------------------------------- ingest -------------------------------- */

// Authenticate resolves a presented event secret to its workspace, connector
// and AWS account, or nil when it is not a live secret: malformed, unknown,
// revoked, or its connector revoked or gone. An error is a database failure,
// never an invalid secret.
func (s *AgentRuntimeIngestService) Authenticate(ctx context.Context, presented string) (*AgentEventPrincipal, error) {
	if !wellFormedAgentEventSecret(presented) {
		return nil, nil
	}
	h := HashAgentEventSecret(presented)
	var cred struct {
		WorkspaceID uuid.UUID
		ConnectorID uuid.UUID
		SecretHash  string
	}
	// TENANT-EXEMPT: the presented event secret decides the workspace, so it
	// is looked up by its hash across workspaces (as discovery ingest tokens);
	// everything after runs under the secret's workspace.
	res := s.db.WithContext(ctx).Table("agent_event_stream").
		Select("workspace_id", "connector_id", "secret_hash").
		Where("secret_hash = ? AND revoked_at IS NULL", h).
		Limit(1).Scan(&cred)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, nil
	}
	// The index decided; compare again in constant time so the decision never
	// rests on a variable-time compare.
	if subtle.ConstantTimeCompare([]byte(cred.SecretHash), []byte(h)) != 1 {
		return nil, nil
	}
	var conn awsConnectorRef
	err := tenancy.InWorkspaceRead(ctx, s.db, cred.WorkspaceID, func(tx *gorm.DB) error {
		var err error
		conn, err = loadAWSConnector(tx, cred.WorkspaceID, cred.ConnectorID)
		return err
	})
	if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if conn.Status == models.CloudConnectorRevoked || conn.AccountID == "" {
		return nil, nil
	}
	return &AgentEventPrincipal{WorkspaceID: cred.WorkspaceID, ConnectorID: cred.ConnectorID, AccountID: conn.AccountID}, nil
}

// splitAgentEventBody splits a request body into events: one EventBridge
// event (a JSON object) or a JSON array of them. An API destination sends one
// event per request; the array form is for replays and tests.
func splitAgentEventBody(body []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, ErrAgentEventBadBody
	}
	switch trimmed[0] {
	case '{':
		if len(trimmed) > AgentEventMaxEventBytes {
			return nil, ErrAgentEventTooLarge
		}
		if !json.Valid(trimmed) {
			return nil, ErrAgentEventBadBody
		}
		return []json.RawMessage{json.RawMessage(trimmed)}, nil
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, ErrAgentEventBadBody
		}
		if len(arr) == 0 {
			return nil, ErrAgentEventBadBody
		}
		if len(arr) > AgentEventMaxEventsPerRequest {
			return nil, ErrAgentEventTooLarge
		}
		return arr, nil
	}
	return nil, ErrAgentEventBadBody
}

// classifyAgentEvent parses one EventBridge event and checks it belongs to
// the connector's account: both the envelope's account and the CloudTrail
// record's recipient account must be it. reason is "" for an accepted event.
func classifyAgentEvent(raw json.RawMessage, accountID string) (agentruntime.Event, string) {
	if len(raw) > AgentEventMaxEventBytes {
		return agentruntime.Event{}, agentEventRejectOversize
	}
	var env agentruntime.EventBridgeEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return agentruntime.Event{}, agentEventRejectInvalid
	}
	e, err := agentruntime.ParseEventBridge(raw)
	if err != nil || len(e.EventID) > agentEventMaxIDLen {
		return agentruntime.Event{}, agentEventRejectInvalid
	}
	if env.Account != accountID || e.AccountID != accountID {
		return agentruntime.Event{}, agentEventRejectAccount
	}
	return e, ""
}

// Ingest takes one request's body for an authenticated connector. Every
// event is parsed and checked against the connector's account; accepted
// events are recorded in agent_event_seen (insert ... on conflict do
// nothing), and only the ones not seen before go to the sinks, with a bounded
// timeout. If the sinks fail, the new events' seen marks are removed again so
// EventBridge's retry delivers them (sinks are idempotent by eventID).
//
// Errors: ErrAgentEventBadBody (400), ErrAgentEventTooLarge (413),
// ErrAgentEventUnauthenticated (401: revoked mid-call), ErrAgentEventDispatch
// (503), or a database failure. A result whose events were all refused is
// returned without error; the caller decides its status.
func (s *AgentRuntimeIngestService) Ingest(ctx context.Context, p AgentEventPrincipal, body []byte) (AgentEventIngestResult, error) {
	var res AgentEventIngestResult
	raws, err := splitAgentEventBody(body)
	if err != nil {
		return res, err
	}
	res.Received = len(raws)

	var (
		valid    []agentruntime.Event
		ids      []string
		inReq    = map[string]bool{}
		maxEvent *time.Time
	)
	for _, raw := range raws {
		e, reason := classifyAgentEvent(raw, p.AccountID)
		switch reason {
		case agentEventRejectAccount:
			res.Rejected++
			res.RejectedAccount++
			continue
		case agentEventRejectInvalid, agentEventRejectOversize:
			res.Rejected++
			res.RejectedInvalid++
			continue
		}
		if inReq[e.EventID] {
			res.Duplicates++
			continue
		}
		inReq[e.EventID] = true
		valid = append(valid, e)
		ids = append(ids, e.EventID)
		if !e.EventTime.IsZero() && (maxEvent == nil || e.EventTime.After(*maxEvent)) {
			t := e.EventTime
			maxEvent = &t
		}
	}

	accepted := len(valid) + res.Duplicates
	fresh := map[string]bool{}
	err = tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		if len(ids) > 0 {
			rows, err := tx.Raw(`INSERT INTO agent_event_seen (workspace_id, connector_id, event_id)
				SELECT ?, ?, unnest(?::text[])
				ON CONFLICT (workspace_id, event_id) DO NOTHING
				RETURNING event_id`, p.WorkspaceID, p.ConnectorID, pq.StringArray(ids)).Rows()
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					_ = rows.Close()
					return err
				}
				fresh[id] = true
			}
			// Closed before the next statement on the same connection.
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
		}
		upd := tx.Exec(`UPDATE agent_event_stream SET
			    received_count   = received_count + ?,
			    rejected_count   = rejected_count + ?,
			    last_received_at = CASE WHEN ? > 0 THEN now() ELSE last_received_at END,
			    last_event_time  = GREATEST(last_event_time, ?::timestamptz)
			WHERE workspace_id = ? AND connector_id = ? AND revoked_at IS NULL`,
			accepted, res.Rejected, accepted, maxEvent, p.WorkspaceID, p.ConnectorID)
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected == 0 {
			// Revoked or rotated since Authenticate: refuse the whole call.
			return ErrAgentEventUnauthenticated
		}
		return nil
	})
	if err != nil {
		return res, err
	}

	var newEvents []agentruntime.Event
	var newIDs []string
	for _, e := range valid {
		if fresh[e.EventID] {
			newEvents = append(newEvents, e)
			newIDs = append(newIDs, e.EventID)
		} else {
			res.Duplicates++
		}
	}
	res.Accepted = len(newEvents)

	if len(newEvents) > 0 {
		dctx, cancel := context.WithTimeout(ctx, s.dispatchTimeout)
		derr := s.dispatch(dctx, p.WorkspaceID, p.ConnectorID, newEvents)
		cancel()
		if derr != nil {
			log.Printf("[agent-event-ingest] stage=dispatch workspace=%s connector=%s events=%d outcome=failed err=%v",
				p.WorkspaceID, p.ConnectorID, len(newEvents), derr)
			s.releaseSeen(p, newIDs)
			return res, ErrAgentEventDispatch
		}
	}
	s.maybePurge(ctx, p.WorkspaceID)
	return res, nil
}

// releaseSeen forgets events whose dispatch failed, so a retry is not
// deduplicated away. Its own failure is logged: the poller remains the
// backstop for management events.
func (s *AgentRuntimeIngestService) releaseSeen(p AgentEventPrincipal, ids []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		return tx.Exec(`DELETE FROM agent_event_seen
			WHERE workspace_id = ? AND connector_id = ? AND event_id = ANY(?::text[])`,
			p.WorkspaceID, p.ConnectorID, pq.StringArray(ids)).Error
	})
	if err != nil {
		log.Printf("[agent-event-ingest] stage=release workspace=%s connector=%s events=%d outcome=failed err=%v",
			p.WorkspaceID, p.ConnectorID, len(ids), err)
	}
}

// maybePurge deletes the workspace's seen eventIDs older than
// AgentEventSeenRetention, at most once per agentEventPurgeEvery per process.
func (s *AgentRuntimeIngestService) maybePurge(ctx context.Context, ws uuid.UUID) {
	now := s.now()
	s.purgeMu.Lock()
	if last, ok := s.lastPurge[ws]; ok && now.Sub(last) < agentEventPurgeEvery {
		s.purgeMu.Unlock()
		return
	}
	s.lastPurge[ws] = now
	s.purgeMu.Unlock()
	if _, err := s.PurgeSeen(ctx, ws, now.Add(-AgentEventSeenRetention)); err != nil {
		log.Printf("[agent-event-ingest] stage=purge workspace=%s outcome=failed err=%v", ws, err)
	}
}

// PurgeSeen deletes the workspace's seen eventIDs received before cutoff and
// returns how many it deleted.
func (s *AgentRuntimeIngestService) PurgeSeen(ctx context.Context, ws uuid.UUID, cutoff time.Time) (int64, error) {
	var n int64
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		res := tx.Exec(`DELETE FROM agent_event_seen WHERE workspace_id = ? AND received_at < ?`, ws, cutoff)
		n = res.RowsAffected
		return res.Error
	})
	return n, err
}
