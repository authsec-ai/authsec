package services

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Trail-bucket backfill (SPEC-secops-backend-upgrade W1, C1).
//
// A trail delivers its log files to S3 as
// <prefix>/AWSLogs/[<org-id>/]<account>/CloudTrail/<region>/YYYY/MM/DD/<file>.json.gz,
// each a gzipped {"Records": [...]} of CloudTrail records. A backfill reads
// the files of one window (list + get, gunzip, parse) with the connector's
// own discovery-role session (AWSOnboardingService.ConfigForConnector, as
// CloudTrail polling) and hands the records to the agent-runtime sinks with
// delivery trail_backfill -- idempotent by eventID like every other path, so
// what the stream or the poller already delivered is stored once.
//
// A backfill is asked for per connector and window
// (POST /api/iga/v1/agent-runtime/backfill, tier 1) or queued automatically
// by the coverage worker for the window an event stream was silent.
//
// LIMITATION: the AuthSec discovery role does not grant s3:ListBucket or
// s3:GetObject on the trail's bucket today; until the customer adds them for
// the trail bucket (decision 3: AuthSec generates, the customer applies), a
// backfill fails with access denied, recorded on the row.

// Backfill limits.
const (
	TrailBackfillMaxWindow  = 7 * 24 * time.Hour
	TrailBackfillMaxAge     = 365 * 24 * time.Hour
	TrailBackfillMaxObjects = 5000
	trailBackfillLease      = 30 * time.Minute
	trailBackfillFileSlack  = time.Hour
	trailBackfillMaxFile    = 64 << 20
)

// TrailBucketAPI is the slice of S3 a backfill uses (a fake in tests).
type TrailBucketAPI interface {
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// TrailLocation is where a trail's log files of one account are.
type TrailLocation struct {
	Bucket    string
	Prefix    string // the trail's S3KeyPrefix, "" when none
	AccountID string
	OrgID     string // set for an organization trail
}

func (l TrailLocation) base() string {
	p := strings.Trim(l.Prefix, "/")
	if p != "" {
		p += "/"
	}
	p += "AWSLogs/"
	if l.OrgID != "" {
		p += l.OrgID + "/"
	}
	return p + l.AccountID + "/CloudTrail/"
}

// TrailReadStats is what one read did.
type TrailReadStats struct {
	Objects int  `json:"objects_read"`
	Events  int  `json:"events_read"`
	Partial bool `json:"partial"`
}

// trailFileStamp is the delivery time in a log file's name
// (<acct>_CloudTrail_<region>_<YYYYMMDDTHHmmZ>_<id>.json.gz); false when the
// name does not carry one.
func trailFileStamp(key string) (time.Time, bool) {
	name := key[strings.LastIndex(key, "/")+1:]
	parts := strings.Split(name, "_")
	for _, p := range parts {
		if len(p) == 14 && p[8] == 'T' && p[13] == 'Z' {
			if t, err := time.Parse("20060102T1504Z", p); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

// ReadTrailWindow reads the log files of [from, to) of the given regions
// (every region the bucket holds when none) and hands each file's records of
// the account, inside the window, to sink. It stops after maxObjects files
// (partial).
func ReadTrailWindow(ctx context.Context, api TrailBucketAPI, loc TrailLocation, regions []string,
	from, to time.Time, maxObjects int, sink func([]agentruntime.Event) error) (TrailReadStats, error) {
	var st TrailReadStats
	if maxObjects <= 0 {
		maxObjects = TrailBackfillMaxObjects
	}
	base := loc.base()
	if len(regions) == 0 {
		out, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(loc.Bucket), Prefix: aws.String(base), Delimiter: aws.String("/")})
		if err != nil {
			return st, fmt.Errorf("list regions: %w", err)
		}
		for _, cp := range out.CommonPrefixes {
			r := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), base), "/")
			if r != "" {
				regions = append(regions, r)
			}
		}
		sort.Strings(regions)
	}
	from, to = from.UTC(), to.UTC()
	for _, region := range regions {
		for day := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC); day.Before(to); day = day.Add(24 * time.Hour) {
			prefix := base + region + "/" + day.Format("2006/01/02") + "/"
			var token *string
			for {
				out, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(loc.Bucket), Prefix: aws.String(prefix), ContinuationToken: token})
				if err != nil {
					return st, fmt.Errorf("list %s: %w", prefix, err)
				}
				for _, obj := range out.Contents {
					key := aws.ToString(obj.Key)
					if stamp, ok := trailFileStamp(key); ok && (stamp.Before(from.Add(-trailBackfillFileSlack)) || stamp.After(to.Add(trailBackfillFileSlack))) {
						continue
					}
					if st.Objects >= maxObjects {
						st.Partial = true
						return st, nil
					}
					events, err := readTrailFile(ctx, api, loc, key, from, to)
					st.Objects++
					if err != nil {
						return st, fmt.Errorf("read %s: %w", key, err)
					}
					if len(events) == 0 {
						continue
					}
					st.Events += len(events)
					if err := sink(events); err != nil {
						return st, err
					}
				}
				if !aws.ToBool(out.IsTruncated) || out.NextContinuationToken == nil {
					break
				}
				token = out.NextContinuationToken
			}
		}
	}
	return st, nil
}

// readTrailFile gets, gunzips and parses one log file; it keeps the
// records of the location's account inside [from, to).
func readTrailFile(ctx context.Context, api TrailBucketAPI, loc TrailLocation, key string, from, to time.Time) ([]agentruntime.Event, error) {
	out, err := api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(loc.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(out.Body, trailBackfillMaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > trailBackfillMaxFile {
		return nil, errors.New("log file larger than 64 MiB")
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		raw, err = io.ReadAll(io.LimitReader(zr, 8*trailBackfillMaxFile+1))
		_ = zr.Close()
		if err != nil {
			return nil, err
		}
		if len(raw) > 8*trailBackfillMaxFile {
			return nil, errors.New("log file decompresses beyond 512 MiB")
		}
	}
	var doc struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("not a CloudTrail log file: %w", err)
	}
	var events []agentruntime.Event
	for _, r := range doc.Records {
		e, err := agentruntime.ParseCloudTrailRecord(r)
		if err != nil || len(e.EventID) > agentEventMaxIDLen {
			continue
		}
		if e.AccountID != loc.AccountID || e.EventTime.Before(from) || !e.EventTime.Before(to) {
			continue
		}
		events = append(events, e)
	}
	return events, nil
}

/* ------------------------------------------------------------------------- */
/*                                The service                                 */
/* ------------------------------------------------------------------------- */

// TrailBackfill is one agent_trail_backfill row.
type TrailBackfill struct {
	ID          uuid.UUID  `json:"id" gorm:"column:id"`
	WorkspaceID uuid.UUID  `json:"-" gorm:"column:workspace_id"`
	ConnectorID uuid.UUID  `json:"connector_id" gorm:"column:connector_id"`
	WindowFrom  time.Time  `json:"window_from" gorm:"column:window_from"`
	WindowTo    time.Time  `json:"window_to" gorm:"column:window_to"`
	Cause       string     `json:"cause" gorm:"column:cause"`
	HeartbeatID *uuid.UUID `json:"heartbeat_id" gorm:"column:heartbeat_id"`
	State       string     `json:"state" gorm:"column:state"`
	RequestedBy *uuid.UUID `json:"requested_by" gorm:"column:requested_by"`
	ObjectsRead int        `json:"objects_read" gorm:"column:objects_read"`
	EventsRead  int        `json:"events_read" gorm:"column:events_read"`
	Partial     bool       `json:"partial" gorm:"column:partial"`
	LastError   string     `json:"last_error" gorm:"column:last_error"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at"`
	StartedAt   *time.Time `json:"started_at" gorm:"column:started_at"`
	FinishedAt  *time.Time `json:"finished_at" gorm:"column:finished_at"`
}

const trailBackfillColumns = `id, workspace_id, connector_id, window_from, window_to, cause, heartbeat_id, state, requested_by,
	objects_read, events_read, partial, last_error, created_at, started_at, finished_at`

// TrailLocator finds a connector's trail bucket and an S3 client for it.
type TrailLocator func(ctx context.Context, ws, connectorID uuid.UUID, accountID string) (TrailBucketAPI, TrailLocation, error)

// TrailBackfillService queues and runs backfills.
type TrailBackfillService struct {
	db       *gorm.DB
	now      func() time.Time
	locate   TrailLocator
	dispatch func(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error
}

// NewTrailBackfillService builds the service. locate nil: backfills can be
// queued but not run (no AWS credentials on this server).
func NewTrailBackfillService(db *gorm.DB, locate TrailLocator) *TrailBackfillService {
	return &TrailBackfillService{db: db, now: time.Now, locate: locate, dispatch: agentruntime.Dispatch}
}

// WithDispatch replaces agentruntime.Dispatch (tests).
func (s *TrailBackfillService) WithDispatch(f func(ctx context.Context, ws, connectorID uuid.UUID, events []agentruntime.Event) error) *TrailBackfillService {
	s.dispatch = f
	return s
}

// WithClock replaces the wall clock (tests).
func (s *TrailBackfillService) WithClock(now func() time.Time) *TrailBackfillService {
	s.now = now
	return s
}

// Request is POST /agent-runtime/backfill: queue a backfill of [from, to)
// for one AWS connector of ws (another workspace's connector is 404). The
// window is at most 7 days, ends no later than now, and starts within a year.
func (s *TrailBackfillService) Request(ctx context.Context, ws, connectorID, actor uuid.UUID, from, to time.Time) (*TrailBackfill, error) {
	now := s.now().UTC()
	from, to = from.UTC(), to.UTC()
	switch {
	case !to.After(from):
		return nil, GovBadParam("to", "to must be after from.")
	case to.Sub(from) > TrailBackfillMaxWindow:
		return nil, GovBadParam("to", "A backfill window is at most 7 days.")
	case to.After(now.Add(time.Minute)):
		return nil, GovBadParam("to", "to must not be in the future.")
	case now.Sub(from) > TrailBackfillMaxAge:
		return nil, GovBadParam("from", "from must be within the last year.")
	}
	var out TrailBackfill
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		conn, err := loadAWSConnector(tx, ws, connectorID)
		if err != nil {
			return err
		}
		if conn.Status == models.CloudConnectorRevoked {
			return govConflict("connector_revoked", "The connector is revoked.", nil)
		}
		return tx.Raw(`INSERT INTO agent_trail_backfill (workspace_id, connector_id, window_from, window_to, cause, requested_by)
		               VALUES (?, ?, ?, ?, 'manual', ?) RETURNING `+trailBackfillColumns, ws, connectorID, from, to, actor).Scan(&out).Error
	})
	if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		return nil, govErr(http.StatusNotFound, "not_found", "Not found.", nil)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// List is GET /agent-runtime/backfill: the workspace's newest 100 backfills.
func (s *TrailBackfillService) List(ctx context.Context, ws uuid.UUID) ([]TrailBackfill, error) {
	var out []TrailBackfill
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT `+trailBackfillColumns+` FROM agent_trail_backfill WHERE workspace_id = ?
		               ORDER BY created_at DESC, id DESC LIMIT 100`, ws).Scan(&out).Error
	})
	if out == nil {
		out = []TrailBackfill{}
	}
	return out, err
}

// RunDue claims and runs due backfills (queued, or running with an expired
// lease), at most max, and returns how many it ran.
func (s *TrailBackfillService) RunDue(ctx context.Context, max int) (int, error) {
	var due []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	// TENANT-EXEMPT: the backfill worker runs across workspaces (no request tenant) and lists due backfill ids only; each is claimed, run and recorded in its own workspace_id-bound RLS transaction.
	if err := s.db.WithContext(ctx).Raw(`SELECT workspace_id, id FROM agent_trail_backfill
	                                    WHERE state = 'queued' OR (state = 'running' AND leased_until < now())
	                                    ORDER BY created_at LIMIT ?`, max).Scan(&due).Error; err != nil {
		return 0, err
	}
	ran := 0
	for _, d := range due {
		if ctx.Err() != nil {
			return ran, ctx.Err()
		}
		ok, err := s.Run(ctx, d.WorkspaceID, d.ID)
		if err != nil {
			log.Printf("[trail-backfill] workspace=%s backfill=%s: %v", d.WorkspaceID, d.ID, err)
		}
		if ok {
			ran++
		}
	}
	return ran, nil
}

// Run claims one backfill and runs it to done or failed. false: another
// worker holds it.
func (s *TrailBackfillService) Run(ctx context.Context, ws, id uuid.UUID) (bool, error) {
	now := s.now().UTC()
	var b TrailBackfill
	var account string
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []TrailBackfill
		if err := tx.Raw(`UPDATE agent_trail_backfill SET state = 'running', started_at = COALESCE(started_at, ?), leased_until = ?
		                   WHERE workspace_id = ? AND id = ? AND (state = 'queued' OR (state = 'running' AND leased_until < ?))
		                   RETURNING `+trailBackfillColumns, now, now.Add(trailBackfillLease), ws, id, now).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		b = rows[0]
		conn, err := loadAWSConnector(tx, ws, b.ConnectorID)
		if err != nil && !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
			return err
		}
		account = conn.AccountID
		return nil
	})
	if err != nil || b.ID == uuid.Nil {
		return false, err
	}
	stats, runErr := s.execute(ctx, ws, b, account)
	state, msg := "done", ""
	if runErr != nil {
		state, msg = "failed", truncate(runErr.Error(), 2000)
	}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Exec(`UPDATE agent_trail_backfill SET state = ?, objects_read = ?, events_read = ?, partial = ?, last_error = ?,
		                       finished_at = ?, leased_until = NULL
		                 WHERE workspace_id = ? AND id = ?`, state, stats.Objects, stats.Events, stats.Partial, msg,
			s.now().UTC(), ws, b.ID).Error
	})
	return true, err
}

func (s *TrailBackfillService) execute(ctx context.Context, ws uuid.UUID, b TrailBackfill, account string) (TrailReadStats, error) {
	if account == "" {
		return TrailReadStats{}, errors.New("the connector is gone or has no AWS account")
	}
	if s.locate == nil {
		return TrailReadStats{}, errors.New("no AWS credentials on this server (VAULT_ADDR/VAULT_TOKEN not configured)")
	}
	api, loc, err := s.locate(ctx, ws, b.ConnectorID, account)
	if err != nil {
		return TrailReadStats{}, err
	}
	dctx := agentruntime.WithDelivery(ctx, agentruntime.Delivery{Kind: agentruntime.DeliveryTrailBackfill,
		Ref: HeartbeatRef(b.ConnectorID) + "/backfill"})
	return ReadTrailWindow(ctx, api, loc, nil, b.WindowFrom, b.WindowTo, TrailBackfillMaxObjects, func(events []agentruntime.Event) error {
		return s.dispatch(dctx, ws, b.ConnectorID, events)
	})
}

// AWSTrailLocator is the production locator: the connector's discovery-role
// session (ConfigForConnector), DescribeTrails for the trail logging the
// account (multi-region preferred), and an S3 client in the trail's home
// region. An organization trail's org id is read from the bucket's AWSLogs/
// listing.
func AWSTrailLocator(svc *AWSOnboardingService) TrailLocator {
	return func(ctx context.Context, ws, connectorID uuid.UUID, accountID string) (TrailBucketAPI, TrailLocation, error) {
		cfg, _, err := svc.ConfigForConnector(ctx, ws, connectorID, "")
		if err != nil {
			return nil, TrailLocation{}, err
		}
		resp, err := cloudtrail.NewFromConfig(cfg).DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(true)})
		if err != nil {
			return nil, TrailLocation{}, fmt.Errorf("describe trails: %w", err)
		}
		var pick *struct {
			bucket, prefix, region string
			org                    bool
		}
		for _, t := range resp.TrailList {
			if aws.ToString(t.S3BucketName) == "" {
				continue
			}
			c := &struct {
				bucket, prefix, region string
				org                    bool
			}{aws.ToString(t.S3BucketName), aws.ToString(t.S3KeyPrefix), aws.ToString(t.HomeRegion), aws.ToBool(t.IsOrganizationTrail)}
			if pick == nil || aws.ToBool(t.IsMultiRegionTrail) {
				pick = c
			}
			if aws.ToBool(t.IsMultiRegionTrail) {
				break
			}
		}
		if pick == nil {
			return nil, TrailLocation{}, errors.New("no trail delivering to S3 is visible to the connector")
		}
		if pick.region != "" {
			cfg.Region = pick.region
		}
		api := s3.NewFromConfig(cfg)
		loc := TrailLocation{Bucket: pick.bucket, Prefix: pick.prefix, AccountID: accountID}
		if pick.org {
			base := strings.Trim(pick.prefix, "/")
			if base != "" {
				base += "/"
			}
			out, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(pick.bucket), Prefix: aws.String(base + "AWSLogs/"), Delimiter: aws.String("/")})
			if err != nil {
				return nil, TrailLocation{}, fmt.Errorf("list organization prefix: %w", err)
			}
			for _, cp := range out.CommonPrefixes {
				p := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(cp.Prefix), base+"AWSLogs/"), "/")
				if strings.HasPrefix(p, "o-") {
					loc.OrgID = p
					break
				}
			}
		}
		return api, loc, nil
	}
}

// RunAgentTrailBackfillWorker runs due backfills every minute.
// AUTHSEC_DISABLE_TRAIL_BACKFILL_WORKER=true turns it off.
func RunAgentTrailBackfillWorker(ctx context.Context, db *gorm.DB, locate TrailLocator) {
	if os.Getenv("AUTHSEC_DISABLE_TRAIL_BACKFILL_WORKER") == "true" {
		log.Printf("[trail-backfill] worker not started: AUTHSEC_DISABLE_TRAIL_BACKFILL_WORKER=true")
		return
	}
	svc := NewTrailBackfillService(db, locate)
	for {
		// TENANT-EXEMPT: the 170 schema check reads the Postgres catalog only.
		if ok, reason := AgentEvidenceStatus(db); !ok {
			agentEvidenceGate.logWait("trail backfill worker", reason)
		} else if _, err := svc.RunDue(ctx, 5); err != nil && ctx.Err() == nil {
			log.Printf("[trail-backfill] %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}
