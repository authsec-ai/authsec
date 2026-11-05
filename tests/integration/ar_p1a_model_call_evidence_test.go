package integration

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

// P1a (SPEC-agent-runtime-visibility.md §5.1) through the real scanner and
// database: model calls land in cloud_usage (source cloudtrail, service
// bedrock) per identity, the stream-completion record is not a call, a
// predecessor incarnation's calls are not the role's, the two CloudTrail
// passes are deduplicated, a second scan does not count a window twice, the
// cursors record how far each stream was read -- and two workspaces holding
// the SAME role ARN see only their own evidence and cursors, under row-level
// security too.

// p1aTrail honours StartTime, EndTime and an EventSource LookupAttribute, as
// LookupEvents does, and returns events newest first in one page.
type p1aTrail struct{ events []cttypes.Event }

func (f *p1aTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	var out []cttypes.Event
	for _, e := range f.events {
		at := aws.ToTime(e.EventTime)
		if in.StartTime != nil && at.Before(*in.StartTime) || in.EndTime != nil && at.After(*in.EndTime) {
			continue
		}
		if len(in.LookupAttributes) == 1 && in.LookupAttributes[0].AttributeKey == cttypes.LookupAttributeKeyEventSource &&
			aws.ToString(in.LookupAttributes[0].AttributeValue) != aws.ToString(e.EventSource) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return aws.ToTime(out[i].EventTime).After(aws.ToTime(out[j].EventTime)) })
	return &cloudtrail.LookupEventsOutput{Events: out}, nil
}

func (f *p1aTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (f *p1aTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, nil
}

// p1aEvent is one record from a session of summarizer-agent (roleID is the
// session issuer's RoleId: AROAEXAMPLEAGENT is the inventory's).
func p1aEvent(t *testing.T, id, source, name, eventType, roleID string, at time.Time, extra map[string]any) cttypes.Event {
	t.Helper()
	rec := map[string]any{
		"eventID": id, "eventSource": source, "eventName": name, "eventType": eventType,
		"eventTime": at.UTC().Format(time.RFC3339), "awsRegion": "us-east-1",
		"userIdentity": map[string]any{
			"type": "AssumedRole", "principalId": roleID + ":summariser-fn",
			"arn": "arn:aws:sts::429418377036:assumed-role/summarizer-agent/summariser-fn", "accountId": "429418377036",
			"sessionContext": map[string]any{"sessionIssuer": map[string]any{
				"type": "Role", "principalId": roleID, "arn": agentRoleARN, "accountId": "429418377036"}},
		},
	}
	for k, v := range extra {
		rec[k] = v
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return cttypes.Event{EventId: aws.String(id), EventSource: aws.String(source), EventName: aws.String(name),
		Username: aws.String("summariser-fn"), EventTime: aws.Time(at), CloudTrailEvent: aws.String(string(raw))}
}

type p1aEnv struct {
	ws, conn uuid.UUID
	svc      *services.AWSOnboardingService
	snap     *services.IAMSnapshot
}

func newP1aEnv(t *testing.T, db *gorm.DB, name string) p1aEnv {
	t.Helper()
	ws := newWorkspace(t, db, name)
	t.Cleanup(func() { cleanWorkloadTables(t, db, ws) })
	svc, conn, _ := onboardWithRun(t, db, ws)
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).Scan(context.Background(), ws, conn)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}
	return p1aEnv{ws: ws, conn: conn, svc: svc, snap: snap}
}

func (e p1aEnv) scan(t *testing.T, db *gorm.DB, trail *p1aTrail, now time.Time) *services.WorkloadSnapshot {
	t.Helper()
	l, ec, c, p := populatedWorkloads()
	out, err := services.NewAWSWorkloadScanner(db, e.svc).WithWorkloadAPIs(l, ec, c, p).
		WithCloudTrailAPI(trail).WithTrailClock(func() time.Time { return now }).
		ScanFromSnapshot(context.Background(), e.ws, e.snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if len(out.Warnings) > 0 {
		t.Fatalf("scan warnings: %v", out.Warnings)
	}
	return out
}

func p1aUsage(t *testing.T, db *gorm.DB, ws uuid.UUID) (map[uuid.UUID]agentruntime.ModelCallUsage, uuid.UUID) {
	t.Helper()
	var rows []struct {
		IdentityID uuid.UUID
		Attrs      []byte
	}
	if err := db.Raw(`SELECT identity_id, attrs FROM cloud_usage
	                   WHERE workspace_id = ? AND source = 'cloudtrail' AND service = 'bedrock'`, ws).
		Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[uuid.UUID]agentruntime.ModelCallUsage{}
	for _, r := range rows {
		var u agentruntime.ModelCallUsage
		if err := json.Unmarshal(r.Attrs, &u); err != nil {
			t.Fatal(err)
		}
		out[r.IdentityID] = u
	}
	var role uuid.UUID
	if err := db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`, ws, agentRoleARN).
		Row().Scan(&role); err != nil {
		t.Fatal(err)
	}
	return out, role
}

func TestP1aModelCallEvidenceIsCumulativeAndWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	a := newP1aEnv(t, db, "p1a-model-calls-a")
	b := newP1aEnv(t, db, "p1a-model-calls-b")

	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-2 * time.Hour)
	model := map[string]any{"requestParameters": map[string]any{"modelId": "anthropic.claude-sonnet"}}
	trailA := &p1aTrail{events: []cttypes.Event{
		p1aEvent(t, "p1a-call", agentruntime.SourceBedrock, "Converse", "AwsApiCall", "AROAEXAMPLEAGENT", at, model),
		p1aEvent(t, "p1a-stream", agentruntime.SourceBedrock, "ConverseStream", "AwsApiCall", "AROAEXAMPLEAGENT", at.Add(time.Minute), model),
		p1aEvent(t, "p1a-stream-done", agentruntime.SourceBedrock, "ConverseStream", "AwsServiceEvent", "AROAEXAMPLEAGENT", at.Add(2*time.Minute),
			map[string]any{"serviceEventDetails": map[string]any{"inputTokens": 40, "outputTokens": 2}}),
		p1aEvent(t, "p1a-denied", agentruntime.SourceBedrock, "InvokeModel", "AwsApiCall", "AROAEXAMPLEAGENT", at,
			map[string]any{"errorCode": "AccessDeniedException"}),
		p1aEvent(t, "p1a-old-incarnation", agentruntime.SourceBedrock, "Converse", "AwsApiCall", "AROAOLDINCARNATION", at, model),
		p1aEvent(t, "p1a-s3", "s3.amazonaws.com", "GetObject", "AwsApiCall", "AROAEXAMPLEAGENT", at, nil),
	}}
	trailB := &p1aTrail{events: []cttypes.Event{
		p1aEvent(t, "p1b-call", agentruntime.SourceBedrock, "InvokeModel", "AwsApiCall", "AROAEXAMPLEAGENT", at, model),
	}}

	if out := a.scan(t, db, trailA, now); out.ModelCallUsageWritten != 1 {
		t.Fatalf("A wrote %d model-call rows, want 1", out.ModelCallUsageWritten)
	}
	b.scan(t, db, trailB, now)

	usageA, roleA := p1aUsage(t, db, a.ws)
	u, ok := usageA[roleA]
	if !ok || len(usageA) != 1 {
		t.Fatalf("A's model-call rows = %v, want one for summarizer-agent", usageA)
	}
	if u.Calls != 2 || u.Denied != 1 || u.Errors != 0 || u.Tokens != 42 {
		t.Fatalf("A usage calls %d denied %d errors %d tokens %d; want 2 (completion record and predecessor not counted), 1, 0, 42",
			u.Calls, u.Denied, u.Errors, u.Tokens)
	}
	if u.Models["anthropic.claude-sonnet"] != 2 || u.OtherServices["s3.amazonaws.com"] != 1 || u.Partial {
		t.Fatalf("A usage models %v other services %v partial %v", u.Models, u.OtherServices, u.Partial)
	}
	if u.CoveredTo == nil || !u.CoveredTo.Equal(now.Add(-awsdiscovery.TrailIngestDelay)) {
		t.Fatalf("A covered_to %v, want the delivery-delayed mark", u.CoveredTo)
	}

	// The cursors: one per stream, read to the mark, whole.
	var cursors []struct {
		Stream  string
		ReadTo  time.Time
		Partial bool
	}
	if err := db.Raw(`SELECT stream, read_to, partial FROM cloud_trail_cursor
	                   WHERE workspace_id = ? AND connector_id = ? AND region = 'us-east-1' ORDER BY stream`,
		a.ws, a.conn).Scan(&cursors).Error; err != nil {
		t.Fatal(err)
	}
	if len(cursors) != 2 || cursors[0].Stream != "bedrock" || cursors[1].Stream != "general" ||
		!cursors[0].ReadTo.Equal(now.Add(-awsdiscovery.TrailIngestDelay)) || cursors[0].Partial {
		t.Fatalf("A cursors = %+v", cursors)
	}

	// A second scan an hour later re-reads the same events: nothing is
	// counted twice, the marks move on.
	a.scan(t, db, trailA, now.Add(time.Hour))
	usageA, _ = p1aUsage(t, db, a.ws)
	if again := usageA[roleA]; again.Calls != 2 || again.Denied != 1 || again.Tokens != 42 || again.OtherServices["s3.amazonaws.com"] != 1 {
		t.Fatalf("second scan double-counted: %+v", again)
	}

	// Isolation: the same role ARN in B holds only B's call.
	usageB, roleB := p1aUsage(t, db, b.ws)
	if roleB == roleA || len(usageB) != 1 || usageB[roleB].Calls != 1 || usageB[roleB].Denied != 0 {
		t.Fatalf("B's evidence = %v (role %s, A's %s); want B's one call only", usageB, roleB, roleA)
	}

	// And under row-level security: B's transaction, even asking for A's
	// workspace, sees none of A's usage rows or cursors.
	err := tenancy.InWorkspaceRead(context.Background(), db, b.ws, func(tx *gorm.DB) error {
		var usage, cursorsA, cursorsB int64
		if err := tx.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ? AND source = 'cloudtrail'`, a.ws).
			Row().Scan(&usage); err != nil {
			return err
		}
		if err := tx.Raw(`SELECT count(*) FROM cloud_trail_cursor WHERE workspace_id = ?`, a.ws).Row().Scan(&cursorsA); err != nil {
			return err
		}
		if err := tx.Raw(`SELECT count(*) FROM cloud_trail_cursor`).Row().Scan(&cursorsB); err != nil {
			return err
		}
		if usage != 0 || cursorsA != 0 || cursorsB != 2 {
			t.Errorf("B's transaction sees A's usage %d, A's cursors %d, cursors %d (want 0, 0, 2)",
				usage, cursorsA, cursorsB)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("B's transaction: %v", err)
	}
}

// A page cap marks the cursor partial with how far the read got, and the
// model-call row partial: no "no calls" for the gap.
func TestP1aCapMarksCursorAndUsagePartial(t *testing.T) {
	db := igaDB(t)
	env := newP1aEnv(t, db, "p1a-model-calls-cap")
	now := time.Now().UTC().Truncate(time.Second)
	trail := &cappedP1aTrail{event: func(i int) cttypes.Event {
		return p1aEvent(t, "p1a-cap-"+strconv.Itoa(i), agentruntime.SourceBedrock, "Converse", "AwsApiCall",
			"AROAEXAMPLEAGENT", now.Add(-time.Hour-time.Duration(i)*time.Second), nil)
	}}
	l, ec, c, p := populatedWorkloads()
	out, err := services.NewAWSWorkloadScanner(db, env.svc).WithWorkloadAPIs(l, ec, c, p).
		WithCloudTrailAPI(trail).WithTrailClock(func() time.Time { return now }).
		ScanFromSnapshot(context.Background(), env.ws, env.snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if len(out.Warnings) == 0 {
		t.Fatal("a capped Bedrock pass must be reported as a warning")
	}
	var partial bool
	var coveredFrom, windowFrom time.Time
	if err := db.Raw(`SELECT partial, covered_from, window_from FROM cloud_trail_cursor
	                   WHERE workspace_id = ? AND stream = 'bedrock'`, env.ws).Row().Scan(&partial, &coveredFrom, &windowFrom); err != nil {
		t.Fatal(err)
	}
	if !partial || !coveredFrom.After(windowFrom) {
		t.Fatalf("bedrock cursor partial %v covered_from %s window_from %s", partial, coveredFrom, windowFrom)
	}
	usage, role := p1aUsage(t, db, env.ws)
	if u := usage[role]; !u.Partial || u.Calls == 0 {
		t.Fatalf("usage %+v; want the calls read, marked partial", u)
	}
}

// cappedP1aTrail always has another page of 50 events, each older than the
// last: a busy account whose window is larger than one read.
type cappedP1aTrail struct {
	event func(i int) cttypes.Event
	n     int
}

func (f *cappedP1aTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	out := &cloudtrail.LookupEventsOutput{NextToken: aws.String("more")}
	for i := 0; i < 50; i++ {
		out.Events = append(out.Events, f.event(f.n))
		f.n++
	}
	return out, nil
}

func (f *cappedP1aTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (f *cappedP1aTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{}, nil
}
