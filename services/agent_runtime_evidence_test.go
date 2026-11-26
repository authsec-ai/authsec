package services

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Pure tests of the model-call evidence (SPEC-agent-runtime-visibility.md
// §5.1): what counts, attribution and its incarnation check, the cumulative
// merge. No database.

const (
	mcRoleARN = "arn:aws:iam::111122223333:role/summariser"
	mcRoleID  = "AROAMODELCALLER"
)

var mcNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

// mcRecord is one CloudTrail record from the summariser role's session.
func mcRecord(id, source, name, eventType string, at time.Time, roleID string, extra map[string]any) awsdiscovery.TrailRecord {
	rec := map[string]any{
		"eventID": id, "eventSource": source, "eventName": name, "eventType": eventType,
		"eventTime": at.UTC().Format(time.RFC3339),
		"userIdentity": map[string]any{
			"type": "AssumedRole", "principalId": roleID + ":summariser-fn",
			"arn": "arn:aws:sts::111122223333:assumed-role/summariser/summariser-fn",
			"sessionContext": map[string]any{"sessionIssuer": map[string]any{
				"type": "Role", "principalId": roleID, "arn": mcRoleARN}},
		},
	}
	for k, v := range extra {
		rec[k] = v
	}
	raw, _ := json.Marshal(rec)
	return awsdiscovery.TrailRecordFrom(cttypes.Event{EventId: aws.String(id), EventSource: aws.String(source),
		EventName: aws.String(name), EventTime: aws.Time(at), CloudTrailEvent: aws.String(string(raw))})
}

// settled is a settled window (since, readTo].
func settled(stream string, since, readTo time.Time) awsdiscovery.TrailWindowRead {
	from := since
	if from.IsZero() {
		from = readTo.Add(-90 * 24 * time.Hour)
	}
	return awsdiscovery.TrailWindowRead{Stream: stream, Since: since, WindowFrom: from, CoveredFrom: from,
		ReadTo: readTo, LookupTo: readTo.Add(awsdiscovery.TrailIngestDelay), Settled: true}
}

// fakeAttributionIdentities answers FindForAttribution with one role.
type fakeAttributionIdentities struct {
	repositories.CloudIdentityRepository
	identities []models.CloudIdentity
}

func (f fakeAttributionIdentities) FindForAttribution(_, _ uuid.UUID, _, _ []string) ([]models.CloudIdentity, error) {
	return f.identities, nil
}

func mcIdentity(t *testing.T, uniqueID string) models.CloudIdentity {
	t.Helper()
	id := models.CloudIdentity{ID: uuid.New(), NativeID: mcRoleARN, Kind: models.CloudIdentityIAMRole, Name: "summariser"}
	if err := id.SetAWSAttrs(models.AWSIdentityAttrs{UniqueID: uniqueID}); err != nil {
		t.Fatal(err)
	}
	return id
}

// mcResolver is the scan's own attribution (trailAttribution) over one role.
func mcResolver(t *testing.T, identity models.CloudIdentity, records []awsdiscovery.TrailRecord) modelCallResolver {
	t.Helper()
	s := &AWSWorkloadScanner{identities: fakeAttributionIdentities{identities: []models.CloudIdentity{identity}}}
	events := make([]awsdiscovery.TrailEvent, 0, len(records))
	for _, r := range records {
		events = append(events, r.Trail)
	}
	resolve, err := s.trailAttribution(uuid.New(), uuid.New(), events)
	if err != nil {
		t.Fatal(err)
	}
	return modelCallResolverFrom(resolve)
}

// Only AwsApiCall model calls count; a streaming call's completion record is
// not a call but carries its tokens; refusals and errors are kept apart; other
// services count in the general window only.
func TestAggregateModelCallsCountsCallsNotCompletionRecords(t *testing.T) {
	at := mcNow.Add(-2 * time.Hour)
	model := map[string]any{"requestParameters": map[string]any{"modelId": "anthropic.claude-sonnet"}}
	records := []awsdiscovery.TrailRecord{
		mcRecord("call-1", agentruntime.SourceBedrock, "Converse", "AwsApiCall", at, mcRoleID, model),
		mcRecord("stream-1", agentruntime.SourceBedrock, "ConverseStream", "AwsApiCall", at.Add(time.Minute), mcRoleID, model),
		mcRecord("stream-1-done", agentruntime.SourceBedrock, "ConverseStream", "AwsServiceEvent", at.Add(2*time.Minute), mcRoleID,
			map[string]any{"serviceEventDetails": map[string]any{"inputTokens": 100, "outputTokens": 50}}),
		mcRecord("denied-1", agentruntime.SourceBedrock, "InvokeModel", "AwsApiCall", at, mcRoleID,
			map[string]any{"errorCode": "AccessDeniedException"}),
		mcRecord("throttled-1", agentruntime.SourceBedrock, "InvokeModel", "AwsApiCall", at, mcRoleID,
			map[string]any{"errorCode": "ThrottlingException"}),
		mcRecord("list-1", agentruntime.SourceBedrock, "ListFoundationModels", "AwsApiCall", at, mcRoleID, nil),
		mcRecord("s3-1", "s3.amazonaws.com", "GetObject", "AwsApiCall", at, mcRoleID, nil),
		mcRecord("s3-denied", "s3.amazonaws.com", "PutObject", "AwsApiCall", at, mcRoleID,
			map[string]any{"errorCode": "AccessDenied"}),
	}
	identity := mcIdentity(t, mcRoleID)
	general := settled(awsdiscovery.TrailStreamGeneral, mcNow.Add(-6*time.Hour), mcNow.Add(-15*time.Minute))
	bedrock := settled(awsdiscovery.TrailStreamBedrock, mcNow.Add(-6*time.Hour), mcNow.Add(-15*time.Minute))
	deltas := aggregateModelCalls(general, bedrock, records, mcResolver(t, identity, records))

	d := deltas[identity.ID]
	if d == nil || !d.ModelActivity {
		t.Fatalf("no model-call delta for the role: %+v", deltas)
	}
	u := d.Usage
	if u.Calls != 2 || u.Denied != 1 || u.Errors != 1 {
		t.Fatalf("calls %d denied %d errors %d; want 2 (the completion record is not a call), 1, 1", u.Calls, u.Denied, u.Errors)
	}
	if u.Tokens != 150 {
		t.Fatalf("tokens %d, want 150 from the completion record", u.Tokens)
	}
	if u.Models["anthropic.claude-sonnet"] != 2 || u.Endpoints[agentruntime.SourceBedrock] != 2 {
		t.Fatalf("models %v endpoints %v", u.Models, u.Endpoints)
	}
	if len(u.OtherServices) != 1 || u.OtherServices["s3.amazonaws.com"] != 1 {
		t.Fatalf("other services %v; want s3 once (a refused call and Bedrock's control plane are not)", u.OtherServices)
	}
	if len(u.SessionNames) != 1 || u.SessionNames[0] != "summariser-fn" {
		t.Fatalf("session names %v", u.SessionNames)
	}
	if u.FirstCallAt == nil || !u.FirstCallAt.Equal(at) || u.LastCallAt == nil || !u.LastCallAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("first %v last %v", u.FirstCallAt, u.LastCallAt)
	}
}

// A role recreated under the same ARN is another principal: its predecessor's
// calls (another RoleId) are attributed to nothing.
func TestAggregateModelCallsChecksTheIncarnation(t *testing.T) {
	at := mcNow.Add(-time.Hour)
	records := []awsdiscovery.TrailRecord{
		mcRecord("old-incarnation", agentruntime.SourceBedrock, "Converse", "AwsApiCall", at, "AROAOLDROLE", nil),
	}
	identity := mcIdentity(t, mcRoleID)
	w := settled(awsdiscovery.TrailStreamBedrock, time.Time{}, mcNow.Add(-15*time.Minute))
	if deltas := aggregateModelCalls(w, w, records, mcResolver(t, identity, records)); len(deltas) != 0 {
		t.Fatalf("a predecessor's call was attributed: %+v", deltas[identity.ID])
	}
}

// The windows decide what counts: a Bedrock event only inside the Bedrock
// pass's window (even when the general pass read it), anything else only
// inside the general pass's; an event both passes returned counts once.
func TestAggregateModelCallsWindowsAndDedupe(t *testing.T) {
	inside := mcNow.Add(-time.Hour)
	beforeBedrockMark := mcNow.Add(-5 * time.Hour)
	call := mcRecord("call", agentruntime.SourceBedrock, "Converse", "AwsApiCall", inside, mcRoleID, nil)
	early := mcRecord("early", agentruntime.SourceBedrock, "Converse", "AwsApiCall", beforeBedrockMark, mcRoleID, nil)
	s3 := mcRecord("s3", "s3.amazonaws.com", "GetObject", "AwsApiCall", beforeBedrockMark, mcRoleID, nil)

	general := settled(awsdiscovery.TrailStreamGeneral, mcNow.Add(-48*time.Hour), mcNow.Add(-15*time.Minute))
	bedrock := settled(awsdiscovery.TrailStreamBedrock, mcNow.Add(-4*time.Hour), mcNow.Add(-15*time.Minute))
	general.Records = []awsdiscovery.TrailRecord{call, early, s3}
	bedrock.Records = []awsdiscovery.TrailRecord{call}
	records := awsdiscovery.MergeTrailRecords(general.Records, bedrock.Records)

	identity := mcIdentity(t, mcRoleID)
	d := aggregateModelCalls(general, bedrock, records, mcResolver(t, identity, records))[identity.ID]
	if d == nil || d.Usage.Calls != 1 {
		t.Fatalf("delta %+v; want exactly one call (deduped; the earlier one is the Bedrock mark's)", d)
	}
	if d.Usage.OtherServices["s3.amazonaws.com"] != 1 {
		t.Fatalf("other services %v", d.Usage.OtherServices)
	}

	failed := bedrock
	failed.Settled = false
	if d := aggregateModelCalls(general, failed, records, mcResolver(t, identity, records))[identity.ID]; d != nil && d.ModelActivity {
		t.Fatal("a failed Bedrock pass must count no model call (its mark does not move)")
	}
}

// Other services alone never make a model-call row.
func TestAggregateModelCallsOtherServicesAloneIsNoModelActivity(t *testing.T) {
	records := []awsdiscovery.TrailRecord{
		mcRecord("s3", "s3.amazonaws.com", "GetObject", "AwsApiCall", mcNow.Add(-time.Hour), mcRoleID, nil),
	}
	w := settled(awsdiscovery.TrailStreamGeneral, time.Time{}, mcNow.Add(-15*time.Minute))
	identity := mcIdentity(t, mcRoleID)
	d := aggregateModelCalls(w, w, records, mcResolver(t, identity, records))[identity.ID]
	if d == nil || d.ModelActivity {
		t.Fatalf("delta %+v; want other services and no model activity", d)
	}
}

// The merge is cumulative; coverage is kept per region, partial is sticky,
// the top level is what holds in every region; a new incarnation starts
// afresh; session names are capped.
func TestMergeModelCallDoc(t *testing.T) {
	t1, t2 := mcNow.Add(-48*time.Hour), mcNow.Add(-time.Hour)
	d1 := &modelCallDelta{Identity: modelCallIdentity{UniqueID: mcRoleID}, ModelActivity: true,
		Usage: agentruntime.ModelCallUsage{Calls: 2, Denied: 1, Tokens: 10,
			Models: map[string]int{"m1": 2}, FirstCallAt: &t1, LastCallAt: &t1, SessionNames: []string{"a"}}}
	cov1 := trailCoverage{CoveredFrom: mcNow.Add(-90 * 24 * time.Hour), CoveredTo: mcNow.Add(-24 * time.Hour)}
	doc := mergeModelCallDoc(modelCallDoc{}, d1, "us-east-1", &cov1)

	d2 := &modelCallDelta{Identity: modelCallIdentity{UniqueID: mcRoleID}, ModelActivity: true,
		Usage: agentruntime.ModelCallUsage{Calls: 1, Models: map[string]int{"m1": 1, "m2": 1},
			OtherServices: map[string]int{"s3.amazonaws.com": 3}, FirstCallAt: &t2, LastCallAt: &t2, SessionNames: []string{"a", "b"}}}
	cov2 := trailCoverage{CoveredFrom: mcNow.Add(-24 * time.Hour), CoveredTo: mcNow.Add(-15 * time.Minute), Partial: true}
	doc = mergeModelCallDoc(doc, d2, "us-east-1", &cov2)

	u := doc.ModelCallUsage
	if u.Calls != 3 || u.Denied != 1 || u.Tokens != 10 || u.Models["m1"] != 3 || u.Models["m2"] != 1 ||
		u.OtherServices["s3.amazonaws.com"] != 3 || len(u.SessionNames) != 2 {
		t.Fatalf("merged usage %+v", u)
	}
	if !u.FirstCallAt.Equal(t1) || !u.LastCallAt.Equal(t2) {
		t.Fatalf("first %v last %v", u.FirstCallAt, u.LastCallAt)
	}
	if !u.CoveredFrom.Equal(cov1.CoveredFrom) || !u.CoveredTo.Equal(cov2.CoveredTo) || !u.Partial {
		t.Fatalf("coverage %v..%v partial %v", u.CoveredFrom, u.CoveredTo, u.Partial)
	}

	// A second region read only since yesterday: the top level is what both
	// regions were read over.
	cov3 := trailCoverage{CoveredFrom: mcNow.Add(-24 * time.Hour), CoveredTo: mcNow.Add(-time.Hour)}
	doc = mergeModelCallDoc(doc, nil, "eu-west-1", &cov3)
	if !doc.CoveredFrom.Equal(cov3.CoveredFrom) || !doc.CoveredTo.Equal(cov3.CoveredTo) || doc.Calls != 3 {
		t.Fatalf("two regions: %v..%v calls %d", doc.CoveredFrom, doc.CoveredTo, doc.Calls)
	}
	if doc.Regions["us-east-1"].Partial != true {
		t.Fatal("a region's partial must be sticky")
	}

	// Round trip through the stored JSON keeps everything, and a reader of the
	// shared contract reads the same counts.
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var shared agentruntime.ModelCallUsage
	if err := json.Unmarshal(raw, &shared); err != nil || shared.Calls != 3 || shared.Denied != 1 {
		t.Fatalf("shared contract read %+v (%v)", shared, err)
	}
	var back modelCallDoc
	if err := json.Unmarshal(raw, &back); err != nil || back.IdentityUniqueID != mcRoleID || len(back.Regions) != 2 {
		t.Fatalf("round trip %+v (%v)", back, err)
	}

	// Another incarnation starts afresh.
	d3 := &modelCallDelta{Identity: modelCallIdentity{UniqueID: "AROANEWROLE"}, ModelActivity: true,
		Usage: agentruntime.ModelCallUsage{Calls: 1}}
	fresh := mergeModelCallDoc(back, d3, "us-east-1", &cov3)
	if fresh.Calls != 1 || fresh.IdentityUniqueID != "AROANEWROLE" || len(fresh.Regions) != 1 || fresh.Partial {
		t.Fatalf("a new incarnation inherited its predecessor's evidence: %+v", fresh)
	}

	// Session names are capped.
	var names []string
	for i := 0; i < 30; i++ {
		names = append(names, fmt.Sprintf("s%d", i))
	}
	capped := mergeModelCallDoc(modelCallDoc{}, &modelCallDelta{Usage: agentruntime.ModelCallUsage{SessionNames: names}}, "", nil)
	if len(capped.SessionNames) != maxModelCallSessionNames {
		t.Fatalf("%d session names kept, want %d", len(capped.SessionNames), maxModelCallSessionNames)
	}
}

// The legacy cloudtrail-events surface: a cap hit further back than 48 hours
// leaves the 48 hours whole (reached); a cap inside them is partial.
func TestLegacyTrailCoverage(t *testing.T) {
	read := awsdiscovery.TrailWindowRead{LookupTo: mcNow, Settled: true, CapHit: true,
		Oldest: mcNow.Add(-72 * time.Hour)}
	if cov := legacyTrailCoverage(read, fmt.Errorf("%w: cap", awsdiscovery.ErrTooManyPages)); cov.State != models.CloudCoverageReached {
		t.Fatalf("cap beyond 48 h: %+v, want reached", cov)
	}
	read.Oldest = mcNow.Add(-time.Hour)
	if cov := legacyTrailCoverage(read, fmt.Errorf("%w: cap", awsdiscovery.ErrTooManyPages)); cov.State != models.CloudCoveragePartial {
		t.Fatalf("cap inside 48 h: %+v, want partial", cov)
	}
}
