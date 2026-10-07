package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/services"
)

// T3.04 (SPEC-iga-phase3-policy.md §8.6) through the real scanner and
// cloud_observation: an assumed-role session is filed under the ROLE that
// issued it (sessionContext.sessionIssuer: ARN and RoleId), never under an
// identity whose name equals the session name; a recreated role does not
// inherit its predecessor's sessions; a role is never matched by name; and
// the stored facts carry the session, the authorization error and its
// classification while keeping every key the earlier readers use.
//
// Safeguard (mutation-checked): the incarnation check in trailAttribution.
func TestP3T304CloudTrailAttributionIsStored(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p3-t304-cloudtrail")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(populatedIAM()).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	record := func(v map[string]any) *string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return aws.String(string(raw))
	}
	session := func(roleARN, roleID, sessionName string) map[string]any {
		return map[string]any{
			"type": "AssumedRole", "principalId": roleID + ":" + sessionName,
			"arn": "arn:aws:sts::429418377036:assumed-role/x/" + sessionName, "accountId": "429418377036",
			"sessionContext": map[string]any{"sessionIssuer": map[string]any{
				"type": "Role", "principalId": roleID, "arn": roleARN, "accountId": "429418377036",
			}},
		}
	}
	at := aws.Time(time.Now().Add(-time.Hour))
	trail := &fakeCloudTrail{events: []cttypes.Event{
		// summarizer-agent's session, named like the IAM user: the old
		// Username match filed this under ci-deployer.
		{EventId: aws.String("p3-evt-boundary"), EventName: aws.String("ListQueues"),
			EventSource: aws.String("sqs.amazonaws.com"), Username: aws.String("ci-deployer"), EventTime: at,
			CloudTrailEvent: record(map[string]any{
				"userIdentity": session(agentRoleARN, "AROAEXAMPLEAGENT", "ci-deployer"),
				"errorCode":    "AccessDenied",
				"errorMessage": "User: arn:aws:sts::429418377036:assumed-role/summarizer-agent/ci-deployer is not authorized to perform: sqs:ListQueues on resource: arn:aws:sqs:us-east-1:429418377036: because no permissions boundary allows the sqs:ListQueues action",
			})},
		// ops-readonly's ARN, but another incarnation's RoleId: not this role.
		{EventId: aws.String("p3-evt-old-incarnation"), EventName: aws.String("GetObject"),
			EventSource: aws.String("s3.amazonaws.com"), Username: aws.String("nightly"), EventTime: at,
			CloudTrailEvent: record(map[string]any{"userIdentity": session(plainRoleARN, "AROAOLDINCARNATION", "nightly")})},
		// The IAM user's own call, by its ARN; a throttle is not a denial.
		{EventId: aws.String("p3-evt-user"), EventName: aws.String("UpdateFunctionCode"),
			EventSource: aws.String("lambda.amazonaws.com"), Username: aws.String("ci-deployer"), EventTime: at,
			CloudTrailEvent: record(map[string]any{
				"userIdentity": map[string]any{"type": "IAMUser", "principalId": "AIDAEXAMPLECI", "arn": ciUserARN, "userName": "ci-deployer"},
				"errorCode":    "ThrottlingException", "errorMessage": "Rate exceeded",
			})},
		// A record with no userIdentity naming a ROLE: the legacy hint is
		// for IAM users only.
		{EventId: aws.String("p3-evt-role-name"), EventName: aws.String("GetObject"),
			EventSource: aws.String("s3.amazonaws.com"), Username: aws.String("ops-readonly"), EventTime: at},
	}}
	l, e, c, p := populatedWorkloads()
	if _, err := services.NewAWSWorkloadScanner(db, svc).WithWorkloadAPIs(l, e, c, p).
		WithCloudTrailAPI(trail).WithEvidence(evidence).ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("workload scan: %v", err)
	}

	var rows []struct {
		NativeID        string
		SubjectNativeID string
		Facts           []byte
	}
	if err := db.Raw(`SELECT ci.native_id, o.subject_native_id, o.sanitized_facts AS facts
	                    FROM cloud_observation o JOIN cloud_identity ci ON ci.id = o.identity_id
	                   WHERE o.workspace_id = ? AND o.source_api = 'cloudtrail:LookupEvents'
	                   ORDER BY o.sanitized_facts->>'event_id'`, ws).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, r := range rows {
		var f map[string]any
		if err := json.Unmarshal(r.Facts, &f); err != nil {
			t.Fatal(err)
		}
		id, _ := f["event_id"].(string)
		if r.SubjectNativeID != igagraph.CloudTrailEventEvidenceKey(r.NativeID, id) {
			t.Errorf("%s: subject_native_id %q, want the event key under %s", id, r.SubjectNativeID, r.NativeID)
		}
		f["_subject"] = r.NativeID
		got[id] = f
	}
	if len(got) != 2 {
		t.Fatalf("attributed events = %v, want exactly p3-evt-boundary and p3-evt-user", keysOf(got))
	}

	b := got["p3-evt-boundary"]
	if b == nil || b["_subject"] != agentRoleARN {
		t.Fatalf("the session was filed under %v, want the issuing role %s (never the user named like the session)", b["_subject"], agentRoleARN)
	}
	for k, want := range map[string]any{
		"attribution": "session_issuer", "principal_type": "AssumedRole",
		"session_issuer_arn": agentRoleARN, "session_issuer_principal_id": "AROAEXAMPLEAGENT",
		"session_name": "ci-deployer", "error_code": "AccessDenied", "denied": true,
		"authorization_denied": true, "denial_policy_type": "permissions_boundary",
		"username": "ci-deployer", "event_name": "ListQueues", "event_source": "sqs.amazonaws.com",
	} {
		if b[k] != want {
			t.Errorf("boundary event %s = %v, want %v", k, b[k], want)
		}
	}
	if _, kept := b["error_message"]; kept {
		t.Error("the error message text was stored; only its classification may be")
	}

	u := got["p3-evt-user"]
	if u == nil || u["_subject"] != ciUserARN || u["attribution"] != "principal_arn" {
		t.Fatalf("user event = %v, want filed under %s by principal_arn", u, ciUserARN)
	}
	if u["denied"] != true || u["authorization_denied"] != false {
		t.Errorf("throttled call: denied=%v authorization_denied=%v, want true/false", u["denied"], u["authorization_denied"])
	}
	if _, has := u["denial_policy_type"]; has {
		t.Error("a throttle carries a denial_policy_type")
	}
	if _, has := u["session_name"]; has {
		t.Error("an IAM user's own call carries a session name")
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
