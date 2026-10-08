package awsenforce_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// Review P1-7: the enforcement session's CloudTrail lookup reads what the
// account received -- applied or refused -- for one session and one
// operation, with each request's target, through LookupEvents' raw records;
// another session's call and another operation are not returned, a request
// matches only its own target, and an unreadable trail is an error.
func TestP3FixSessionTrailLookup(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	b := f.AddPolicy("/authsec/", "AuthSecBoundary-trail", map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue}, sqsOnly)
	f.AddRole("TrailRole", "/", nil)
	dep, other := uuid.New(), uuid.New()
	session := awsenforce.DeploymentSessionName(dep)
	assume := func(id uuid.UUID) awsenforce.IAM {
		iam, _, err := f.AssumeEnforcement(ctx, awsenforce.AssumeInput{RoleARN: f.RoleARN, ExternalID: extID, Region: "us-east-1",
			SessionName: awsenforce.DeploymentSessionName(id)})
		if err != nil {
			t.Fatal(err)
		}
		return iam
	}
	put := igagov.Op{Op: igagov.OpPutRolePermissionsBoundary, RoleName: "TrailRole", PolicyARN: b.ARN}
	req, err := awsenforce.NewRequest(put, dep, "")
	if err != nil {
		t.Fatal(err)
	}
	if r := awsenforce.Send(ctx, assume(dep), req, ""); r.Kind != igagov.RespOK {
		t.Fatalf("put: %+v", r)
	}
	if r := awsenforce.Send(ctx, assume(other), req, ""); r.Kind != igagov.RespOK {
		t.Fatalf("other session's put: %+v", r)
	}
	q := awsenforce.TrailQuery{SessionName: session, EventName: igagov.OpPutRolePermissionsBoundary,
		From: time.Now().Add(-time.Minute), To: time.Now().Add(time.Minute)}
	evs, err := awsenforce.LookupSessionEvents(ctx, f, q)
	if err != nil || len(evs) != 1 {
		t.Fatalf("session events: %+v %v", evs, err)
	}
	if ev := evs[0]; !ev.Applied() || ev.SessionName != session || ev.RoleName != "TrailRole" || ev.BoundaryARN != b.ARN || !req.MatchesTrail(ev) {
		t.Fatalf("event: %+v", ev)
	}
	otherTarget, _ := awsenforce.NewRequest(igagov.Op{Op: igagov.OpPutRolePermissionsBoundary, RoleName: "AnotherRole", PolicyARN: b.ARN}, dep, "")
	if otherTarget.MatchesTrail(evs[0]) {
		t.Fatal("a request on another role matched the event")
	}
	// A refused request (no such policy) is recorded with its error code.
	cpv, _ := awsenforce.NewRequest(igagov.Op{Op: igagov.OpCreatePolicyVersion, PolicyARN: "arn:aws:iam::" + f.Account + ":policy/authsec/Missing",
		DocumentHash: "sha256:x", SetAsDefault: true}, dep, "")
	_ = awsenforce.Send(ctx, assume(dep), cpv, sqsOnly)
	evs, err = awsenforce.LookupSessionEvents(ctx, f, awsenforce.TrailQuery{SessionName: session, EventName: igagov.OpCreatePolicyVersion,
		From: q.From, To: q.To})
	if err != nil || len(evs) != 1 || evs[0].Applied() || evs[0].ErrorCode == "" {
		t.Fatalf("refused: %+v %v", evs, err)
	}
	// Outside the window: nothing.
	if evs, err := awsenforce.LookupSessionEvents(ctx, f, awsenforce.TrailQuery{SessionName: session, EventName: igagov.OpPutRolePermissionsBoundary,
		From: time.Now().Add(time.Hour), To: time.Now().Add(2 * time.Hour)}); err != nil || len(evs) != 0 {
		t.Fatalf("outside the window: %+v %v", evs, err)
	}
	// Unreadable: an error, never "no events".
	f.TrailErr = errors.New("AccessDeniedException")
	if _, err := awsenforce.LookupSessionEvents(ctx, f, q); err == nil {
		t.Fatal("an unreadable trail answered no events")
	}
	f.TrailErr = nil
}
