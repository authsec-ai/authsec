package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func govCode(err error) string {
	var ge *GovError
	if errors.As(err, &ge) {
		return ge.Code
	}
	return ""
}

func TestReviewDueIs24Hours(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	if got := ReviewDue(now); !got.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("ReviewDue = %s", got)
	}
	// Every mechanism's own constant is the shared window.
	for name, d := range map[string]time.Duration{"pending_change": PendingChangeReviewDue, "coverage": coverageBreakGlassReviewWithin,
		"audit": auditBreakGlassDue, "history": historyBreakGlassReview} {
		if d != SecondPersonReviewWindow {
			t.Errorf("%s review window %s, want %s", name, d, SecondPersonReviewWindow)
		}
	}
}

func TestGovActorContextMarker(t *testing.T) {
	if IsGovAutomationActor(context.Background()) || IsGovAutomationActor(nil) { //nolint:staticcheck // nil is a case
		t.Fatal("an unmarked context is a person's")
	}
	ctx := WithGovActorAutomation(context.Background(), true)
	if !IsGovAutomationActor(ctx) {
		t.Fatal("marked automation context not seen")
	}
	if IsGovAutomationActor(WithGovActorAutomation(ctx, false)) {
		t.Fatal("a person's mark must override")
	}
}

// An automation identity is refused before any database read: requesting a
// tier-3 change, approving, rejecting someone else's request, breaking glass.
func TestAutomationNeverDecides(t *testing.T) {
	ctx := WithGovActorAutomation(context.Background(), true)
	a, b, ws := uuid.New(), uuid.New(), uuid.New()
	if code := govCode(CheckTier3Requester(ctx)); code != GovCodeAutomationTier {
		t.Errorf("tier-3 request: %q", code)
	}
	if code := govCode(CheckApprover(ctx, nil, ws, a, b)); code != GovCodeAutomationNotDecider {
		t.Errorf("approve: %q", code)
	}
	if code := govCode(CheckRejecter(ctx, nil, ws, a, b)); code != GovCodeAutomationNotDecider {
		t.Errorf("reject: %q", code)
	}
	if code := govCode(CheckRejecter(ctx, nil, ws, a, a)); code != GovCodeAutomationNotDecider {
		t.Errorf("withdraw by automation: %q", code)
	}
	if ok, err := BreakGlassAllowed(ctx, nil, ws, a); ok || err != nil {
		t.Errorf("break-glass: %v %v", ok, err)
	}
	if err := CheckStopCase(ctx, nil, ws, nil); govCode(err) != GovCodeStopCaseRequired {
		t.Errorf("stop without a case: %v", err)
	}
	if err := CheckStopCase(context.Background(), nil, ws, nil); err != nil {
		t.Errorf("a person's stop needs no case: %v", err)
	}
	if err := CheckTier3Requester(context.Background()); err != nil {
		t.Errorf("a person requests tier 3: %v", err)
	}
}

// The requester and the users a change is about never decide it; checked
// before the database.
func TestSelfAndSubjectNeverDecide(t *testing.T) {
	ctx, ws, a, b := context.Background(), uuid.New(), uuid.New(), uuid.New()
	if code := govCode(CheckApprover(ctx, nil, ws, a, a)); code != GovCodeSelfApproval {
		t.Errorf("self: %q", code)
	}
	if code := govCode(CheckApprover(ctx, nil, ws, a, uuid.Nil)); code != GovCodeSelfApproval {
		t.Errorf("no approver: %q", code)
	}
	if code := govCode(CheckApprover(ctx, nil, ws, a, b, ExcludingUsers(b))); code != GovCodeSelfApproval {
		t.Errorf("subject: %q", code)
	}
	if err := CheckRejecter(ctx, nil, ws, a, a); err != nil {
		t.Errorf("requester withdraws: %v", err)
	}
	o := secondPersonOptions([]SecondPersonOption{ExcludingUsers(uuid.Nil, b), ConcerningCases(uuid.Nil), ConcerningIdentities(a)})
	if len(o.exclude) != 1 || len(o.cases) != 0 || len(o.identities) != 1 {
		t.Errorf("options: %+v", o)
	}
	if subject, err := IsCaseSubject(nil, ws, a, nil, nil); subject || err != nil {
		t.Errorf("nothing concerned: %v %v", subject, err)
	}
}
