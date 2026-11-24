package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/services"
)

// Containment drift (a change undone outside AuthSec while contained) is
// re-applied through the engine step that applied it, with an event; never
// after release; and the loop breaker stops after 3 re-applications within
// an hour (one paused event) until the window allows again. Needs
// IGA_TEST_DSN (skipped otherwise).

func (l *acLab) containmentEvents(ws, id uuid.UUID, name string) int64 {
	l.t.Helper()
	var n int64
	if err := l.db.Table("iga_gov_event").Where("workspace_id = ? AND event = ? AND payload->>'containment_id' = ?", ws, name, id.String()).
		Count(&n).Error; err != nil {
		l.t.Fatal(err)
	}
	return n
}

func (l *acLab) setReserved(fn string, n int32) {
	l.fake.mu.Lock()
	l.fake.lambda[fn] = &n
	l.fake.mu.Unlock()
}

func (l *acLab) reserved(fn string) *int32 {
	l.fake.mu.Lock()
	defer l.fake.mu.Unlock()
	return l.fake.lambda[fn]
}

// containWorkload contains the tenant's Lambda function and runs it to
// contained.
func (l *acLab) containWorkload(tn *acTenant) uuid.UUID {
	l.t.Helper()
	c, err := l.svc.Contain(context.Background(), tn.g.ws, tn.g.author, services.AgentContainRequest{IdentityID: tn.identity.String(),
		WorkloadIDs: []string{tn.lambda.String()}, Level: agentcontain.LevelWorkload, Reason: "drift test"})
	if err != nil {
		l.t.Fatal(err)
	}
	if got := l.run(tn.g.ws, c.ID); got.State != agentcontain.StateContained {
		l.t.Fatalf("contain: %s (%s)", got.State, got.StateReason)
	}
	if v := l.reserved(tn.fnARN); v == nil || *v != 0 {
		l.t.Fatalf("reserved concurrency %v, want 0", v)
	}
	return c.ID
}

func TestAgentContainReappliesDrift(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-reapply")
	id := l.containWorkload(a)

	// Someone outside AuthSec gives the function its concurrency back.
	l.setReserved(a.fnARN, 5)
	l.clock = l.clock.Add(16 * time.Minute)
	got := l.run(a.g.ws, id)
	if got.State != agentcontain.StateContained {
		t.Fatalf("after drift: %s (%s)", got.State, got.StateReason)
	}
	if v := l.reserved(a.fnARN); v == nil || *v != 0 {
		t.Fatalf("drift not re-applied: reserved concurrency %v, want 0", v)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentDrifted); n != 1 {
		t.Fatalf("drifted events %d, want 1", n)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplied); n != 1 {
		t.Fatalf("reapplied events %d, want 1", n)
	}
	if strings.Contains(string(got.Verification), `"read": "reserved concurrency 5"`) {
		t.Fatalf("verification still reports the drift after the re-apply: %s", got.Verification)
	}

	// Release restores the recorded before-state (7), not the drifted 5.
	if _, err := l.svc.Release(context.Background(), a.g.ws, a.g.author, id, services.AgentContainReleaseRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	if got = l.run(a.g.ws, id); got.State != agentcontain.StateReleased {
		t.Fatalf("release: %s (%s)", got.State, got.StateReason)
	}
	if v := l.reserved(a.fnARN); v == nil || *v != 7 {
		t.Fatalf("after release reserved concurrency %v, want the before-state 7", v)
	}
}

func TestAgentContainReappliesDetachedAndDeletedPolicy(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-reapply-iam")
	ctx := context.Background()
	c, err := l.svc.Contain(ctx, a.g.ws, a.g.author, services.AgentContainRequest{IdentityID: a.identity.String(),
		Level: agentcontain.LevelIdentity, Reason: "compromised"})
	if err != nil {
		t.Fatal(err)
	}
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateContained {
		t.Fatalf("identity level: %s (%s)", got.State, got.StateReason)
	}
	name := "agent-" + a.g.ws.String()[:8]
	ours := func() (attached, total int) {
		l.fake.mu.Lock()
		defer l.fake.mu.Unlock()
		for _, p := range l.fake.policies {
			if p.tags[agentcontain.TagContainment] == c.ID.String() {
				total++
				if p.attached[name] {
					attached++
				}
			}
		}
		return
	}
	if at, tot := ours(); at != 2 || tot != 2 {
		t.Fatalf("before drift: %d of %d policies attached, want 2 of 2", at, tot)
	}
	// Outside AuthSec: one deny policy detached, the other deleted.
	l.fake.mu.Lock()
	i := 0
	for arn, p := range l.fake.policies {
		if p.tags[agentcontain.TagContainment] != c.ID.String() {
			continue
		}
		if i == 0 {
			delete(p.attached, name)
		} else {
			delete(l.fake.policies, arn)
		}
		i++
	}
	l.fake.mu.Unlock()
	if at, _ := ours(); at != 0 {
		t.Fatalf("the fake did not drift: %d attached", at)
	}

	l.clock = l.clock.Add(16 * time.Minute)
	if got := l.run(a.g.ws, c.ID); got.State != agentcontain.StateContained {
		t.Fatalf("after drift: %s (%s)", got.State, got.StateReason)
	}
	if at, tot := ours(); at != 2 || tot != 2 {
		t.Fatalf("after re-apply: %d of %d policies attached, want 2 of 2", at, tot)
	}
	if n := l.containmentEvents(a.g.ws, c.ID, services.GovEventContainmentReapplied); n != 1 {
		t.Fatalf("reapplied events %d, want 1 (one run re-applies both steps)", n)
	}
}

func TestAgentContainDriftAfterReleaseIsNotReapplied(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-reapply-rel")
	id := l.containWorkload(a)
	if _, err := l.svc.Release(context.Background(), a.g.ws, a.g.author, id, services.AgentContainReleaseRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	if got := l.run(a.g.ws, id); got.State != agentcontain.StateReleased {
		t.Fatalf("release: %s (%s)", got.State, got.StateReason)
	}
	// The owner changes the function after release: AuthSec leaves it.
	l.setReserved(a.fnARN, 3)
	l.clock = l.clock.Add(16 * time.Minute)
	l.run(a.g.ws, id)
	if v := l.reserved(a.fnARN); v == nil || *v != 3 {
		t.Fatalf("a released containment touched the function: reserved concurrency %v, want 3", v)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplied); n != 0 {
		t.Fatalf("reapplied events after release %d, want 0", n)
	}
}

func TestAgentContainReapplyLoopBreaker(t *testing.T) {
	l := newACLab(t)
	a := l.tenant("p3-contain-reapply-loop")
	id := l.containWorkload(a)
	start := l.clock

	// Three re-applications within the hour.
	for k := 1; k <= 3; k++ {
		l.clock = start.Add(time.Duration(k) * 10 * time.Minute)
		l.setReserved(a.fnARN, 5)
		l.run(a.g.ws, id)
		if v := l.reserved(a.fnARN); v == nil || *v != 0 {
			t.Fatalf("re-apply %d: reserved concurrency %v, want 0", k, v)
		}
		if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplied); n != int64(k) {
			t.Fatalf("re-apply %d: %d reapplied events", k, n)
		}
	}

	// The fourth drift within the hour is left alone and reported once.
	l.clock = start.Add(40 * time.Minute)
	l.setReserved(a.fnARN, 5)
	got := l.run(a.g.ws, id)
	if v := l.reserved(a.fnARN); v == nil || *v != 5 {
		t.Fatalf("4th drift within the hour was re-applied: reserved concurrency %v, want 5", v)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplied); n != 3 {
		t.Fatalf("reapplied events %d, want 3", n)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplyPaused); n != 1 {
		t.Fatalf("reapply_paused events %d, want 1", n)
	}
	if got.State != agentcontain.StateContained || !strings.Contains(got.StateReason, "paused") {
		t.Fatalf("paused containment: %s (%q)", got.State, got.StateReason)
	}
	// Still within the window: still paused, not reported again.
	l.clock = start.Add(55 * time.Minute)
	l.run(a.g.ws, id)
	if v := l.reserved(a.fnARN); v == nil || *v != 5 {
		t.Fatalf("re-applied while paused: reserved concurrency %v", v)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplyPaused); n != 1 {
		t.Fatalf("reapply_paused events %d, want still 1", n)
	}

	// Once the first re-application has left the window, AuthSec re-applies.
	l.clock = start.Add(10*time.Minute + time.Hour + time.Minute)
	got = l.run(a.g.ws, id)
	if v := l.reserved(a.fnARN); v == nil || *v != 0 {
		t.Fatalf("after the window: reserved concurrency %v, want 0", v)
	}
	if n := l.containmentEvents(a.g.ws, id, services.GovEventContainmentReapplied); n != 4 {
		t.Fatalf("reapplied events after the window %d, want 4", n)
	}
	if got.StateReason != "" {
		t.Fatalf("state_reason after the re-apply %q, want cleared", got.StateReason)
	}
}
