package agentcontain

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// Proof by refusal: a containment is verified only by a refused call naming
// its own policy after the cutoff, never by the absence of successful calls.

func proofFixture() (Contained, func(id string, tm time.Time, errCode, msg string) agentruntime.Event) {
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	s := roleSubject()
	c := Contained{ID: uuid.MustParse("0b9c6c2e-1111-4222-8333-444455556666"), Level: LevelIdentity,
		IdentityARN: s.ARN, UniqueID: s.UniqueID, ContainedAt: at}
	ev := func(id string, tm time.Time, errCode, msg string) agentruntime.Event {
		return agentruntime.Event{EventID: id, EventTime: tm, EventSource: "s3.amazonaws.com", EventName: "GetObject",
			EventType: "AwsApiCall", SessionIssuerARN: s.ARN, SessionIssuerPrincipalID: s.UniqueID,
			ErrorCode: errCode, ErrorMessage: msg, AuthorizationDenied: errCode == "AccessDenied" || errCode == "UnauthorizedOperation"}
	}
	return c, ev
}

func denyMsg(policy string) string {
	return "User: arn:aws:sts::111111111111:assumed-role/agent-role/s is not authorized to perform: s3:GetObject " +
		"with an explicit deny in an identity-based policy: arn:aws:iam::111111111111:policy/authsec/" + policy
}

func TestProofSuccessAfterCutoffIsNotEffective(t *testing.T) {
	c, ev := proofFixture()
	ok := ev("ok-1", c.CutOff().Add(time.Minute), "", "")
	if late := Late(c, []agentruntime.Event{ok}); len(late) != 1 || late[0].EventID != "ok-1" {
		t.Fatalf("a successful call after the cutoff is not-effective evidence: %+v", late)
	}
	if p := Proof(c, []agentruntime.Event{ok}); p != nil {
		t.Fatalf("a successful call proves nothing: %+v", p)
	}
}

func TestProofRefusalNamingPolicyVerifies(t *testing.T) {
	c, ev := proofFixture()
	name := ContainPolicyName(c.UniqueID, c.ID)
	early := ev("r-early", c.CutOff().Add(2*time.Minute), "AccessDenied", denyMsg(name))
	later := ev("r-later", c.CutOff().Add(9*time.Minute), "AccessDenied", denyMsg(name))
	p := Proof(c, []agentruntime.Event{later, early})
	if p == nil || p.EventID != "r-early" || p.Policy != name || p.ErrorCode != "AccessDenied" {
		t.Fatalf("the earliest refusal naming the deny policy proves it: %+v", p)
	}
	if late := Late(c, []agentruntime.Event{early}); len(late) != 0 {
		t.Fatalf("a refusal is not a late call: %+v", late)
	}
	// The identity level's session revocation proves it too.
	rev := ev("r-rev", c.CutOff().Add(time.Minute), "AccessDenied", denyMsg(RevokePolicyName(c.UniqueID, c.ID)))
	if p := Proof(c, []agentruntime.Event{rev}); p == nil || p.EventID != "r-rev" {
		t.Fatalf("a refusal naming the containment's revocation policy proves it: %+v", p)
	}
	// EC2's UnauthorizedOperation is an authorization denial as well.
	ec2 := ev("r-ec2", c.CutOff().Add(time.Minute), "UnauthorizedOperation", denyMsg(name)+" Encoded authorization failure message: x")
	if p := Proof(c, []agentruntime.Event{ec2}); p == nil {
		t.Fatal("UnauthorizedOperation naming the policy proves it")
	}
}

func TestProofRefusalNotNamingPolicyDoesNotVerify(t *testing.T) {
	c, ev := proofFixture()
	name := ContainPolicyName(c.UniqueID, c.ID)
	other := ContainPolicyName(c.UniqueID, uuid.MustParse("deadbeef-0000-4000-8000-000000000000"))
	cases := []agentruntime.Event{
		ev("no-policy", c.CutOff().Add(time.Minute), "AccessDenied",
			"User: arn:aws:sts::111111111111:assumed-role/agent-role/s is not authorized to perform: s3:GetObject because no identity-based policy allows the s3:GetObject action"),
		ev("generic", c.CutOff().Add(time.Minute), "AccessDenied", "with an explicit deny in an identity-based policy"),
		ev("other-containment", c.CutOff().Add(time.Minute), "AccessDenied", denyMsg(other)),
		ev("longer-name", c.CutOff().Add(time.Minute), "AccessDenied", denyMsg(name+"x")),
		ev("not-a-denial", c.CutOff().Add(time.Minute), "NoSuchKey", denyMsg(name)),
		ev("no-message", c.CutOff().Add(time.Minute), "AccessDenied", ""),
	}
	for _, e := range cases {
		if p := Proof(c, []agentruntime.Event{e}); p != nil {
			t.Errorf("%s must not prove the containment: %+v", e.EventID, p)
		}
	}
	// Another identity's refusal naming the policy (a recreated role) proves nothing.
	re := ev("recreated", c.CutOff().Add(time.Minute), "AccessDenied", denyMsg(name))
	re.SessionIssuerPrincipalID = "AROARECREATED0000001"
	if p := Proof(c, []agentruntime.Event{re}); p != nil {
		t.Fatalf("a recreated identity's refusal: %+v", p)
	}
	// Model level: a refused non-model call does not prove the model deny.
	m := c
	m.Level = LevelModel
	if p := Proof(m, []agentruntime.Event{ev("s3", c.CutOff().Add(time.Minute), "AccessDenied", denyMsg(name))}); p != nil {
		t.Fatalf("model level needs a refused model call: %+v", p)
	}
	conv := ev("conv", c.CutOff().Add(time.Minute), "AccessDeniedException", denyMsg(name))
	conv.EventSource, conv.EventName, conv.AuthorizationDenied = agentruntime.SourceBedrock, "Converse", true
	if p := Proof(m, []agentruntime.Event{conv}); p == nil || p.EventID != "conv" {
		t.Fatalf("model level: a refused model call naming the policy proves it: %+v", p)
	}
	// Workload level attaches no policy: nothing proves it.
	w := c
	w.Level, w.Dedicated = LevelWorkload, true
	if p := Proof(w, []agentruntime.Event{ev("w", c.CutOff().Add(time.Minute), "AccessDenied", denyMsg(name))}); p != nil {
		t.Fatalf("workload level: %+v", p)
	}
}

func TestProofRefusalBeforeCutoffIgnored(t *testing.T) {
	c, ev := proofFixture()
	name := ContainPolicyName(c.UniqueID, c.ID)
	for _, tm := range []time.Time{c.ContainedAt.Add(-time.Minute), c.ContainedAt.Add(time.Minute), c.CutOff()} {
		if p := Proof(c, []agentruntime.Event{ev("early", tm, "AccessDenied", denyMsg(name))}); p != nil {
			t.Fatalf("a refusal at %s (cutoff %s) is inside the skew allowance: %+v", tm, c.CutOff(), p)
		}
	}
}

func TestPendingSilenceNeverVerifies(t *testing.T) {
	c, _ := proofFixture()
	for _, tc := range []struct {
		at    time.Time
		want  string
		final bool
	}{
		{c.ContainedAt.Add(time.Minute), PendingWait, false},
		{c.CutOff().Add(time.Second), PendingWait, false},
		{c.ContainedAt.Add(VerifyGiveUp - time.Minute), PendingWait, false},
		{c.ContainedAt.Add(VerifyGiveUp), PendingUnverifiable, false},
		{c.ContainedAt.Add(VerifyGiveUp + time.Hour), PendingUnverifiable, false},
	} {
		got, final, _ := Pending(c, tc.at)
		if got != tc.want || final != tc.final {
			t.Errorf("at +%s: %s final=%v, want %s final=%v", tc.at.Sub(c.ContainedAt), got, final, tc.want, tc.final)
		}
	}
	// No refusal can prove a workload containment: unverifiable for good
	// once the grace has passed, with the reason.
	w := c
	w.Level, w.Dedicated = LevelWorkload, true
	if got, _, _ := Pending(w, c.ContainedAt.Add(time.Minute)); got != PendingWait {
		t.Fatalf("workload inside the grace: %s", got)
	}
	got, final, why := Pending(w, c.CutOff().Add(time.Second))
	if got != PendingUnverifiable || !final || why == "" {
		t.Fatalf("workload after the grace: %s final=%v %q", got, final, why)
	}
}
