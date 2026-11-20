package services

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func sharedRoleDraft(ids ...uuid.UUID) findingDraft {
	var wls []map[string]any
	for _, id := range ids {
		wls = append(wls, map[string]any{"cloud_workload_id": id, "native_id": id.String()})
	}
	return findingDraft{Kind: FindingSharedRole, SubjectKey: "identity:role-1",
		Subject:  map[string]any{"arn": "arn:aws:iam::1:role/Shared", "workloads": wls},
		Evidence: map[string]any{"model_calls": map[string]any{"models": map[string]int{"claude": 3}}}}
}

func dnsFinding(t *testing.T, subject map[string]any) unresolvedDNSFinding {
	t.Helper()
	b, err := json.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	return unresolvedDNSFinding{ID: uuid.New(), SubjectKey: "lambda_eni:us-east-1:eni-1", Subject: b}
}

func TestAgentReviewRequestsFromSharedRole(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	reqs := agentReviewRequests([]findingDraft{
		sharedRoleDraft(a, b, a), // duplicates collapse
		{Kind: FindingLongLivedKey, Subject: map[string]any{}},
	}, nil)
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1 (only the shared role)", len(reqs))
	}
	r := reqs[0]
	if r.Reason != AgentReviewReasonSharedRole || len(r.Workloads) != 2 {
		t.Fatalf("request = %+v, want shared_role with both workloads", r)
	}
	if r.Context["role_arn"] != "arn:aws:iam::1:role/Shared" || r.Context["candidates"] != 2 {
		t.Errorf("context = %v, want the role and the candidate count", r.Context)
	}
}

func TestAgentReviewRequestsSkipRolesWithoutTwoWorkloads(t *testing.T) {
	// A role shared with EKS service accounts only lists one workload: there is
	// nothing in cloud_workload to tell apart.
	if reqs := agentReviewRequests([]findingDraft{sharedRoleDraft(uuid.New())}, nil); len(reqs) != 0 {
		t.Fatalf("got %v, want none", reqs)
	}
}

func TestAgentReviewRequestsFromUnresolvedDNS(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	resolved, unresolved := true, false
	reqs := agentReviewRequests(nil, []unresolvedDNSFinding{
		dnsFinding(t, map[string]any{"kind": "workload_set", "resolved": unresolved, "region": "us-east-1",
			"eni_id": "eni-1", "candidates": []map[string]any{{"cloud_workload_id": a}, {"cloud_workload_id": b}}}),
		dnsFinding(t, map[string]any{"kind": "workload_set", "resolved": resolved,
			"candidates": []map[string]any{{"cloud_workload_id": a}}}),
		dnsFinding(t, map[string]any{"kind": "workload", "cloud_workload_id": a}),
	})
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1 (only the unresolved set)", len(reqs))
	}
	if reqs[0].Reason != AgentReviewReasonUnattributedDNS || len(reqs[0].Workloads) != 2 ||
		reqs[0].Context["eni_id"] != "eni-1" {
		t.Fatalf("request = %+v, want unattributed_dns for both candidates", reqs[0])
	}
}

func TestAgentReviewQueueNeedsTheServiceToken(t *testing.T) {
	t.Setenv(AgentReviewServiceTokenEnv, "")
	if agentReviewQueueEnabled() {
		t.Fatal("queueing must stay off without a review service")
	}
	n, err := queueAgentReviews(nil, uuid.New(), uuid.New(), []findingDraft{sharedRoleDraft(uuid.New(), uuid.New())}, reviewTestNow())
	if err != nil || n != 0 {
		t.Fatalf("queueAgentReviews = %d, %v; want 0, nil without touching the database", n, err)
	}
	t.Setenv(AgentReviewServiceTokenEnv, "svc")
	if !agentReviewQueueEnabled() {
		t.Fatal("queueing must run once the token is set")
	}
}
