// The enforcement plan — phase 4 of ENFORCEMENT-ARCHITECTURE.md §7.
//
// The plan is the WHOLE interface between governance and a customer's cluster: the
// agent makes no decision, evaluates no policy, and enforces exactly the
// fingerprints it is handed. These tests pin the properties that make that safe.
//
// In order of how badly getting them wrong would hurt:
//
//  1. PER-CONNECTOR. One cluster's plan can never contain another's fingerprints,
//     which is what bounds a leaked actuation token to the cluster it was minted for.
//  2. VERSION CHANGES ON CONTENT, NOT TRAFFIC. The agent re-indexes on a version
//     change and the console reads a version gap as drift; a version that ticked
//     because somebody polled would make both meaningless.
//  3. AN EMPTY PLAN IS A REAL ANSWER, and is distinguishable from no plan.
//  4. A RELEASE PROPAGATES. A plan that only ever grows would leave an agent
//     contained after a human released it, with nothing to show why.
//
// This build is mode=observe (EN-10): the agent counts what it WOULD have denied
// and allows everything, so nothing here asserts a cluster effect.
package ownership

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

type planFixture struct {
	actFixture
	pm services.EnforcementPlanManager
}

func newPlanFixture(t *testing.T) planFixture {
	t.Helper()
	f := newActFixture(t)
	return planFixture{actFixture: f, pm: services.NewEnforcementPlanManager(gormFor(t, f.raw))}
}

// doc publishes and decodes the served document.
func (f planFixture) doc(t *testing.T) (*models.EnforcementPlanDoc, bool) {
	t.Helper()
	row, minted, err := f.pm.Publish(f.ws, f.source)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	var d models.EnforcementPlanDoc
	if err := json.Unmarshal(row.Plan, &d); err != nil {
		t.Fatalf("decode served plan: %v", err)
	}
	return &d, minted
}

/* ------------------------------- the document ---------------------------- */

// An empty plan is an answer, not an absence. If the agent could not tell "nothing
// is contained" from "I never got a plan", EN-7 would have nothing to hold on to
// during a control-plane outage.
func TestEmptyPlanIsPublishedAndCarriesAnEmptyList(t *testing.T) {
	f := newPlanFixture(t)

	d, minted := f.doc(t)
	if !minted {
		t.Error("the first publish must mint a version")
	}
	if d.Version != 1 {
		t.Errorf("first plan must be version 1, got %d", d.Version)
	}
	if d.Cluster != "prod-1" {
		t.Errorf("plan must name the cluster it is for, got %q", d.Cluster)
	}
	if d.Deny == nil {
		t.Fatal("deny must serialise as [], never null: an agent decoding null has to " +
			"special-case it to avoid reading an empty plan as no plan at all")
	}
	if len(d.Deny) != 0 {
		t.Errorf("nothing is quarantined; got %d entries", len(d.Deny))
	}
	// The wire form, not just the decoded value — this is a contract with every
	// deployed agent. Compacted first because the document is stored as jsonb,
	// which normalises whitespace and key order on the way back out.
	row, _, _ := f.pm.Publish(f.ws, f.source)
	var compact bytes.Buffer
	if err := json.Compact(&compact, row.Plan); err != nil {
		t.Fatalf("served plan is not valid JSON: %v", err)
	}
	if !strings.Contains(compact.String(), `"deny":[]`) {
		t.Errorf("served bytes must carry an empty array, got %s", compact.String())
	}
}

func TestQuarantinePutsTheAgentOnThePlanWithItsReason(t *testing.T) {
	f := newPlanFixture(t)
	f.doc(t) // v1, empty

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "suspicious egress", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	d, minted := f.doc(t)
	if !minted {
		t.Fatal("a new containment must mint a new version")
	}
	if d.Version != 2 {
		t.Errorf("want version 2, got %d", d.Version)
	}
	if len(d.Deny) != 1 {
		t.Fatalf("want 1 denied agent, got %d", len(d.Deny))
	}
	e := d.Deny[0]
	if e.Fingerprint != "fp-prov-1" {
		t.Errorf("the agent must be identified by fingerprint, got %q", e.Fingerprint)
	}
	if e.DecisionID != f.agent.String() {
		t.Errorf("decision_id must be the agent row an operator can look up, got %q", e.DecisionID)
	}
	if !strings.Contains(e.Reason, "suspicious egress") {
		t.Errorf("the operator's own words must survive to the cluster, got %q", e.Reason)
	}
	// Coordinates are for a human reading the plan; the agent matches on the
	// fingerprint. They still have to be right.
	if e.Namespace != "default" || e.WorkloadKind != "Deployment" ||
		e.WorkloadName != "research-agent" {
		t.Errorf("workload coordinates wrong: %+v", e)
	}
	if e.Since.IsZero() {
		t.Error("since must say when the decision was taken")
	}
}

// Version is a change signal. A 30-second poll must not consume version numbers, or
// "decided at v43, enforcing v42" stops meaning anything.
func TestRepeatedPollsDoNotBumpTheVersion(t *testing.T) {
	f := newPlanFixture(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	first, _ := f.doc(t)

	for i := 0; i < 5; i++ {
		d, minted := f.doc(t)
		if minted {
			t.Fatalf("poll %d minted a version with no change", i)
		}
		if d.Version != first.Version {
			t.Fatalf("poll %d moved the version %d -> %d with no change",
				i, first.Version, d.Version)
		}
		if !d.GeneratedAt.Equal(first.GeneratedAt) {
			t.Fatalf("poll %d re-stamped generated_at with no change; every poll would "+
				"look like a change", i)
		}
	}

	var rows int
	if err := f.raw.QueryRow(`SELECT count(*) FROM enforcement_plans
	                           WHERE discovery_source_id = $1`, f.source).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("six polls of an unchanged plan wrote %d rows; want 1", rows)
	}
}

// A plan that only grows would leave an agent contained after a human released it.
func TestReleasePropagatesToThePlan(t *testing.T) {
	f := newPlanFixture(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	contained, _ := f.doc(t)
	if len(contained.Deny) != 1 {
		t.Fatalf("setup: want the agent contained, got %d entries", len(contained.Deny))
	}

	if _, err := f.dm.ReleaseQuarantine(f.ws, f.agent, nil); err != nil {
		t.Fatalf("release: %v", err)
	}

	released, minted := f.doc(t)
	if !minted {
		t.Error("a release must mint a version: the cluster has to be told")
	}
	if len(released.Deny) != 0 {
		t.Errorf("a released agent must leave the plan, got %d entries", len(released.Deny))
	}
	if released.Version <= contained.Version {
		t.Errorf("version must advance on release: %d -> %d",
			contained.Version, released.Version)
	}
}

// The property that bounds a leaked actuation token.
func TestPlanNeverLeaksAnotherClustersFingerprints(t *testing.T) {
	f := newPlanFixture(t)

	other, _, err := f.dm.RegisterAgent(f.ws, services.AgentRegistrationInput{
		Kind:        models.DiscoverySourceK8sWebhook,
		InstanceID:  "k8s:staging-1",
		ClusterName: "staging-1",
	})
	if err != nil {
		t.Fatalf("register second connector: %v", err)
	}

	// A quarantined agent in the OTHER cluster.
	stranger := uuid.New()
	exec(t, f.raw, `INSERT INTO discovered_agents
	    (id, workspace_id, source, discovery_source_id, fingerprint, display_name,
	     status, quarantine_reason, quarantined_at, matched_client_id, owner_user_id,
	     runtime_status, metadata)
	  VALUES ($1,$2,'k8s_webhook',$3,'fp-staging-1','stranger','quarantined','elsewhere',
	          now(),$4,$5,'running','{"kubernetes":{"namespace":"other"}}')`,
		stranger, f.ws, other.ID, f.client, claimOwner)

	// And one in ours, so the plan is not trivially empty.
	if _, qerr := f.dm.QuarantineAgent(f.ws, f.agent, "ours", nil); qerr != nil {
		t.Fatalf("quarantine: %v", qerr)
	}

	d, _ := f.doc(t)
	for _, e := range d.Deny {
		if e.Fingerprint == "fp-staging-1" {
			t.Fatal("prod-1's plan contains staging-1's fingerprint; an actuation token " +
				"would read decisions about a cluster it was never minted for")
		}
	}
	if len(d.Deny) != 1 || d.Deny[0].Fingerprint != "fp-prov-1" {
		t.Errorf("want exactly our own agent, got %+v", d.Deny)
	}
}

// The hash is over contents, sorted. Two plans with the same decisions in a
// different row order must be the same plan, or a query-plan change would look like
// a governance change and make the whole fleet re-index.
func TestPlanHashIgnoresOrderAndTimestamps(t *testing.T) {
	a := models.EnforcementPlanDoc{Version: 1, Deny: []models.EnforcementPlanEntry{
		{Fingerprint: "bbb", DecisionID: "2"}, {Fingerprint: "aaa", DecisionID: "1"},
	}}
	b := models.EnforcementPlanDoc{Version: 99, Deny: []models.EnforcementPlanEntry{
		{Fingerprint: "aaa", DecisionID: "1"}, {Fingerprint: "bbb", DecisionID: "2"},
	}}
	if a.Hash() != b.Hash() {
		t.Error("row order or version changed the content hash; every reorder would " +
			"publish a new version the whole fleet re-fetches")
	}

	c := models.EnforcementPlanDoc{Deny: []models.EnforcementPlanEntry{
		{Fingerprint: "aaa", DecisionID: "1"}, {Fingerprint: "bbb", DecisionID: "3"},
	}}
	if b.Hash() == c.Hash() {
		t.Error("a changed decision id did not change the hash")
	}

	// Field-separated, so two entries cannot be confused by concatenation.
	d1 := models.EnforcementPlanDoc{Deny: []models.EnforcementPlanEntry{{Fingerprint: "ab", Namespace: "c"}}}
	d2 := models.EnforcementPlanDoc{Deny: []models.EnforcementPlanEntry{{Fingerprint: "a", Namespace: "bc"}}}
	if d1.Hash() == d2.Hash() {
		t.Error(`("ab","c") and ("a","bc") hash the same; the fields are not separated`)
	}

	// The document FORMAT is part of the hash. Without this, adding a field to the
	// plan would change no deny list, mint no version, and every existing cluster
	// would keep being served the old shape until something unrelated happened to
	// be quarantined.
	if models.PlanDocFormat == "" {
		t.Error("the plan document format must be a non-empty version marker")
	}
	empty := models.EnforcementPlanDoc{Deny: []models.EnforcementPlanEntry{}}
	if empty.Hash() == sha256Hex("") {
		t.Error("an empty plan must not hash to the digest of nothing; the format " +
			"marker is not being mixed in")
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// A policy asking for quarantine explains an entry. The AUTHORITY is still the
// agent's status — a dry-run reconcile must never contain anything.
func TestPolicyAttributionIsAnExplanationNotTheAuthority(t *testing.T) {
	f := newPlanFixture(t)
	pol, err := policyMgr(t, f.provFixture).Create(f.ws, "u", services.AgentPolicyInput{
		Name: "contain", DiscoveredAgentID: &f.agent,
		DesiredState: models.AgentPolicyStateQuarantined,
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	// The policy exists and asks for quarantine, but nothing has moved the status.
	d, _ := f.doc(t)
	if len(d.Deny) != 0 {
		t.Fatal("a policy alone must not contain an agent: the plan follows the DECISION " +
			"of record, so a dry-run reconcile can never reach a cluster")
	}

	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "policy asked", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	d, _ = f.doc(t)
	if len(d.Deny) != 1 {
		t.Fatalf("want 1 entry, got %d", len(d.Deny))
	}
	if d.Deny[0].PolicyID != pol.ID.String() {
		t.Errorf("the entry must name the policy that asked for it, got %q", d.Deny[0].PolicyID)
	}
}

/* ------------------------------ agent report ----------------------------- */

func TestReportFoldsIntoTheConnectorRow(t *testing.T) {
	f := newPlanFixture(t)
	v := int64(7)
	n := int64(3)
	if err := f.pm.RecordReport(f.source, models.EnforcementReport{
		Mode: models.EnforcementModeObserve, Version: &v, DenialsTotal: &n,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	var mode string
	var gotV, gotN int64
	if err := f.raw.QueryRow(`SELECT enforcement_mode, enforced_plan_version,
	                                 enforcement_denials_total
	                            FROM discovery_sources WHERE id = $1`, f.source).
		Scan(&mode, &gotV, &gotN); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if mode != "observe" || gotV != 7 || gotN != 3 {
		t.Errorf("report not stored: mode=%q version=%d denials=%d", mode, gotV, gotN)
	}

	// The counter resets when the agent process restarts. Clamping a decrease
	// upward would turn a restart into a permanently inflated total nobody can
	// explain.
	lower := int64(1)
	if err := f.pm.RecordReport(f.source, models.EnforcementReport{
		Mode: models.EnforcementModeObserve, DenialsTotal: &lower,
	}); err != nil {
		t.Fatalf("record after restart: %v", err)
	}
	if err := f.raw.QueryRow(`SELECT enforcement_denials_total FROM discovery_sources
	                           WHERE id = $1`, f.source).Scan(&gotN); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if gotN != 1 {
		t.Errorf("a restarted agent's lower count must be stored as reported, got %d", gotN)
	}
}

// An agent on an older build fetches the plan without reporting. Refusing it would
// take enforcement away from exactly the clusters that most need upgrading.
func TestSilentAgentIsNotAnError(t *testing.T) {
	f := newPlanFixture(t)
	if err := f.pm.RecordReport(f.source, models.EnforcementReport{}); err != nil {
		t.Fatalf("an agent that reports nothing must still be served: %v", err)
	}
	var mode string
	if err := f.raw.QueryRow(`SELECT enforcement_mode FROM discovery_sources WHERE id = $1`,
		f.source).Scan(&mode); err != nil {
		t.Fatalf("read: %v", err)
	}
	if mode != "" {
		t.Errorf(`a silent agent must leave the mode unreported (""), got %q`, mode)
	}
}

func TestUnknownModeIsRefused(t *testing.T) {
	f := newPlanFixture(t)
	if err := f.pm.RecordReport(f.source, models.EnforcementReport{Mode: "enforce-everything"}); err == nil {
		t.Error("an unknown mode must be refused: it would render as a status badge " +
			"in the console asserting something no agent can do")
	}
}

/* -------------------------------- plumbing ------------------------------- */

// The plan is scoped to the caller's workspace as well as its connector.
func TestPublishRefusesAConnectorFromAnotherWorkspace(t *testing.T) {
	f := newPlanFixture(t)
	if _, _, err := f.pm.Publish(uuid.New(), f.source); err == nil {
		t.Error("publishing another workspace's connector must be refused")
	}
}

func TestHistoryIsNewestFirst(t *testing.T) {
	f := newPlanFixture(t)
	f.doc(t)
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "hold", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	f.doc(t)

	rows, err := f.pm.History(f.ws, f.source, 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 published versions, got %d", len(rows))
	}
	if rows[0].Version != 2 || rows[1].Version != 1 {
		t.Errorf("history must be newest-first, got %d then %d", rows[0].Version, rows[1].Version)
	}
}
