// Phase 4 tests: access certification.
//
// The properties worth testing are the ones that separate a real review from a rubber
// stamp, and they are mostly about EVIDENCE and IMMUTABILITY:
//
//   - items are SNAPSHOTS, so what the reviewer saw is what the export contains even
//     after the underlying grant changes
//   - evidence is assembled from provenance + token usage + discovery's runtime state
//   - open SoD violations, because a reviewer with only a role name is guessing
//   - a 'revoke' decision goes through the ONE de-provision path (PG-6), including
//     killing live tokens
//   - 'keep' requires a note, because unjustified confirmation is the failure mode
package ownership

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// certFixture provisions an agent (so there is something real to certify) and returns
// a certification manager.
type certFixture struct {
	provFixture
	cm       services.CertifyManager
	standing uuid.UUID // provenance id of the standing role-binding grant
	binding  uuid.UUID
	anchor   uuid.UUID
}

func newCertFixture(t *testing.T) certFixture {
	t.Helper()
	f := newProvFixture(t)

	// Make the workspace owner a real user, so reviewer resolution has a fallback.
	exec(t, f.raw, `UPDATE workspaces SET owner_user_id = $1 WHERE id = $2`,
		"aaaaaaaa-0000-0000-0000-000000000001", wsA)

	// A STANDING grant is what certification is for: it never lapses on its own.
	out, err := f.pm.Provision(f.ws, f.provisionInput(nil, true, "shared build agent, reviewed quarterly"))
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	var standing uuid.UUID
	if err := f.raw.QueryRow(
		`SELECT id FROM entitlement_provenance WHERE role_binding_id = $1`, out.RoleBindingID).
		Scan(&standing); err != nil {
		t.Fatalf("find provenance: %v", err)
	}

	db := gormFor(t, f.raw)
	return certFixture{
		provFixture: f,
		cm:          services.NewCertifyManager(db, services.NewOAuthASService(db)),
		standing:    standing,
		binding:     out.RoleBindingID,
		anchor:      out.ServiceAccountID,
	}
}

func (f certFixture) campaign(t *testing.T, scope services.CampaignScope) uuid.UUID {
	t.Helper()
	due := time.Now().Add(720 * time.Hour)
	c, err := f.cm.CreateCampaign(f.ws, "admin@a.com", services.CampaignInput{
		Name: "Q3 standing access review", Scope: scope, DueAt: &due,
	})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	return c.ID
}

func (f certFixture) evidenceOf(t *testing.T, item models.CertificationItem) map[string]interface{} {
	t.Helper()
	var ev map[string]interface{}
	if err := json.Unmarshal(item.Evidence, &ev); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	return ev
}

/* ------------------------------- generation ------------------------------ */

// The default scope is standing-only, which is the whole design point: expiring grants
// lapse on their own, so reviewing them wastes the reviewer's attention.
func TestCampaignDefaultsToStandingGrantsOnly(t *testing.T) {
	f := newCertFixture(t)

	// Add an EXPIRING grant on a second app. It must not be picked up.
	rs2 := uuid.New()
	role2 := uuid.New()
	exec(t, f.raw, `INSERT INTO resource_servers (id,workspace_id,name,resource_uri,public_base_url)
	                VALUES ($1,$2,'ledger','authsec://rs/ledger','https://ledger.example')`, rs2, wsA)
	exec(t, f.raw, `INSERT INTO roles (id,name,workspace_id) VALUES ($1,'ledger-reader',$2)`, role2, wsA)
	in := f.provisionInput(future(time.Hour), false, "")
	in.ResourceServerID = rs2
	in.RoleID = role2
	if _, err := f.pm.Provision(f.ws, in); err != nil {
		t.Fatalf("second provision: %v", err)
	}

	cid := f.campaign(t, services.CampaignScope{})
	res, err := f.cm.Generate(f.ws, cid)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	items, total, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list items: %v", err)
	}
	// The standing role binding plus the standing registration provenance from each
	// provision. The EXPIRING binding must be absent.
	for _, it := range items {
		ev := f.evidenceOf(t, it)
		if standing, ok := ev["is_standing"].(bool); ok && !standing {
			t.Errorf("an expiring grant was pulled into a standing-only campaign: %s",
				it.EntitlementLabel)
		}
	}
	if res.ItemsCreated == 0 || total == 0 {
		t.Fatal("expected the standing grants to be picked up")
	}

	// The campaign is now reviewable.
	c, err := f.cm.GetCampaign(f.ws, cid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Status != models.CampaignStatusActive || c.GeneratedAt == nil {
		t.Errorf("campaign should be active and generated, got %+v", c.Status)
	}
	if c.ItemsTotal != res.ItemsCreated {
		t.Errorf("items_total = %d, want %d", c.ItemsTotal, res.ItemsCreated)
	}
}

// THE test for what makes a review real. A reviewer shown only a role name is guessing.
func TestItemEvidenceAnswersTheReviewersQuestions(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}

	items, _, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	var bindingItem *models.CertificationItem
	for i := range items {
		if items[i].EntitlementType == models.EntitlementRoleBinding {
			bindingItem = &items[i]
			break
		}
	}
	if bindingItem == nil {
		t.Fatal("expected a role-binding item")
	}
	ev := f.evidenceOf(t, *bindingItem)

	// Why it exists, from provenance.
	if ev["justification"] != "shared build agent, reviewed quarterly" {
		t.Errorf("justification missing from evidence: %v", ev["justification"])
	}
	if ev["origin"] != models.GrantOriginDiscoveryClaim {
		t.Errorf("origin = %v", ev["origin"])
	}
	if ev["is_standing"] != true {
		t.Errorf("is_standing = %v", ev["is_standing"])
	}
	// Whether it has ever been used — the single most useful fact.
	if ev["never_used"] != true {
		t.Errorf("never_used = %v; the agent has issued no tokens", ev["never_used"])
	}
	// Whether the workload is even running: evidence no traditional IGA has.
	if ev["runtime_status"] != models.RuntimeStatusRunning {
		t.Errorf("runtime_status = %v, want running (from the discovered agent)", ev["runtime_status"])
	}
	// A suggestion, with its reason, so the reviewer can disagree.
	if ev["recommendation"] == nil || ev["recommendation_reason"] == "" {
		t.Errorf("expected a recommendation with a reason, got %v / %v",
			ev["recommendation"], ev["recommendation_reason"])
	}

	// And a reviewer was assigned, so the item is somebody's job.
	if bindingItem.ReviewerUserID == nil {
		t.Error("no reviewer resolved; an unassigned item is one nobody will decide")
	}
	if bindingItem.ReviewerSource == "" {
		t.Error("reviewer_source should record WHY this person is the reviewer")
	}
}

// A gone workload should be recommended for revocation — that is discovery's runtime
// signal feeding governance, which is the whole point of the two halves sharing a
// control plane.
func TestGoneWorkloadIsRecommendedForRevocation(t *testing.T) {
	f := newCertFixture(t)
	exec(t, f.raw, `UPDATE discovered_agents SET runtime_status = 'gone' WHERE id = $1`, f.agent)

	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	items, _, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	found := false
	for _, it := range items {
		ev := f.evidenceOf(t, it)
		if ev["runtime_status"] == models.RuntimeStatusGone {
			found = true
			if ev["recommendation"] != "revoke" {
				t.Errorf("a gone workload should be recommended for revoke, got %v", ev["recommendation"])
			}
			if !strings.Contains(ev["recommendation_reason"].(string), "no longer running") {
				t.Errorf("reason should explain why: %v", ev["recommendation_reason"])
			}
		}
	}
	if !found {
		t.Fatal("expected at least one item carrying the gone runtime status")
	}
}

// An open SoD violation must surface ON the item, so risk sits next to the grant rather
// than in a separate report the reviewer never opens.
func TestOpenSoDViolationAppearsOnTheItem(t *testing.T) {
	f := newCertFixture(t)
	// A rule the agent's existing role now violates.
	grantRolePermission(t, f.provFixture, f.role, "governance:admin")
	exec(t, f.raw, `INSERT INTO sod_rules
	    (workspace_id,name,kind,severity,subject_scope,left_label,left_permissions,enforcement)
	    VALUES ($1,'no-governance-for-agents','prohibition','critical','agents',
	            'governance authority','{governance:admin}','warn')`, wsA)
	if _, err := services.NewSoDManager(gormFor(t, f.raw)).Scan(f.ws); err != nil {
		t.Fatalf("scan: %v", err)
	}

	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	items, _, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	found := false
	for _, it := range items {
		ev := f.evidenceOf(t, it)
		v, _ := ev["open_sod_violations"].([]interface{})
		if len(v) > 0 {
			found = true
			if ev["recommendation"] != "revoke" {
				t.Errorf("an item with an open SoD violation should recommend revoke, got %v",
					ev["recommendation"])
			}
		}
	}
	if !found {
		t.Error("the open SoD violation should appear on the agent's item")
	}
}

// Regenerating must not duplicate a reviewer's work.
func TestGenerateIsIdempotent(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})

	first, err := f.cm.Generate(f.ws, cid)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	second, err := f.cm.Generate(f.ws, cid)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if second.ItemsCreated != 0 || second.ItemsSkipped != first.ItemsCreated {
		t.Errorf("regeneration should skip everything already under review: %+v", second)
	}
	c, _ := f.cm.GetCampaign(f.ws, cid)
	if c.ItemsTotal != first.ItemsCreated {
		t.Errorf("items_total drifted to %d, want %d", c.ItemsTotal, first.ItemsCreated)
	}
}

/* -------------------------------- decisions ------------------------------ */

func (f certFixture) firstBindingItem(t *testing.T, cid uuid.UUID) models.CertificationItem {
	t.Helper()
	items, _, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, it := range items {
		if it.EntitlementType == models.EntitlementRoleBinding {
			return it
		}
	}
	t.Fatal("no role-binding item")
	return models.CertificationItem{}
}

// 'keep' without a reason is exactly the rubber stamp certification exists to prevent.
func TestKeepRequiresANote(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	item := f.firstBindingItem(t, cid)

	if _, err := f.cm.Decide(f.ws, item.ID, services.DecisionInput{
		Decision: models.DecisionKeep,
	}); err == nil {
		t.Fatal("keeping access with no stated reason must be refused")
	}

	owner := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	out, err := f.cm.Decide(f.ws, item.ID, services.DecisionInput{
		Decision: models.DecisionKeep,
		Note:     "still required for the nightly build",
		By:       &owner,
	})
	if err != nil {
		t.Fatalf("keep: %v", err)
	}
	if out.Decision != models.DecisionKeep || out.DecidedAt == nil || out.DecidedBy == nil {
		t.Errorf("a decision must record who and when: %+v", out)
	}
	// The access itself is untouched.
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE id = $1`, f.binding); n != 1 {
		t.Error("a 'keep' must not remove the binding")
	}
}

// A 'revoke' goes through the ONE de-provision path, including killing live tokens.
func TestRevokeDecisionExecutesTheRealRevocation(t *testing.T) {
	f := newCertFixture(t)

	// A live token the agent holds under the grant being certified.
	jti := uuid.New()
	exec(t, f.raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','service_account',$3,'agent-client-1',
	            $4,'authsec://rs/payments','read',now(),now() + interval '55 minutes')`,
		jti, wsA, f.anchor, f.rs)

	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	item := f.firstBindingItem(t, cid)

	owner := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	out, err := f.cm.Decide(f.ws, item.ID, services.DecisionInput{
		Decision: models.DecisionRevoke,
		Note:     "agent decommissioned",
		By:       &owner,
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if out.RevocationExecutedAt == nil {
		t.Error("revocation_executed_at must be set, so a decision that failed to " +
			"execute is distinguishable from one that succeeded")
	}

	// The binding is gone.
	if n := f.count(t, `SELECT count(*) FROM role_bindings WHERE id = $1`, f.binding); n != 0 {
		t.Error("the certified-away binding should have been removed")
	}
	// The live token is in the kill list — otherwise the revoked access keeps working
	// for up to its remaining hour.
	if n := f.count(t, `SELECT count(*) FROM revoked_tokens WHERE jti = $1::text`, jti); n != 1 {
		t.Error("the live token was not revoked")
	}
	// Provenance is closed, attributed to certification.
	var via, reason string
	if err := f.raw.QueryRow(
		`SELECT revoked_via, revoked_reason FROM entitlement_provenance WHERE id = $1`, f.standing).
		Scan(&via, &reason); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if via != models.RevokedViaCertification {
		t.Errorf("revoked_via = %q, want certification", via)
	}
	if !strings.Contains(reason, "agent decommissioned") {
		t.Errorf("the reviewer's note should be in the reason, got %q", reason)
	}
}

// Deciding twice must not double-revoke or double-count.
func TestItemCannotBeDecidedTwice(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	item := f.firstBindingItem(t, cid)
	owner := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")

	if _, err := f.cm.Decide(f.ws, item.ID, services.DecisionInput{
		Decision: models.DecisionKeep, Note: "needed", By: &owner,
	}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := f.cm.Decide(f.ws, item.ID, services.DecisionInput{
		Decision: models.DecisionRevoke, Note: "changed my mind", By: &owner,
	}); err == nil {
		t.Fatal("an already-decided item must not be re-decided")
	}
	c, _ := f.cm.GetCampaign(f.ws, cid)
	if c.ItemsDecided != 1 || c.ItemsKept != 1 {
		t.Errorf("counters drifted: decided=%d kept=%d", c.ItemsDecided, c.ItemsKept)
	}
}

// Delegating reassigns and leaves the item pending: handing an item on is not a
// decision about the access.
func TestDelegateReassignsAndLeavesItemPending(t *testing.T) {
	f := newCertFixture(t)
	other := uuid.New()
	exec(t, f.raw, `INSERT INTO users (id,email,workspace_id) VALUES ($1,'other@a.com',$2)`, other, wsA)

	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	item := f.firstBindingItem(t, cid)

	out, err := f.cm.Decide(f.ws, item.ID, services.DecisionInput{
		Decision: models.DecisionDelegate, Note: "not my system", DelegateTo: &other,
	})
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	if out.Decision != models.DecisionPending {
		t.Errorf("a delegated item stays pending, got %q", out.Decision)
	}
	if out.ReviewerUserID == nil || *out.ReviewerUserID != other {
		t.Error("the item should now belong to the delegate")
	}
	if out.ReviewerSource != "delegated" {
		t.Errorf("reviewer_source = %q, want delegated", out.ReviewerSource)
	}
}

/* ---------------------------------- close -------------------------------- */

// Closing with undecided items would produce an export claiming a review happened
// where it did not.
func TestCloseRefusesWhileDecisionsAreOutstanding(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := f.cm.Close(f.ws, cid, nil, false); err == nil {
		t.Fatal("closing with pending items must be refused")
	}

	// Forcing is allowed, and the gap goes IN the artifact rather than being hidden.
	c, err := f.cm.Close(f.ws, cid, nil, true)
	if err != nil {
		t.Fatalf("forced close: %v", err)
	}
	if c.Status != models.CampaignStatusClosed || c.Export == nil {
		t.Fatalf("a closed campaign must carry its export: %+v", c.Status)
	}
	var export map[string]interface{}
	if err := json.Unmarshal(c.Export, &export); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if export["closed_with_force"] != true {
		t.Error("a forced close must be recorded in the export")
	}
	if export["items_undecided"] == nil || export["items_undecided"].(float64) == 0 {
		t.Error("the export must state how many items were left undecided")
	}
}

// THE immutability property. The export is what the reviewer saw, not what the world
// looks like when an auditor reads it later.
func TestExportIsFrozenAtClose(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	item := f.firstBindingItem(t, cid)
	owner := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")

	// Decide everything so the close is clean.
	items, _, _ := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	for _, it := range items {
		if _, err := f.cm.Decide(f.ws, it.ID, services.DecisionInput{
			Decision: models.DecisionKeep, Note: "confirmed with the owning team", By: &owner,
		}); err != nil {
			t.Fatalf("decide %s: %v", it.ID, err)
		}
	}
	closed, err := f.cm.Close(f.ws, cid, &owner, false)
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	// Now change the world underneath it: revoke the grant the campaign certified.
	if _, err := f.pm.Deprovision(f.ws, services.DeprovisionInput{
		DiscoveredAgentID: &f.agent, Via: models.RevokedViaAdmin, Reason: "later change",
	}); err != nil {
		t.Fatalf("deprovision: %v", err)
	}

	// The export still says what the reviewer decided, on the evidence they had.
	reread, err := f.cm.GetCampaign(f.ws, cid)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if string(reread.Export) != string(closed.Export) {
		t.Error("the export must not change after close")
	}
	var export struct {
		Items []struct {
			ID           uuid.UUID `json:"id"`
			Decision     string    `json:"decision"`
			DecisionNote string    `json:"decision_note"`
		} `json:"items"`
	}
	if err := json.Unmarshal(reread.Export, &export); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(export.Items) == 0 {
		t.Fatal("the export must contain the items")
	}
	for _, it := range export.Items {
		if it.Decision != models.DecisionKeep || it.DecisionNote == "" {
			t.Errorf("export item %s lost its decision: %+v", it.ID, it)
		}
	}
	_ = item

	// And a closed campaign cannot be regenerated — its export is frozen evidence.
	if _, err := f.cm.Generate(f.ws, cid); err == nil {
		t.Error("regenerating a closed campaign must be refused")
	}
}

// Items survive their provenance row being removed, or closing a campaign could lose
// the very record it certified.
func TestItemSurvivesProvenanceRemoval(t *testing.T) {
	f := newCertFixture(t)
	cid := f.campaign(t, services.CampaignScope{})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}

	exec(t, f.raw, `DELETE FROM entitlement_provenance WHERE id = $1`, f.standing)

	items, total, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total == 0 {
		t.Fatal("items must survive provenance removal")
	}
	for _, it := range items {
		// The snapshot still reads, which is why it is a snapshot.
		if it.EntitlementLabel == "" || it.SubjectLabel == "" {
			t.Errorf("the snapshot lost its content: %+v", it)
		}
	}
}

// A campaign scoped to dormant access should skip an entitlement that is actively used.
func TestDormantScopeSkipsActivelyUsedAccess(t *testing.T) {
	f := newCertFixture(t)
	// A token issued right now makes the anchor non-dormant.
	exec(t, f.raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','service_account',$3,'agent-client-1',
	            $4,'authsec://rs/payments','read',now(),now() + interval '55 minutes')`,
		uuid.New(), wsA, f.anchor, f.rs)

	cid := f.campaign(t, services.CampaignScope{DormantDays: 30})
	if _, err := f.cm.Generate(f.ws, cid); err != nil {
		t.Fatalf("generate: %v", err)
	}
	items, _, err := f.cm.ListItems(f.ws, cid, services.ItemFilter{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, it := range items {
		if it.SubjectID == f.anchor {
			t.Errorf("an actively-used entitlement must not appear in a dormant-only "+
				"campaign: %s", it.EntitlementLabel)
		}
	}
}
