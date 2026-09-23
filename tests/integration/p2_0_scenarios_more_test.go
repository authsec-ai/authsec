package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Scenario 2. Lambda switches RoleA -> RoleB: the old executes_as ENDS (with
// valid_to and a reason) and the new one is current; both stay readable.
func TestP2RoleSwitchEndsOldExecutesAs(t *testing.T) {
	l := newP2Lab(t, "p2-role-switch", true)
	a := l.account(accountA)
	roleA := a.role("RoleA", "AROAROLEAAAAAAAAAAAA")
	roleB := a.role("RoleB", "AROAROLEBBBBBBBBBBBB")
	a.lambda("us-east-1", "ticket-tools", roleA)
	l.scanAndProject(a)

	a.lambda("us-east-1", "ticket-tools", roleB)
	l.scanAndProject(a)

	var rows []struct {
		Target      string
		State       string
		ValidTo     *time.Time
		EndedReason string
	}
	l.db.Raw(`SELECT i.display_name AS target, r.state, r.valid_to, r.ended_reason
	            FROM iga_relationship r JOIN iga_identity_accounts i ON i.id = r.target_identity_account_id
	           WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as' ORDER BY r.created_at`,
		l.ws).Scan(&rows)
	if len(rows) != 2 {
		t.Fatalf("executes_as rows = %d, want 2 (old ended, new current): %+v", len(rows), rows)
	}
	if rows[0].Target != "RoleA" || rows[0].State != models.RelEnded || rows[0].ValidTo == nil || rows[0].EndedReason == "" {
		t.Errorf("old edge = %+v, want RoleA ended with valid_to and a reason", rows[0])
	}
	if rows[1].Target != "RoleB" || rows[1].State != models.RelCurrent {
		t.Errorf("new edge = %+v, want RoleB current", rows[1])
	}
}

// Scenario 3. Two policies grant the same action; one is detached. Two
// statements, two grants -- then one grant ends and the other stays current.
func TestP2TwoPoliciesOneDetached(t *testing.T) {
	l := newP2Lab(t, "p2-two-policies", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	// TicketRead is ALSO held by another role, so detaching it here does not
	// retire the policy: only the ASSIGNMENT partition can end this grant, which
	// is the mechanism under test (a retired policy would cascade instead).
	a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	ticket := a.managed("TicketRead", docTicketRead)
	a.attach("SharedToolRole", ticket)
	a.attach("OtherRole", ticket)
	a.attach("SharedToolRole", a.managed("ToolboxRead", docToolboxRead))
	l.scanAndProject(a)

	g := l.grants()
	if len(grantsOf(g, "TicketRead")) != 2 || len(grantsOf(g, "ToolboxRead")) != 1 {
		t.Fatalf("grants before detach = %+v, want one per policy (merged grants?)", g)
	}

	a.detach("SharedToolRole", ticket)
	l.scanAndProject(a)

	g = l.grants()
	tr, tb := grantsOf(g, "TicketRead"), grantsOf(g, "ToolboxRead")
	ended, current := 0, 0
	for _, r := range tr {
		switch {
		case r.State == models.RelEnded && r.ValidTo != nil && r.EndedReason == models.EndedNotSeen:
			ended++
		case r.State == models.RelCurrent:
			current++
		}
	}
	if ended != 1 || current != 1 {
		t.Errorf("TicketRead grants = %+v, want the detached role's ended not_seen and the other role's current", tr)
	}
	if len(tb) != 1 || tb[0].State != models.RelCurrent {
		t.Errorf("ToolboxRead grant = %+v, want one, current: the path must remain", tb)
	}
	var detached []assignmentRow
	for _, r := range l.assignments("TicketRead") {
		if r.State == models.RelEnded {
			detached = append(detached, r)
		}
	}
	if len(detached) != 1 || detached[0].EndedReason != models.EndedNotSeen {
		t.Errorf("TicketRead assignments ended = %+v, want exactly the detached one, not_seen", detached)
	}
}

// Scenario 4. One previously collected policy becomes UNREADABLE and another is
// genuinely DETACHED, in the same account and run. The unreadable policy's
// statements, grants and the support of resources only it names go STALE; the
// detached policy's assignment and grants END.
func TestP2UnreadableAndDetachedInOneRun(t *testing.T) {
	l := newP2Lab(t, "p2-unreadable", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	ticket := a.managed("TicketRead", `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::support-tickets/*","arn:aws:s3:::ticket-archive/*"]}]}`)
	other := a.managed("OtherPolicy", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",`+
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}]}`)
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", a.managed("ToolboxRead", docToolboxRead))
	a.attach("SharedToolRole", other)
	l.scanAndProject(a)

	a.iam.failPolicyVersion[ticket] = denied("iam:GetPolicyVersion")
	a.detach("SharedToolRole", other)
	run := l.scanAndProject(a)

	// Coverage names the unreadable document; the scan continued.
	cov := models.DecodeScanCoverage(run.Coverage).Surfaces[models.SurfacePolicyDocuments]
	if cov.State == models.CloudCoverageReached || !strings.Contains(cov.Error, "TicketRead") {
		t.Errorf("policy_documents = %+v, want partial naming TicketRead", cov)
	}

	g := l.grants()
	if tr := grantsOf(g, "TicketRead"); len(tr) != 1 || tr[0].State != models.RelStale || tr[0].ValidTo != nil {
		t.Errorf("unreadable policy's grant = %+v, want stale (never ended)", tr)
	}
	if oth := grantsOf(g, "OtherPolicy"); len(oth) != 1 || oth[0].State != models.RelEnded {
		t.Errorf("detached policy's grant = %+v, want ended", oth)
	}
	if tb := grantsOf(g, "ToolboxRead"); len(tb) != 1 || tb[0].State != models.RelCurrent {
		t.Errorf("readable policy's grant = %+v, want current", tb)
	}
	if asg := l.assignments("TicketRead"); len(asg) != 1 || asg[0].State != models.RelCurrent {
		t.Errorf("unreadable policy's assignment = %+v, want CURRENT: attachment lists are read independently", asg)
	}
	if asg := l.assignments("OtherPolicy"); len(asg) != 1 || asg[0].State != models.RelEnded {
		t.Errorf("detached policy's assignment = %+v, want ended", asg)
	}
	// The statement of the unreadable policy: support stale, still active.
	var stmtID uuid.UUID
	var stmtLife string
	l.db.Raw(`SELECT e.id, e.lifecycle FROM iga_entitlements e JOIN iga_policy p ON p.id = e.policy_id
	           WHERE e.workspace_id = ? AND p.display_name = 'TicketRead'`, l.ws).Row().Scan(&stmtID, &stmtLife)
	if s := l.supportOf("entitlement_id", stmtID)[a.conn]; s != models.RelStale || stmtLife != models.IGALifecycleActive {
		t.Errorf("unreadable statement support = %q lifecycle %q, want stale/active", s, stmtLife)
	}
	// A resource ONLY the unreadable policy names keeps its support, stale.
	archive, archiveLife := l.resourceID("arn:aws:s3:::ticket-archive/*")
	if s := l.supportOf("resource_id", archive)[a.conn]; s != models.RelStale || archiveLife != models.IGALifecycleActive {
		t.Errorf("resource named only by the unreadable policy = support %q, %q; want stale, active", s, archiveLife)
	}
	// One named by a readable policy too is confirmed anyway.
	tickets, _ := l.resourceID("arn:aws:s3:::support-tickets/*")
	if s := l.supportOf("resource_id", tickets)[a.conn]; s != models.RelCurrent {
		t.Errorf("shared resource support = %q, want current", s)
	}
	// And one named only by the DETACHED policy is gone.
	otherRes, otherLife := l.resourceID("arn:aws:s3:::other-bucket/*")
	if s := l.supportOf("resource_id", otherRes)[a.conn]; s != models.RelEnded || otherLife != models.IGALifecycleRetired {
		t.Errorf("detached policy's resource = support %q, %q; want ended, retired", s, otherLife)
	}
}

// Scenario 5. Attach -> detach -> reattach. The first assignment period ends
// with valid_to; the reattach creates a SECOND row and leaves the first as it
// was; the grants follow each period.
func TestP2AttachDetachReattach(t *testing.T) {
	l := newP2Lab(t, "p2-reattach", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	// A second holder keeps the policy alive, so the period can only end
	// through the assignment partition (not a policy-retirement cascade).
	a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	ticket := a.managed("TicketRead", docTicketRead)
	a.attach("SharedToolRole", ticket)
	a.attach("OtherRole", ticket)
	l.scanAndProject(a)
	holder := func() []assignmentRow {
		var out []assignmentRow
		l.db.Raw(`SELECT a.id, p.display_name AS policy, a.state, a.valid_to, a.ended_reason
		            FROM iga_policy_assignment a
		            JOIN iga_policy p ON p.id = a.policy_id
		            JOIN iga_identity_accounts i ON i.id = a.holder_identity_account_id
		           WHERE a.workspace_id = ? AND p.display_name = 'TicketRead' AND i.display_name = 'SharedToolRole'
		           ORDER BY a.valid_from, a.id`, l.ws).Scan(&out)
		return out
	}

	a.detach("SharedToolRole", ticket)
	l.scanAndProject(a)
	first := holder()
	if len(first) != 1 || first[0].State != models.RelEnded || first[0].ValidTo == nil ||
		first[0].EndedReason != models.EndedNotSeen {
		t.Fatalf("after detach: %+v, want one period, ended not_seen", first)
	}
	endedAt := *first[0].ValidTo

	a.attach("SharedToolRole", ticket)
	l.scanAndProject(a)

	periods := holder()
	if len(periods) != 2 {
		t.Fatalf("assignment periods = %d, want 2 (reattach is a NEW row): %+v", len(periods), periods)
	}
	if periods[0].ID != first[0].ID || periods[0].State != models.RelEnded ||
		periods[0].ValidTo == nil || !periods[0].ValidTo.Equal(endedAt) {
		t.Errorf("the ended period changed: %+v (was ended at %s)", periods[0], endedAt)
	}
	if periods[1].State != models.RelCurrent || periods[1].ID == first[0].ID {
		t.Errorf("the reattach period = %+v, want a new current row", periods[1])
	}
	var g []grantRow
	for _, r := range l.grants() {
		if r.Assignment == periods[0].ID || r.Assignment == periods[1].ID {
			g = append(g, r)
		}
	}
	if len(g) != 2 || g[0].State != models.RelEnded || g[1].State != models.RelCurrent ||
		g[0].Assignment != periods[0].ID || g[1].Assignment != periods[1].ID {
		t.Errorf("grants = %+v, want one per period, each through its own assignment", g)
	}
}

// Scenario 6. A NotResource statement produces a grant to the "*" selector and
// NO path to the excluded resource: it is a target of mode not_resource, never
// a destination.
func TestP2NotResourceIsAnExclusion(t *testing.T) {
	l := newP2Lab(t, "p2-notresource", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("AllButFinance", `{"Version":"2012-10-17","Statement":[{`+
		`"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}]}`))
	l.scanAndProject(a)

	if g := grantsOf(l.grants(), "AllButFinance"); len(g) != 1 || g[0].State != models.RelCurrent {
		t.Fatalf("grants = %+v, want one current grant", g)
	}
	var targets []struct {
		Resource string
		Mode     string
	}
	l.db.Raw(`SELECT r.display_name AS resource, t.target_mode AS mode
	            FROM iga_entitlement_target t JOIN iga_resources r ON r.id = t.resource_id
	           WHERE t.workspace_id = ? ORDER BY t.target_mode`, l.ws).Scan(&targets)
	byMode := map[string]string{}
	for _, tg := range targets {
		byMode[tg.Resource] = tg.Mode
	}
	if byMode["*"] != models.TargetResource {
		t.Errorf("targets = %+v, want the implicit * selector as the destination", targets)
	}
	if byMode["arn:aws:s3:::finance/*"] != models.TargetNotResource {
		t.Errorf("targets = %+v, want finance/* as an EXCLUSION (not_resource)", targets)
	}
	var negated bool
	l.db.Raw(`SELECT negated FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws'`, l.ws).Scan(&negated)
	if !negated {
		t.Error("the statement is not marked negated")
	}
}

// Scenario 7. A customer-managed policy RECREATED under the same ARN and Sid is
// a new policy with new statements, assignments and grants; the old ones are
// retired or ended policy_recreated, and no key or id is reused.
func TestP2RecreatedPolicySharesNothing(t *testing.T) {
	l := newP2Lab(t, "p2-recreated-policy", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	ticket := a.managed("TicketRead", docTicketRead)
	a.attach("SharedToolRole", ticket)
	a.iam.policyIDs[ticket] = "ANPAOLDOLDOLDOLDOLD1"
	l.scanAndProject(a)

	a.iam.policyIDs[ticket] = "ANPANEWNEWNEWNEWNEW2" // deleted and recreated
	l.scanAndProject(a)

	var pols []struct {
		ID            uuid.UUID
		ImmutableKey  string
		Lifecycle     string
		RetiredReason string
	}
	l.db.Raw(`SELECT id, immutable_key, lifecycle, retired_reason FROM iga_policy
	           WHERE workspace_id = ? AND native_ref = ? ORDER BY first_seen_at, id`, l.ws, ticket).Scan(&pols)
	if len(pols) != 2 || pols[0].ImmutableKey != "ANPAOLDOLDOLDOLDOLD1" ||
		pols[0].Lifecycle != models.IGALifecycleRetired || pols[0].RetiredReason != models.RetiredRecreated ||
		pols[1].Lifecycle != models.IGALifecycleActive {
		t.Fatalf("policies = %+v, want the old retired 'recreated' and the new active", pols)
	}
	var stmts []struct {
		ID            uuid.UUID
		PolicyID      uuid.UUID
		SourceKey     string
		Lifecycle     string
		RetiredReason string
	}
	l.db.Raw(`SELECT id, policy_id, source_key, lifecycle, retired_reason FROM iga_entitlements
	           WHERE workspace_id = ? AND provider = 'aws' ORDER BY first_seen_at, id`, l.ws).Scan(&stmts)
	if len(stmts) != 2 || stmts[0].PolicyID != pols[0].ID || stmts[1].PolicyID != pols[1].ID {
		t.Fatalf("statements = %+v, want one per incarnation", stmts)
	}
	if stmts[0].SourceKey == stmts[1].SourceKey || stmts[0].ID == stmts[1].ID {
		t.Error("the recreated policy's statement reused its predecessor's key or id")
	}
	if stmts[0].Lifecycle != models.IGALifecycleRetired || stmts[0].RetiredReason != models.RetiredPolicyRecreated {
		t.Errorf("old statement = %s/%s, want retired/policy_recreated", stmts[0].Lifecycle, stmts[0].RetiredReason)
	}
	asg := l.assignments("TicketRead")
	if len(asg) != 2 || asg[0].State != models.RelEnded || asg[0].EndedReason != models.EndedPolicyRecreated ||
		asg[1].State != models.RelCurrent {
		t.Errorf("assignments = %+v, want old ended policy_recreated and new current", asg)
	}
	g := grantsOf(l.grants(), "TicketRead")
	if len(g) != 2 || g[0].State != models.RelEnded || g[0].EndedReason != models.EndedPolicyRecreated ||
		g[1].State != models.RelCurrent || g[0].StatementID == g[1].StatementID {
		t.Errorf("grants = %+v, want old ended policy_recreated and a new one on the new statement", g)
	}
	// And the Changes history: the old incarnation retired, the new first seen.
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ? AND policy_id = ?
	                  AND event = 'retired' AND reason = 'recreated'`, l.ws, pols[0].ID); n != 1 {
		t.Errorf("retired/recreated events for the old policy = %d, want 1", n)
	}
}

// Scenario 8. A Deny statement produces NO grant. It is stored, with its
// effect, as a restriction.
func TestP2DenyIsNeverAGrant(t *testing.T) {
	l := newP2Lab(t, "p2-deny", true)
	a := l.account(accountA)
	a.role("DenyRole", "AROADENYROLEDENYROLE")
	a.attach("DenyRole", a.managed("ReadButNotDelete", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},`+
		`{"Sid":"NoDelete","Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"}]}`))
	l.scanAndProject(a)

	var effects []string
	l.db.Raw(`SELECT effect FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' ORDER BY sid`,
		l.ws).Scan(&effects)
	if len(effects) != 2 {
		t.Fatalf("statements = %v, want both, with their effects", effects)
	}
	g := grantsOf(l.grants(), "ReadButNotDelete")
	if len(g) != 1 || g[0].Sid != "Read" {
		t.Fatalf("grants = %+v, want exactly one, for the Allow statement", g)
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges g JOIN iga_entitlements e ON e.id = g.entitlement_id
	                  WHERE g.workspace_id = ? AND e.effect = 'deny'`, l.ws); n != 0 {
		t.Errorf("%d grants on a Deny statement", n)
	}
}

// Scenario 9. One region denied, another clean: per-region partitions are
// independent. The clean region ends what it no longer sees; the denied one
// keeps its edge stale.
//
// The clean region's Lambda STAYS and switches role, so its old edge can end
// only through ITS REGION'S executes_as partition -- not through a workload
// retirement cascade, which would pass this test without exercising the
// partition at all.
func TestP2RegionPartitionsIndependent(t *testing.T) {
	l := newP2Lab(t, "p2-regions", true)
	a := l.account(accountA, "us-east-1", "eu-west-1")
	roleA := a.role("RoleA", "AROAROLEAAAAAAAAAAAA")
	roleB := a.role("RoleB", "AROAROLEBBBBBBBBBBBB")
	a.lambda("us-east-1", "east-fn", roleA)
	a.lambda("eu-west-1", "west-fn", roleA)
	l.scanAndProject(a)

	a.lambda("us-east-1", "east-fn", roleB)                      // clean read, role changed
	a.lambdas["eu-west-1"].fail = denied("lambda:ListFunctions") // could not look
	l.scanAndProject(a)

	var rows []struct {
		Workload string
		Target   string
		State    string
	}
	l.db.Raw(`SELECT w.display_name AS workload, i.display_name AS target, r.state FROM iga_relationship r
	            JOIN iga_workload w ON w.id = r.source_workload_id
	            JOIN iga_identity_accounts i ON i.id = r.target_identity_account_id
	           WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as'`, l.ws).Scan(&rows)
	got := map[string]string{}
	for _, r := range rows {
		got[r.Workload+"->"+r.Target] = r.State
	}
	if got["east-fn->RoleA"] != models.RelEnded || got["east-fn->RoleB"] != models.RelCurrent {
		t.Errorf("clean region edges = %v, want east-fn->RoleA ended and ->RoleB current", got)
	}
	if got["west-fn->RoleA"] != models.RelStale {
		t.Errorf("denied region's edge = %q, want stale -- a denied region must not close anything", got["west-fn->RoleA"])
	}
	var westLife string
	l.db.Raw(`SELECT lifecycle FROM iga_workload WHERE workspace_id = ? AND display_name = 'west-fn'`, l.ws).Scan(&westLife)
	if westLife != models.IGALifecycleActive {
		t.Errorf("denied region's workload = %q, want active", westLife)
	}
}

// Scenario 10. Two accounts naming one bucket: ONE resource reference, two
// support rows; neither grant becomes "*". Then B stops naming it: B's support
// ends, A's stays current, the resource stays active and A's grant is untouched.
func TestP2TwoAccountsOneBucket(t *testing.T) {
	l := newP2Lab(t, "p2-shared-bucket", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERDATARE")
	bPolicy := b.managed("SandboxTickets", docToolboxRead)
	b.attach("data-reader", bPolicy)
	l.scanAndProject(a)
	l.scanAndProject(b)

	res, life := l.resourceID("arn:aws:s3:::support-tickets/*")
	sup := l.supportOf("resource_id", res)
	if res == uuid.Nil || life != models.IGALifecycleActive || sup[a.conn] != models.RelCurrent || sup[b.conn] != models.RelCurrent {
		t.Fatalf("shared resource = %s (%s) support %v, want one active resource supported by both", res, life, sup)
	}
	if n := l.count(`SELECT count(*) FROM iga_resources WHERE workspace_id = ? AND display_name = '*'`, l.ws); n != 0 {
		t.Errorf("%d '*' resources: a grant naming the shared bucket became a wildcard", n)
	}

	b.detach("data-reader", bPolicy)
	l.scanAndProject(b)

	res2, life2 := l.resourceID("arn:aws:s3:::support-tickets/*")
	sup = l.supportOf("resource_id", res2)
	if res2 != res || life2 != models.IGALifecycleActive {
		t.Errorf("resource = %s (%s), want the same object, still active", res2, life2)
	}
	if sup[a.conn] != models.RelCurrent || sup[b.conn] != models.RelEnded {
		t.Errorf("supports = %v, want A current, B ended", sup)
	}
	if g := grantsOf(l.grants(), "TicketRead"); len(g) != 1 || g[0].State != models.RelCurrent {
		t.Errorf("A's grant = %+v, want unchanged and current", g)
	}
}

// Scenario 11. Two consecutive scans through the worker, switch OFF: both
// publish; no projection job; no barrier row; nothing in the graph tables.
func TestP2SwitchOffTwoScans(t *testing.T) {
	l := newP2Lab(t, "p2-switch-off", false)
	a := oneLambda(l)
	l.scan(a, "scan-worker-off-1")
	l.scan(a, "scan-worker-off-2")

	if n := l.count(`SELECT count(*) FROM cloud_scan_run WHERE workspace_id = ? AND status = 'published'`, l.ws); n != 2 {
		t.Fatalf("published runs = %d, want 2", n)
	}
	for table, where := range map[string]string{
		"iga_projection_job": "workspace_id = ?", "iga_pipeline_lease": "workspace_id = ?",
		"iga_publication": "workspace_id = ?", "iga_policy": "workspace_id = ?",
		"iga_access_edges": "workspace_id = ? AND provider = 'aws'", "iga_workload": "workspace_id = ?",
	} {
		if n := l.count(`SELECT count(*) FROM `+table+` WHERE `+where, l.ws); n != 0 {
			t.Errorf("%s has %d rows with the switch off; Phase 1 must write nothing to the graph", table, n)
		}
	}
}

// Scenario 12. Two consecutive scans, switch ON, with DIFFERENT worker names:
// each projection completes on its FIRST pass, and the second scan starts.
func TestP2SwitchOnHandOffDifferentOwners(t *testing.T) {
	l := newP2Lab(t, "p2-handoff", true)
	a := oneLambda(l)

	l.scan(a, "scan-worker-A")
	var holder string
	l.db.Raw(`SELECT holder FROM iga_pipeline_lease WHERE workspace_id = ?`, l.ws).Scan(&holder)
	if !strings.HasPrefix(holder, "job:") {
		t.Fatalf("barrier holder after publish = %q, want job:<id> -- held by the JOB, not the scan worker", holder)
	}
	l.project("projector-X") // requires completion on this first pass

	l.scan(a, "scan-worker-B") // the second scan must start
	l.project("projector-Y")

	if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws); n != 2 {
		t.Errorf("publications = %d, want 2", n)
	}
}

// Scenario 13. A superseded scan worker: its writes AND ITS DELETES are
// refused (§2.10A). Deletes were the unfenced half on the graph branch.
func TestP2SupersededWorkerDeletesRefused(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-superseded-delete")
	defer cleanIdentities(t, db, ws)
	runs := scanRuns(t, db)
	conn := connectorFor(t, db, ws)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatal(err)
	}
	w1, err := runs.Claim("w1", time.Minute, time.Now())
	if err != nil || w1 == nil {
		t.Fatalf("claim w1: %v", err)
	}
	// An old identity at an earlier generation, which a reconcile at w1's
	// generation would delete.
	if err := db.Exec(`INSERT INTO cloud_identity (workspace_id, connector_id, kind, native_id, name, last_seen_generation)
	                   VALUES (?, ?, 'iam_role', 'arn:aws:iam::1:role/old', 'old', 0)`, ws, conn).Error; err != nil {
		t.Fatal(err)
	}
	// w2 reclaims: w1 is superseded.
	db.Exec(`UPDATE cloud_scan_run SET lease_expires_at = now() - interval '1 minute' WHERE id = ?`, w1.ID)
	if w2, err := runs.Claim("w2", time.Minute, time.Now()); err != nil || w2 == nil {
		t.Fatalf("reclaim w2: %v", err)
	}
	stale := repositories.ScanFence{RunID: w1.ID, Owner: "w1", LeaseVersion: w1.LeaseVersion}

	_, _, err = repositories.NewCloudIdentityRepository(db).Fenced(stale).ReconcileGeneration(ws, conn, w1.Generation)
	if !errors.Is(err, repositories.ErrScanFenceLost) {
		t.Fatalf("superseded identity delete: err = %v, want ErrScanFenceLost", err)
	}
	_, _, err = repositories.NewCloudPolicyRepository(db).Fenced(stale).ReconcilePolicies(ws, conn, w1.Generation)
	if !errors.Is(err, repositories.ErrScanFenceLost) {
		t.Fatalf("superseded policy delete: err = %v, want ErrScanFenceLost", err)
	}
	var n int64
	db.Raw(`SELECT count(*) FROM cloud_identity WHERE workspace_id = ?`, ws).Scan(&n)
	if n != 1 {
		t.Errorf("a superseded worker's delete LANDED: %d identity rows remain, want 1", n)
	}
}

// Scenario 14. A crash after the graph commit: the replay returns
// AlreadyPublished, writes nothing, and completes -- through the real service.
func TestP2CrashAfterCommitReplays(t *testing.T) {
	l := newP2Lab(t, "p2-crash-after-commit", true)
	a := oneLambda(l)
	run := l.scan(a, "scan-worker-1")
	l.project("projector-dead")
	before := len(l.shape())
	events := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?`, l.ws)

	// Put back the state a worker that died AFTER the graph commit and BEFORE
	// completeAndRelease leaves: the job running under an expired lease, the
	// barrier projecting and held by the job.
	var jobID uuid.UUID
	var version int64
	if err := l.db.Raw(`SELECT id FROM iga_projection_job WHERE workspace_id = ?`, l.ws).Row().Scan(&jobID); err != nil {
		t.Fatalf("read job: %v", err)
	}
	l.db.Raw(`SELECT version FROM iga_pipeline_lease WHERE workspace_id = ?`, l.ws).Scan(&version)
	if res := l.db.Exec(`UPDATE iga_projection_job SET status = 'running', lease_owner = 'projector-dead',
	          lease_expires_at = now() - interval '1 minute', completed_at = NULL WHERE id = ?`, jobID); res.Error != nil || res.RowsAffected != 1 {
		t.Fatalf("restore the dead worker's job: rows=%d err=%v", res.RowsAffected, res.Error)
	}
	if err := l.db.Exec(`UPDATE iga_pipeline_lease SET state = 'projecting', holder = ?, scan_run_id = ?,
	          expires_at = now() + interval '15 minutes' WHERE workspace_id = ?`,
		models.PipelineJobHolder(jobID), run.ID, l.ws).Error; err != nil {
		t.Fatal(err)
	}

	l.project("projector-replay") // must COMPLETE on its first pass

	if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ? AND scan_run_id = ?`, l.ws, run.ID); n != 1 {
		t.Errorf("publications for the run = %d, want exactly 1", n)
	}
	if after := len(l.shape()); after != before {
		t.Errorf("the replay changed the graph: %d -> %d rows", before, after)
	}
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?`, l.ws); n != events {
		t.Errorf("the replay wrote lifecycle events: %d -> %d", events, n)
	}
}

// Scenario 15. A schema verification ERROR at startup: the worker claims
// nothing and /capabilities says misconfigured, with the reason. B14: the
// fail-open cache is the defect this catches.
func TestP2SchemaVerificationErrorFailsClosed(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p2-verify-error")
	runs := scanRuns(t, db)
	conn := connectorFor(t, db, ws)
	queued, err := runs.Enqueue(ws, conn, "manual")
	if err != nil {
		t.Fatal(err)
	}

	// A verification that ERRORS: a closed connection pool, as a database
	// that is unreachable at startup looks to the check.
	gate := services.NewGraphProjectionGate(true, "")
	if err := gate.Verify(closedGorm(t)); err == nil {
		t.Fatal("verification against an unreachable database succeeded")
	}

	worked, err := services.NewAWSScanWorker(db, nil).WithOwner("fail-closed").
		WithGraphProjection(gate).RunOnce(context.Background())
	if err != nil || worked {
		t.Fatalf("worker with an unverified switch: worked=%v err=%v, want no claim at all", worked, err)
	}
	var status string
	db.Raw(`SELECT status FROM cloud_scan_run WHERE id = ?`, queued.ID).Scan(&status)
	if status != models.CloudScanRunQueued {
		t.Fatalf("run status = %s, want queued: a fail-closed worker claims nothing", status)
	}

	// /capabilities reports it.
	prev := services.GraphProjection()
	services.SetGraphProjection(gate)
	defer services.SetGraphProjection(prev)
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/iga/v1/capabilities", nil)
	platform.NewIGAGraphReadController().GetCapabilities(c)
	var body struct {
		Data struct {
			GraphProjection string          `json:"graph_projection"`
			Reason          *string         `json:"reason"`
			Features        map[string]bool `json:"features"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	if body.Data.GraphProjection != services.GraphProjectionMisconfigured || body.Data.Reason == nil || *body.Data.Reason == "" {
		t.Errorf("/capabilities = %s, want misconfigured with a reason", rec.Body.String())
	}
	if len(body.Data.Features) != 8 {
		t.Errorf("features = %v, want the eight §5.3 keys", body.Data.Features)
	}
}

// B15 / T1.3. A busy barrier: the refused run goes to the BACK of the queue
// and the worker backs off, so another workspace's scan is claimed instead of
// the refused run in a tight loop.
//
// Workspace 1 is projecting (account A published, no projector has run). Its
// SECOND account's scan is queued first -- the per-connector projection
// predicate does not exclude it, so it is the barrier that refuses it.
// Workspace 2's scan is queued after.
func TestP2BusyBarrierDoesNotStarveAnotherWorkspace(t *testing.T) {
	l := newP2Lab(t, "p2-busy-1", true)
	a := oneLambda(l)
	a2 := l.account("111122223333")
	other := &p2Lab{t: t, db: l.db, ws: newWorkspace(t, l.db, "p2-busy-2"), gate: l.gate, runs: l.runs}
	t.Cleanup(other.cleanup)
	b := other.account(accountB)
	b.role("r", "AROABUSYBUSYBUSYBUSY")

	l.scan(a, "scan-worker-seed") // publishes; the barrier is now projecting
	if l.barrier() != models.PipelineProjecting {
		t.Fatalf("setup: workspace 1 barrier = %s, want projecting", l.barrier())
	}
	blocked, err := l.runs.Enqueue(l.ws, a2.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	waiting, err := other.runs.Enqueue(other.ws, b.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}

	w := services.NewAWSScanWorker(l.db, b.svc).WithOwner("busy-worker").
		WithGraphProjection(l.gate).WithScannerHook(b.hook())
	// Pass 1 claims the OLDEST run -- workspace 1's -- and is refused. It must
	// report no work, so Run sleeps its poll interval instead of spinning.
	if worked, err := w.RunOnce(context.Background()); worked || err != nil {
		t.Fatalf("refused claim: worked=%v err=%v, want worked=false (back off)", worked, err)
	}
	var st string
	l.db.Raw(`SELECT status FROM cloud_scan_run WHERE id = ?`, blocked.ID).Scan(&st)
	if st != models.CloudScanRunQueued {
		t.Fatalf("refused run is %s, want requeued", st)
	}
	// Pass 2 must take workspace 2's run: the refused one went to the back.
	if worked, err := w.RunOnce(context.Background()); !worked || err != nil {
		t.Fatalf("second pass: worked=%v err=%v", worked, err)
	}
	l.db.Raw(`SELECT status FROM cloud_scan_run WHERE id = ?`, waiting.ID).Scan(&st)
	if st != models.CloudScanRunPublished {
		t.Fatalf("workspace 2's run is %s after the second pass, want published: "+
			"the refused run was re-claimed ahead of it (starvation)", st)
	}
}

// T1.5. A reclaimed run keeps the generation assigned at its first claim: rows
// and evidence of the reclaiming attempt land at ONE generation.
func TestP2ReclaimedRunKeepsItsGeneration(t *testing.T) {
	l := newP2Lab(t, "p2-generation", true)
	a := oneLambda(l)
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	first, err := l.runs.ClaimForPipeline("dead-worker", time.Minute, time.Now())
	if err != nil || first == nil || first.ID != queued.ID {
		t.Fatalf("first claim: %v", err)
	}
	gen := first.Generation
	// The dead worker's IAM scan got as far as commitScan: scan_generation
	// moved to the run's generation. A recomputing scanner would now stamp
	// gen+1.
	l.db.Exec(`UPDATE cloud_connector SET scan_generation = ? WHERE id = ?`, gen, a.conn)
	l.db.Exec(`UPDATE cloud_scan_run SET lease_expires_at = now() - interval '1 minute' WHERE id = ?`, queued.ID)

	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner("reclaimer").
		WithGraphProjection(l.gate).WithScannerHook(a.hook())
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("reclaim: worked=%v err=%v", worked, err)
	}
	var gens []int
	l.db.Raw(`SELECT DISTINCT last_seen_generation FROM cloud_identity WHERE workspace_id = ?`, l.ws).Scan(&gens)
	if len(gens) != 1 || gens[0] != gen {
		t.Errorf("identity rows at generations %v, want only the run's own %d", gens, gen)
	}
	var obsGens []int
	l.db.Raw(`SELECT DISTINCT generation FROM cloud_observation WHERE workspace_id = ?`, l.ws).Scan(&obsGens)
	if len(obsGens) != 1 || obsGens[0] != gen {
		t.Errorf("evidence at generations %v, want only %d", obsGens, gen)
	}
	l.project("projector-after-reclaim")
}

// closedGorm is a connection whose every query fails -- the transient error a
// startup check can meet. (GORM pings at open, so an unreachable host cannot
// be opened at all; a closed pool behaves exactly like one.)
func closedGorm(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(os.Getenv("IGA_TEST_DSN")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	return db
}

// E16 / T4.8. AWS rows share the canonical tables with GitHub's, and must never
// appear in GitHub's lists: every GitHub reader filters provider = 'github'.
func TestP2AWSRowsAbsentFromGitHubReaders(t *testing.T) {
	l := newP2Lab(t, "p2-github-isolation", true)
	a := oneLambda(l)
	l.scanAndProject(a)
	if n := l.count(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'`, l.ws); n == 0 {
		t.Fatal("setup: no AWS identity was projected")
	}
	// A GitHub identity, written by the GitHub writer.
	repo := repositories.NewIGARepository(l.db)
	gh := &models.IGAIdentityAccount{WorkspaceID: l.ws, DisplayName: "octo-bot", AccountKind: "github_app"}
	if err := repo.UpsertIdentityAccount(gh); err != nil {
		t.Fatalf("github writer: %v", err)
	}
	t.Cleanup(func() { l.db.Exec(`DELETE FROM iga_identity_accounts WHERE id = ?`, gh.ID) })
	if gh.Provider != models.ProviderGitHub {
		t.Errorf("the GitHub writer stamped provider %q, want github", gh.Provider)
	}

	listed, err := repo.ListIdentityAccounts(l.ws, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != gh.ID {
		t.Errorf("GET /identity-accounts would return %d rows %+v; want only the GitHub identity", len(listed), listed)
	}
}

// B7 / B21 / E8a. A role deleted and recreated under the same ARN (new RoleId)
// is a NEW identity: the old one retires `recreated`, its edges end
// `subject_recreated`, and its same-named INLINE policy is a new incarnation --
// nothing of the old history carries over.
func TestP2RecreatedRoleIsANewObject(t *testing.T) {
	l := newP2Lab(t, "p2-recreated-role", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROAOLDOLDOLDOLDOLD1")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	a.iam.inlineRolePolicies["SharedToolRole"] = map[string]string{"ToolsInline": docToolboxRead}
	a.lambda("us-east-1", "ticket-tools", role)
	l.scanAndProject(a)

	a.role("SharedToolRole", "AROANEWNEWNEWNEWNEW2") // same name, new RoleId
	l.scanAndProject(a)

	var ids []struct {
		ID            uuid.UUID
		ImmutableKey  string
		Lifecycle     string
		RetiredReason string
	}
	l.db.Raw(`SELECT id, immutable_key, lifecycle, retired_reason FROM iga_identity_accounts
	           WHERE workspace_id = ? AND provider = 'aws' ORDER BY first_seen_at, id`, l.ws).Scan(&ids)
	if len(ids) != 2 || ids[0].ImmutableKey != "AROAOLDOLDOLDOLDOLD1" ||
		ids[0].Lifecycle != models.IGALifecycleRetired || ids[0].RetiredReason != models.RetiredRecreated ||
		ids[1].Lifecycle != models.IGALifecycleActive {
		t.Fatalf("identities = %+v, want the old retired 'recreated' and a new active one", ids)
	}
	old, neu := ids[0].ID, ids[1].ID
	for what, q := range map[string]string{
		"executes_as": `SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND target_identity_account_id = ?
		                AND state = 'ended' AND ended_reason = 'subject_recreated'`,
		"assignments": `SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ? AND holder_identity_account_id = ?
		                AND state = 'ended' AND ended_reason = 'subject_recreated'`,
		"grants": `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ?
		           AND state = 'ended' AND ended_reason = 'subject_recreated'`,
	} {
		if n := l.count(q, l.ws, old); n == 0 {
			t.Errorf("the old role's %s did not end subject_recreated", what)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND target_identity_account_id = ?
	                  AND state = 'current' AND relationship_type = 'executes_as'`, l.ws, neu); n != 1 {
		t.Errorf("the new role has %d current executes_as, want 1 (the Lambda runs as it now)", n)
	}
	// The inline policy: two incarnations, the old retired, none shared.
	var inl []struct {
		ID            uuid.UUID
		Lifecycle     string
		RetiredReason string
	}
	l.db.Raw(`SELECT id, lifecycle, retired_reason FROM iga_policy WHERE workspace_id = ? AND display_name = 'ToolsInline'
	           ORDER BY first_seen_at, id`, l.ws).Scan(&inl)
	if len(inl) != 2 || inl[0].Lifecycle != models.IGALifecycleRetired || inl[1].Lifecycle != models.IGALifecycleActive {
		t.Errorf("inline policies = %+v, want the old incarnation retired and a new one", inl)
	}
	if n := l.count(`SELECT count(*) FROM (SELECT source_key FROM iga_entitlements WHERE workspace_id = ?
	                  AND provider = 'aws' GROUP BY source_key HAVING count(*) > 1) d`, l.ws); n != 0 {
		t.Errorf("%d statement keys reused across incarnations", n)
	}
}
