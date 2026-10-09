package integration

// GET /identities/:id/permissions over time (§5.3, T6.3; §2.6, §5.1; D-12,
// D-25, D-74): what stops applying -- a membership the user left, a statement
// an edit replaced, a policy recreated under the same ARN -- leaves the
// default tab and returns, marked ended, only on request; a stale grant says
// why it is stale; and Access Advisor never mixes a newer, unpublished scan
// into the revision it is read at. Every fixture runs through the real
// worker and projector.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// §2.6 / D-12: a group's policies reach a user ONLY through a live member_of.
// priya leaves ops (the next scan's GroupList no longer names it), so by
// default she inherits nothing -- not the group's policies, not its grants,
// which are still current for the GROUP -- and with include_ended ops
// returns under its ENDED membership, dated and marked.
func TestP2IdetailPermissionsLeftGroup(t *testing.T) {
	l, a, f, _ := idetailPriyaLab(t, "p2-idetail-perm-leftgroup")
	api := l.api()
	priyaID, opsID := idetailIdentityID(t, l, "priya"), idetailIdentityID(t, l, "ops")
	path := "/identities/" + priyaID.String() + "/permissions"
	if inh := digl(idetailGet(t, api, path), "data", "inherited"); len(inh) != 1 {
		t.Fatalf("setup: inherited = %s, want ops", idetailJSON(inh))
	}

	a.iam.userGroups["priya"] = nil
	time.Sleep(10 * time.Millisecond)
	s3bScanAndProject(l, a, f)

	d := dig(idetailGet(t, api, path), "data")
	if inh := digl(d, "inherited"); len(inh) != 0 {
		t.Errorf("inherited after leaving ops = %s, want []: an ended membership passes nothing on", idetailJSON(inh))
	}
	if got := fmt.Sprint(idetailNames(digl(d, "policies"), "name")); got != "[PriyaAttached PriyaOwn]" {
		t.Errorf("policies = %v, want her own two, unchanged", got)
	}
	// The group itself still holds its policies and current grants: what
	// ended is the membership, and only that.
	own := digl(idetailGet(t, api, "/identities/"+opsID.String()+"/permissions"), "data", "policies")
	if got := fmt.Sprint(idetailNames(own, "name")); got != "[OpsInline OpsRead]" {
		t.Errorf("ops' own policies = %v, want [OpsInline OpsRead]", got)
	}

	all := digl(idetailGet(t, api, path+qs("include_ended", "true")), "data", "inherited")
	if len(all) != 1 || digs(all[0], "group") != refOf("identity", opsID) {
		t.Fatalf("include_ended inherited = %s, want ops under its ended membership", idetailJSON(all))
	}
	m := dig(all[0], "membership")
	if digs(m, "state") != "ended" || digs(m, "valid_to") == "" || digs(m, "ended_reason") != models.EndedNotSeen ||
		digs(m, "type") != models.RelTypeMemberOf {
		t.Errorf("membership = %s, want member_of, ended not_seen, with valid_to", idetailJSON(m))
	}
	for _, p := range digl(all[0], "policies") {
		if digs(p, "assignment", "via_group") != refOf("identity", opsID) {
			t.Errorf("%s via_group = %v, want ops", digs(p, "name"), dig(p, "assignment", "via_group"))
		}
	}
}

// §2.6 / D-12 / E8(b): what a policy no longer has.
//
//   - A Sid-less statement is REPLACED by an edit, never revised: by default
//     the policy shows exactly its two statements, the new one and the one the
//     edit did not touch -- never the retired one beside them as a second
//     "index 1".
//   - With include_ended the replaced statement returns, ended, with the grant
//     that ended with it, AFTER every live statement (it is history, not a
//     part of the policy: were it ordered by index it would sort before the
//     untouched index 2); and a policy RECREATED under the same ARN (new
//     PolicyId) shows its old incarnation's ended assignment WITH the
//     statements it declared and their ended grants -- not "statements: []",
//     which would read as a policy that declared nothing.
func TestP2IdetailPermissionsReplacedAndRecreated(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-perm-replaced", true)
	a := l.account(accountA)
	a.role("ReplaceRole", "AROAREPLACEROLEREPLA")
	toolbox := a.managed("ToolboxRead", idetailTwoSidless("s3:GetObject"))
	ticket := a.managed("TicketRead", s3aDoc("ReadTickets", "s3:GetObject", "arn:aws:s3:::support-tickets/*"))
	a.iam.policyIDs[ticket] = "ANPAIDETAILTICKETOLD"
	a.attach("ReplaceRole", toolbox)
	a.attach("ReplaceRole", ticket)
	l.scanAndProject(a)
	var oldToolboxGrant uuid.UUID
	if err := l.db.Raw(`SELECT g.id FROM iga_access_edges g
	                      JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                      JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                     WHERE g.workspace_id = ? AND p.display_name = 'ToolboxRead' AND e.sid = ''
	                       AND position('s3:GetObject' in e.native_rights::text) > 0`,
		l.ws).Row().Scan(&oldToolboxGrant); err != nil {
		t.Fatalf("ToolboxRead's s3:GetObject grant: %v", err)
	}
	oldTicketGrant := idetailGrantOf(t, l, "ReplaceRole", "TicketRead", "ReadTickets")
	var oldTicket uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_policy WHERE workspace_id = ? AND display_name = 'TicketRead'`,
		l.ws).Row().Scan(&oldTicket); err != nil {
		t.Fatalf("old TicketRead: %v", err)
	}

	a.managed("ToolboxRead", idetailTwoSidless("s3:PutObject"))
	a.iam.policyIDs[ticket] = "ANPAIDETAILTICKETNEW"
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	api := l.api()
	path := "/identities/" + idetailIdentityID(t, l, "ReplaceRole").String() + "/permissions"

	d := dig(idetailGet(t, api, path), "data")
	if got := fmt.Sprint(idetailNames(digl(d, "policies"), "name")); got != "[TicketRead ToolboxRead]" {
		t.Errorf("policies = %v, want [TicketRead ToolboxRead]: the recreated policy's old incarnation only on request", got)
	}
	tb := digl(idetailPolicy(t, digl(d, "policies"), "ToolboxRead"), "statements")
	if len(tb) != 2 || fmt.Sprint(dig(tb[0], "actions")) != "[s3:PutObject]" || digs(tb[0], "state") != "current" ||
		num(tb[0], "index") != 1 || digs(tb[0], "grant_state") != "current" ||
		fmt.Sprint(dig(tb[1], "actions")) != "[s3:ListBucket]" || num(tb[1], "index") != 2 || digs(tb[1], "state") != "current" {
		t.Errorf("ToolboxRead = %s, want exactly its new statement and the untouched one (the replaced one is not part of "+
			"the policy)", idetailJSON(tb))
	}
	tr := idetailPolicy(t, digl(d, "policies"), "TicketRead")
	if digs(tr, "ref") == refOf("policy", oldTicket) || len(digl(tr, "statements")) != 1 {
		t.Errorf("TicketRead = %s, want the NEW incarnation with its one statement", idetailJSON(tr))
	}

	all := dig(idetailGet(t, api, path+qs("include_ended", "true")), "data")
	var toolboxes, liveTickets, endedTickets []map[string]any
	for _, p := range digl(all, "policies") {
		pm := p.(map[string]any)
		switch {
		case digs(pm, "name") == "ToolboxRead":
			toolboxes = append(toolboxes, pm)
		case digs(pm, "assignment", "state") == "ended":
			endedTickets = append(endedTickets, pm)
		default:
			liveTickets = append(liveTickets, pm)
		}
	}
	if len(toolboxes) != 1 || len(liveTickets) != 1 || len(endedTickets) != 1 {
		t.Fatalf("include_ended policies = %s, want ToolboxRead once, TicketRead current and its ended old incarnation",
			idetailJSON(digl(all, "policies")))
	}
	sts := digl(toolboxes[0], "statements")
	if len(sts) != 3 || fmt.Sprint(dig(sts[0], "actions")) != "[s3:PutObject]" || digs(sts[0], "state") != "current" ||
		fmt.Sprint(dig(sts[1], "actions")) != "[s3:ListBucket]" || digs(sts[1], "state") != "current" {
		t.Fatalf("include_ended ToolboxRead = %s, want the live statements first, in index order, then the replaced one",
			idetailJSON(sts))
	}
	if old := sts[2]; fmt.Sprint(dig(old, "actions")) != "[s3:GetObject]" || digs(old, "state") != "ended" ||
		digs(old, "grant") != refOf("grant", oldToolboxGrant) || digs(old, "grant_state") != "ended" {
		t.Errorf("replaced statement = %s, want s3:GetObject, ended, with its ended grant %s", idetailJSON(old), oldToolboxGrant)
	}
	old := endedTickets[0]
	ost := digl(old, "statements")
	if digs(old, "ref") != refOf("policy", oldTicket) || digs(old, "assignment", "valid_to") == "" ||
		len(ost) != 1 || digs(ost[0], "sid") != "ReadTickets" || digs(ost[0], "state") != "ended" ||
		digs(ost[0], "grant") != refOf("grant", oldTicketGrant) || digs(ost[0], "grant_state") != "ended" {
		t.Errorf("old TicketRead = %s, want its ended assignment with ReadTickets, ended, and the grant that ended with it",
			idetailJSON(old))
	}
	if n := len(digl(liveTickets[0], "statements")); n != 1 {
		t.Errorf("new TicketRead statements = %d, want 1: the old incarnation's statements are not the new one's", n)
	}
}

// D-25 / §5.1: Access Advisor is the answer of the run the revision was built
// from, never of a newer scan that has not published. cloud_usage is upserted
// in place, so a scan collected but not yet projected (the real pipeline,
// stopped between the worker and the projector) has already rewritten the
// rows: the tab says not_collected (newer_scan_not_published) rather than
// mixing that scan's services into the pinned revision, and collects again
// once the scan publishes.
func TestP2IdetailActivityNewerScanNotMixed(t *testing.T) {
	l, a, f, _ := idetailPriyaLab(t, "p2-idetail-activity-newer")
	api := l.api()
	path := "/identities/" + idetailIdentityID(t, l, "priya").String() + "/permissions"
	before := idetailGet(t, api, path)
	if act := dig(before, "data", "activity"); digs(act, "state") != "collected" {
		t.Fatalf("setup: activity = %s, want collected", idetailJSON(act))
	}

	f.activity = &fakeActivity{services: []iamtypes.ServiceLastAccessed{
		{ServiceNamespace: aws.String("ec2"), ServiceName: aws.String("Amazon EC2"), LastAuthenticated: ago(time.Hour)},
	}}
	time.Sleep(10 * time.Millisecond)
	scanSeq++
	s3bScan(l, a, f, fmt.Sprintf("scan-worker-idetail-newer-%d", scanSeq)) // collected, NOT projected

	mid := idetailGet(t, api, path)
	if num(mid, "meta", "rev") != num(before, "meta", "rev") {
		t.Fatalf("rev moved from %v to %v without a projection", num(before, "meta", "rev"), num(mid, "meta", "rev"))
	}
	act := dig(mid, "data", "activity").(map[string]any)
	if act["state"] != "not_collected" || act["reason"] != "newer_scan_not_published" || act["services"] != nil {
		t.Errorf("activity while a newer scan is unpublished = %s, want not_collected (newer_scan_not_published), "+
			"services null: never that scan's rows at this revision", idetailJSON(act))
	}

	l.project(fmt.Sprintf("projector-idetail-newer-%d", scanSeq))
	after := dig(idetailGet(t, api, path), "data", "activity")
	if digs(after, "state") != "collected" || fmt.Sprint(idetailNames(digl(after, "services"), "namespace")) != "[ec2]" {
		t.Errorf("activity once the scan published = %s, want collected with its one service", idetailJSON(after))
	}
}

// The newer scan leaves no row to betray it: it REACHED activity, AWS
// reported no service for anyone, and its reconcile deleted every row the
// revision's run wrote. Nothing in cloud_usage carries the newer generation,
// yet the revision's answer (s3, dynamodb) is gone: reading what is left as
// "collected, no services" would state that AWS reported no attempts at a
// revision whose run saw two. The newer run's coverage says it reached
// activity, so the tab is not_collected until it publishes -- and then it is
// that run's answer, collected with services [].
func TestP2IdetailActivityNewerScanDeletedEverything(t *testing.T) {
	l, a, f, _ := idetailPriyaLab(t, "p2-idetail-activity-emptied")
	api := l.api()
	path := "/identities/" + idetailIdentityID(t, l, "priya").String() + "/permissions"
	before := idetailGet(t, api, path)
	if act := dig(before, "data", "activity"); digs(act, "state") != "collected" || len(digl(act, "services")) != 2 {
		t.Fatalf("setup: activity = %s, want collected with s3 and dynamodb", idetailJSON(act))
	}

	f.activity = &fakeActivity{} // every report completes with no service
	time.Sleep(10 * time.Millisecond)
	scanSeq++
	run := s3bScan(l, a, f, fmt.Sprintf("scan-worker-idetail-emptied-%d", scanSeq)) // collected, NOT projected
	var left int64
	if err := l.db.Raw(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ? AND connector_id = ?`,
		l.ws, a.conn).Row().Scan(&left); err != nil {
		t.Fatalf("count usage: %v", err)
	}
	if left != 0 || s3bRunCoverage(t, l, run.ID).Surfaces[models.SurfaceActivity].State != models.CloudCoverageReached {
		t.Fatalf("setup: %d usage rows left, activity %+v: want the newer run to have reached activity and reconciled "+
			"every row away", left, s3bRunCoverage(t, l, run.ID).Surfaces[models.SurfaceActivity])
	}

	mid := idetailGet(t, api, path)
	if num(mid, "meta", "rev") != num(before, "meta", "rev") {
		t.Fatalf("rev moved from %v to %v without a projection", num(before, "meta", "rev"), num(mid, "meta", "rev"))
	}
	act := dig(mid, "data", "activity").(map[string]any)
	if act["state"] != "not_collected" || act["reason"] != "newer_scan_not_published" || act["services"] != nil {
		t.Errorf("activity after a newer scan emptied cloud_usage = %s, want not_collected (newer_scan_not_published): "+
			"the revision's run saw two services", idetailJSON(act))
	}

	l.project(fmt.Sprintf("projector-idetail-emptied-%d", scanSeq))
	after := dig(idetailGet(t, api, path), "data", "activity")
	if digs(after, "state") != "collected" || len(digl(after, "services")) != 0 || dig(after, "services") == nil {
		t.Errorf("activity once the scan published = %s, want collected with services [] (its own answer)", idetailJSON(after))
	}
}

// The newer scan leaves nothing in its coverage to betray it: one identity's
// report fails, so activity is PARTIAL (never reconciled), yet every other
// identity's rows were rewritten in place with the newer generation -- priya's
// s3 row now holds the newer scan's date. Read by the revision's generation
// alone, priya would show dynamodb without s3, an answer no scan ever gave;
// the rows' newer generation is what says the revision's answer is gone.
func TestP2IdetailActivityNewerPartialScanNotMixed(t *testing.T) {
	l, a, f, _ := idetailPriyaLab(t, "p2-idetail-activity-partial")
	api := l.api()
	path := "/identities/" + idetailIdentityID(t, l, "priya").String() + "/permissions"
	before := idetailGet(t, api, path)
	if got := fmt.Sprint(idetailNames(digl(before, "data", "activity", "services"), "namespace")); got != "[dynamodb s3]" {
		t.Fatalf("setup: services = %s, want [dynamodb s3]", got)
	}

	f.activity = &idetailSplitActivity{failARN: "arn:aws:iam::" + accountA + ":group/ops",
		services: []iamtypes.ServiceLastAccessed{
			{ServiceNamespace: aws.String("s3"), ServiceName: aws.String("Amazon S3"), LastAuthenticated: ago(time.Hour)},
			{ServiceNamespace: aws.String("ec2"), ServiceName: aws.String("Amazon EC2"), LastAuthenticated: ago(time.Hour)},
		}}
	time.Sleep(10 * time.Millisecond)
	scanSeq++
	run := s3bScan(l, a, f, fmt.Sprintf("scan-worker-idetail-partial-%d", scanSeq)) // collected, NOT projected
	if st := s3bRunCoverage(t, l, run.ID).Surfaces[models.SurfaceActivity].State; st != models.CloudCoveragePartial {
		t.Fatalf("setup: the newer run's activity is %s, want partial (ops' report failed)", st)
	}

	mid := idetailGet(t, api, path)
	if num(mid, "meta", "rev") != num(before, "meta", "rev") {
		t.Fatalf("rev moved from %v to %v without a projection", num(before, "meta", "rev"), num(mid, "meta", "rev"))
	}
	act := dig(mid, "data", "activity").(map[string]any)
	if act["state"] != "not_collected" || act["reason"] != "newer_scan_not_published" || act["services"] != nil {
		t.Errorf("activity while a partial newer scan is unpublished = %s, want not_collected (newer_scan_not_published)",
			idetailJSON(act))
	}

	l.project(fmt.Sprintf("projector-idetail-partial-%d", scanSeq))
	after := dig(idetailGet(t, api, path), "data", "activity")
	if digs(after, "state") != "collected" || fmt.Sprint(idetailNames(digl(after, "services"), "namespace")) != "[ec2 s3]" {
		t.Errorf("activity once the partial scan published = %s, want collected with exactly its rows [ec2 s3] "+
			"(dynamodb, which it did not report, is an older answer)", idetailJSON(after))
	}
}

// idetailSplitActivity is Access Advisor where failARN's report job fails and
// every other identity's completes with services, at once (the job id is the
// principal's ARN): a partial activity surface that still rewrote rows.
type idetailSplitActivity struct {
	failARN  string
	services []iamtypes.ServiceLastAccessed
}

func (f *idetailSplitActivity) GenerateServiceLastAccessedDetails(_ context.Context,
	in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: in.Arn}, nil
}

func (f *idetailSplitActivity) GetServiceLastAccessedDetails(_ context.Context,
	in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	if aws.ToString(in.JobId) == f.failARN {
		return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeFailed,
			Error: &iamtypes.ErrorDetails{Message: aws.String("report unavailable")}}, nil
	}
	completed := time.Now().Add(-2 * time.Hour)
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted,
		JobCompletionDate: &completed, ServicesLastAccessed: f.services}, nil
}

// idetailTwoSidless is a policy of two Sid-less statements: first the given
// action on the ticket objects, then s3:ListBucket on the bucket.
func idetailTwoSidless(first string) string {
	return `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Action":"` + first + `","Resource":"arn:aws:s3:::support-tickets/*"},` +
		`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::support-tickets"}]}`
}
