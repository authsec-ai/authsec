package integration

// GET /identities/:id/permissions (§5.3, T6.3; §2.6, §2.14.8; D-12, D-77,
// D-84, D-86): E4's priya -- her own policies, her group's under inherited
// with via_group, her boundary under boundary and NEVER as a grant, a Deny
// under its policy with no grant -- and Access Advisor labelled as attempts,
// collected or honestly not.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

const idetailPriyaAttached = `{"Version":"2012-10-17","Statement":[` +
	`{"Sid":"AllowList","Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::priya-scratch"},` +
	`{"Sid":"DenyDelete","Effect":"Deny","Action":["s3:DeleteObject","s3:DeleteBucket"],"Resource":"*"},` +
	`{"Sid":"AllButFinance","Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::finance/*",` +
	`"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`

// idetailPriyaLab is E4's account: priya with an inline policy of her own, an
// attached policy with an Allow, a Deny and a NotResource statement, an
// AWS-managed boundary, and membership of ops, which has an attached and an
// inline policy of its own. Access Advisor reports two services for every
// identity (the lab's activity fake answers every identity alike).
func idetailPriyaLab(t *testing.T, name string) (*p2Lab, *p2Account, *s3bFakes, models.CloudScanRun) {
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	opsRead := a.managed("OpsRead", s3aDoc("ReadOps", "s3:GetObject", "arn:aws:s3:::ops-bucket/*"))
	attached := a.managed("PriyaAttached", idetailPriyaAttached)
	boundary := s3aAWSManaged(a, "PowerUserAccess", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","NotAction":["iam:*","organizations:*"],"Resource":"*"}]}`)
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aGroupAttach(t, a, "ops", opsRead)
	s3aGroupInline(t, a, "ops", "OpsInline", s3aDoc("ListOps", "s3:ListBucket", "arn:aws:s3:::ops-bucket"))
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aEditUser(t, a, "priya", func(u *iamtypes.User) { u.PermissionsBoundary = s3aBoundary(boundary) })
	s3aJoin(a, "priya", "ops")
	a.iam.inlineUserPolicies["priya"] = map[string]string{
		"PriyaOwn": s3aDoc("OwnRead", "s3:GetObject", "arn:aws:s3:::priya-scratch/*"),
	}
	a.iam.attachedUserPolicies["priya"] = []iamtypes.AttachedPolicy{
		{PolicyArn: aws.String(attached), PolicyName: aws.String("PriyaAttached")},
	}
	f := &s3bFakes{activity: &fakeActivity{services: []iamtypes.ServiceLastAccessed{
		{ServiceNamespace: aws.String("s3"), ServiceName: aws.String("Amazon S3"), LastAuthenticated: ago(72 * time.Hour)},
		// Reported with no date: no attempt in the tracking period.
		{ServiceNamespace: aws.String("dynamodb"), ServiceName: aws.String("Amazon DynamoDB")},
	}}}
	run := s3bScanAndProject(l, a, f)
	return l, a, f, run
}

// idetailGrantOf is the grant row of (holder name, policy name, Sid).
func idetailGrantOf(t *testing.T, l *p2Lab, holder, policy, sid string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT g.id FROM iga_access_edges g
	                      JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                      JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                      JOIN iga_identity_accounts h ON h.workspace_id = g.workspace_id AND h.id = g.subject_identity_account_id
	                     WHERE g.workspace_id = ? AND h.display_name = ? AND p.display_name = ? AND e.sid = ? AND g.state <> 'ended'`,
		l.ws, holder, policy, sid).Row().Scan(&id); err != nil {
		t.Fatalf("grant %s/%s/%s: %v", holder, policy, sid, err)
	}
	return id
}

// idetailStatement finds a statement by Sid in a policy's statements.
func idetailStatement(t *testing.T, policy map[string]any, sid string) map[string]any {
	t.Helper()
	return idetailByRef(t, digl(policy, "statements"), sid, "sid")
}

func TestP2IdetailPermissionsUserGroupBoundary(t *testing.T) {
	l, _, _, _ := idetailPriyaLab(t, "p2-idetail-perm")
	api := l.api()
	priyaID, opsID := idetailIdentityID(t, l, "priya"), idetailIdentityID(t, l, "ops")
	body := idetailGet(t, api, "/identities/"+priyaID.String()+"/permissions")
	d := dig(body, "data").(map[string]any)

	// Her OWN policies only: never the boundary, never the group's (§2.6:
	// nothing is copied onto the user), by policy name.
	pols := digl(d, "policies")
	if got := fmt.Sprint(idetailNames(pols, "name")); got != "[PriyaAttached PriyaOwn]" {
		t.Fatalf("policies = %v, want [PriyaAttached PriyaOwn]: %s", got, idetailJSON(pols))
	}
	own := idetailPolicy(t, pols, "PriyaOwn")
	if digs(own, "kind") != models.PolicyKindInline || digs(own, "assignment", "kind") != models.AssignmentInline ||
		dig(own, "assignment", "via_group") != nil || digs(own, "assignment", "state") != "current" ||
		!strings.HasPrefix(digs(own, "assignment", "claim"), "assignment:") || digs(own, "assignment", "valid_from") == "" ||
		!strings.HasPrefix(digs(own, "ref"), "policy:") {
		t.Errorf("PriyaOwn = %s, want inline, her own current assignment, via_group null", idetailJSON(own))
	}
	st := idetailStatement(t, own, "OwnRead")
	if num(st, "index") != 1 || digs(st, "effect") != models.EffectAllow || fmt.Sprint(dig(st, "actions")) != "[s3:GetObject]" ||
		len(digl(st, "not_actions")) != 0 || dig(st, "condition") != nil || num(st, "revision_count") != 1 ||
		digs(st, "grant") != refOf("grant", idetailGrantOf(t, l, "priya", "PriyaOwn", "OwnRead")) ||
		digs(st, "grant_state") != "current" || digs(st, "state") != "current" || !strings.HasPrefix(digs(st, "ref"), "statement:") {
		t.Errorf("OwnRead = %s, want index 1 (D-84), allow, its actions, HER grant, one revision", idetailJSON(st))
	}
	if tg := digl(st, "targets"); len(tg) != 1 || digs(tg[0], "text") != "arn:aws:s3:::priya-scratch/*" ||
		digs(tg[0], "kind") != "selector" || digs(tg[0], "mode") != models.TargetResource ||
		!strings.HasPrefix(digs(tg[0], "ref"), "resource:") || !strings.HasPrefix(digs(tg[0], "claim"), "target:") {
		t.Errorf("OwnRead targets = %s, want the selector, mode resource", idetailJSON(tg))
	}

	// The attached policy: statements by index; the Deny under its policy,
	// effect deny, NO grant (B10); NotResource labelled in both modes.
	att := idetailPolicy(t, pols, "PriyaAttached")
	if got := fmt.Sprint(idetailNames(digl(att, "statements"), "sid")); got != "[AllowList DenyDelete AllButFinance]" {
		t.Errorf("PriyaAttached statements = %v, want document order", got)
	}
	deny := idetailStatement(t, att, "DenyDelete")
	if digs(deny, "effect") != models.EffectDeny || dig(deny, "grant") != nil || dig(deny, "grant_state") != nil ||
		num(deny, "index") != 2 || fmt.Sprint(dig(deny, "actions")) != "[s3:DeleteObject s3:DeleteBucket]" {
		t.Errorf("DenyDelete = %s, want effect deny under its policy, no grant, index 2", idetailJSON(deny))
	}
	nr := idetailStatement(t, att, "AllButFinance")
	modes := map[string]string{}
	for _, tg := range digl(nr, "targets") {
		modes[digs(tg, "text")] = digs(tg, "mode")
	}
	if len(modes) != 2 || modes["*"] != models.TargetResource || modes["arn:aws:s3:::finance/*"] != models.TargetNotResource ||
		digs(nr, "condition", "Bool", "aws:SecureTransport") != "true" || digs(nr, "grant") == "" {
		t.Errorf("AllButFinance = %s, want the implicit * (resource) and finance/* (not_resource, an exclusion), its condition verbatim, its grant",
			idetailJSON(nr))
	}

	// The boundary: here ONLY, and never a grant.
	b := dig(d, "boundary", "policy")
	if b == nil || digs(b, "name") != "PowerUserAccess" || digs(b, "kind") != models.PolicyKindAWSManaged ||
		digs(b, "assignment", "kind") != models.AssignmentBoundary || dig(d, "boundary", "others") != nil {
		t.Fatalf("boundary = %s, want PowerUserAccess, aws_managed, assignment kind boundary", idetailJSON(dig(d, "boundary")))
	}
	for _, s := range digl(b, "statements") {
		if dig(s, "grant") != nil || dig(s, "grant_state") != nil {
			t.Errorf("boundary statement %s names a grant: a boundary is a ceiling, never a grant (§2.6)", idetailJSON(s))
		}
		if fmt.Sprint(dig(s, "not_actions")) != "[iam:* organizations:*]" || len(digl(s, "actions")) != 0 {
			t.Errorf("boundary statement = %s, want its NotAction verbatim", idetailJSON(s))
		}
	}
	if len(digl(b, "statements")) != 1 {
		t.Errorf("boundary statements = %s, want its one statement", idetailJSON(digl(b, "statements")))
	}

	// Inherited: the group, its membership claim, and the GROUP's policies and
	// grants, each assignment via_group = the group.
	inh := digl(d, "inherited")
	if len(inh) != 1 || digs(inh[0], "group") != refOf("identity", opsID) || digs(inh[0], "name") != "ops" ||
		digs(inh[0], "membership", "type") != models.RelTypeMemberOf || digs(inh[0], "membership", "state") != "current" ||
		!strings.HasPrefix(digs(inh[0], "membership", "claim"), "relationship:") {
		t.Fatalf("inherited = %s, want ops with its current membership", idetailJSON(inh))
	}
	gp := digl(inh[0], "policies")
	if got := fmt.Sprint(idetailNames(gp, "name")); got != "[OpsInline OpsRead]" {
		t.Errorf("ops' policies = %v, want [OpsInline OpsRead]", got)
	}
	for _, p := range gp {
		if digs(p, "assignment", "via_group") != refOf("identity", opsID) {
			t.Errorf("inherited %s via_group = %v, want the group", digs(p, "name"), dig(p, "assignment", "via_group"))
		}
	}
	read := idetailStatement(t, idetailPolicy(t, gp, "OpsRead"), "ReadOps")
	if digs(read, "grant") != refOf("grant", idetailGrantOf(t, l, "ops", "OpsRead", "ReadOps")) {
		t.Errorf("inherited ReadOps grant = %v, want the GROUP's grant (nothing is copied onto the user)", dig(read, "grant"))
	}

	// Access Advisor: attempts, labelled (§2.14.8).
	act := dig(d, "activity").(map[string]any)
	note := strings.ToLower(digs(act, "tracking_note"))
	if act["source"] != "access_advisor" || act["state"] != "collected" || act["reason"] != nil ||
		!strings.Contains(note, "attempt") || !strings.Contains(note, "cloudtrail") || !strings.Contains(note, "resource-based") {
		t.Errorf("activity = %s, want collected from access_advisor, the note naming attempts, CloudTrail and what is excluded", idetailJSON(act))
	}
	for _, forbidden := range []string{"last used", "never used", "unused"} {
		if strings.Contains(note, forbidden) {
			t.Errorf("tracking_note says %q (§2.14.8 forbids it): %s", forbidden, note)
		}
	}
	svcs := digl(act, "services")
	if len(svcs) != 2 || digs(svcs[0], "namespace") != "dynamodb" || dig(svcs[0], "last_authenticated_attempt") != nil ||
		digs(svcs[1], "namespace") != "s3" || digs(svcs[1], "last_authenticated_attempt") == "" {
		t.Errorf("services = %s, want dynamodb (no attempt reported: null) and s3 (dated)", idetailJSON(svcs))
	}
	if d["truncated"] != false || len(digl(body, "meta", "coverage")) != 0 {
		t.Errorf("truncated = %v, meta.coverage = %s; want false and [] on a complete scan", d["truncated"], idetailJSON(dig(body, "meta", "coverage")))
	}

	// The group's own tab: its policies as its own, no boundary, no inherited.
	g := dig(idetailGet(t, api, "/identities/"+opsID.String()+"/permissions"), "data").(map[string]any)
	if got := fmt.Sprint(idetailNames(digl(g, "policies"), "name")); got != "[OpsInline OpsRead]" ||
		dig(g, "boundary", "policy") != nil || len(digl(g, "inherited")) != 0 {
		t.Errorf("ops' permissions = %s, want its two policies, boundary null, inherited []", idetailJSON(g))
	}
	for _, p := range digl(g, "policies") {
		if dig(p, "assignment", "via_group") != nil {
			t.Errorf("the group's own %s via_group = %v, want null", digs(p, "name"), dig(p, "assignment", "via_group"))
		}
	}
}

// A boundary and a Deny never render as grants -- whatever a defective row
// says. The projector refuses both (UpsertGrant, projectGrants), and 036 has
// no CHECK against either, so the read's own guards are what stand between a
// projector defect and "a policy grants this": grants are looked up only
// through assignments that can grant, and only for Allow statements (§3 rule
// 7). The defective grant rows below are INSERTED DIRECTLY -- a state the
// real pipeline cannot produce.
func TestP2IdetailPermissionsNeverGrantBoundaryOrDeny(t *testing.T) {
	l, _, _, _ := idetailPriyaLab(t, "p2-idetail-perm-guard")
	priyaID := idetailIdentityID(t, l, "priya")
	template := idetailGrantOf(t, l, "priya", "PriyaOwn", "OwnRead")
	defect := func(policy, kind, effect, suffix string) {
		t.Helper()
		res := l.db.Exec(`INSERT INTO iga_access_edges (workspace_id, subject_kind, subject_id, subject_identity_account_id,
		                         provider, entitlement_id, assignment_id, direction, path_kind, calculation_state,
		                         effective_conclusion, basis, state, source_key, partition_key, connector_id)
		                  SELECT g.workspace_id, g.subject_kind, g.subject_id, g.subject_identity_account_id, g.provider,
		                         e.id, a.id, g.direction, g.path_kind, g.calculation_state, g.effective_conclusion,
		                         g.basis, 'current', g.source_key || ?, g.partition_key, g.connector_id
		                    FROM iga_access_edges g, iga_policy_assignment a
		                    JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
		                    JOIN iga_entitlements e ON e.workspace_id = p.workspace_id AND e.policy_id = p.id
		                   WHERE g.id = ? AND a.workspace_id = ? AND a.holder_identity_account_id = ?
		                     AND p.display_name = ? AND a.assignment_kind = ? AND e.effect = ?`,
			suffix, template, l.ws, priyaID, policy, kind, effect)
		if res.Error != nil || res.RowsAffected == 0 {
			t.Fatalf("seed defective %s grant: %v (%d rows)", suffix, res.Error, res.RowsAffected)
		}
	}
	defect("PowerUserAccess", models.AssignmentBoundary, models.EffectAllow, "#defect-boundary")
	defect("PriyaAttached", models.AssignmentAttached, models.EffectDeny, "#defect-deny")
	// A replaced boundary whose partition could not end it: a STALE boundary
	// assignment beside the current one, on a policy whose name sorts first.
	// DIRECT INSERT (the lab cannot deny the assignment partition alone).
	if res := l.db.Exec(`INSERT INTO iga_policy_assignment (workspace_id, policy_id, holder_identity_account_id,
	                            assignment_kind, basis, state, source_key, partition_key, connector_id)
	                     SELECT a.workspace_id, p.id, a.holder_identity_account_id, 'boundary', 'declared', 'stale',
	                            a.source_key || '#replaced', a.partition_key, a.connector_id
	                       FROM iga_policy_assignment a
	                       JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.display_name = 'OpsRead'
	                      WHERE a.workspace_id = ? AND a.holder_identity_account_id = ? AND a.assignment_kind = 'boundary'`,
		l.ws, priyaID); res.Error != nil || res.RowsAffected != 1 {
		t.Fatalf("seed a stale boundary: %v (%d rows)", res.Error, res.RowsAffected)
	}

	d := dig(idetailGet(t, l.api(), "/identities/"+priyaID.String()+"/permissions"), "data")
	for _, s := range digl(d, "boundary", "policy", "statements") {
		if dig(s, "grant") != nil {
			t.Errorf("boundary statement renders grant %v: a boundary never grants, whatever a row says", dig(s, "grant"))
		}
	}
	if deny := idetailStatement(t, idetailPolicy(t, digl(d, "policies"), "PriyaAttached"), "DenyDelete"); dig(deny, "grant") != nil {
		t.Errorf("Deny statement renders grant %v: a Deny is never access (§3 rule 7)", dig(deny, "grant"))
	}
	if got := fmt.Sprint(idetailNames(digl(d, "policies"), "name")); got != "[PriyaAttached PriyaOwn]" {
		t.Errorf("policies = %v: a boundary must never appear among them", got)
	}
	// The boundary in force is the current one; the stale one is not dropped.
	if digs(d, "boundary", "policy", "name") != "PowerUserAccess" || digs(d, "boundary", "policy", "assignment", "state") != "current" {
		t.Errorf("boundary.policy = %s, want the CURRENT boundary, not the alphabetically first", idetailJSON(dig(d, "boundary", "policy")))
	}
	others := digl(d, "boundary", "others")
	if len(others) != 1 || digs(others[0], "name") != "OpsRead" || digs(others[0], "assignment", "state") != "stale" {
		t.Errorf("boundary.others = %s, want the stale OpsRead boundary, marked", idetailJSON(others))
	}
	for _, s := range digl(others, 0, "statements") {
		if dig(s, "grant") != nil {
			t.Errorf("stale boundary statement renders grant %v: OpsRead's grants are the group's, never a boundary's", dig(s, "grant"))
		}
	}
}

// Activity is not_collected -- never "no attempts" -- when the run did not
// read it for THIS principal (D-86). The 500-identity cap cannot be reached
// with the lab's fakes at a sane cost, so the run's stamped activity coverage
// is set directly to what a capped scan stamps (partial, capped_after); the
// successor-principal and stale-row cases are likewise direct writes of states
// the fakes cannot produce. Each says so.
func TestP2IdetailActivityNotCollected(t *testing.T) {
	l, a, f, run := idetailPriyaLab(t, "p2-idetail-activity")
	api := l.api()
	priyaID, opsID := idetailIdentityID(t, l, "priya"), idetailIdentityID(t, l, "ops")
	activity := func(id uuid.UUID) map[string]any {
		t.Helper()
		return dig(idetailGet(t, api, "/identities/"+id.String()+"/permissions"), "data", "activity").(map[string]any)
	}
	if act := activity(priyaID); act["state"] != "collected" {
		t.Fatalf("setup: priya's activity = %s, want collected", idetailJSON(act))
	}

	// A row the run did not confirm (an older generation) is not the
	// revision's answer. DIRECT INSERT: an older scan's leftover.
	var cloudPriya uuid.UUID
	l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND name = 'priya'`, l.ws).Row().Scan(&cloudPriya)
	if err := l.db.Exec(`INSERT INTO cloud_usage (workspace_id, connector_id, identity_id, service, source, last_used_at, last_seen_generation)
	                     VALUES (?, ?, ?, 'ec2', 'service_last_accessed', now(), ?)`,
		l.ws, a.conn, cloudPriya, run.Generation-1).Error; err != nil {
		t.Fatalf("seed an older usage row: %v", err)
	}
	if got := idetailNames(digl(activity(priyaID), "services"), "namespace"); fmt.Sprint(got) != "[dynamodb s3]" {
		t.Errorf("services = %v, want [dynamodb s3]: a row the run did not confirm is not part of its answer", got)
	}

	// A capped run: an identity whose ARN sorts after capped_after was not
	// sampled -- not_collected, never "no attempts". DIRECT WRITE of the
	// run's stamped coverage (see above).
	if err := l.db.Exec(`UPDATE cloud_scan_run SET coverage = jsonb_set(coverage, '{surfaces,activity}',
	                        jsonb_build_object('state', 'partial', 'count', 4, 'capped_after', ?::text))
	                      WHERE id = ?`, "arn:aws:iam::"+accountA+":group/ops", run.ID).Error; err != nil {
		t.Fatalf("stamp a capped activity surface: %v", err)
	}
	if act := activity(priyaID); act["state"] != "not_collected" || act["reason"] != "outside_sample" || act["services"] != nil {
		t.Errorf("priya above the cap = %s, want not_collected, outside_sample, services null", idetailJSON(act))
	}
	// ops IS the last sampled identity: collected, its rows from the run.
	if act := activity(opsID); act["state"] != "collected" || len(digl(act, "services")) != 2 {
		t.Errorf("ops at the cap boundary = %s, want collected with its two services", idetailJSON(act))
	}

	// The cloud row now describes a DIFFERENT principal under priya's ARN
	// (recreated, not yet projected): its activity is not hers. DIRECT WRITE:
	// scan and projection always land together in the lab.
	if err := l.db.Exec(`UPDATE cloud_identity SET attrs = jsonb_set(attrs, '{unique_id}', '"AIDAPRIYASUCCESSOR01"')
	                      WHERE id = ?`, cloudPriya).Error; err != nil {
		t.Fatalf("stamp a successor principal: %v", err)
	}
	if err := l.db.Exec(`UPDATE cloud_scan_run SET coverage = jsonb_set(coverage, '{surfaces,activity}',
	                        '{"state":"reached","count":4}'::jsonb) WHERE id = ?`, run.ID).Error; err != nil {
		t.Fatalf("restore the activity surface: %v", err)
	}
	if act := activity(priyaID); act["state"] != "not_collected" || act["reason"] != "not_in_scan" {
		t.Errorf("priya's successor's activity = %s, want not_collected (not_in_scan): never another principal's attempts", idetailJSON(act))
	}

	// A failed surface through the REAL pipeline: every report fails.
	f.activity = &fakeActivity{failJob: true}
	time.Sleep(10 * time.Millisecond)
	s3bScanAndProject(l, a, f)
	if act := activity(opsID); act["state"] != "not_collected" || act["services"] != nil || act["reason"] == nil {
		t.Errorf("activity after every report failed = %s, want not_collected with a reason, services null", idetailJSON(act))
	}
}

// E6/E7 on Permissions: a Sid-keyed edit is a new REVISION of the same
// statement; a detached policy leaves the tab by default and returns with
// include_ended as an ended assignment whose grants ended with it (D-12).
func TestP2IdetailPermissionsRevisionsAndDetach(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-perm-history", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	ticket := a.managed("TicketRead", s3aDoc("ReadTickets", "s3:GetObject", "arn:aws:s3:::support-tickets/*"))
	toolbox := a.managed("ToolboxRead", s3aDoc("", "s3:GetObject", "arn:aws:s3:::support-tickets/*"))
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", toolbox)
	l.scanAndProject(a)
	roleID := idetailIdentityID(t, l, "SharedToolRole")
	path := "/identities/" + roleID.String() + "/permissions"

	a.managed("TicketRead", s3aDoc("ReadTickets", "s3:GetObjectVersion", "arn:aws:s3:::support-tickets/*"))
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	d := dig(idetailGet(t, l.api(), path), "data")
	rt := idetailStatement(t, idetailPolicy(t, digl(d, "policies"), "TicketRead"), "ReadTickets")
	if num(rt, "revision_count") != 2 || fmt.Sprint(dig(rt, "actions")) != "[s3:GetObjectVersion]" {
		t.Errorf("ReadTickets after an edit = %s, want its new actions and two revisions", idetailJSON(rt))
	}
	nosid := digl(idetailPolicy(t, digl(d, "policies"), "ToolboxRead"), "statements")
	if len(nosid) != 1 || digs(nosid[0], "sid") != "" || num(nosid[0], "revision_count") != 0 || num(nosid[0], "index") != 1 {
		t.Errorf("ToolboxRead = %s, want its Sid-less statement, index 1, no recorded revision (§2.6: replaced, never revised)", idetailJSON(nosid))
	}

	a.detach("SharedToolRole", ticket)
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	now := dig(idetailGet(t, l.api(), path), "data")
	if got := fmt.Sprint(idetailNames(digl(now, "policies"), "name")); got != "[ToolboxRead]" {
		t.Errorf("after detach = %v, want [ToolboxRead] (the ended assignment only on request)", got)
	}
	all := dig(idetailGet(t, l.api(), path+qs("include_ended", "true")), "data")
	tr := idetailPolicy(t, digl(all, "policies"), "TicketRead")
	if digs(tr, "assignment", "state") != "ended" || digs(tr, "assignment", "valid_to") == "" ||
		digs(tr, "assignment", "ended_reason") == "" {
		t.Errorf("detached TicketRead = %s, want its ended assignment with valid_to and ended_reason", idetailJSON(tr))
	}
	if g := idetailStatement(t, tr, "ReadTickets"); digs(g, "grant") == "" || digs(g, "grant_state") != "ended" {
		t.Errorf("detached ReadTickets = %s, want its grant, ended with its assignment", idetailJSON(g))
	}
}

// D-49 / D-74 on Permissions: a document with an unusable statement is
// unreadable, so its statements and grants go STALE -- returned and marked,
// with the reason (policy_documents), never shown as current and never
// dropped -- while the attachment, read independently, stays current. The
// tab's meta.coverage names the same gap (D-73).
func TestP2IdetailPermissionsStaleStatements(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-perm-stale", true)
	a := l.account(accountA)
	a.role("MixedRole", "AROAMIXEDROLEMIXEDRO")
	mixed := a.managed("Mixed", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"KeepA","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"},`+
		`{"Sid":"LoseB","Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}`)
	a.attach("MixedRole", mixed)
	l.scanAndProject(a)
	a.iam.managedPolicies[mixed] = `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"KeepA","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"},` +
		`{"Sid":"LoseB","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"}]}`
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)

	body := idetailGet(t, l.api(), "/identities/"+idetailIdentityID(t, l, "MixedRole").String()+"/permissions")
	p := idetailPolicy(t, digl(body, "data", "policies"), "Mixed")
	if digs(p, "assignment", "state") != "current" {
		t.Errorf("Mixed's assignment = %s, want current: the attachment list is read independently of the document", idetailJSON(p["assignment"]))
	}
	for _, sid := range []string{"KeepA", "LoseB"} {
		st := idetailStatement(t, p, sid)
		var named bool
		for _, r := range digl(st, "stale_reason") {
			if digs(r, "surface") == models.SurfacePolicyDocuments && digs(r, "state") == models.CloudCoveragePartial {
				named = true
			}
		}
		if digs(st, "state") != "stale" || !named || digs(st, "grant_state") != "stale" || digs(st, "grant") == "" {
			t.Errorf("%s = %s, want stale with stale_reason policy_documents partial, and its grant, stale", sid, idetailJSON(st))
		}
	}
	var covered bool
	for _, c := range digl(body, "meta", "coverage") {
		if digs(c, "surface") == models.SurfacePolicyDocuments && digs(c, "state") == models.CloudCoveragePartial {
			covered = true
		}
	}
	if !covered {
		t.Errorf("meta.coverage = %s, want the policy_documents gap", idetailJSON(dig(body, "meta", "coverage")))
	}
}
